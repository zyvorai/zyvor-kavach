// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Offline normalisation of exported Zscaler logs (observation only): ZIA NSS web, firewall and DNS
// feeds and ZPA LSS user-activity logs, as JSON, JSON lines, CSV or TSV with a header row. Nothing is
// fetched and nothing contacts Zscaler. Field names are matched after lower-casing and dropping
// every non-alphanumeric character, so `ClientIP`, `client_ip` and `clientip` are one key. Which
// names each feed really emits is documented in docs/zscaler-analytics.md, including the ones that
// could not be verified against Zscaler's own pages.
const (
	zsRecordsMax = 100000
	zsErrorsMax  = 5
	zsFieldsMax  = 200
)

// ZsEvent is one normalised Zscaler record. Kind is web, fw, dns or zpa.
type ZsEvent struct {
	T                              time.Time
	Kind                           string
	Line                           int
	User, Dept, Location           string
	ClientIP, ServerIP, Host, URL  string
	URLCat, URLSuper, URLClass     string
	Action, RawAction, Reason      string // Action is allow, block or other
	Method, Proto                  string
	App, AppClass                  string
	Threat, ThreatCat, ThreatClass string
	ThreatSev                      string
	PageRisk                       int
	DLP                            []string
	FileType                       string
	Unscannable                    string
	Up, Down                       int64
	DPort                          int
	Query, QType                   string
	Country                        string
	Lat, Lon                       float64
	HasGeo                         bool
	Segment, Connector, ConnStatus string
	Policy                         string
}

type zsParsed struct {
	Format   string
	Events   []ZsEvent
	Received int
	Rejected int
	ByKind   map[string]int
	Errors   []string
}

func (p *zsParsed) reject(i int, why string) {
	p.Rejected++
	if len(p.Errors) < zsErrorsMax {
		p.Errors = append(p.Errors, fmt.Sprintf("record %d: %s", i, why))
	}
}

// zsKey folds a field name to lower-case alphanumerics.
func zsKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		}
	}
	return b.String()
}

func zsFlatten(m map[string]any, out map[string]string, depth int) {
	for k, v := range m {
		if len(out) >= zsFieldsMax {
			return
		}
		nk := zsKey(k)
		switch x := v.(type) {
		case string:
			out[nk] = x
		case json.Number:
			out[nk] = x.String()
		case bool:
			out[nk] = strconv.FormatBool(x)
		case []any:
			var parts []string
			for _, e := range x {
				switch y := e.(type) {
				case string:
					parts = append(parts, y)
				case json.Number:
					parts = append(parts, y.String())
				}
			}
			out[nk] = strings.Join(parts, ";")
		case map[string]any:
			if depth < 2 {
				zsFlatten(x, out, depth+1)
			}
		}
	}
}

func zsGet(r map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := r[k]; ok {
			v = strings.TrimSpace(v)
			if v != "" && v != "-" && !strings.EqualFold(v, "none") && !strings.EqualFold(v, "n/a") && v != "NA" {
				return v
			}
		}
	}
	return ""
}

func zsHas(r map[string]string, keys ...string) bool {
	for _, k := range keys {
		if _, ok := r[k]; ok {
			return true
		}
	}
	return false
}

var zsTimeLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "Mon Jan 02 15:04:05 2006", "Mon Jan _2 15:04:05 2006", "Jan 02 15:04:05 2006", "Jan _2 15:04:05 2006", "2006-01-02 15:04:05 MST", "02/Jan/2006:15:04:05 -0700"}

func zsTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 48 {
		return time.Time{}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > 0 {
		switch {
		case f > 1e17:
			return time.Unix(0, int64(f)).UTC()
		case f > 1e14:
			return time.UnixMicro(int64(f)).UTC()
		case f > 1e11:
			return time.UnixMilli(int64(f)).UTC()
		case f > 1e8:
			return time.Unix(int64(f), 0).UTC()
		}
		return time.Time{}
	}
	for _, l := range zsTimeLayouts {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func zsInt(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f < 9e15 {
		return int64(f)
	}
	return 0
}

func zsFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// zsAction folds the per-feed action words (Allowed, Blocked, REQ_BLOCK_DROP, Reject, ...) into allow, block or other.
func zsAction(s string) string {
	l := strings.ToLower(s)
	switch {
	case l == "":
		return ""
	case strings.Contains(l, "block"), strings.Contains(l, "deny"), strings.Contains(l, "denied"), strings.Contains(l, "drop"), strings.Contains(l, "reject"), strings.Contains(l, "reset"), strings.Contains(l, "fail"):
		return "block"
	case strings.Contains(l, "allow"), strings.Contains(l, "permit"), strings.Contains(l, "pass"), strings.Contains(l, "open"), strings.Contains(l, "active"), strings.Contains(l, "success"), strings.Contains(l, "authenticated"):
		return "allow"
	}
	return "other"
}

func zsList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '|' }) {
		p = strings.TrimSpace(p)
		if p != "" && !strings.EqualFold(p, "none") && p != "-" && !strings.EqualFold(p, "n/a") {
			out = append(out, p)
		}
	}
	return out
}

// zsSafeURL drops the query string, fragment and any userinfo so a token in a URL never reaches a finding.
func zsSafeURL(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			if k := strings.LastIndexByte(rest[:j], '@'); k >= 0 {
				rest = rest[k+1:]
			}
		} else if k := strings.LastIndexByte(rest, '@'); k >= 0 {
			rest = rest[k+1:]
		}
		u = u[:i+3] + rest
	}
	return webTruncate(webSanitise(u), 160)
}

func zsHostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.LastIndexByte(u, ':'); i > 0 && !strings.Contains(u[i:], "]") && strings.Count(u, ":") == 1 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

func zsKind(r map[string]string) string {
	switch {
	case zsHas(r, "connectionstatus", "connectorzen", "clientzen", "connectorip", "connectorgroup", "applicationsegment") || (zsHas(r, "application") && zsHas(r, "connector")):
		return "zpa"
	case zsHas(r, "dnsreq", "dnsreqtype", "dnsquery", "dnsresp", "reqaction", "resaction", "dnsrequest"):
		return "dns"
	case zsHas(r, "csip", "cdip", "csport", "cdport", "nwsvc", "stateful", "ssip", "sdip", "cdaddr", "csaddr", "ipcat", "nwapp"):
		return "fw"
	case zsHas(r, "url", "hostname", "urlcategory", "requestmethod", "reqmethod", "appname", "urlclass", "useragent", "threatname", "fullurl", "host"):
		return "web"
	}
	return ""
}

func zsBuild(r map[string]string, line int) (ZsEvent, bool) {
	kind := zsKind(r)
	if kind == "" {
		return ZsEvent{}, false
	}
	e := ZsEvent{Kind: kind, Line: line}
	e.T = zsTime(zsGet(r, "datetime", "logtimestamp", "time", "timestamp", "eventtime", "epochtime", "date", "recordtime", "txtime"))
	e.User = strings.ToLower(zsGet(r, "user", "username", "login", "ouser", "cuser", "usr"))
	e.Dept = zsGet(r, "department", "dept", "departmentname")
	e.Location = zsGet(r, "location", "locationname", "loc")
	e.ClientIP = zsGet(r, "clientip", "cip", "clientpublicip", "csip", "clientprivateip", "srcip")
	e.ServerIP = zsGet(r, "serverip", "sip", "cdip", "sdip", "dstip", "connectorip")
	e.Action = zsAction(zsGet(r, "action", "reqaction", "resaction", "connectionstatus", "policyaction", "fwaction"))
	e.RawAction = webTruncate(webSanitise(zsGet(r, "action", "reqaction", "resaction", "connectionstatus", "policyaction")), 40)
	if kind == "dns" {
		// a block on either the request or the response counts
		if zsAction(zsGet(r, "resaction")) == "block" || zsAction(zsGet(r, "reqaction")) == "block" {
			e.Action = "block"
		}
	}
	e.Reason = webTruncate(webSanitise(zsGet(r, "reason", "internalreason", "blockreason")), 80)
	e.Proto = strings.ToLower(zsGet(r, "protocol", "proto", "nwsvc"))
	e.App = strings.TrimSpace(zsGet(r, "appname", "cloudapp", "cloudapplication", "applicationname", "nwapp", "dnsapp"))
	e.AppClass = zsGet(r, "appclass", "appcategory")
	e.Up, e.Down = zsInt(zsGet(r, "requestsize", "outbytes", "bytestx", "upload", "transactionsize2")), zsInt(zsGet(r, "responsesize", "inbytes", "bytesrx", "download"))
	if e.Up == 0 && e.Down == 0 {
		e.Down = zsInt(zsGet(r, "transactionsize"))
	}
	switch kind {
	case "web":
		e.URL = zsGet(r, "url", "fullurl", "requrl")
		e.Host = strings.ToLower(zsGet(r, "hostname", "host", "serverhostname"))
		if e.Host == "" {
			e.Host = zsHostOf(e.URL)
		}
		e.URLCat = zsGet(r, "urlcategory", "urlcat")
		e.URLSuper = zsGet(r, "urlsupercategory", "urlsupercat")
		e.URLClass = zsGet(r, "urlclass")
		e.Method = strings.ToUpper(zsGet(r, "requestmethod", "reqmethod", "method"))
		e.Threat = zsGet(r, "threatname", "malwarename", "virusname")
		e.ThreatCat = zsGet(r, "threatcategory", "malwarecategory", "malwarecat")
		e.ThreatClass = zsGet(r, "threatclass", "malwareclass")
		e.ThreatSev = zsGet(r, "threatseverity", "severity")
		e.PageRisk = int(zsInt(zsGet(r, "pagerisk", "risk", "pagerisks")))
		e.DLP = append(zsList(zsGet(r, "dlpdictionaries", "dlpdictnames", "dlpdictionary", "dlpdict")), zsList(zsGet(r, "dlpengine", "dlpenginenames", "dlpengines"))...)
		e.FileType = zsGet(r, "filetype", "fileclass")
		e.Unscannable = zsGet(r, "unscannabletype", "unscannable")
	case "fw":
		e.DPort = int(zsInt(zsGet(r, "cdport", "sdport", "dstport", "dport")))
		e.Host = strings.ToLower(zsGet(r, "cdip", "sdip", "dstip", "serverip"))
		e.ClientIP = zsGet(r, "csip", "ssip", "clientip", "srcip")
		e.ThreatCat = zsGet(r, "threatcat", "threatcategory", "ipcat")
		e.Threat = zsGet(r, "threatname")
		e.URLCat = zsGet(r, "ipcat", "urlcategory")
		e.Country = zsGet(r, "destcountry")
	case "dns":
		e.Query = strings.ToLower(strings.TrimSuffix(zsGet(r, "dnsreq", "dnsquery", "query", "dnsrequest", "qname"), "."))
		e.QType = strings.ToUpper(zsGet(r, "dnsreqtype", "qtype", "dnstype"))
		e.Host = e.Query
		e.URLCat = zsGet(r, "category", "dnscategory", "urlcategory")
		e.DPort = int(zsInt(zsGet(r, "srvdport", "dport")))
	case "zpa":
		e.Host = strings.ToLower(zsGet(r, "host", "hostname", "domain"))
		e.Segment = zsGet(r, "application", "applicationsegment", "appsegment", "appname")
		e.App = e.Segment
		e.Connector = zsGet(r, "connector", "connectorgroup")
		e.ConnStatus = zsGet(r, "connectionstatus")
		e.Policy = zsGet(r, "policy", "policyname")
		e.Country = strings.ToUpper(zsGet(r, "clientcountrycode", "clientcountry", "country"))
		e.ClientIP = zsGet(r, "clientpublicip", "clientip", "publicip")
		if la, ok := zsFloat(zsGet(r, "clientlatitude", "latitude", "lat")); ok {
			if lo, ok2 := zsFloat(zsGet(r, "clientlongitude", "longitude", "lon")); ok2 && math.Abs(la) <= 90 && math.Abs(lo) <= 180 && (la != 0 || lo != 0) {
				e.Lat, e.Lon, e.HasGeo = la, lo, true
			}
		}
		e.DPort = int(zsInt(zsGet(r, "port", "serverport")))
		if e.Action == "" {
			e.Action = "other"
		}
	}
	if kind != "zpa" && e.Country == "" {
		e.Country = strings.ToUpper(zsGet(r, "clientcountry", "clientcountrycode"))
	}
	e.User = webTruncate(webSanitise(e.User), 120)
	e.Host = webTruncate(webSanitise(e.Host), 200)
	e.URL = zsSafeURL(e.URL)
	return e, true
}

func zsDelim(head string) rune {
	tabs, commas := strings.Count(head, "\t"), strings.Count(head, ",")
	if tabs > commas {
		return '\t'
	}
	return ','
}

// zsParseLog reads JSON, JSON lines, CSV or TSV (format auto, json, csv or tsv).
func zsParseLog(raw []byte, format string) (*zsParsed, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil, fmt.Errorf("empty log")
	}
	p := &zsParsed{ByKind: map[string]int{}}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		if trim[0] == '{' || trim[0] == '[' {
			format = "json"
		} else {
			head := string(trim[:min(len(trim), 4096)])
			if i := strings.IndexByte(head, '\n'); i >= 0 {
				head = head[:i]
			}
			if zsDelim(head) == '\t' {
				format = "tsv"
			} else {
				format = "csv"
			}
		}
	}
	p.Format = format
	add := func(i int, rec map[string]string) {
		p.Received++
		if p.Received > zsRecordsMax {
			return
		}
		e, ok := zsBuild(rec, i)
		if !ok {
			p.reject(i, "no recognised Zscaler field names")
			return
		}
		p.Events = append(p.Events, e)
		p.ByKind[e.Kind]++
	}
	switch format {
	case "json":
		dec := json.NewDecoder(bytes.NewReader(trim))
		dec.UseNumber()
		i := 0
		for {
			var v any
			if err := dec.Decode(&v); err != nil {
				if err != io.EOF {
					p.reject(i+1, "invalid JSON")
				}
				break
			}
			emit := func(x any) {
				i++
				m, ok := x.(map[string]any)
				if !ok {
					p.Received++
					p.reject(i, "not a JSON object")
					return
				}
				rec := map[string]string{}
				zsFlatten(m, rec, 0)
				add(i, rec)
			}
			if arr, ok := v.([]any); ok {
				for _, x := range arr {
					emit(x)
					if p.Received > zsRecordsMax {
						return nil, errNetTooMany
					}
				}
			} else {
				emit(v)
			}
			if p.Received > zsRecordsMax {
				return nil, errNetTooMany
			}
		}
	case "csv", "tsv":
		rd := csv.NewReader(bytes.NewReader(trim))
		rd.LazyQuotes = true
		rd.FieldsPerRecord = -1
		if format == "tsv" {
			rd.Comma = '\t'
		}
		hdr, err := rd.Read()
		if err != nil {
			return nil, fmt.Errorf("could not read a header row")
		}
		keys := make([]string, len(hdr))
		for i, h := range hdr {
			keys[i] = zsKey(h)
		}
		for i := 1; ; i++ {
			row, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				p.Received++
				p.reject(i, "unreadable row")
				continue
			}
			rec := map[string]string{}
			for j, v := range row {
				if j < len(keys) && keys[j] != "" {
					rec[keys[j]] = v
				}
			}
			add(i, rec)
			if p.Received > zsRecordsMax {
				return nil, errNetTooMany
			}
		}
	default:
		return nil, fmt.Errorf("unknown format %q (use auto, json, csv or tsv)", webTruncate(webSanitise(format), 20))
	}
	return p, nil
}
