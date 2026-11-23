// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Offline network-log normalisation (observation only). Logs that operators export from Zeek,
// Suricata, cloud flow logs, NetFlow/IPFIX CSV, DNS query logs and a documented subset of firewall
// logs are parsed into one small NetEvent model. Nothing is captured, fetched or looked up; free
// text is sanitised and credential-looking values redacted before it can reach a finding.
const (
	netLinesMax   = 100000
	netErrorsMax  = 5
	netAnswersMax = 16
	netMsgMax     = 200
)

// NetEvent is one normalised network record. Kind is one of conn, flow, dns, tls, http, ssh, alert,
// fw, notice, smb, x509 or other.
type NetEvent struct {
	T                    time.Time
	Kind                 string
	Src, Dst             string
	SrcA, DstA           netip.Addr
	SPort, DPort         int
	Proto                string
	Service              string
	OrigBytes, RespBytes int64
	Dur                  float64
	State                string
	Start                bool   // counts as a new connection attempt (not a continuation record)
	Action               string // allow, deny or ""
	Query, QType, RCode  string
	Answers              []string
	TTL                  int // smallest answer TTL, -1 when unknown
	JA3, JA3S, JA4, SNI  string
	Subject, Issuer      string
	NotAfter             time.Time
	SelfSigned           bool
	Sig, Category, SigID string
	Sev                  int
	Note, Msg            string
	AuthOK               int // ssh: 1 success, 0 failure, -1 unknown
	Source               string
	User                 string
}

type netParsed struct {
	Format   string
	Events   []NetEvent
	Received int
	Rejected int
	ByKind   map[string]int
	Errors   []string
}

func (p *netParsed) reject(i int, why string) {
	p.Rejected++
	if len(p.Errors) < netErrorsMax {
		p.Errors = append(p.Errors, fmt.Sprintf("record %d: %s", i, why))
	}
}

func (p *netParsed) add(e NetEvent) {
	p.Events = append(p.Events, e)
	p.ByKind[e.Kind]++
}

var errNetTooMany = errors.New("too many records")

var netSecretRe = regexp.MustCompile(`(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth\w*|cookie|session\w*|bearer|credential\w*|private[_-]?key)(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`)
var netUserinfoRe = regexp.MustCompile(`(?i)(://[^/\s:@]+):[^@\s/]+@`)
var netBearerRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)

// netRedact removes credential-looking values from free text and bounds its length.
func netRedact(s string) string {
	s = webSanitise(webTruncate(s, 4*netMsgMax))
	s = netUserinfoRe.ReplaceAllString(s, "$1:REDACTED@")
	s = netBearerRe.ReplaceAllString(s, "$1 REDACTED")
	s = netSecretRe.ReplaceAllString(s, "$1$2REDACTED")
	return webTruncate(s, netMsgMax)
}

func netPrivate(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // carrier-grade NAT
			return true
		}
	}
	return false
}

func netParseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" || len(s) > 64 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func netPort(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return -1
	}
	return n
}

func netInt64(s string) int64 {
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

func netFloat(s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 || f > 1e9 {
		return 0
	}
	return f
}

func netBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "t", "true", "1", "yes":
		return true
	}
	return false
}

func netProto(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "6", "tcp", "t":
		return "tcp"
	case "17", "udp", "u":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "58", "icmp6", "ipv6-icmp", "icmpv6":
		return "icmp6"
	case "", "-":
		return ""
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "ip" + s
	}
	return webTruncate(webSanitise(s), 12)
}

// netSetTuple fills addresses and ports; it needs at least one valid address.
func netSetTuple(e *NetEvent, src, sp, dst, dp string) bool {
	sa, ok1 := netParseAddr(src)
	da, ok2 := netParseAddr(dst)
	if !ok1 && !ok2 {
		return false
	}
	if ok1 {
		e.Src, e.SrcA = sa.String(), sa
	}
	if ok2 {
		e.Dst, e.DstA = da.String(), da
	}
	e.SPort, e.DPort = netPort(sp), netPort(dp)
	return true
}

func netList(f map[string]string, raw map[string]any, key string) []string {
	var out []string
	if raw != nil {
		if arr, ok := raw[key].([]any); ok {
			for _, x := range arr {
				switch v := x.(type) {
				case string:
					out = append(out, v)
				case float64:
					out = append(out, strconv.FormatFloat(v, 'f', -1, 64))
				}
				if len(out) >= netAnswersMax {
					break
				}
			}
			return out
		}
	}
	if v := f[key]; v != "" && v != "-" {
		for _, p := range strings.Split(v, ",") {
			out = append(out, p)
			if len(out) >= netAnswersMax {
				break
			}
		}
	}
	return out
}

func netCleanQuery(q string) string {
	q = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(webSanitise(q)), "."))
	return webTruncate(q, 255)
}

// ---------------------------------------------------------------------------------------------
// entry point

// netParseLog normalises one uploaded log. format is auto, zeek, eve, dns, vpc, nsg, flowcsv,
// panos, fortigate or asa.
func netParseLog(raw []byte, format string) (*netParsed, error) {
	p := &netParsed{ByKind: map[string]int{}}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.ReplaceAll(text, "\x00", "")
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		format = netSniff(text)
	}
	p.Format = format
	switch format {
	case "zeek":
		return p, netParseZeek(text, p)
	case "eve", "dns", "zeek-json":
		return p, netParseJSONLines(text, p, format)
	case "nsg":
		return p, netParseNSG(raw, p)
	case "vpc":
		return p, netParseVPC(text, p)
	case "flowcsv", "dnscsv":
		return p, netParseCSV(text, p)
	case "panos", "fortigate", "asa":
		return p, netParseFirewall(text, p, format)
	}
	return nil, fmt.Errorf("unknown or undetectable format %q (zeek|eve|dns|vpc|nsg|flowcsv|panos|fortigate|asa)", format)
}

func netFirstLine(text string) string {
	for _, l := range strings.Split(webTruncate(text, 1<<16), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

func netSniff(text string) string {
	l := netFirstLine(text)
	low := strings.ToLower(l)
	switch {
	case strings.HasPrefix(l, "#separator") || strings.HasPrefix(l, "#fields") || strings.HasPrefix(l, "#set_separator"):
		return "zeek"
	case strings.Contains(l, "%ASA-") || strings.Contains(l, "%FTD-"):
		return "asa"
	case strings.Contains(l, ",TRAFFIC,") || strings.Contains(l, ",THREAT,") || strings.Contains(l, ",CONFIG,") || strings.Contains(l, ",SYSTEM,"):
		return "panos"
	case strings.Contains(l, "devname=") || strings.Contains(l, "logid="):
		return "fortigate"
	case strings.HasPrefix(low, "version account-id") || strings.HasPrefix(low, "version "):
		return "vpc"
	case strings.HasPrefix(l, "{") || strings.HasPrefix(l, "["):
		head := webTruncate(text, 8192)
		if strings.Contains(webTruncate(text, 4096), `"flowTuples"`) || (strings.Contains(webTruncate(text, 4096), `"NetworkSecurityGroupFlowEvent"`)) || strings.Contains(webTruncate(text, 1024), `"records"`) && strings.Contains(webTruncate(text, 16384), `"flows"`) {
			return "nsg"
		}
		if strings.Contains(l, `"event_type"`) {
			return "eve"
		}
		if strings.Contains(head, `"id.orig_h"`) || strings.Contains(head, `"uid"`) || strings.Contains(head, `"_path"`) || strings.Contains(head, `"note"`) {
			return "zeek-json"
		}
		return "dns"
	case strings.Count(l, ",") >= 3:
		h := strings.ToLower(l)
		if strings.Contains(h, "ibyt") || strings.Contains(h, "srcaddr") || strings.Contains(h, "src_ip") || strings.Contains(h, "sa,") || strings.Contains(h, "bytes") {
			return "flowcsv"
		}
		return "dnscsv"
	}
	return "unknown"
}

func netLines(text string) ([]string, error) {
	lines := strings.Split(text, "\n")
	n := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	if n > netLinesMax {
		return nil, errNetTooMany
	}
	return lines, nil
}

// ---------------------------------------------------------------------------------------------
// Zeek

func netParseZeek(text string, p *netParsed) error {
	lines, err := netLines(text)
	if err != nil {
		return err
	}
	sep, unset, empty := "\t", "-", "(empty)"
	var fields []string
	path := ""
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p.Received++
		if len(line) > webLineMax {
			p.reject(i, "line too long")
			continue
		}
		if line[0] == '#' {
			p.Received--
			k, v, _ := strings.Cut(line, sep)
			if strings.HasPrefix(line, "#separator") {
				v = strings.TrimSpace(strings.TrimPrefix(line, "#separator"))
				if strings.HasPrefix(v, `\x`) {
					if b, err := hex.DecodeString(v[2:]); err == nil && len(b) == 1 {
						sep = string(b)
					}
				}
				continue
			}
			switch k {
			case "#fields":
				fields = strings.Split(v, sep)
				if len(fields) > 200 {
					fields = fields[:200]
				}
			case "#path":
				path = strings.ToLower(webTruncate(webSanitise(strings.TrimSpace(v)), 32))
			case "#unset_field":
				unset = v
			case "#empty_field":
				empty = v
			case "#close", "#open", "#types", "#set_separator":
			}
			continue
		}
		if fields == nil {
			p.reject(i, "data line before #fields header")
			continue
		}
		parts := strings.Split(line, sep)
		if len(parts) != len(fields) {
			p.reject(i, "field count does not match #fields")
			continue
		}
		f := make(map[string]string, len(parts))
		for j, v := range parts {
			if v == unset {
				continue
			}
			if v == empty {
				v = ""
			}
			f[fields[j]] = v
		}
		ev, why := zeekEvent(path, f, nil)
		if why != "" {
			p.reject(i, why)
			continue
		}
		p.add(ev)
	}
	return nil
}

func netZeekInfer(f map[string]string) string {
	has := func(k string) bool { _, ok := f[k]; return ok }
	switch {
	case has("_path"):
		return strings.ToLower(f["_path"])
	case has("note") && has("msg"):
		return "notice"
	case has("auth_success") || has("auth_attempts"):
		return "ssh"
	case has("query") && (has("qtype_name") || has("qtype") || has("rcode_name")):
		return "dns"
	case has("ja3") || has("server_name") || has("cert_chain_fps") || has("validation_status"):
		return "ssl"
	case has("certificate.subject") || has("certificate.issuer"):
		return "x509"
	case has("method") && (has("uri") || has("host")):
		return "http"
	case has("conn_state") || has("orig_bytes") || has("duration") || has("history"):
		return "conn"
	}
	return "other"
}

func zeekEvent(path string, f map[string]string, raw map[string]any) (NetEvent, string) {
	var e NetEvent
	t, ok := parseWebTime(f["ts"])
	if !ok {
		return e, "no parseable ts"
	}
	e.T, e.Source, e.TTL, e.AuthOK = t, "zeek", -1, -1
	if path == "" {
		path = netZeekInfer(f)
	}
	tuple := func() bool {
		return netSetTuple(&e, f["id.orig_h"], f["id.orig_p"], f["id.resp_h"], f["id.resp_p"])
	}
	switch path {
	case "conn":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind, e.Start = "conn", true
		e.Proto, e.Service, e.State = netProto(f["proto"]), webTruncate(webSanitise(f["service"]), 24), webTruncate(webSanitise(f["conn_state"]), 8)
		e.Dur = netFloat(f["duration"])
		e.OrigBytes, e.RespBytes = netInt64(f["orig_bytes"]), netInt64(f["resp_bytes"])
	case "dns":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind, e.Start, e.Proto = "dns", true, netProto(f["proto"])
		e.Query = netCleanQuery(f["query"])
		if e.Query == "" {
			return e, "dns record without query"
		}
		e.QType = strings.ToUpper(webTruncate(webSanitise(f["qtype_name"]), 12))
		e.RCode = strings.ToUpper(webTruncate(webSanitise(f["rcode_name"]), 16))
		for _, a := range netList(f, raw, "answers") {
			e.Answers = append(e.Answers, webTruncate(webSanitise(a), 255))
		}
		for _, s := range netList(f, raw, "TTLs") {
			if v, err := strconv.ParseFloat(s, 64); err == nil && v >= 0 && (e.TTL < 0 || int(v) < e.TTL) {
				e.TTL = int(v)
			}
		}
	case "ssl", "tls":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind, e.Start = "tls", true
		e.SNI = netCleanQuery(f["server_name"])
		e.JA3, e.JA3S, e.JA4 = strings.ToLower(webTruncate(f["ja3"], 64)), strings.ToLower(webTruncate(f["ja3s"], 64)), webTruncate(webSanitise(f["ja4"]), 64)
		e.Subject, e.Issuer = netRedact(f["subject"]), netRedact(f["issuer"])
		e.Msg = webTruncate(webSanitise(f["validation_status"]), 80)
		if f["subject"] != "" && f["subject"] == f["issuer"] || strings.Contains(strings.ToLower(f["validation_status"]), "self signed") {
			e.SelfSigned = true
		}
		e.State = "established"
		if f["established"] != "" && !netBool(f["established"]) {
			e.State = "failed"
		}
	case "x509":
		e.Kind = "x509"
		e.Subject, e.Issuer = netRedact(f["certificate.subject"]), netRedact(f["certificate.issuer"])
		if f["certificate.subject"] != "" && f["certificate.subject"] == f["certificate.issuer"] {
			e.SelfSigned = true
		}
		if t, ok := parseWebTime(f["certificate.not_valid_after"]); ok {
			e.NotAfter = t
		}
		e.SNI = netCleanQuery(webPick(f, "san.dns"))
	case "http":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind, e.Start = "http", true
		e.SNI = netCleanQuery(f["host"])
		e.Msg = webTruncate(webSanitise(f["status_code"]), 8)
	case "ssh":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind, e.Start = "ssh", true
		switch {
		case f["auth_success"] == "":
		case netBool(f["auth_success"]):
			e.AuthOK = 1
		default:
			e.AuthOK = 0
		}
	case "notice":
		e.Kind = "notice"
		_ = netSetTuple(&e, webPick(f, "src", "id.orig_h"), "", webPick(f, "dst", "id.resp_h"), webPick(f, "p", "id.resp_p"))
		e.DPort = netPort(webPick(f, "p", "id.resp_p"))
		e.Note = webTruncate(webSanitise(f["note"]), 64)
		e.Msg = netRedact(f["msg"])
		if e.Note == "" {
			return e, "notice without note"
		}
	case "smb_files", "smb_mapping", "dce_rpc":
		if !tuple() {
			return e, "no valid address"
		}
		e.Kind = "smb"
		e.Note = path
		e.Msg = netRedact(webPick(f, "path", "name", "operation", "endpoint"))
		if path == "dce_rpc" {
			e.Msg = netRedact(webPick(f, "endpoint") + "::" + webPick(f, "operation"))
		}
		if a := webPick(f, "action"); a != "" {
			e.Msg += " " + netRedact(a)
		}
	default:
		e.Kind = "other"
		e.Note = webTruncate(webSanitise(path), 24)
		_ = tuple()
	}
	return e, ""
}

// ---------------------------------------------------------------------------------------------
// JSON lines: Suricata EVE, Zeek JSON and generic DNS logs

func netJSONObjects(text string, p *netParsed) ([]map[string]any, error) {
	trim := strings.TrimSpace(text)
	if strings.HasPrefix(trim, "[") {
		var arr []any
		if err := json.Unmarshal([]byte(trim), &arr); err != nil {
			return nil, errors.New("invalid JSON array")
		}
		if len(arr) > netLinesMax {
			return nil, errNetTooMany
		}
		out := make([]map[string]any, 0, len(arr))
		for _, x := range arr {
			m, _ := x.(map[string]any)
			out = append(out, m)
		}
		return out, nil
	}
	lines, err := netLines(text)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > webLineMax {
			out = append(out, nil)
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			out = append(out, nil)
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func netParseJSONLines(text string, p *netParsed, format string) error {
	objs, err := netJSONObjects(text, p)
	if err != nil {
		return err
	}
	for i, m := range objs {
		p.Received++
		if m == nil {
			p.reject(i, "not a JSON object")
			continue
		}
		f := map[string]string{}
		webFlatten(m, "", 0, f)
		var ev NetEvent
		var why string
		switch {
		case format == "eve" || (f["event_type"] != "" && format != "zeek-json"):
			ev, why = eveEvent(f, m)
		case format == "zeek-json":
			ev, why = zeekEvent(strings.ToLower(f["_path"]), f, m)
		default:
			ev, why = netDNSGeneric(f, m)
		}
		if why != "" {
			p.reject(i, why)
			continue
		}
		p.add(ev)
	}
	return nil
}

func eveEvent(f map[string]string, m map[string]any) (NetEvent, string) {
	var e NetEvent
	t, ok := parseWebTime(f["timestamp"])
	if !ok {
		return e, "no parseable timestamp"
	}
	e.T, e.Source, e.TTL, e.AuthOK = t, "suricata", -1, -1
	if !netSetTuple(&e, f["src_ip"], f["src_port"], f["dest_ip"], f["dest_port"]) {
		return e, "no valid address"
	}
	e.Proto = netProto(f["proto"])
	e.Service = webTruncate(webSanitise(strings.ToLower(f["app_proto"])), 24)
	switch f["event_type"] {
	case "alert":
		e.Kind = "alert"
		e.Sig = netRedact(f["alert.signature"])
		e.Category = strings.ToLower(webTruncate(webSanitise(f["alert.category"]), 80))
		e.SigID = webTruncate(webSanitise(f["alert.signature_id"]), 12)
		e.Sev = netPort(f["alert.severity"])
		e.Action = "allow"
		if f["alert.action"] == "blocked" {
			e.Action = "deny"
		}
		if e.Sig == "" {
			return e, "alert without signature"
		}
	case "flow":
		e.Kind, e.Start = "flow", true
		e.OrigBytes, e.RespBytes = netInt64(f["flow.bytes_toserver"]), netInt64(f["flow.bytes_toclient"])
		e.Dur = netFloat(f["flow.age"])
		e.State = webTruncate(webSanitise(f["flow.state"]), 16)
	case "dns":
		e.Kind, e.Start = "dns", true
		q := webPick(f, "dns.rrname")
		if q == "" {
			return e, "dns event without rrname"
		}
		e.Query = netCleanQuery(q)
		e.QType = strings.ToUpper(webTruncate(webSanitise(webPick(f, "dns.rrtype")), 12))
		e.RCode = strings.ToUpper(webTruncate(webSanitise(webPick(f, "dns.rcode")), 16))
		if d, ok := m["dns"].(map[string]any); ok {
			if arr, ok := d["answers"].([]any); ok {
				for _, x := range arr {
					if am, ok := x.(map[string]any); ok {
						if s, ok := am["rdata"].(string); ok && len(e.Answers) < netAnswersMax {
							e.Answers = append(e.Answers, webTruncate(webSanitise(s), 255))
						}
						if ttl, ok := am["ttl"].(float64); ok && ttl >= 0 && (e.TTL < 0 || int(ttl) < e.TTL) {
							e.TTL = int(ttl)
						}
					}
				}
			}
			if s, ok := d["rdata"].(string); ok && len(e.Answers) == 0 {
				e.Answers = append(e.Answers, webTruncate(webSanitise(s), 255))
			}
			if ttl, ok := d["ttl"].(float64); ok && ttl >= 0 {
				e.TTL = int(ttl)
			}
		}
	case "tls":
		e.Kind, e.Start = "tls", true
		e.SNI = netCleanQuery(f["tls.sni"])
		e.JA3 = strings.ToLower(webTruncate(webPick(f, "tls.ja3.hash", "tls.ja3"), 64))
		e.JA3S = strings.ToLower(webTruncate(webPick(f, "tls.ja3s.hash", "tls.ja3s"), 64))
		e.JA4 = webTruncate(webSanitise(webPick(f, "tls.ja4")), 64)
		e.Subject, e.Issuer = netRedact(f["tls.subject"]), netRedact(f["tls.issuerdn"])
		if e.Issuer == "" {
			e.Issuer = netRedact(f["tls.issuer"])
		}
		e.SelfSigned = e.Subject != "" && e.Subject == e.Issuer
		if t, ok := parseWebTime(f["tls.notafter"]); ok {
			e.NotAfter = t
		}
		e.State = "established"
	case "http":
		e.Kind, e.Start = "http", true
		e.SNI = netCleanQuery(f["http.hostname"])
		e.Msg = webTruncate(webSanitise(f["http.status"]), 8)
	default:
		e.Kind = "other"
		e.Note = webTruncate(webSanitise(f["event_type"]), 24)
	}
	return e, ""
}

var dnsRCodeNames = map[string]string{"0": "NOERROR", "2": "SERVFAIL", "3": "NXDOMAIN", "5": "REFUSED"}

func netDNSGeneric(f map[string]string, m map[string]any) (NetEvent, string) {
	var e NetEvent
	t, ok := parseWebTime(webPick(f, "ts", "time", "timestamp", "@timestamp", "datetime", "_time"))
	if !ok {
		return e, "no parseable timestamp"
	}
	e.T, e.Source, e.TTL, e.AuthOK = t, "dns", -1, -1
	e.Kind, e.Start = "dns", true
	e.Query = netCleanQuery(webPick(f, "qname", "query", "domain", "name", "dns.question.name", "queryname", "rrname"))
	if e.Query == "" {
		return e, "no query name"
	}
	cl := webPick(f, "client", "src_ip", "src", "source_ip", "clientip", "client_ip", "id.orig_h", "srcip", "internalip", "source.ip", "srcaddr")
	if _, ok := netParseAddr(cl); !ok {
		return e, "no valid client address"
	}
	_ = netSetTuple(&e, cl, "", webPick(f, "resolver", "dst_ip", "server", "dst", "id.resp_h"), "53")
	e.QType = strings.ToUpper(webTruncate(webSanitise(webPick(f, "qtype", "qtype_name", "querytype", "dns.question.type", "rrtype")), 12))
	rc := strings.ToUpper(webTruncate(webSanitise(webPick(f, "rcode", "rcode_name", "response_code", "responsecode", "dns.response_code")), 16))
	if n, ok := dnsRCodeNames[rc]; ok {
		rc = n
	}
	e.RCode = rc
	for _, a := range netList(f, m, "answers") {
		e.Answers = append(e.Answers, webTruncate(webSanitise(a), 255))
	}
	if v := webPick(f, "ttl", "min_ttl"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			e.TTL = n
		}
	}
	return e, ""
}

// ---------------------------------------------------------------------------------------------
// CSV flow / DNS exports

var netCSVAlias = map[string][]string{
	"time":    {"ts", "time", "timestamp", "first_switched", "start", "flow_start", "start_time", "flowstart", "te", "datetime", "@timestamp"},
	"src":     {"sa", "srcaddr", "src", "src_ip", "sourceipv4address", "sourceaddress", "source_ip", "client", "client_ip", "clientip", "internalip"},
	"dst":     {"da", "dstaddr", "dst", "dst_ip", "destinationipv4address", "destinationaddress", "dest_ip", "destination_ip"},
	"sport":   {"sp", "srcport", "src_port", "sourcetransportport", "source_port"},
	"dport":   {"dp", "dstport", "dst_port", "destinationtransportport", "dest_port", "destination_port"},
	"proto":   {"pr", "proto", "protocol", "protocolidentifier"},
	"bytes":   {"ibyt", "bytes", "octetdeltacount", "in_bytes", "byt", "total_bytes"},
	"rbytes":  {"obyt", "out_bytes", "resp_bytes", "reverseoctetdeltacount"},
	"action":  {"action", "flowstatus", "disposition"},
	"query":   {"qname", "query", "domain", "queryname", "domain_name"},
	"qtype":   {"qtype", "querytype", "query_type", "qtype_name"},
	"rcode":   {"rcode", "responsecode", "response_code", "rcode_name"},
	"answers": {"answers", "answer", "resolved_ips"},
	"ttl":     {"ttl", "min_ttl"},
}

func netParseCSV(text string, p *netParsed) error {
	if _, err := netLines(text); err != nil {
		return err
	}
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = false
	recs, err := r.ReadAll()
	if err != nil && len(recs) == 0 {
		return errors.New("invalid CSV")
	}
	if len(recs) < 2 {
		return errors.New("CSV needs a header row and at least one record")
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		for k, names := range netCSVAlias {
			for _, n := range names {
				if h == n {
					if _, dup := idx[k]; !dup {
						idx[k] = i
					}
				}
			}
		}
	}
	get := func(rec []string, k string) string {
		if i, ok := idx[k]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	_, isDNS := idx["query"]
	if _, ok := idx["time"]; !ok {
		return errors.New("CSV header has no recognised time column")
	}
	if !isDNS {
		if _, ok := idx["src"]; !ok {
			return errors.New("CSV header has no recognised source address column")
		}
	}
	for i, rec := range recs[1:] {
		p.Received++
		total := 0
		for _, c := range rec {
			total += len(c)
		}
		if total > webLineMax {
			p.reject(i+1, "record too long")
			continue
		}
		t, ok := parseWebTime(get(rec, "time"))
		if !ok {
			p.reject(i+1, "no parseable time")
			continue
		}
		var e NetEvent
		e.T, e.TTL, e.AuthOK = t, -1, -1
		if isDNS {
			f := map[string]string{"ts": get(rec, "time"), "qname": get(rec, "query"), "client": get(rec, "src"), "qtype": get(rec, "qtype"), "rcode": get(rec, "rcode"), "answers": get(rec, "answers"), "ttl": get(rec, "ttl")}
			ev, why := netDNSGeneric(f, nil)
			if why != "" {
				p.reject(i+1, why)
				continue
			}
			p.add(ev)
			continue
		}
		if !netSetTuple(&e, get(rec, "src"), get(rec, "sport"), get(rec, "dst"), get(rec, "dport")) {
			p.reject(i+1, "no valid address")
			continue
		}
		e.Kind, e.Source, e.Start = "flow", "flowcsv", true
		e.Proto = netProto(get(rec, "proto"))
		e.OrigBytes, e.RespBytes = netInt64(get(rec, "bytes")), netInt64(get(rec, "rbytes"))
		switch strings.ToLower(get(rec, "action")) {
		case "accept", "allow", "allowed", "permit", "pass":
			e.Action = "allow"
		case "reject", "deny", "denied", "drop", "block", "blocked":
			e.Action = "deny"
		}
		p.add(e)
	}
	return nil
}

// AWS VPC flow logs, default (version 2) space-separated format or a custom header line.
var netVPCDefault = strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status")

func netParseVPC(text string, p *netParsed) error {
	lines, err := netLines(text)
	if err != nil {
		return err
	}
	cols := netVPCDefault
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > webLineMax {
			p.Received++
			p.reject(i, "line too long")
			continue
		}
		parts := strings.Fields(line)
		if parts[0] == "version" {
			cols = make([]string, len(parts))
			for j, c := range parts {
				cols[j] = strings.ToLower(c)
			}
			continue
		}
		p.Received++
		f := map[string]string{}
		for j, v := range parts {
			if j < len(cols) && v != "-" {
				f[cols[j]] = v
			}
		}
		if f["log-status"] == "NODATA" || f["log-status"] == "SKIPDATA" {
			p.reject(i, "no data in interval")
			continue
		}
		src, dst := webPick(f, "pkt-srcaddr", "srcaddr"), webPick(f, "pkt-dstaddr", "dstaddr")
		var e NetEvent
		if !netSetTuple(&e, src, f["srcport"], dst, f["dstport"]) {
			p.reject(i, "no valid address")
			continue
		}
		t, ok := parseWebTime(f["start"])
		if !ok {
			p.reject(i, "no parseable start")
			continue
		}
		e.T, e.Kind, e.Source, e.TTL, e.AuthOK, e.Start = t, "flow", "vpc", -1, -1, true
		e.Proto = netProto(f["protocol"])
		e.OrigBytes = netInt64(f["bytes"])
		if end, ok := parseWebTime(f["end"]); ok && end.After(t) && end.Sub(t) < 24*time.Hour {
			e.Dur = end.Sub(t).Seconds()
		}
		switch strings.ToUpper(f["action"]) {
		case "ACCEPT":
			e.Action = "allow"
		case "REJECT":
			e.Action = "deny"
		}
		p.add(e)
	}
	return nil
}

// Azure NSG flow logs, JSON version 1 or 2.
func netParseNSG(raw []byte, p *netParsed) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return errors.New("invalid JSON")
	}
	var recs []any
	switch v := doc.(type) {
	case map[string]any:
		if r, ok := v["records"].([]any); ok {
			recs = r
		} else {
			recs = []any{v}
		}
	case []any:
		recs = v
	}
	n := 0
	for ri, r := range recs {
		rm, _ := r.(map[string]any)
		props, _ := rm["properties"].(map[string]any)
		if props == nil {
			p.Received++
			p.reject(ri, "record without properties")
			continue
		}
		rt, _ := parseWebTime(strAny(rm["time"]))
		flows, _ := props["flows"].([]any)
		for _, rule := range flows {
			rulem, _ := rule.(map[string]any)
			inner, _ := rulem["flows"].([]any)
			for _, fl := range inner {
				flm, _ := fl.(map[string]any)
				tuples, _ := flm["flowTuples"].([]any)
				for _, tup := range tuples {
					s, _ := tup.(string)
					p.Received++
					n++
					if n > netLinesMax {
						return errNetTooMany
					}
					if len(s) > 512 {
						p.reject(n, "tuple too long")
						continue
					}
					c := strings.Split(s, ",")
					if len(c) < 8 {
						p.reject(n, "short flow tuple")
						continue
					}
					var e NetEvent
					if !netSetTuple(&e, c[1], c[3], c[2], c[4]) {
						p.reject(n, "no valid address")
						continue
					}
					t, ok := parseWebTime(c[0])
					if !ok {
						t = rt
					}
					if t.IsZero() {
						p.reject(n, "no timestamp")
						continue
					}
					e.T, e.Kind, e.Source, e.TTL, e.AuthOK = t, "flow", "nsg", -1, -1
					e.Proto = netProto(c[5])
					if c[7] == "A" {
						e.Action = "allow"
					} else if c[7] == "D" {
						e.Action = "deny"
					}
					if c[6] == "I" {
						e.State = "inbound"
					} else {
						e.State = "outbound"
					}
					if len(c) >= 13 {
						e.Start = c[8] == "B"
						e.OrigBytes, e.RespBytes = netInt64(c[10]), netInt64(c[12])
					} else {
						e.Start = true
					}
					p.add(e)
				}
			}
		}
	}
	return nil
}

func strAny(v any) string {
	s, _ := v.(string)
	return s
}
