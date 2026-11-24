// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"time"
)

// Offline normalisation of exported Cloudflare (Logpush HTTP requests, firewall events, Gateway DNS and
// Gateway HTTP) and Cisco Umbrella (DNS and proxy CSV) logs. Observation only: nothing is fetched and
// nothing contacts either vendor. Field names are folded the same way as the Zscaler reader (lower-case
// alphanumerics), so `ClientIP` and `client_ip` are one key. Which names are verified against vendor
// pages is recorded in docs/sase-log-analytics.md.
const (
	svRecordsMax = 100000
	svCapPerRule = 25
)

// SvEvent is one normalised Cloudflare or Umbrella record. Kind is cf-http, cf-fw, cf-gwdns,
// cf-gwhttp, umb-dns or umb-proxy.
type SvEvent struct {
	Vendor, Kind string
	Line         int
	T            time.Time
	User, Src    string // identity and source IP
	Host, Path   string
	Method, UA   string
	Action, Raw  string // Action is allow, block, challenge, log or other
	Status       int
	Country      string
	Cats         []string
	Query, RCode string
	Score, RCE   int // WAF attack score and RCE score, 1..99, 0 when absent
	SQLi, XSS    int
	Bot          int // bot score 1..99, 0 when absent
	BotSrc       string
	IPClass      string
	Leaked       string
	CertAct      string
	DLP          []string
	AV           string
}

type svParsed struct {
	Vendor, Format string
	Events         []SvEvent
	Received       int
	Rejected       int
	ByKind         map[string]int
	Errors         []string
}

func (p *svParsed) reject(i int, why string) {
	p.Rejected++
	if len(p.Errors) < zsErrorsMax {
		p.Errors = append(p.Errors, fmt.Sprintf("record %d: %s", i, why))
	}
}

type svBuilder func(r map[string]string, line int) (SvEvent, bool)

// svRow reports whether a CSV row has no header (Umbrella S3 logs carry none): its first cell is a time.
func svHeaderless(row []string) bool {
	return len(row) >= 8 && !zsTime(row[0]).IsZero()
}

func svParseLog(raw []byte, format string, allowHeaderless bool, build svBuilder) (*svParsed, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil, fmt.Errorf("empty log")
	}
	p := &svParsed{ByKind: map[string]int{}}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		if trim[0] == '{' || trim[0] == '[' {
			format = "json"
		} else {
			head := string(trim[:min(len(trim), 4096)])
			if i := strings.IndexByte(head, '\n'); i >= 0 {
				head = head[:i]
			}
			format = "csv"
			if zsDelim(head) == '\t' {
				format = "tsv"
			}
		}
	}
	p.Format = format
	add := func(i int, rec map[string]string) {
		p.Received++
		if p.Received > svRecordsMax {
			return
		}
		e, ok := build(rec, i)
		if !ok {
			p.reject(i, "no recognised field names")
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
					if p.Received > svRecordsMax {
						return nil, errNetTooMany
					}
				}
			} else {
				emit(v)
			}
			if p.Received > svRecordsMax {
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
		first, err := rd.Read()
		if err != nil {
			return nil, fmt.Errorf("could not read a first row")
		}
		var keys []string
		headerless := allowHeaderless && svHeaderless(first)
		rowRec := func(row []string) map[string]string {
			rec := map[string]string{}
			for j, v := range row {
				if j >= zsFieldsMax {
					break
				}
				if headerless {
					rec[fmt.Sprintf("c%d", j)] = v
				} else if j < len(keys) && keys[j] != "" {
					rec[keys[j]] = v
				}
			}
			return rec
		}
		i := 0
		if headerless {
			i++
			add(i, rowRec(first))
		} else {
			for _, h := range first {
				keys = append(keys, zsKey(h))
			}
		}
		for {
			row, err := rd.Read()
			if err == io.EOF {
				break
			}
			i++
			if err != nil {
				p.Received++
				p.reject(i, "unreadable row")
				continue
			}
			add(i, rowRec(row))
			if p.Received > svRecordsMax {
				return nil, errNetTooMany
			}
		}
	default:
		return nil, fmt.Errorf("unknown format %q (use auto, json, csv or tsv)", webTruncate(webSanitise(format), 20))
	}
	return p, nil
}

// SvRule is the metadata of one cf-an, umb-an or cfpol rule.
type SvRule struct{ ID, Tactic, Technique, TechID, Sev, Title, Why, Benign string }

type svFinding struct {
	Rule, Sev, User, Key, Desc, Sample string
	T                                  time.Time
}

type SvIdentityRisk struct {
	Identity string   `json:"identity"`
	Score    int      `json:"risk_score"`
	Level    string   `json:"risk_level"`
	Findings int      `json:"findings"`
	Rules    []string `json:"rules"`
}

// SvReport is the result of one Cloudflare or Umbrella log analysis.
type SvReport struct {
	Mode          string           `json:"mode"`
	Vendor        string           `json:"vendor"`
	Format        string           `json:"format"`
	Received      int              `json:"received"`
	Parsed        int              `json:"parsed"`
	Rejected      int              `json:"rejected"`
	ByKind        map[string]int   `json:"by_kind"`
	ByRule        map[string]int   `json:"by_rule"`
	From          *time.Time       `json:"from,omitempty"`
	To            *time.Time       `json:"to,omitempty"`
	Identities    int              `json:"identities"`
	TopIdentities []SvIdentityRisk `json:"top_identities"`
	Findings      int              `json:"findings"`
	Errors        []string         `json:"errors,omitempty"`
	Truncated     bool             `json:"truncated,omitempty"`
	Note          string           `json:"note"`
}

type SvOptions struct{ Host string }

const svNote = "heuristics over an exported log, not proof of compromise or of a policy failure: the export may omit fields, actions and categories are as the vendor labelled them, and score and category vocabularies not marked verified in docs/sase-log-analytics.md may differ in your tenant. Nothing was sent to or fetched from the vendor."

func svMeta(rules []SvRule, id string) *SvRule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

// svFinish turns raw hits into capped, ranked findings and per-identity risk.
func svFinish(vendor string, rules []SvRule, p *svParsed, out []svFinding, opt SvOptions, users map[string]bool, first, last time.Time, truncated bool) (*SvReport, []Finding) {
	rep := &SvReport{Mode: "observe-only", Vendor: vendor, Format: p.Format, Received: p.Received, Parsed: len(p.Events), Rejected: p.Rejected,
		ByKind: p.ByKind, ByRule: map[string]int{}, Errors: p.Errors, Note: svNote, TopIdentities: []SvIdentityRisk{}, Truncated: truncated || p.Received > svRecordsMax}
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Sev] != rank[out[j].Sev] {
			return rank[out[i].Sev] < rank[out[j].Sev]
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Key < out[j].Key
	})
	w := map[string]int{"high": 8, "medium": 3, "low": 1}
	score := map[string]int{}
	rl := map[string]map[string]int{}
	nf := map[string]int{}
	host := opt.Host
	if host == "" {
		host = vendor
	}
	per := map[string]int{}
	var fs []Finding
	for _, f := range out {
		if f.User != "" {
			if rl[f.User] == nil {
				rl[f.User] = map[string]int{}
			}
			rl[f.User][f.Rule]++
			if rl[f.User][f.Rule] <= 5 {
				score[f.User] += w[f.Sev]
			}
			nf[f.User]++
		}
		if per[f.Rule] >= svCapPerRule {
			rep.Truncated = true
			continue
		}
		per[f.Rule]++
		rep.ByRule[f.Rule]++
		m := svMeta(rules, f.Rule)
		if m == nil {
			continue
		}
		t := f.T
		if t.IsZero() {
			t = time.Now().UTC()
		}
		h := fnv.New64a()
		h.Write([]byte(f.Key + "|" + f.Desc))
		desc := fmt.Sprintf("%s: %s. %s (heuristic over an exported %s log. Possible benign cause: %s)", m.Title, f.Desc, m.Why, vendor, m.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, f.Rule, h.Sum64(), t.UnixNano()), Time: t, Host: host, Rule: f.Rule, Severity: f.Sev,
			Description: webTruncate(desc, 900), Tags: []string{m.TechID, vendor, "observe-only"},
			Evidence: Event{Time: t, Host: host, Executable: vendor + ":log", Command: webTruncate(webSanitise(f.Sample), 300)}})
	}
	rep.Findings = len(fs)
	for u, s := range score {
		if s > 100 {
			s = 100
		}
		var rs []string
		for r := range rl[u] {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		rep.TopIdentities = append(rep.TopIdentities, SvIdentityRisk{Identity: u, Score: s, Level: zsLevel(s), Findings: nf[u], Rules: rs})
	}
	sort.Slice(rep.TopIdentities, func(i, j int) bool {
		if rep.TopIdentities[i].Score != rep.TopIdentities[j].Score {
			return rep.TopIdentities[i].Score > rep.TopIdentities[j].Score
		}
		return rep.TopIdentities[i].Identity < rep.TopIdentities[j].Identity
	})
	if len(rep.TopIdentities) > 20 {
		rep.TopIdentities = rep.TopIdentities[:20]
	}
	rep.Identities = len(users)
	if !first.IsZero() {
		rep.From, rep.To = &first, &last
	}
	return rep, fs
}

func svRuleList(rules []SvRule) []map[string]string {
	out := make([]map[string]string, 0, len(rules))
	for _, a := range rules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

func svGuidance(rules []SvRule, vendor string) []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range rules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". A heuristic over an exported "+vendor+" log, not proof of compromise.", r.Why, r.Benign, r.TechID,
			[]string{"Open the identity's other records in the same export around the time of the finding.", "Check whether the action in the log matches what the policy is meant to do."},
			[]string{"Consider tightening the matching policy or moving it out of monitor-only mode (advisory; Kavach changes nothing)."}))
	}
	return out
}

func svRegister() {
	for _, rs := range [][]SvRule{cfRules, umbRules, cfPolRules} {
		for _, r := range rs {
			ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
		}
	}
}

func init() { svRegister() }

// svTimeRange tracks the first and last timestamp seen.
func svTimeRange(first, last *time.Time, t time.Time) {
	if t.IsZero() {
		return
	}
	if first.IsZero() || t.Before(*first) {
		*first = t
	}
	if t.After(*last) {
		*last = t
	}
}

func svWho(e *SvEvent) string {
	if e.User != "" {
		return e.User
	}
	return e.Src
}

// svDNSLong reports a DNS name with a very long name or label.
func svDNSLong(q string) bool {
	if len(q) >= 80 {
		return true
	}
	for _, l := range strings.Split(q, ".") {
		if len(l) >= 40 {
			return true
		}
	}
	return false
}
