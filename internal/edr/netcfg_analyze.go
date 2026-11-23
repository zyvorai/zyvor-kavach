// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"
	"time"
)

type NetcfgOptions struct {
	Host string
	Now  time.Time // reference time for expiry markers; zero means now
}

type NetcfgItem struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Technique string `json:"technique"`
	Location  string `json:"location"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Why       string `json:"why_it_matters"`
	Benign    string `json:"benign_explanation"`
	Reference string `json:"reference"`
}

type NetcfgReport struct {
	Mode       string         `json:"mode"`
	Format     string         `json:"format"`
	Vendor     string         `json:"vendor"`
	Lines      int            `json:"lines"`
	Rules      int            `json:"rules"`
	Objects    int            `json:"objects"`
	Score      int            `json:"posture_score"`
	Grade      string         `json:"grade"`
	ByRule     map[string]int `json:"by_rule"`
	BySeverity map[string]int `json:"by_severity"`
	Items      []NetcfgItem   `json:"items"`
	Findings   int            `json:"findings"`
	Truncated  bool           `json:"truncated,omitempty"`
	Skipped    int            `json:"rules_skipped_by_shadow_analysis"`
	Notes      []string       `json:"notes,omitempty"`
	Note       string         `json:"note"`
}

const netcfgNote = "heuristics over a configuration export, not proof of exploitability or of exposure: the export may omit inherited, global or shared policy, objects may resolve differently on the device, and zone or interface trust is guessed from names. Credential values are never shown."

var ncSevW = map[string]int{"critical": 20, "high": 8, "medium": 3, "low": 1}

func ncScore(items []NetcfgItem) (int, string) {
	per := map[string]int{}
	pen := 0
	for _, it := range items {
		if per[it.Rule] >= 5 {
			continue
		}
		per[it.Rule]++
		pen += ncSevW[it.Severity]
	}
	s := 100 - pen
	if s < 0 {
		s = 0
	}
	g := "F"
	switch {
	case s >= 90:
		g = "A"
	case s >= 75:
		g = "B"
	case s >= 60:
		g = "C"
	case s >= 40:
		g = "D"
	}
	return s, g
}

var (
	ncFortiRe = regexp.MustCompile(`(?m)^\s*config (firewall|system|vpn|log|router|user) `)
	ncIptRe   = regexp.MustCompile(`(?m)^\*(filter|nat|mangle|raw)\s*$`)
	ncNftRe   = regexp.MustCompile(`(?m)^\s*table (inet|ip|ip6|arp|bridge|netdev) \S+ \{`)
	ncAsaRe   = regexp.MustCompile(`(?m)^(access-list |object-group |object network |access-group |ASA Version|: Saved|ssh \S+ \S+ \S+$)`)
)

func ncDetect(raw []byte) string {
	head := raw
	if len(head) > 1<<20 {
		head = head[:1<<20]
	}
	s := string(head)
	switch {
	case strings.HasPrefix(strings.TrimSpace(s), "<"):
		return "pan-xml"
	case ncFortiRe.MatchString(s):
		return "fortigate"
	case ncIptRe.MatchString(s):
		return "iptables"
	case ncNftRe.MatchString(s):
		return "nft"
	case ncAsaRe.MatchString(s):
		return "asa"
	}
	return ""
}

func ncParse(raw []byte, format string) (*ncModel, string, error) {
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("empty configuration")
	}
	if format == "" || format == "auto" {
		format = ncDetect(raw)
		if format == "" {
			return nil, "", fmt.Errorf("could not recognise the configuration format; set format to one of %s", ncFormatsLabel)
		}
	}
	var (
		m   *ncModel
		err error
	)
	switch format {
	case "pan-xml":
		m, err = ncParsePAN(raw)
	case "fortigate":
		m, err = ncParseForti(string(raw))
	case "asa":
		m, err = ncParseASA(string(raw))
	case "iptables":
		m, err = ncParseIptables(string(raw))
	case "nft":
		m, err = ncParseNft(string(raw))
	default:
		return nil, "", fmt.Errorf("unknown format %q (use %s)", webTruncate(webSanitise(format), 20), ncFormatsLabel)
	}
	return m, format, err
}

func ncCovers(a, b *ncRule) bool {
	if a.Extra != "" && a.Extra != b.Extra {
		return false
	}
	return a.SrcZ.covers(&b.SrcZ) && a.DstZ.covers(&b.DstZ) && a.Src.covers(&b.Src) && a.Dst.covers(&b.Dst) && a.Svc.covers(&b.Svc) && a.App.covers(&b.App)
}

// ncPermitSeverity grades how broad one permit rule is (also used by the diff).
func ncPermitSeverity(r *ncRule) (string, string) {
	switch {
	case r.Extra == "" && r.Src.Any && r.Dst.Any && r.Svc.Any && r.App.Any && r.SrcZ.Any && r.DstZ.Any:
		return "critical", "any source, destination, service and zone"
	case r.Extra == "" && r.Src.Any && r.Dst.Any && r.Svc.Any && r.App.Any:
		return "high", "any source, destination and service"
	case r.Svc.Any && r.App.Any && (r.Src.Any || r.Dst.Any):
		return "high", "all services"
	}
	if rk := r.risky(); len(rk) > 0 && r.exposed() {
		return "high", "risky service from an untrusted source: " + strings.Join(rk, ", ")
	}
	if r.exposed() {
		return "medium", "permit from any or an untrusted source"
	}
	return "low", "permit"
}

func ncAnalyze(m *ncModel, opt NetcfgOptions) ([]NetcfgItem, int) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	deadline := time.Now().Add(ncBudget)
	var items []NetcfgItem
	add := func(rule, sev, loc, detail string) {
		mt := ncMeta(rule)
		if mt == nil {
			return
		}
		if sev == "" {
			sev = mt.Sev
		}
		items = append(items, NetcfgItem{Rule: rule, Severity: sev, Technique: mt.TechID, Location: webTruncate(ncClean(loc), 200), Title: mt.Title,
			Detail: ncClean(detail), Why: mt.Why, Benign: mt.Benign, Reference: mt.Reference})
	}
	for _, is := range m.Issues {
		add(is.Rule, is.Sev, is.Loc, is.Detail)
	}
	for _, r := range m.Rules {
		if r.Disabled {
			add("netcfg-rule-disabled", "", r.Loc, fmt.Sprintf("rule %s is disabled", r.Name))
			continue
		}
		if r.Allow && r.Terminal && !r.Egress {
			sev, why := ncPermitSeverity(r)
			switch {
			case why == "any source, destination, service and zone" || why == "any source, destination and service":
				add("netcfg-permit-any-any", sev, r.Loc, fmt.Sprintf("rule %s permits %s", r.Name, why))
			case why == "all services":
				add("netcfg-permit-any-service", sev, r.Loc, fmt.Sprintf("rule %s permits all services between its source and destination", r.Name))
			}
			if !r.Svc.Any || len(r.Apps) > 0 {
				if rk := r.risky(); len(rk) > 0 && r.exposed() {
					s := "high"
					if len(rk) == 1 && rk[0] == "ssh" {
						s = "medium"
					}
					add("netcfg-permit-risky-service", s, r.Loc, fmt.Sprintf("rule %s permits %s from an any or untrusted-looking source", r.Name, strings.Join(rk, ", ")))
				}
			}
			if r.Inspect == "no" && (r.exposed() || ncDstUntrusted(r)) {
				add("netcfg-permit-no-inspection", "", r.Loc, fmt.Sprintf("rule %s has no security or inspection profile in the export", r.Name))
			}
			if m.DescSupported && strings.TrimSpace(r.Desc) == "" {
				add("netcfg-rule-no-description", "", r.Loc, fmt.Sprintf("permit rule %s has no description", r.Name))
			}
		}
		if r.Terminal && r.Log == "off" {
			s := "medium"
			if !r.Allow {
				s = "low"
			}
			add("netcfg-rule-no-logging", s, r.Loc, fmt.Sprintf("rule %s has logging turned off", r.Name))
		}
		txt := r.Name + " " + r.Desc
		if d, expired := ncExpiredDate(txt, now); expired {
			s := "low"
			if r.Allow {
				s = "medium"
			}
			add("netcfg-rule-temporary", s, r.Loc, fmt.Sprintf("rule %s carries the date %s, which has passed", r.Name, d))
		} else if ncTempRe.MatchString(txt) {
			add("netcfg-rule-temporary", "", r.Loc, fmt.Sprintf("rule %s name or description suggests a temporary rule", r.Name))
		}
	}
	skipped := ncShadowAnalysis(m, deadline, add)
	// objects
	sigs := map[string][]*ncObj{}
	var objs []*ncObj
	for _, o := range m.Objs {
		objs = append(objs, o)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Kind+objs[i].Name < objs[j].Kind+objs[j].Name })
	for _, o := range objs {
		if !o.Used {
			add("netcfg-object-unused", "", o.Loc, fmt.Sprintf("%s object %s is not referenced", o.Kind, o.Name))
		}
		if o.Sig != "" && o.Sig != "any" {
			k := o.Kind + "|" + o.Sig
			sigs[k] = append(sigs[k], o)
		}
	}
	var dk []string
	for k, v := range sigs {
		if len(v) > 1 {
			dk = append(dk, k)
		}
	}
	sort.Strings(dk)
	for _, k := range dk {
		v := sigs[k]
		var names []string
		for _, o := range v {
			names = append(names, o.Name)
		}
		add("netcfg-object-duplicate", "", v[1].Loc, fmt.Sprintf("%s objects %s hold the same value", v[0].Kind, strings.Join(names, ", ")))
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(items, func(i, j int) bool {
		if rank[items[i].Severity] != rank[items[j].Severity] {
			return rank[items[i].Severity] < rank[items[j].Severity]
		}
		return items[i].Rule < items[j].Rule
	})
	return items, skipped
}

func ncDstUntrusted(r *ncRule) bool {
	if r.DstZ.Any {
		return false
	}
	for z := range r.DstZ.M {
		if ncUntrustedName(z) {
			return true
		}
	}
	return false
}

// ncShadowAnalysis compares enabled terminal rules pairwise inside each scope. Cost is bounded by
// ncShadowMax rules per scope, ncCompareMax comparisons overall and the time budget.
func ncShadowAnalysis(m *ncModel, deadline time.Time, add func(rule, sev, loc, detail string)) int {
	byScope := map[string][]*ncRule{}
	var order []string
	skipped := 0
	for _, r := range m.Rules {
		if !r.Terminal || r.Disabled {
			continue
		}
		if r.Complex {
			skipped++
			continue
		}
		if _, ok := byScope[r.Scope]; !ok {
			order = append(order, r.Scope)
		}
		byScope[r.Scope] = append(byScope[r.Scope], r)
	}
	budget := 0
	for _, sc := range order {
		rs := byScope[sc]
		if len(rs) > ncShadowMax {
			skipped += len(rs) - ncShadowMax
			m.note(fmt.Sprintf("scope %s has %d analysable rules; only the first %d were compared", ncClean(sc), len(rs), ncShadowMax))
			rs = rs[:ncShadowMax]
		}
		for j := 1; j < len(rs); j++ {
			for i := 0; i < j; i++ {
				budget++
				if budget > ncCompareMax {
					m.note("shadow analysis stopped at the comparison budget")
					m.truncated = true
					return skipped
				}
				if budget&1023 == 0 && time.Now().After(deadline) {
					m.note("shadow analysis stopped at the time budget")
					m.truncated = true
					return skipped
				}
				a, b := rs[i], rs[j]
				if !ncCovers(a, b) {
					continue
				}
				if a.Allow != b.Allow {
					sev := "medium"
					if !b.Allow {
						sev = "high" // a deny that never applies
					}
					add("netcfg-rule-shadowed", sev, b.Loc, fmt.Sprintf("rule %s (%s) is covered by earlier rule %s (%s, %s)", b.Name, actWord(b.Allow), a.Name, actWord(a.Allow), a.Loc))
				} else {
					add("netcfg-rule-redundant", "", b.Loc, fmt.Sprintf("rule %s is covered by earlier rule %s (%s, same action %s)", b.Name, a.Name, a.Loc, actWord(b.Allow)))
				}
				break
			}
		}
	}
	return skipped
}

func actWord(allow bool) string {
	if allow {
		return "permit"
	}
	return "deny"
}

// NetcfgRun parses and analyses one configuration export.
func NetcfgRun(raw []byte, format string, opt NetcfgOptions) (*NetcfgReport, []Finding, error) {
	m, f, err := ncParse(raw, format)
	if err != nil {
		return nil, nil, err
	}
	items, skipped := ncAnalyze(m, opt)
	rep := &NetcfgReport{Mode: "observe-only", Format: f, Vendor: m.Vendor, Lines: m.Lines, Rules: len(m.Rules), Objects: len(m.Objs),
		ByRule: map[string]int{}, BySeverity: map[string]int{}, Items: []NetcfgItem{}, Truncated: m.truncated, Skipped: skipped, Notes: m.Notes, Note: netcfgNote}
	for _, it := range items {
		rep.ByRule[it.Rule]++
		rep.BySeverity[it.Severity]++
	}
	rep.Score, rep.Grade = ncScore(items)
	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	host := opt.Host
	if host == "" {
		host = "netcfg:" + m.Vendor
	}
	per := map[string]int{}
	var fs []Finding
	for _, it := range items {
		if per[it.Rule] >= ncCapPerRule {
			continue
		}
		per[it.Rule]++
		rep.Items = append(rep.Items, it)
		h := fnv.New64a()
		h.Write([]byte(it.Location + "|" + it.Detail))
		desc := fmt.Sprintf("%s at %s: %s. %s (heuristic over a configuration export; the export may omit inherited or global policy. Possible benign cause: %s)", it.Title, it.Location, it.Detail, it.Why, it.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, it.Rule, h.Sum64(), now.UnixNano()), Time: now, Host: host, Rule: it.Rule, Severity: it.Severity,
			Description: webTruncate(desc, 900), Tags: []string{it.Technique, "network", "netcfg", "observe-only"},
			Evidence: Event{Time: now, Host: host, Executable: "netcfg:config", Command: webTruncate(it.Location+" | "+it.Detail, ncEvidenceMax)}})
	}
	rep.Findings = len(fs)
	return rep, fs, nil
}
