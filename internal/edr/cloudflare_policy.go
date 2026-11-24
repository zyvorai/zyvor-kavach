// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"
)

// Offline posture review of an exported Cloudflare ruleset list (observation only). The export is the
// JSON a Rulesets API list or get call returns, saved to a file by the operator: one ruleset object,
// an array of them, or an object whose `result` is either. Ruleset fields (`kind`, `rules`, per-rule
// `action`, `expression`, `enabled`, `description`, `action_parameters`) are from Cloudflare's
// ruleset-engine JSON object page; the `phase` names and action values are from memory and marked
// unverified in docs/sase-log-analytics.md. Nothing connects to Cloudflare.
const cfpMax = 20000

var cfPolRules = []SvRule{
	{"cfpol-no-managed-waf", "Defense Evasion", "Impair Defenses", "T1562", "high", "No enabled managed WAF ruleset is deployed",
		"The export has no enabled execute rule in the managed-rules phase, so no Cloudflare managed ruleset is evaluated for the zone.",
		"The managed phase is controlled at account level and was not part of this export, or the zone is not on a plan with managed rules."},
	{"cfpol-no-rate-limit", "Impact", "Endpoint Denial of Service", "T1499", "medium", "No rate-limiting rule is deployed",
		"The export has no enabled rule in the rate-limiting phase, so nothing slows brute force, scraping or request floods.",
		"Rate limiting is configured at another level or by the origin."},
	{"cfpol-skip-broad", "Defense Evasion", "Impair Defenses", "T1562", "high", "Skip rule covers all traffic or the whole internet",
		"A skip rule whose expression is always true, or that matches every source address, turns off the skipped protections for everyone.",
		"A temporary rule while debugging, or a skip scoped to a path the expression text does not show."},
	{"cfpol-log-only-action", "Defense Evasion", "Impair Defenses", "T1562", "medium", "Security rules are in log-only mode",
		"Rules with the log action record matches but do not stop the request, so a rule set that is all log gives visibility without protection.",
		"A new rule being tuned before it is switched to block."},
	{"cfpol-disabled-rules", "Defense Evasion", "Impair Defenses", "T1562", "low", "Several rules are disabled",
		"Three or more disabled rules usually mean protections were switched off and not revisited.",
		"Rules kept for seasonal or incident use."},
	{"cfpol-undocumented-rules", "Defense Evasion", "Impair Defenses", "T1562", "low", "Several enabled rules have no description",
		"Rules with no description are hard to review, so an overly broad one can survive unnoticed.",
		"An automated tool that creates rules and leaves the description empty."},
}

func cfpMeta(id string) *SvRule { return svMeta(cfPolRules, id) }

type CfPolItem struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Technique string `json:"technique"`
	Location  string `json:"location"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Why       string `json:"why"`
	Benign    string `json:"benign"`
}

type CfPolReport struct {
	Mode       string         `json:"mode"`
	Rulesets   int            `json:"rulesets"`
	Rules      int            `json:"rules"`
	Phases     map[string]int `json:"rules_by_phase"`
	Score      int            `json:"posture_score"`
	Grade      string         `json:"grade"`
	ByRule     map[string]int `json:"by_rule"`
	BySeverity map[string]int `json:"by_severity"`
	Items      []CfPolItem    `json:"items"`
	Findings   int            `json:"findings"`
	Note       string         `json:"note"`
}

type CfPolOptions struct {
	Host string
	Now  time.Time
}

const cfpNote = "heuristics over a ruleset export, not proof of exposure: the export may omit account-level and managed rulesets, expressions are read as text and not evaluated, and phase and action names follow docs/sase-log-analytics.md. Nothing contacted Cloudflare."

type cfpRule struct {
	Phase, Action, Expr, Desc, Loc string
	Enabled                        bool
	Override                       string // action override from action_parameters.overrides.action
}

func cfpRulesets(root any) []map[string]any {
	var out []map[string]any
	switch v := root.(type) {
	case []any:
		for _, e := range v {
			out = append(out, cfpRulesets(e)...)
		}
	case map[string]any:
		if r, ok := v["result"]; ok {
			return cfpRulesets(r)
		}
		if _, ok := v["rules"]; ok {
			out = append(out, v)
		} else if _, ok := v["phase"]; ok {
			out = append(out, v)
		}
	}
	return out
}

func cfpStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return strings.TrimSpace(s)
}

// CfPolicyRun reviews one exported Cloudflare ruleset list.
func CfPolicyRun(raw []byte, opt CfPolOptions) (*CfPolReport, []Finding, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, fmt.Errorf("empty ruleset export")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("ruleset export must be JSON (one ruleset, an array, or an object with result)")
	}
	sets := cfpRulesets(root)
	if len(sets) == 0 {
		return nil, nil, fmt.Errorf("no ruleset recognised (expected objects with phase and rules)")
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rep := &CfPolReport{Mode: "observe-only", Rulesets: len(sets), Phases: map[string]int{}, ByRule: map[string]int{}, BySeverity: map[string]int{}, Items: []CfPolItem{}, Note: cfpNote}
	var rules []cfpRule
	for si, rs := range sets {
		phase := strings.ToLower(cfpStr(rs, "phase"))
		name := webTruncate(webSanitise(cfpStr(rs, "name")), 60)
		arr, _ := rs["rules"].([]any)
		for ri, e := range arr {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if len(rules) >= cfpMax {
				return nil, nil, fmt.Errorf("more than %d rules", cfpMax)
			}
			r := cfpRule{Phase: phase, Action: strings.ToLower(cfpStr(m, "action")), Expr: cfpStr(m, "expression"), Desc: cfpStr(m, "description"), Enabled: true,
				Loc: fmt.Sprintf("ruleset %d (%s) rule %d", si+1, orUnknown(name), ri+1)}
			if en, ok := m["enabled"].(bool); ok {
				r.Enabled = en
			}
			if ap, ok := m["action_parameters"].(map[string]any); ok {
				if ov, ok := ap["overrides"].(map[string]any); ok {
					r.Override = strings.ToLower(cfpStr(ov, "action"))
				}
			}
			rules = append(rules, r)
			rep.Phases[phase]++
		}
	}
	rep.Rules = len(rules)
	var items []CfPolItem
	add := func(rule, loc, detail string) {
		mt := cfpMeta(rule)
		items = append(items, CfPolItem{Rule: rule, Severity: mt.Sev, Technique: mt.TechID, Location: webTruncate(ncClean(loc), 200), Title: mt.Title, Detail: ncClean(detail), Why: mt.Why, Benign: mt.Benign})
	}
	managed, rate := 0, 0
	disabled, undocumented := 0, 0
	var logLoc string
	logN := 0
	for _, r := range rules {
		if !r.Enabled {
			disabled++
			continue
		}
		if strings.Contains(r.Phase, "firewall_managed") && r.Action == "execute" {
			managed++
		}
		if strings.Contains(r.Phase, "ratelimit") {
			rate++
		}
		if r.Desc == "" {
			undocumented++
		}
		if r.Action == "skip" {
			ex := strings.ToLower(strings.ReplaceAll(r.Expr, " ", ""))
			if ex == "" || ex == "true" || ex == "(true)" || (strings.Contains(ex, "ip.src") && strings.Contains(ex, "0.0.0.0/0")) {
				add("cfpol-skip-broad", r.Loc, "skip rule with expression "+webTruncate(webSanitise(r.Expr), 80))
			}
		}
		if (strings.Contains(r.Phase, "firewall_custom") || strings.Contains(r.Phase, "firewall_managed")) && (r.Action == "log" || r.Override == "log") {
			logN++
			if logLoc == "" {
				logLoc = r.Loc
			}
		}
	}
	if managed == 0 {
		add("cfpol-no-managed-waf", "export", "no enabled execute rule in the managed-rules phase")
	}
	if rate == 0 {
		add("cfpol-no-rate-limit", "export", "no enabled rule in the rate-limiting phase")
	}
	if logN > 0 {
		add("cfpol-log-only-action", logLoc, fmt.Sprintf("%d enabled rule(s) use the log action", logN))
	}
	if disabled >= 3 {
		add("cfpol-disabled-rules", "export", fmt.Sprintf("%d rules are disabled", disabled))
	}
	if undocumented >= 3 {
		add("cfpol-undocumented-rules", "export", fmt.Sprintf("%d enabled rules have no description", undocumented))
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(items, func(i, j int) bool {
		if rank[items[i].Severity] != rank[items[j].Severity] {
			return rank[items[i].Severity] < rank[items[j].Severity]
		}
		return items[i].Rule < items[j].Rule
	})
	pen := 0
	pw := map[string]int{"critical": 25, "high": 15, "medium": 8, "low": 3}
	per := map[string]int{}
	for _, it := range items {
		if per[it.Rule] < 5 {
			pen += pw[it.Severity]
		}
		per[it.Rule]++
	}
	rep.Score = max(0, 100-pen)
	switch {
	case rep.Score >= 90:
		rep.Grade = "A"
	case rep.Score >= 80:
		rep.Grade = "B"
	case rep.Score >= 70:
		rep.Grade = "C"
	case rep.Score >= 60:
		rep.Grade = "D"
	default:
		rep.Grade = "F"
	}
	host := opt.Host
	if host == "" {
		host = "cloudflare:policy"
	}
	var fs []Finding
	for _, it := range items {
		rep.ByRule[it.Rule]++
		rep.BySeverity[it.Severity]++
		if rep.ByRule[it.Rule] > ncCapPerRule {
			continue
		}
		rep.Items = append(rep.Items, it)
		h := fnv.New64a()
		h.Write([]byte(it.Location + "|" + it.Detail))
		desc := fmt.Sprintf("%s at %s: %s. %s (heuristic over a ruleset export; the export may omit account-level rulesets. Possible benign cause: %s)", it.Title, it.Location, it.Detail, it.Why, it.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, it.Rule, h.Sum64(), now.UnixNano()), Time: now, Host: host, Rule: it.Rule, Severity: it.Severity,
			Description: webTruncate(desc, 900), Tags: []string{it.Technique, "cloudflare", "policy", "observe-only"},
			Evidence: Event{Time: now, Host: host, Executable: "cloudflare:policy", Command: webTruncate(it.Location+" | "+it.Detail, 300)}})
	}
	rep.Findings = len(fs)
	return rep, fs, nil
}

func cfPolicyGuidance() []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range cfPolRules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". A heuristic over a ruleset export, not proof of exposure.", r.Why, r.Benign, r.TechID,
			[]string{"Check whether the missing or loose control is handled at account level or by the origin."},
			[]string{"Consider adding or tightening the rule (advisory; Kavach changes nothing)."}))
	}
	return out
}
