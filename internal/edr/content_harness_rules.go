// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule inventory, built-in examples (selftest) and the ATT&CK coverage-by-tested-rule report.
//
// Every web- content rule carries positive and negative LabEvent samples in its pack. The harness
// turns each sample back into the raw access-log line a web server would have written and runs it
// through the real parser, so the examples also exercise the log parser and normaliser. Built-in
// analytic rules (web-an-, auth-an-, idp-an-, rwlog-an-, tripwire-) have no per-event samples, so
// their examples live in content_examples/*.jsonl in the same test-file format, one line per
// example with "rule" and "polarity". A rule without both a positive and a negative example, or one
// that does not fire on its own positive example, or fires on its own negative example, fails
// SelfTest and the CI test.

//go:embed content_examples/*.jsonl
var harnessExampleFS embed.FS

// HarnessRule describes one registered rule and the state of its examples.
type HarnessRule struct {
	ID        string `json:"id"`
	Family    string `json:"family"` // web-content, web-analytic, auth-analytic, idp-analytic, ransom-analytic, tripwire, content-pack
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"` // ATT&CK id, e.g. T1110.004
	Name      string `json:"technique_name,omitempty"`
	Severity  string `json:"severity"`
}

type harnessAnalytic struct {
	HarnessRule
}

func harnessAnalytics() []harnessAnalytic {
	var out []harnessAnalytic
	add := func(fam, id, tac, name, tid, sev string) {
		out = append(out, harnessAnalytic{HarnessRule{ID: id, Family: fam, Tactic: tac, Technique: tid, Name: name, Severity: sev}})
	}
	for _, r := range webAnalyticRules {
		add("web-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range authAnalyticRules {
		add("auth-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range idpRules {
		add("idp-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range rwRules {
		add("ransom-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range netcfgRules {
		add("netcfg-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range zsRules {
		add("zscaler-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range zsPolRules {
		add("zscaler-policy", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range zdxRules {
		add("zdx-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range cfRules {
		add("cloudflare-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range umbRules {
		add("umbrella-analytic", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range cfPolRules {
		add("cloudflare-policy", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	for _, r := range twRules {
		add("tripwire", r.ID, r.Tactic, r.Technique, r.TechID, r.Sev)
	}
	return out
}

// HarnessInventory lists every rule the harness knows: content-pack rules (web- ones tagged
// web-content) and the built-in analytic rules, sorted by id.
func HarnessInventory(reg *ContentRegistry) []HarnessRule {
	var out []HarnessRule
	if reg != nil {
		for _, r := range reg.rules {
			fam := "content-pack"
			if r.Batch == webBatchTag {
				fam = "web-content"
			}
			out = append(out, HarnessRule{ID: r.ID, Family: fam, Tactic: r.Tactic, Technique: r.Technique, Name: r.TechniqueName, Severity: r.Severity})
		}
	}
	for _, a := range harnessAnalytics() {
		out = append(out, a.HarnessRule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// harnessEncodeTarget escapes only what would break the request line of a common-log record.
func harnessEncodeTarget(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '"' || c == '\\' || c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, "%%%02X", c)
		case c == '%' && i+2 < len(s) && webHexVal(s[i+1]) >= 0 && webHexVal(s[i+2]) >= 0:
			b.WriteString("%25")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// harnessEncodeEvasive percent-encodes every byte except letters, digits and /?&=_- (the
// structural characters), once per decode pass the rule sample recorded, so the pipeline's own
// decoder reproduces the sampled decoded target after exactly that many passes.
func harnessEncodeEvasive(s string, passes int) string {
	for p := 0; p < passes; p++ {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/?&=_-", c) >= 0 {
				b.WriteByte(c)
				continue
			}
			fmt.Fprintf(&b, "%%%02X", c)
		}
		s = b.String()
	}
	return s
}

var harnessCmdRe = regexp.MustCompile(`^status=(\d+) bytes=(\d+) len=(\d+) dec=(\d+) target=(.*)$`)

// harnessWebLine renders a rule-sample LabEvent as a combined-log line (false when it cannot). The
// sample's recorded decode passes (dec=) and raw length (len=) are reproduced, so rules that depend
// on them see the same values the real parser would compute.
func harnessWebLine(ev LabEvent) (string, bool) {
	m := harnessCmdRe.FindStringSubmatch(ev.Command)
	if m == nil || ev.Executable != webExecutable {
		return "", false
	}
	want, _ := strconv.Atoi(m[3])
	passes, _ := strconv.Atoi(m[4])
	target := m[5]
	if passes > 0 {
		target = harnessEncodeEvasive(target, passes)
	} else {
		target = harnessEncodeTarget(target)
	}
	if pad := want - len(target); pad > 4 {
		sep := "&"
		if !strings.Contains(target, "?") {
			sep = "?"
		}
		target += sep + "p=" + strings.Repeat("A", pad-len(sep)-2)
	}
	ip := ev.Destination
	if ip == "" {
		ip = "203.0.113.7"
	}
	req := ev.Operation + " " + target + " HTTP/1.1"
	if ev.Operation == "INVALID" || ev.Operation == "" {
		req = target
	}
	ua := strings.ReplaceAll(ev.ParentExe, `"`, "'")
	if ua == "" {
		ua = "-"
	}
	return fmt.Sprintf(`%s - - [15/Jan/2026:10:00:00 +0000] "%s" %s %s "-" "%s"`, ip, req, m[1], m[2], ua), true
}

// derivedWebExamples turns the web- content rules' own samples into raw-log cases.
func derivedWebExamples(reg *ContentRegistry) []harnessSpec {
	var out []harnessSpec
	for _, r := range reg.rules {
		if r.Batch != webBatchTag || r.Tests == nil {
			continue
		}
		for _, pe := range []struct {
			pol string
			evs []LabEvent
		}{{"positive", r.Tests.Positive}, {"negative", r.Tests.Negative}} {
			pol, evs := pe.pol, pe.evs
			for i, ev := range evs {
				line, ok := harnessWebLine(ev)
				if !ok {
					continue
				}
				sp := harnessSpec{line: i + 1}
				sp.Case = fmt.Sprintf("derived/%s/%s-%d", r.ID, pol, i+1)
				sp.Kind, sp.Format, sp.Lines, sp.Rule, sp.Polarity = "web", "combined", []string{line}, r.ID, pol
				out = append(out, sp)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Case < out[j].Case })
	return out
}

// sidecarExamples reads the embedded content_examples/*.jsonl files.
func sidecarExamples(known map[string]bool) ([]harnessSpec, []HarnessCaseResult) {
	var specs []harnessSpec
	var errs []HarnessCaseResult
	ents, err := harnessExampleFS.ReadDir("content_examples")
	if err != nil {
		return nil, []HarnessCaseResult{{Case: "(sidecar)", File: "content_examples", Error: err.Error(), Diff: []string{"! " + err.Error()}, Fired: []HarnessFired{}}}
	}
	for _, e := range ents {
		b, err := harnessExampleFS.ReadFile("content_examples/" + e.Name())
		if err != nil {
			continue
		}
		sp, perr := harnessParse(b, known)
		if perr != nil {
			errs = append(errs, HarnessCaseResult{Case: "(file)", File: e.Name(), Error: perr.Error(), Diff: []string{"! " + perr.Error()}, Fired: []HarnessFired{}})
		}
		for i := range sp {
			sp[i].Note = e.Name()
			if sp[i].perr == "" && (sp[i].Rule == "" || sp[i].Polarity == "") {
				sp[i].perr = "sidecar examples must set rule and polarity"
			}
		}
		specs = append(specs, sp...)
	}
	return specs, errs
}

// HarnessRuleStatus is the example state of one rule.
type HarnessRuleStatus struct {
	HarnessRule
	Positive     int    `json:"positive_examples"`
	Negative     int    `json:"negative_examples"`
	PositivePass int    `json:"positive_passing"`
	NegativePass int    `json:"negative_passing"`
	Status       string `json:"status"`
}

// SelfTestReport is the result of SelfTest.
type SelfTestReport struct {
	HarnessReport
	Rules        []HarnessRuleStatus `json:"rules"`
	RulesTotal   int                 `json:"rules_total"`
	RulesOK      int                 `json:"rules_ok"`
	RulesFailing int                 `json:"rules_failing"`
	ByFamily     map[string][2]int   `json:"by_family"` // family -> [ok, total]
}

func harnessRuleStatusFill(st *HarnessRuleStatus) {
	switch {
	case st.Positive == 0 && st.Negative == 0:
		st.Status = "no-examples"
	case st.Positive == 0:
		st.Status = "no-positive-example"
	case st.Negative == 0:
		st.Status = "no-negative-example"
	case st.PositivePass < st.Positive:
		st.Status = "positive-not-firing"
	case st.NegativePass < st.Negative:
		st.Status = "negative-fires"
	default:
		st.Status = "ok"
	}
}

// SelfTest generates, for every registered rule, its positive and negative examples, runs them
// through the real detection paths and reports rules whose examples are missing or wrong.
func SelfTest(opts HarnessOptions) (*SelfTestReport, error) {
	reg, err := opts.reg()
	if reg == nil {
		return nil, fmt.Errorf("content packs unavailable: %v", err)
	}
	known := HarnessKnownRules(reg)
	inv := HarnessInventory(reg)
	inInv := map[string]bool{}
	for _, r := range inv {
		inInv[r.ID] = true
	}
	st := &SelfTestReport{HarnessReport: *newHarnessReport([]string{"builtin:web-content-samples", "builtin:content_examples", "builtin:content-pack-samples"}), ByFamily: map[string][2]int{}}
	stats := map[string]*HarnessRuleStatus{}
	for _, r := range inv {
		stats[r.ID] = &HarnessRuleStatus{HarnessRule: r}
	}
	specs := derivedWebExamples(reg)
	side, errs := sidecarExamples(known)
	for _, e := range errs {
		st.add(e)
	}
	specs = append(specs, side...)
	for _, sp := range specs {
		file := "builtin:web-content-samples"
		if sp.Note != "" {
			file = sp.Note
		}
		if sp.perr == "" && !inInv[sp.Rule] {
			sp.perr = fmt.Sprintf("example names rule %q which is not a registered rule", sp.Rule)
		}
		res := harnessRunSpec(sp, file, "", reg)
		st.add(res)
		if s := stats[sp.Rule]; s != nil && sp.perr == "" {
			if sp.Polarity == "positive" {
				s.Positive++
				if res.Pass {
					s.PositivePass++
				}
			} else {
				s.Negative++
				if res.Pass {
					s.NegativePass++
				}
			}
		}
	}
	// content-pack rules (including web- ones) also carry LabEvent samples checked directly
	for _, r := range reg.rules {
		s := stats[r.ID]
		if r.Batch == webBatchTag || r.Tests == nil {
			continue
		}
		for _, pe := range []struct {
			pol string
			evs []LabEvent
		}{{"positive", r.Tests.Positive}, {"negative", r.Tests.Negative}} {
			pol, evs := pe.pol, pe.evs
			for i, ev := range evs {
				ok := r.Matches(ev) == (pol == "positive")
				if pol == "positive" {
					s.Positive++
					if ok {
						s.PositivePass++
					}
				} else {
					s.Negative++
					if ok {
						s.NegativePass++
					}
				}
				if !ok {
					msg := fmt.Sprintf("rule %s %s sample %d: matcher returned %v", r.ID, pol, i+1, r.Matches(ev))
					st.add(HarnessCaseResult{Case: fmt.Sprintf("pack/%s/%s-%d", r.ID, pol, i+1), File: "builtin:content-pack-samples", Kind: "event", Rule: r.ID, Polarity: pol,
						Error: msg, Diff: []string{"! " + msg}, Fired: []HarnessFired{}})
				}
			}
		}
	}
	for _, r := range inv {
		s := stats[r.ID]
		harnessRuleStatusFill(s)
		st.Rules = append(st.Rules, *s)
		st.RulesTotal++
		f := st.ByFamily[r.Family]
		f[1]++
		if s.Status == "ok" {
			st.RulesOK++
			f[0]++
		} else {
			st.RulesFailing++
		}
		st.ByFamily[r.Family] = f
	}
	if st.RulesFailing > 0 && st.Failed == 0 {
		// a rule with no examples has no failing case; make the failure visible in the totals
		st.Failed = st.RulesFailing
	}
	return st, nil
}

// Failing returns the rules whose status is not ok.
func (s *SelfTestReport) Failing() []HarnessRuleStatus {
	var out []HarnessRuleStatus
	for _, r := range s.Rules {
		if r.Status != "ok" {
			out = append(out, r)
		}
	}
	return out
}

// OK reports whether every rule is ok and every example case passed.
func (s *SelfTestReport) OK() bool { return s.RulesFailing == 0 && s.Failed == 0 }

// CoverageTechnique is one ATT&CK technique and the rules that detect it.
type CoverageTechnique struct {
	ID       string   `json:"technique"`
	Name     string   `json:"name,omitempty"`
	Tactics  []string `json:"tactics"`
	Tested   []string `json:"tested_rules"`
	Untested []string `json:"untested_rules"`
}

// TestedCoverage is the ATT&CK coverage-by-tested-rule report.
type TestedCoverage struct {
	Mode             string              `json:"mode"`
	Techniques       []CoverageTechnique `json:"techniques"`
	TechniquesTotal  int                 `json:"techniques_total"`
	TechniquesTested int                 `json:"techniques_with_a_passing_positive_example"`
	RulesTested      int                 `json:"rules_tested"`
	RulesTotal       int                 `json:"rules_total"`
	Note             string              `json:"note"`
}

// CoverageByTestedRule counts a technique as covered only when at least one rule that maps to it
// fires on its own positive example and stays quiet on its own negative example.
func CoverageByTestedRule(st *SelfTestReport) *TestedCoverage {
	by := map[string]*CoverageTechnique{}
	tacs := map[string]map[string]bool{}
	for _, r := range st.Rules {
		id := r.Technique
		if id == "" {
			id = "(unmapped)"
		}
		t := by[id]
		if t == nil {
			t = &CoverageTechnique{ID: id, Tested: []string{}, Untested: []string{}, Tactics: []string{}}
			by[id] = t
			tacs[id] = map[string]bool{}
		}
		if t.Name == "" {
			t.Name = r.Name
		}
		if r.Tactic != "" && !tacs[id][r.Tactic] {
			tacs[id][r.Tactic] = true
			t.Tactics = append(t.Tactics, r.Tactic)
		}
		if r.Status == "ok" {
			t.Tested = append(t.Tested, r.ID)
		} else {
			t.Untested = append(t.Untested, r.ID)
		}
	}
	rep := &TestedCoverage{Mode: "observe-only", RulesTotal: st.RulesTotal, RulesTested: st.RulesOK,
		Note: "a technique is counted only when a rule mapped to it fires on its own positive example and not on its own negative example; this measures example coverage of the shipped rules, not coverage of real attacker behaviour"}
	for _, t := range by {
		sort.Strings(t.Tested)
		sort.Strings(t.Untested)
		sort.Strings(t.Tactics)
		rep.Techniques = append(rep.Techniques, *t)
		rep.TechniquesTotal++
		if len(t.Tested) > 0 {
			rep.TechniquesTested++
		}
	}
	sort.Slice(rep.Techniques, func(i, j int) bool { return rep.Techniques[i].ID < rep.Techniques[j].ID })
	return rep
}
