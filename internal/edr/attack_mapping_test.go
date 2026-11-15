// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"strings"
	"testing"
	"time"
)

// Rules that have no honest ATT&CK technique today. They must surface as unmapped, not as a guess.
var intentionallyUnmapped = map[string]bool{
	"ransomware-churn":         true, // weak canary-path churn signal; no single technique
	"identity-from-finding":    true, // identity event derived from findings, not a Finding rule
	"custom-rule":              true, // placeholder for operator-authored custom-* rules
	"ioc-generic":              true, // placeholder for operator-added IOC types
	"ioa-generic":              true, // placeholder for operator-added IOA ids
}

func TestMapDetectionUnmappedIsExplicit(t *testing.T) {
	d := MapDetection(Finding{ID: "x", Rule: "zz-no-such-rule", Severity: "low", Host: "h"})
	if !d.Unmapped || d.TechniqueID != "" || d.Tactic != "" || d.Technique != "" {
		t.Fatalf("unmapped rule must carry no technique: %+v", d)
	}
	if d2 := MapDetection(Finding{ID: "y", Rule: "ransomware-burst", Host: "h"}); d2.Unmapped || d2.TechniqueID != "T1486" {
		t.Fatalf("mapped rule regressed: %+v", d2)
	}
}

func TestFormerlyDefaultedRulesNowMapped(t *testing.T) {
	want := map[string][2]string{
		"unsafe-permissions":      {"T1222.002", "Defense Evasion"},
		"persistence-attempt":     {"T1053", "Persistence"},
		"script-inline-execution": {"T1059", "Execution"},
		"root-history-clear":      {"T1070.003", "Defense Evasion"},
	}
	for rule, w := range want {
		d := MapDetection(Finding{ID: "x", Rule: rule, Host: "h"})
		if d.Unmapped || d.TechniqueID != w[0] || d.Tactic != w[1] {
			t.Errorf("%s: got %s/%s unmapped=%v, want %s/%s", rule, d.TechniqueID, d.Tactic, d.Unmapped, w[0], w[1])
		}
	}
}

// Every built-in rule id (emitted-rule catalogue, ruleMITRE keys and the default IOC types) must
// either map or be on the explicit unmapped list, and none may land on T1082 by default.
func TestNoRuleDefaultsToT1082(t *testing.T) {
	ids := map[string]bool{"ioc-domain": true, "ioc-ipv4": true, "ioc-sha256": true, "ioc-ipv6": true, "ioc-md5": true}
	for _, r := range EmittedRuleNames {
		ids[r] = true
	}
	for r := range ruleMITRE {
		ids[r] = true
	}
	for r := range ids {
		d := MapDetection(Finding{ID: "x", Rule: r, Host: "h"})
		m, mapped := mitreFor(r)
		if d.Unmapped == mapped {
			t.Errorf("%s: Unmapped=%v disagrees with mitreFor ok=%v", r, d.Unmapped, mapped)
		}
		if !mapped && !intentionallyUnmapped[r] {
			t.Errorf("%s is neither mapped nor on the intentionally-unmapped list", r)
		}
		if mapped && intentionallyUnmapped[r] {
			t.Errorf("%s is mapped but still listed as intentionally unmapped", r)
		}
		if d.TechniqueID == "T1082" && !(mapped && m.ID == "T1082") {
			t.Errorf("%s maps to T1082 without T1082 being its technique", r)
		}
		if d.Unmapped && (d.TechniqueID != "" || d.Tactic != "") {
			t.Errorf("%s unmapped but carries a technique: %+v", r, d)
		}
	}
	// And an arbitrary unknown rule never becomes T1082.
	if d := MapDetection(Finding{ID: "x", Rule: "anything-else"}); d.TechniqueID == "T1082" {
		t.Fatal("unknown rule defaulted to T1082")
	}
}

func iocEvent(cmd string) Event {
	return Event{Host: "h1", PID: 11, Time: time.Now().UTC(), Executable: "/usr/bin/curl", Command: cmd, ParentExe: "/bin/bash"}
}

func findRule(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

// Drives a real IOC match through Detect: the emitted rule ids are ioc-<type>, and they must map.
func TestIOCFindingsMapToTechniques(t *testing.T) {
	cases := []struct{ cmd, rule, tech, tactic string }{
		{"curl http://evil-c2.example/x", "ioc-domain", "T1071", "Command and Control"},
		{"curl http://203.0.113.66/x", "ioc-ipv4", "T1071", "Command and Control"},
		{"sha256sum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc-sha256", "T1204", "Execution"},
	}
	for _, c := range cases {
		f := findRule(Detect(iocEvent(c.cmd)), c.rule)
		if f == nil {
			t.Fatalf("%s: IOC finding not produced by Detect", c.rule)
		}
		d := MapDetection(*f)
		if d.Unmapped || d.TechniqueID != c.tech || d.Tactic != c.tactic {
			t.Errorf("%s: got %+v", c.rule, d)
		}
		m := BuildATTACKMatrix([]Finding{*f})
		if m["observed_hits"].(int) != 1 {
			t.Errorf("%s: IOC finding not counted as an observed hit: %v", c.rule, m["observed_hits"])
		}
	}
}

func techniqueNode(m map[string]any, tech string) *ATTACKTechnique {
	for _, tac := range m["tactics"].([]*ATTACKTactic) {
		for i := range tac.Techniques {
			if tac.Techniques[i].ID == tech {
				return &tac.Techniques[i]
			}
		}
	}
	return nil
}

func TestIOAFindingsInMatrixCoverageAndHits(t *testing.T) {
	cov := BuildATTACKMatrix(nil)
	for _, tech := range []string{"T1003", "T1059", "T1490"} {
		n := techniqueNode(cov, tech)
		if n == nil || !n.Covered {
			t.Fatalf("IOA technique %s missing from matrix coverage", tech)
		}
	}
	if n := techniqueNode(cov, "T1490"); !contains(n.Rules, "ioa-ioa-3") {
		t.Fatalf("T1490 should list the IOA rule: %v", n.Rules)
	}
	f := findRule(Detect(iocEvent("vssadmin delete shadows /all /quiet")), "ioa-ioa-3")
	if f == nil {
		t.Fatal("IOA did not fire through Detect")
	}
	m := BuildATTACKMatrix([]Finding{*f})
	if m["observed_hits"].(int) != 1 {
		t.Fatalf("IOA finding not an observed hit: %v", m["observed_hits"])
	}
	if n := techniqueNode(m, "T1490"); n == nil || n.Hits != 1 {
		t.Fatalf("T1490 hits: %+v", n)
	}
	if d := MapDetection(*f); d.Unmapped || d.TechniqueID != "T1490" || d.Tactic != "Impact" {
		t.Fatalf("IOA detection mapping: %+v", d)
	}
	// An IOA that was deleted after firing still maps through the technique tag on the finding.
	orphan := *f
	orphan.Rule = "ioa-ioa-gone"
	if d := MapDetection(orphan); d.Unmapped || d.TechniqueID != "T1490" {
		t.Fatalf("orphaned IOA finding should keep its tagged technique: %+v", d)
	}
}

func TestCustomIOAWithTechniqueCountsAndDisabledDoesNot(t *testing.T) {
	ioaMu.Lock()
	saved := ioas
	ioas = append(append([]IOARule{}, saved...),
		IOARule{ID: "zz-on", Name: "n", Pattern: "zz-on-pat", TechniqueID: "T1087", Enabled: true},
		IOARule{ID: "zz-off", Name: "n", Pattern: "zz-off-pat", TechniqueID: "T1046", Enabled: false},
		IOARule{ID: "zz-bad", Name: "n", Pattern: "zz-bad-pat", TechniqueID: "T9999", Enabled: true})
	ioaMu.Unlock()
	defer func() { ioaMu.Lock(); ioas = saved; ioaMu.Unlock() }()
	m := BuildATTACKMatrix(nil)
	if n := techniqueNode(m, "T1087"); n == nil || !contains(n.Rules, "ioa-zz-on") {
		t.Fatalf("enabled custom IOA missing: %+v", n)
	}
	if n := techniqueNode(m, "T1046"); n != nil && contains(n.Rules, "ioa-zz-off") {
		t.Fatal("disabled IOA must not count toward coverage")
	}
	if n := techniqueNode(m, "T9999"); n != nil {
		t.Fatal("IOA with an unknown technique must not invent coverage")
	}
}

func TestMatrixReportsUnmappedRules(t *testing.T) {
	now := time.Now().UTC()
	fs := []Finding{
		{ID: "1", Rule: "zz-unknown-rule", Host: "h", Time: now},
		{ID: "2", Rule: "ransomware-burst", Host: "h", Time: now},
	}
	m := BuildATTACKMatrix(fs)
	un := m["unmapped_rules"].([]string)
	if !contains(un, "zz-unknown-rule") || !contains(un, "ransomware-churn") || !contains(un, "identity-from-finding") {
		t.Fatalf("unmapped_rules incomplete: %v", un)
	}
	for _, r := range []string{"unsafe-permissions", "persistence-attempt", "script-inline-execution", "root-history-clear", "ioc-domain", "ioa-ioa-1"} {
		if contains(un, r) {
			t.Errorf("%s should be mapped now", r)
		}
	}
	for _, r := range un {
		if strings.HasPrefix(r, "custom-rule") || r == "ioc-generic" || r == "ioa-generic" {
			t.Errorf("placeholder %s leaked into unmapped_rules", r)
		}
	}
	if m["observed_hits"].(int) != 1 || m["unmapped_hits"].(int) != 1 {
		t.Fatalf("hits: observed=%v unmapped=%v", m["observed_hits"], m["unmapped_hits"])
	}
	if n := techniqueNode(m, "T1082"); n != nil && n.Hits > 0 {
		t.Fatal("unmapped finding leaked into T1082 hits")
	}
	// A rule with no mapping must not be counted as covered anywhere.
	for _, tac := range m["tactics"].([]*ATTACKTactic) {
		for _, tn := range tac.Techniques {
			if contains(tn.Rules, "zz-unknown-rule") {
				t.Fatal("unmapped rule listed under a technique")
			}
		}
	}
}

func TestNewlyMappedRulesInMatrix(t *testing.T) {
	m := BuildATTACKMatrix(nil)
	for tech, rule := range map[string]string{"T1222.002": "unsafe-permissions", "T1053": "persistence-attempt", "T1059": "script-inline-execution", "T1070.003": "root-history-clear"} {
		n := techniqueNode(m, tech)
		if n == nil || !contains(n.Rules, rule) {
			t.Errorf("matrix: %s should list %s: %+v", tech, rule, n)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
