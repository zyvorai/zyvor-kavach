// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"strings"
	"testing"
)

func TestGuidanceCatalogIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range guidanceCatalog {
		if seen[strings.ToLower(e.ID)] {
			t.Fatalf("duplicate id %s", e.ID)
		}
		seen[strings.ToLower(e.ID)] = true
		if e.Kind == "technique" && !techniqueIDRe.MatchString(e.ID) {
			t.Errorf("bad technique id %s", e.ID)
		}
		if len(e.HowToInvestigate) == 0 || len(e.HowToRemediate) == 0 || e.WhatItMeans == "" {
			t.Errorf("incomplete entry %s", e.ID)
		}
		all := strings.ToLower(strings.Join(e.HowToRemediate, " ") + e.WhyItMatters)
		for _, bad := range []string{"automatically", "auto-remediat", "kavach will", "kavach has"} {
			if strings.Contains(all, bad) {
				t.Errorf("%s claims automatic action: %s", e.ID, bad)
			}
		}
		for _, ref := range e.References {
			if !strings.HasPrefix(ref, "https://attack.mitre.org/techniques/T") {
				t.Errorf("%s bad reference %s", e.ID, ref)
			}
		}
	}
	if len(guidanceCatalog) < 140 {
		t.Errorf("catalog too small: %d", len(guidanceCatalog))
	}
}

func TestGuidanceCoversEmittedRulesAndMITRE(t *testing.T) {
	for _, r := range EmittedRuleNames {
		if _, ok := guidanceByID(r); !ok {
			t.Errorf("no guidance for rule %s", r)
		}
	}
	for r := range ruleMITRE {
		if _, ok := ResolveGuidance(r); !ok {
			t.Errorf("rule in ruleMITRE unresolved: %s", r)
		}
	}
}

func TestResolveFallsBackToTechnique(t *testing.T) {
	ruleMITRE["zz-test-rule"] = struct{ Tactic, Technique, ID string }{"Discovery", "x", "T1082"}
	defer delete(ruleMITRE, "zz-test-rule")
	e, ok := ResolveGuidance("zz-test-rule")
	if !ok || e.Kind != "technique" || e.ID != "T1082" {
		t.Fatalf("got %+v ok=%v", e, ok)
	}
	ruleMITRE["zz-sub"] = struct{ Tactic, Technique, ID string }{"Discovery", "x", "T1082.999"}
	defer delete(ruleMITRE, "zz-sub")
	if e, ok := ResolveGuidance("zz-sub"); !ok || e.ID != "T1082" {
		t.Fatalf("parent fallback failed: %+v", e)
	}
	if e, ok := ResolveGuidance("ransomware-burst"); !ok || e.Kind != "rule" {
		t.Fatal("rule-first failed")
	}
	if _, ok := ResolveGuidance("custom-foo"); !ok {
		t.Fatal("custom prefix")
	}
}
