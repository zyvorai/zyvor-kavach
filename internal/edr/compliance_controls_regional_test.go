// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"strings"
	"testing"
)

func TestRegionalCatalogCoverage(t *testing.T) {
	if len(regionalFrameworks) < 18 {
		t.Fatalf("frameworks=%d", len(regionalFrameworks))
	}
	if len(regionalControls) < 200 {
		t.Fatalf("controls=%d want >=200", len(regionalControls))
	}
	per := map[string]int{}
	ids := map[string]bool{}
	for _, c := range regionalControls {
		per[c.Framework]++
		if ids[c.ID] {
			t.Errorf("duplicate id %s", c.ID)
		}
		ids[c.ID] = true
		if c.Title == "" {
			t.Errorf("%s: empty title", c.ID)
		}
		if c.Kind != "" && strings.TrimSpace(c.Note) == "" {
			t.Errorf("%s: not_observable control needs a reason", c.ID)
		}
		if c.Kind == "" && len(c.Signals) == 0 {
			t.Errorf("%s: evidence claim without signals", c.ID)
		}
	}
	for _, f := range regionalFrameworks {
		if per[f.ID] < 6 {
			t.Errorf("%s has only %d controls", f.ID, per[f.ID])
		}
	}
}

func TestRegionalScoringAndBackCompat(t *testing.T) {
	out := BuildComplianceScore(newTestStore(t), nil)
	fws := out["frameworks"].([]map[string]any)
	have := map[string]bool{}
	for _, f := range fws {
		have[f["id"].(string)] = true
		for _, k := range []string{"framework", "score", "grade", "failing", "id", "name", "controls_total"} {
			if _, ok := f[k]; !ok {
				t.Fatalf("missing key %s", k)
			}
		}
	}
	for _, f := range regionalFrameworks {
		if !have[f.ID] {
			t.Errorf("score missing %s", f.ID)
		}
	}
	for _, id := range []string{"cis-v8", "nist-csf-2", "soc2", "iso27001", "rbi", "cert-in", "dpdp", "pci-dss-4", "hipaa", "nist-800-53"} {
		if !have[id] {
			t.Errorf("legacy framework %s missing", id)
		}
	}
	// With no evidence, nothing may be reported as met.
	s := evSignals{Counts: map[string]int{}, Level: map[string]int{}}
	for _, c := range regionalControls {
		if r := scoreControl(c, s); r.Status == scoreMet {
			t.Errorf("%s met without evidence", c.ID)
		}
	}
	if _, ok := lookupFramework("nis2"); !ok {
		t.Fatal("nis2 not resolvable")
	}
}
