// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"testing"
	"time"
)

func bsRules() []ContentRule {
	return []ContentRule{
		{ID: "r-reg-1", Technique: "T1547.001", EventType: "registry"},
		{ID: "r-reg-2", Technique: "T1112", EventType: "registry"},
		{ID: "r-proc-1", Technique: "T1059", EventType: "process"},
		{ID: "r-proc-2", Technique: "T1547.001", EventType: "process"}, // T1547.001 is degraded, not unobservable
		{ID: "r-dns-1", Technique: "T1071.004", EventType: "dns"},
		{ID: "r-auth-1", Technique: "T1110", EventType: "auth"},
		{ID: "r-auth-2", Technique: "T1078", EventType: "auth"},
	}
}

func TestBlindspotsLogic(t *testing.T) {
	now := time.Now()
	obs := map[string]catObs{
		"process":  {Count: 10, Last: now.Add(-time.Hour)},
		"registry": {},                                              // never seen
		"dns":      {Count: 3, Last: now.Add(-30 * 24 * time.Hour)}, // stale
		"auth":     {},
		"file":     {Count: 1, Last: now},
	}
	val := &blindValidation{Missed: []ValTechScore{{ID: "T1003", Status: "missed"}}, NotTestable: []ValTechScore{{ID: "T1200", Status: "not_testable"}}}
	rep := buildBlindspots(obs, bsRules(), now, 7*24*time.Hour, val)
	un := rep["techniques_unobservable"].([]blindTech)
	ids := map[string]bool{}
	for _, u := range un {
		ids[u.Technique] = true
	}
	if !ids["T1112"] || !ids["T1110"] || !ids["T1078"] || ids["T1547.001"] || ids["T1059"] || ids["T1071.004"] {
		t.Fatalf("unobservable: %v", ids)
	}
	if rep["techniques_unobservable_count"].(int) != 3 {
		t.Fatalf("count %v", rep["techniques_unobservable_count"])
	}
	risk := rep["techniques_at_risk_stale"].([]blindTech)
	if len(risk) != 1 || risk[0].Technique != "T1071.004" {
		t.Fatalf("stale: %+v", risk)
	}
	gaps := rep["collection_gaps"].([]blindGap)
	var reg, dns *blindGap
	for i := range gaps {
		switch gaps[i].Category {
		case "registry":
			reg = &gaps[i]
		case "dns":
			dns = &gaps[i]
		case "process", "file":
			t.Fatalf("active category listed as gap: %s", gaps[i].Category)
		}
	}
	if reg == nil || reg.State != catNever || reg.RulesCannotFire != 2 || reg.TechniquesCannotFire != 1 || reg.TechniquesDegraded != 1 {
		t.Fatalf("registry gap: %+v", reg)
	}
	if dns == nil || dns.State != catStale || dns.LastSeen == "" {
		t.Fatalf("dns gap: %+v", dns)
	}
	prio := rep["enable_first"].([]blindPriority)
	if len(prio) != 2 || prio[0].Category != "auth" || prio[0].TechniquesUnlocked != 2 || prio[0].Rank != 1 {
		t.Fatalf("priority: %+v", prio)
	}
	v := rep["validation"].(map[string]any)
	if len(v["missed"].([]ValTechScore)) != 1 || len(v["not_testable"].([]ValTechScore)) != 1 {
		t.Fatalf("validation: %+v", v)
	}
}

func TestBlindspotsAllPresent(t *testing.T) {
	now := time.Now()
	obs := map[string]catObs{}
	for _, c := range telemetryCategories() {
		obs[c] = catObs{Count: 1, Last: now}
	}
	rep := buildBlindspots(obs, bsRules(), now, 24*time.Hour, nil)
	if len(rep["collection_gaps"].([]blindGap)) != 0 || len(rep["techniques_unobservable"].([]blindTech)) != 0 {
		t.Fatalf("unexpected gaps: %+v", rep["collection_gaps"])
	}
}

func TestBlindspotsEmptyStoreNoPanic(t *testing.T) {
	obs := collectCategoryObs(nil)
	obs2 := collectCategoryObs(&Store{})
	if len(obs) == 0 || len(obs2) == 0 {
		t.Fatal("expected all categories present as never_seen")
	}
	rep := buildBlindspots(obs2, nil, time.Now(), time.Hour, nil)
	if rep["techniques_claimed"].(int) != 0 {
		t.Fatal("no rules expected")
	}
	_ = buildBlindspots(nil, bsRules(), time.Now(), time.Hour, nil)
	inv := buildTelemetryInventory(obs, time.Now(), time.Hour)
	for _, c := range inv {
		if c.State != catNever || c.LastSeen != nil {
			t.Fatalf("empty store category %+v", c)
		}
	}
}

func TestCollectCategoryObsFromStore(t *testing.T) {
	now := time.Now()
	s := &Store{
		recentEvents:  []Event{{Time: now.Add(-time.Minute)}, {Time: now}},
		networkEvents: []NetworkEvent{{Time: now.Add(-48 * time.Hour)}},
	}
	o := collectCategoryObs(s)
	if o["process"].Count != 2 || !o["process"].Last.Equal(now) || o["network"].Count != 1 || o["file"].Count != 0 {
		t.Fatalf("%+v", o)
	}
	if categoryState(o["network"], now, 24*time.Hour) != catStale || categoryState(o["process"], now, time.Hour) != catActive {
		t.Fatal("state")
	}
}

func TestRunBlindValidation(t *testing.T) {
	if v := runBlindValidation(); v == nil {
		t.Fatal("validation lab did not load")
	}
}
