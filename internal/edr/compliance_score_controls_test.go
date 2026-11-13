// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir()+"/f.jsonl", 1000)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScoreControlStatuses(t *testing.T) {
	s := evSignals{Counts: map[string]int{}, Level: map[string]int{sigFleet: 2, sigSBOM: 1}}
	if r := scoreControl(ctl("x", "A", "t", "", "n", sigFleet), s); r.Status != scoreMet || *r.Score != 100 || r.Reason == "" {
		t.Fatalf("met: %+v", r)
	}
	if r := scoreControl(ctl("x", "B", "t", "", "n", sigFleet, sigSBOM), s); r.Status != scorePartial || *r.Score != 75 {
		t.Fatalf("partial: %+v", r)
	}
	if r := scoreControl(ctl("x", "C", "t", "", "n", sigFIM), s); r.Status != scoreUnmet || *r.Score != 0 {
		t.Fatalf("unmet: %+v", r)
	}
	for _, kind := range []string{"manual", "not_applicable"} {
		r := scoreControl(ctl("x", "D", "t", kind, "why", sigFleet), s)
		if r.Status != scoreNotObservable || r.Score != nil || r.Reason == "" {
			t.Fatalf("%s must be not_observable: %+v", kind, r)
		}
	}
}

func TestBuildComplianceScoreCoversCatalog(t *testing.T) {
	store := newTestStore(t)
	out := BuildComplianceScore(store, nil)
	fws := out["frameworks"].([]map[string]any)
	if len(fws) != len(evidenceFrameworks) || len(fws) < 10 {
		t.Fatalf("frameworks=%d want %d", len(fws), len(evidenceFrameworks))
	}
	for _, k := range []string{"overall", "grade", "mode", "source"} {
		if _, ok := out[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	total := 0
	for _, f := range fws {
		for _, k := range []string{"framework", "score", "grade", "failing"} {
			if _, ok := f[k]; !ok {
				t.Fatalf("framework entry missing %s", k)
			}
		}
		total += f["controls_total"].(int)
		if f["observable"].(int)+f["not_observable"].(int) != f["controls_total"].(int) {
			t.Fatalf("counts inconsistent: %v", f)
		}
	}
	if total != len(evidenceCatalog) {
		t.Fatalf("controls %d != catalog %d", total, len(evidenceCatalog))
	}
	one := BuildComplianceScoreWith(store, nil, nil, nil, "hipaa")
	cs := one["controls"].([]ScoredControl)
	if len(cs) == 0 {
		t.Fatal("no controls")
	}
	for _, c := range cs {
		if c.Reason == "" || (c.Status == scoreNotObservable) != (c.Score == nil) {
			t.Fatalf("bad control %+v", c)
		}
	}
}

func TestComplianceScoreHTTPFramework(t *testing.T) {
	mux := http.NewServeMux()
	RegisterComplianceScoreFull(mux, "tok", newTestStore(t), nil, nil, nil)
	do := func(q string) int {
		req := httptest.NewRequest("GET", "/v1/compliance/score"+q, nil)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if c := do(""); c != 200 {
		t.Fatal(c)
	}
	if c := do("?framework=soc2"); c != 200 {
		t.Fatal(c)
	}
	if c := do("?framework=nope"); c != 400 {
		t.Fatal(c)
	}
}
