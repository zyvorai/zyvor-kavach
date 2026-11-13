// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestAdversaryPacksValid(t *testing.T) {
	ps, err := Adversaries()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 60 {
		t.Fatalf("want >=60 profiles, got %d", len(ps))
	}
	for _, p := range ps {
		if err := validateAdversary(p); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
	}
}

func TestAdversaryValidationRejects(t *testing.T) {
	good := `{"pack":"x","profiles":[{"id":"a","name":"A","aliases":[],"kind":"cybercrime","attributed_origin":"","motivation":"m","targets":"t","techniques":["T1059.001"],"confidence":"low","sources":[{"title":"s","url":"https://example.com"}]}]}`
	if _, err := parseAdversaryPacks(map[string][]byte{"a.json": []byte(good)}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdversaryPacks(map[string][]byte{"a.json": []byte(good), "b.json": []byte(good)}); err == nil {
		t.Fatal("duplicate id accepted")
	}
	bad := map[string]string{
		"tech":    `"techniques":["T10"]`,
		"nosrc":   `"sources":[]`,
		"conf":    `"confidence":"certain"`,
		"nourl":   `"sources":[{"title":"s","url":"http://x"}]`,
		"notechs": `"techniques":[]`,
	}
	for name, repl := range bad {
		var m map[string]any
		_ = json.Unmarshal([]byte(good), &m)
		p := m["profiles"].([]any)[0].(map[string]any)
		var frag map[string]any
		_ = json.Unmarshal([]byte("{"+repl+"}"), &frag)
		for k, v := range frag {
			p[k] = v
		}
		b, _ := json.Marshal(m)
		if _, err := parseAdversaryPacks(map[string][]byte{"a.json": b}); err == nil {
			t.Errorf("%s: invalid profile accepted", name)
		}
	}
}

func TestAdversaryEndpoints(t *testing.T) {
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	if err := LoadContentPacks(); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterAdversaries(mux, "tok", store)
	get := func(path string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	for _, p := range []string{"/v1/adversaries", "/v1/adversaries/apt29", "/v1/adversaries/coverage"} {
		if w := get(p, false); w.Code != 401 {
			t.Fatalf("%s unauth: %d", p, w.Code)
		}
	}
	var list struct {
		Count int `json:"count"`
	}
	w := get("/v1/adversaries?kind=ransomware", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || list.Count != 10 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var one struct {
		Profile  AdversaryProfile  `json:"profile"`
		Coverage AdversaryCoverage `json:"coverage"`
	}
	w = get("/v1/adversaries/apt29", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &one) != nil || one.Profile.ID != "apt29" {
		t.Fatalf("show: %d %s", w.Code, w.Body.String())
	}
	c := one.Coverage
	if c.Total != len(one.Profile.Techniques) || len(c.Techniques) != c.Total || c.Exact+c.Related+len(c.Gaps) != c.Total {
		t.Fatalf("coverage arithmetic: %+v", c)
	}
	if c.CoveragePct <= 0 {
		t.Fatalf("expected some coverage from embedded content: %+v", c)
	}
	if w = get("/v1/adversaries/nope", true); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	var cov struct {
		Count      int                 `json:"count"`
		ByCoverage []AdversaryCoverage `json:"by_coverage"`
		ByHits     []AdversaryCoverage `json:"by_observed_hits"`
	}
	w = get("/v1/adversaries/coverage", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cov) != nil || cov.Count < 60 || len(cov.ByHits) != cov.Count {
		t.Fatalf("coverage: %d", w.Code)
	}
	for i := 1; i < len(cov.ByCoverage); i++ {
		if cov.ByCoverage[i-1].CoveragePct < cov.ByCoverage[i].CoveragePct {
			t.Fatal("not ranked by coverage")
		}
	}
}
