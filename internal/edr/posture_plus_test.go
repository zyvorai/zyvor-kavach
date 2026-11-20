// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type postureFixture struct {
	srv   *httptest.Server
	svc   *postureSvc
	store *Store
	tok   string
	rows  map[string][]map[string]any
	vulns []Vulnerability
	path  string
}

func newPostureFixture(t *testing.T) *postureFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.jsonl")
	s, err := testStore(t, path, 50)
	if err != nil {
		t.Fatal(err)
	}
	f := &postureFixture{store: s, tok: "0123456789abcdef", rows: map[string][]map[string]any{}, path: path}
	f.svc = newPostureSvc(s)
	f.svc.rows = func(d string) []map[string]any { return f.rows[d] }
	f.svc.vulns = func() []Vulnerability { return f.vulns }
	mux := http.NewServeMux()
	registerPosturePlus(mux, f.tok, f.svc)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *postureFixture) do(t *testing.T, method, p, tok, body string) (int, string) {
	t.Helper()
	r, b := send(t, method, f.srv.URL+p, tok, body)
	return r.StatusCode, b
}

func TestPostureAuth(t *testing.T) {
	f := newPostureFixture(t)
	for _, p := range []string{"/v1/posture/assets", "/v1/posture/vuln-priority", "/v1/posture/drift?host=a", "/v1/posture/summary"} {
		if c, _ := f.do(t, "GET", p, "", ""); c != 401 {
			t.Fatalf("%s unauth = %d", p, c)
		}
	}
	for _, m := range [][2]string{{"POST", "/v1/posture/assets"}, {"DELETE", "/v1/posture/assets?host=a"}, {"POST", "/v1/posture/baseline"}} {
		if c, _ := f.do(t, m[0], m[1], "", "{}"); c != 401 {
			t.Fatalf("%v unauth = %d", m, c)
		}
	}
}

func TestPostureEmptyState(t *testing.T) {
	f := newPostureFixture(t)
	c, b := f.do(t, "GET", "/v1/posture/summary", f.tok, "")
	if c != 200 || !strings.Contains(b, `"registered":0`) || !strings.Contains(b, `"total":0`) {
		t.Fatalf("%d %s", c, b)
	}
	c, b = f.do(t, "GET", "/v1/posture/vuln-priority", f.tok, "")
	if c != 200 || !strings.Contains(b, `"items":[]`) {
		t.Fatalf("%d %s", c, b)
	}
	c, b = f.do(t, "GET", "/v1/posture/drift?host=nope", f.tok, "")
	if c != 200 || !strings.Contains(b, `"has_baseline":false`) {
		t.Fatalf("%d %s", c, b)
	}
	if c, _ := f.do(t, "GET", "/v1/posture/drift", f.tok, ""); c != 400 {
		t.Fatalf("missing host = %d", c)
	}
}

func TestPostureAssetsPersistAndValidate(t *testing.T) {
	f := newPostureFixture(t)
	c, b := f.do(t, "POST", "/v1/posture/assets", f.tok, `{"host":"db1","criticality":5,"owner":"<b>ops</b>","tags":["internet","<x>"]}`)
	if c != 201 || strings.Contains(b, "<b>") || strings.Contains(b, "<x>") {
		t.Fatalf("%d %s", c, b)
	}
	for _, bad := range []string{`{"host":"","criticality":3}`, `{"host":"a","criticality":0}`, `{"host":"a","criticality":6}`, `nope`} {
		if c, _ := f.do(t, "POST", "/v1/posture/assets", f.tok, bad); c != 400 {
			t.Fatalf("%s = %d", bad, c)
		}
	}
	// Reload from disk.
	again := newPostureSvc(f.store)
	if a, ok := again.st.Assets["db1"]; !ok || a.Criticality != 5 || len(a.Tags) != 2 {
		t.Fatalf("not persisted: %+v", again.st.Assets)
	}
	if c, _ := f.do(t, "DELETE", "/v1/posture/assets?host=db1", f.tok, ""); c != 204 {
		t.Fatal(c)
	}
	if c, _ := f.do(t, "DELETE", "/v1/posture/assets?host=db1", f.tok, ""); c != 404 {
		t.Fatal(c)
	}
	if len(newPostureSvc(f.store).st.Assets) != 0 {
		t.Fatal("delete not persisted")
	}
}

func TestPostureAssetCap(t *testing.T) {
	f := newPostureFixture(t)
	for i := 0; i < maxPostureAssets; i++ {
		f.svc.st.Assets[fmt.Sprintf("h%d", i)] = PostureAsset{Host: fmt.Sprintf("h%d", i), Criticality: 1}
	}
	if c, _ := f.do(t, "POST", "/v1/posture/assets", f.tok, `{"host":"extra","criticality":2}`); c != 400 {
		t.Fatalf("cap = %d", c)
	}
	if c, _ := f.do(t, "POST", "/v1/posture/assets", f.tok, `{"host":"h1","criticality":2}`); c != 201 {
		t.Fatalf("update at cap = %d", c)
	}
}

func TestPostureVulnPriorityMath(t *testing.T) {
	f := newPostureFixture(t)
	f.vulns = []Vulnerability{
		{ID: "a", CVE: "CVE-1", Host: "web1", Severity: "high", ExPRTScore: 8, Exploited: true},
		{ID: "b", CVE: "CVE-2", Host: "lab", Severity: "medium"},
		{ID: "c", CVE: "CVE-3", Host: "web1", Severity: "low", ExPRTScore: 2},
	}
	f.do(t, "POST", "/v1/posture/assets", f.tok, `{"host":"web1","criticality":5,"tags":["internet-facing"]}`)
	_ = f.store.Append(Finding{ID: "f1", Host: "web1", Severity: "critical", Rule: "r"})
	_ = f.store.Append(Finding{ID: "f2", Host: "web1", Severity: "low", Rule: "r"})

	c, b := f.do(t, "GET", "/v1/posture/vuln-priority", f.tok, "")
	if c != 200 {
		t.Fatal(c, b)
	}
	var out struct {
		Items []PrioritizedVuln `json:"items"`
	}
	if err := json.Unmarshal([]byte(b), &out); err != nil || len(out.Items) != 3 {
		t.Fatalf("%v %s", err, b)
	}
	// a: 8*4=32 + 5*6=30 + (5+1)=6 + 10 + 10 = 88
	a := out.Items[0]
	if a.ID != "a" || a.Score != 88 || a.Rank != 1 || len(a.Breakdown) != 5 {
		t.Fatalf("%+v", a)
	}
	want := map[string]float64{"cvss": 32, "asset_criticality": 30, "host_findings": 6, "internet_exposure": 10, "known_exploited": 10}
	for _, bc := range a.Breakdown {
		if want[bc.Factor] != bc.Points || bc.Detail == "" {
			t.Fatalf("component %+v", bc)
		}
	}
	// b: severity medium=5 -> 20 + default crit 3 -> 18 = 38 ; c: 8 + 30 + 6 = 44
	if out.Items[1].ID != "c" || out.Items[1].Score != 54 || out.Items[2].ID != "b" || out.Items[2].Score != 38 {
		t.Fatalf("%+v", out.Items)
	}
	_, b = f.do(t, "GET", "/v1/posture/vuln-priority?limit=1", f.tok, "")
	if strings.Count(b, `"rank"`) != 1 {
		t.Fatalf("limit not applied: %s", b)
	}
}

func TestPostureDriftAndBaseline(t *testing.T) {
	f := newPostureFixture(t)
	f.rows["sbom"] = []map[string]any{
		{"host": "h1", "component": "openssl", "version": "3.0.1"},
		{"host": "h1", "component": "curl", "version": "8.0"},
		{"host": "other", "component": "zlib", "version": "1"},
	}
	f.rows["persistence"] = []map[string]any{{"host": "h1", "type": "cron", "name": "backup", "risk": "low"}}
	f.rows["fim"] = []map[string]any{{"host": "h1", "path": "/etc/hosts", "size": 10, "mtime": "t1"}}

	if c, _ := f.do(t, "POST", "/v1/posture/baseline?host=h1", f.tok, ""); c != 200 {
		t.Fatal(c)
	}
	_, b := f.do(t, "GET", "/v1/posture/drift?host=h1", f.tok, "")
	if !strings.Contains(b, `"total":0`) || !strings.Contains(b, `"has_baseline":true`) {
		t.Fatalf("expected no drift: %s", b)
	}

	f.rows["sbom"] = []map[string]any{
		{"host": "h1", "component": "openssl", "version": "3.0.2"}, // changed
		{"host": "h1", "component": "<img>", "version": "1"},       // added, escaped
	} // curl removed
	f.rows["persistence"] = append(f.rows["persistence"], map[string]any{"host": "h1", "type": "systemd", "name": "x.service", "risk": "high"})
	f.rows["fim"] = []map[string]any{
		{"host": "h1", "path": "/etc/hosts", "size": 11, "mtime": "t2"},
		{"host": "h1", "path": "/usr/bin/su2", "mode": "4755"},
	}
	_, b = f.do(t, "GET", "/v1/posture/drift?host=h1", f.tok, "")
	var rep DriftReport
	if err := json.Unmarshal([]byte(b), &rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b, "<img>") {
		t.Fatal("unescaped")
	}
	find := func(items []DriftItem, key string) *DriftItem {
		for i := range items {
			if strings.Contains(items[i].Key, key) {
				return &items[i]
			}
		}
		return nil
	}
	if it := find(rep.Added, "x.service"); it == nil || it.Severity != "critical" {
		t.Fatalf("persistence add: %+v", rep.Added)
	}
	if it := find(rep.Added, "su2"); it == nil || it.Severity != "critical" {
		t.Fatalf("setuid add: %+v", rep.Added)
	}
	if it := find(rep.Added, "img"); it == nil || it.Severity != "medium" {
		t.Fatalf("sbom add: %+v", rep.Added)
	}
	if it := find(rep.Changed, "openssl"); it == nil || it.Before != "3.0.1" || it.After != "3.0.2" {
		t.Fatalf("sbom change: %+v", rep.Changed)
	}
	if it := find(rep.Changed, "/etc/hosts"); it == nil || it.Severity != "high" {
		t.Fatalf("fim change: %+v", rep.Changed)
	}
	if it := find(rep.Removed, "curl"); it == nil || it.Severity != "low" {
		t.Fatalf("sbom remove: %+v", rep.Removed)
	}
	if rep.Highest != "critical" || rep.Total != 6 {
		t.Fatalf("highest=%s total=%d", rep.Highest, rep.Total)
	}
	// Ordering: highest severity first.
	if rep.Added[0].Severity != "critical" {
		t.Fatalf("not sorted: %+v", rep.Added)
	}

	// Summary reflects drift.
	_, b = f.do(t, "GET", "/v1/posture/summary", f.tok, "")
	if !strings.Contains(b, `"baselined_hosts":1`) || !strings.Contains(b, `"highest_severity":"critical"`) {
		t.Fatalf("summary: %s", b)
	}

	// Baseline persists across reload.
	if _, ok := newPostureSvc(f.store).st.Baselines["h1"]; !ok {
		t.Fatal("baseline not persisted")
	}
	f.rows["fim"] = append(f.rows["fim"], map[string]any{"host": "other", "path": "/etc/hosts"})
	// Baseline-all covers every observed host.
	_, b = f.do(t, "POST", "/v1/posture/baseline", f.tok, "")
	if !strings.Contains(b, `"baselined":2`) {
		t.Fatalf("baseline all: %s", b)
	}
}

func TestPostureBaselineCaps(t *testing.T) {
	f := newPostureFixture(t)
	for i := 0; i < maxBaselineItems+50; i++ {
		f.rows["sbom"] = append(f.rows["sbom"], map[string]any{"host": "big", "component": fmt.Sprintf("c%d", i), "version": "1"})
	}
	if err := f.svc.takeBaseline("big"); err != nil {
		t.Fatal(err)
	}
	bl := f.svc.st.Baselines["big"]
	if len(bl.Items["sbom"]) != maxBaselineItems || !bl.Truncated {
		t.Fatalf("items=%d truncated=%v", len(bl.Items["sbom"]), bl.Truncated)
	}
	// Drift report items are capped too.
	f.rows["sbom"] = nil
	for i := 0; i < maxDriftItems+30; i++ {
		f.rows["sbom"] = append(f.rows["sbom"], map[string]any{"host": "big", "component": fmt.Sprintf("n%d", i), "version": "1"})
	}
	rep := f.svc.drift("big")
	if len(rep.Added) != maxDriftItems || rep.Total != maxDriftItems+30+maxBaselineItems {
		t.Fatalf("added=%d total=%d", len(rep.Added), rep.Total)
	}
	// Host cap.
	for i := 0; i < maxPostureHosts; i++ {
		f.svc.st.Baselines[fmt.Sprintf("x%d", i)] = PostureBaseline{}
	}
	if c, _ := f.do(t, "POST", "/v1/posture/baseline?host=brandnew", f.tok, ""); c != 400 {
		t.Fatalf("host cap = %d", c)
	}
}
