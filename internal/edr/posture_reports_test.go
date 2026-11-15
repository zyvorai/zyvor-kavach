// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const prTok = "posture-test-token-123456"

func prServer(t *testing.T) http.Handler {
	t.Helper()
	old := postureFirstDelay
	postureFirstDelay = time.Hour // no automatic snapshot during tests
	t.Cleanup(func() { postureFirstDelay = old })
	store, err := NewStore(filepath.Join(t.TempDir(), "s.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	return APIWithCredentials(prTok, store, nil)
}

func prGet(h http.Handler, path, tok string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func prPut(h http.Handler, path, body, tok string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("PUT", path, strings.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPostureReportsRequireAuth(t *testing.T) {
	h := prServer(t)
	for _, p := range []string{"/v1/posture/trend", "/v1/posture/trend/diff?from=2026-01-01", "/v1/posture/trend/config", "/v1/reports/digest", "/v1/compliance/auditor-bundle"} {
		if c := prGet(h, p, "").Code; c != 401 {
			t.Errorf("%s without token: %d", p, c)
		}
		if c := prGet(h, p, "wrong").Code; c != 401 {
			t.Errorf("%s wrong token: %d", p, c)
		}
	}
	if c := prPut(h, "/v1/posture/trend/config", `{"interval_hours":2,"enabled":true}`, "").Code; c != 401 && c != 403 {
		t.Errorf("unauthenticated PUT: %d", c)
	}
	if c := prPut(h, "/v1/posture/trend/config", `{"interval_hours":0,"enabled":true}`, prTok).Code; c != 400 {
		t.Errorf("bad interval: %d", c)
	}
	if c := prPut(h, "/v1/posture/trend/config", `{"interval_hours":2,"enabled":true,"x":1}`, prTok).Code; c != 400 {
		t.Errorf("unknown field: %d", c)
	}
	if c := prPut(h, "/v1/posture/trend/config", `{"interval_hours":2,"enabled":true}`, prTok).Code; c != 200 {
		t.Errorf("admin PUT: %d", c)
	}
}

func TestPostureEngineCapPersistAndDiff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.posturetrend.json")
	e := newPostureEngine(path, nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < postureTrendCap+25; i++ {
		e.Record(PostureSnapshot{Time: base.Add(time.Duration(i) * time.Hour), ComplianceScore: i % 100})
	}
	if got := len(e.Snapshots()); got != postureTrendCap {
		t.Fatalf("cap: %d", got)
	}
	e2 := newPostureEngine(path, nil)
	if len(e2.Snapshots()) != postureTrendCap {
		t.Fatalf("not persisted: %d", len(e2.Snapshots()))
	}
	if !e2.due(base.AddDate(1, 0, 0)) || e2.due(e2.Snapshots()[postureTrendCap-1].Time.Add(time.Minute)) {
		t.Fatal("due logic")
	}
	hb1, hb2 := 90.0, 70.0
	a := PostureSnapshot{ComplianceScore: 40, FindingsBySev: map[string]int{"high": 3}, FrameworkScores: map[string]int{"soc2": 30}, HeartbeatBudgetPct: &hb1}
	b := PostureSnapshot{ComplianceScore: 55, FindingsBySev: map[string]int{"high": 1, "low": 2}, FrameworkScores: map[string]int{"soc2": 50}, HeartbeatBudgetPct: &hb2}
	d := diffPosture(a, b)
	if d.ComplianceScore != 15 || d.FindingsBySev["high"] != -2 || d.FindingsBySev["low"] != 2 || d.FrameworkScores["soc2"] != 20 || *d.HeartbeatBudget != -20 || d.Continuity != nil {
		t.Fatalf("diff %+v", d)
	}
}

func TestPostureTrendEndpointValidation(t *testing.T) {
	h := prServer(t)
	if c := prGet(h, "/v1/posture/trend", prTok).Code; c != 200 {
		t.Fatal(c)
	}
	for p, want := range map[string]int{
		"/v1/posture/trend?days=0":                             400,
		"/v1/posture/trend?days=9999":                          400,
		"/v1/posture/trend/diff?from=nope":                     400,
		"/v1/posture/trend/diff?from=2020-01-01&to=2020-1-5":   400,
		"/v1/posture/trend/diff?from=2020-02-01&to=2020-01-05": 400,
		"/v1/posture/trend/diff?from=2020-01-01&to=2020-01-05": 404,
	} {
		if c := prGet(h, p, prTok).Code; c != want {
			t.Errorf("%s: got %d want %d", p, c, want)
		}
	}
}

func TestSnapshotAtOrBefore(t *testing.T) {
	d := func(day int) time.Time { return time.Date(2026, 3, day, 12, 0, 0, 0, time.UTC) }
	snaps := []PostureSnapshot{{Time: d(1)}, {Time: d(3)}, {Time: d(7)}}
	if s, ok := snapshotAtOrBefore(snaps, d(5)); !ok || !s.Time.Equal(d(3)) {
		t.Fatal("at or before")
	}
	if _, ok := snapshotAtOrBefore(snaps, d(1).Add(-time.Second)); ok {
		t.Fatal("expected none")
	}
}

func prSnap() (PostureSnapshot, *PostureSnapshot) {
	hb := 80.5
	cur := PostureSnapshot{Time: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), ComplianceScore: 42, ComplianceGrade: "F", FrameworkScores: map[string]int{"soc2": 42},
		TacticsCovered: 12, TacticsTotal: 14, FindingsTotal: 5, FindingsBySev: map[string]int{"critical": 1, "high": 2}, AgentsActive: 3, HeartbeatBudgetPct: &hb,
		RulesTotal: 100, RulesSilent: 40, RulesNoisy: 2}
	b := cur
	b.Time = cur.Time.AddDate(0, 0, -7)
	b.ComplianceScore = 40
	b.FindingsBySev = map[string]int{"critical": 0, "high": 2}
	return cur, &b
}

func TestDigestDeterministicAndFactorBacked(t *testing.T) {
	cur, base := prSnap()
	now := time.Date(2026, 11, 15, 1, 0, 0, 0, time.UTC)
	d1, d2 := buildDigest(cur, base, 7, now), buildDigest(cur, base, 7, now)
	j1, _ := json.Marshal(d1)
	j2, _ := json.Marshal(d2)
	if !bytes.Equal(j1, j2) || d1.Markdown() != d2.Markdown() || !bytes.Equal(d1.HTML(), d2.HTML()) {
		t.Fatal("digest not deterministic")
	}
	for _, s := range d1.Statements {
		if len(s.Factors) == 0 {
			t.Errorf("statement without factors: %s", s.Text)
		}
	}
	if !strings.Contains(d1.Statements[0].Text, "+2 points") {
		t.Errorf("delta text: %s", d1.Statements[0].Text)
	}
	d3 := buildDigest(cur, nil, 7, now)
	if strings.Contains(d3.Markdown(), "baseline: total") || len(d3.NotAssessed) == 0 {
		t.Fatalf("baseline-free digest: %+v", d3.NotAssessed)
	}
	cur.HeartbeatBudgetPct = nil
	d4 := buildDigest(cur, base, 7, now)
	if strings.Contains(d4.Markdown(), "heartbeat error budget") || !strings.Contains(strings.Join(d4.NotAssessed, " "), "SLO") {
		t.Fatal("SLO must be not assessed")
	}
	if !strings.Contains(string(d1.HTML()), "<title>") || strings.Contains(string(d1.HTML()), "<script") {
		t.Fatal("html")
	}
}

func TestDigestEndpointFormats(t *testing.T) {
	h := prServer(t)
	for f, ct := range map[string]string{"json": "application/json", "md": "text/markdown", "html": "text/html"} {
		w := prGet(h, "/v1/reports/digest?format="+f, prTok)
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), ct) {
			t.Errorf("%s: %d %s", f, w.Code, w.Header().Get("Content-Type"))
		}
	}
	if prGet(h, "/v1/reports/digest?format=pdf", prTok).Code != 400 || prGet(h, "/v1/reports/digest?days=999", prTok).Code != 400 {
		t.Error("validation")
	}
}

func TestAuditorBundleDeterministicManifestAndNoSecrets(t *testing.T) {
	now := time.Date(2026, 11, 15, 1, 0, 0, 0, time.UTC)
	n := 0
	raw := []byte(`{"b":1,"a":{"api_token":"x","note":"call with ` + prTok + `","ok":true},"password":"p"}`)
	parts := func() []bundlePart {
		return []bundlePart{{"z.json", scrubJSON(raw, prTok, &n)}, {"a.json", []byte("{}\n")}}
	}
	z1, m1, err := buildAuditorBundle(parts(), now, 3)
	if err != nil {
		t.Fatal(err)
	}
	z2, _, _ := buildAuditorBundle(parts(), now, 3)
	if !bytes.Equal(z1, z2) {
		t.Fatal("bundle not deterministic")
	}
	if n != 6 { // 3 per scrub call, two calls
		t.Errorf("redactions %d", n)
	}
	zr, err := zip.NewReader(bytes.NewReader(z1), int64(len(z1)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = b
		if strings.Contains(string(b), prTok) || strings.Contains(string(b), "api_token") || strings.Contains(string(b), `"password"`) {
			t.Errorf("secret leaked in %s", f.Name)
		}
	}
	for _, e := range m1.Files {
		h := sha256.Sum256(got[e.Path])
		if hex.EncodeToString(h[:]) != e.SHA256 {
			t.Errorf("manifest hash mismatch for %s", e.Path)
		}
		if !strings.Contains(string(got["MANIFEST.sha256"]), e.SHA256+"  "+e.Path) {
			t.Errorf("sha256 file missing %s", e.Path)
		}
	}
	if _, ok := got["MANIFEST.json"]; !ok {
		t.Fatal("no MANIFEST.json")
	}
}

func TestAuditorBundleCaps(t *testing.T) {
	now := time.Now()
	big := bytes.Repeat([]byte("a"), bundlePartCap+1)
	_, m, err := buildAuditorBundle([]bundlePart{{"big.json", big}}, now, 0)
	if err != nil || !strings.Contains(m.Files[0].Note, "truncated") {
		t.Fatalf("part cap: %v %+v", err, m.Files)
	}
	var many []bundlePart
	for i := 0; i < 8; i++ {
		many = append(many, bundlePart{"f" + string(rune('a'+i)) + ".json", bytes.Repeat([]byte("b"), bundlePartCap)})
	}
	if _, _, err := buildAuditorBundle(many, now, 0); err == nil {
		t.Fatal("total cap not enforced")
	}
}

func TestAuditorBundleEndpoint(t *testing.T) {
	h := prServer(t)
	w := prGet(h, "/v1/compliance/auditor-bundle", prTok)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(b), prTok) {
			t.Errorf("token in %s", f.Name)
		}
	}
	for _, want := range []string{"compliance/evidence.json", "content/versions.json", "lab/validation-coverage.json", "config-assessment/policy-catalog.json", "CAVEATS.md", "MANIFEST.json", "MANIFEST.sha256"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
	m := prGet(h, "/v1/compliance/auditor-bundle?manifest=1", prTok)
	var man BundleManifest
	if m.Code != 200 || json.Unmarshal(m.Body.Bytes(), &man) != nil || len(man.Files) < 6 {
		t.Fatalf("manifest %d", m.Code)
	}
}
