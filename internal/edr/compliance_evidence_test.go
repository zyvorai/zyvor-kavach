// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const evTok = "0123456789abcdef"

func evSetup(t *testing.T) (http.Handler, *Store, *IncidentStore) {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := NewIncidentStore(s)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterComplianceEvidence(mux, evTok, s, nil, inc, nil)
	return mux, s, inc
}

func evGet(h http.Handler, path string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if auth {
		r.Header.Set("Authorization", "Bearer "+evTok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEvidenceAuth(t *testing.T) {
	h, _, _ := evSetup(t)
	for _, p := range []string{"/v1/compliance/controls", "/v1/compliance/evidence", "/v1/compliance/cert-in-clock"} {
		if w := evGet(h, p, false); w.Code != 401 {
			t.Fatalf("%s: got %d", p, w.Code)
		}
	}
}

func TestEvidenceFrameworkFilterAndUnknown(t *testing.T) {
	h, _, _ := evSetup(t)
	if w := evGet(h, "/v1/compliance/controls?framework=nope", true); w.Code != 400 {
		t.Fatalf("got %d", w.Code)
	}
	if w := evGet(h, "/v1/compliance/evidence?framework=nope", true); w.Code != 400 {
		t.Fatalf("got %d", w.Code)
	}
	w := evGet(h, "/v1/compliance/controls?framework=soc2", true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var out struct {
		Controls []ControlResult `json:"controls"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Controls) == 0 {
		t.Fatal("no controls")
	}
	for _, c := range out.Controls {
		if c.Framework != "soc2" {
			t.Fatalf("leak %s", c.Framework)
		}
	}
}

func TestEvidenceStatusDerivation(t *testing.T) {
	s := evSignals{Counts: map[string]int{}, Level: map[string]int{sigFleet: 2, sigSBOM: 0, sigFIM: 0}}
	if r := evaluateControl(ctl("x", "a", "t", "", "", sigFleet), s); r.Status != "pass" {
		t.Fatal(r.Status)
	}
	if r := evaluateControl(ctl("x", "a", "t", "", "", sigFleet, sigSBOM), s); r.Status != "partial" {
		t.Fatal(r.Status)
	}
	if r := evaluateControl(ctl("x", "a", "t", "", "", sigSBOM, sigFIM), s); r.Status != "fail" {
		t.Fatal(r.Status)
	}
	if r := evaluateControl(ctl("x", "a", "t", "manual", ""), s); r.Status != "manual" {
		t.Fatal(r.Status)
	}
	if r := evaluateControl(ctl("x", "a", "t", "not_applicable", ""), s); r.Status != "not_applicable" {
		t.Fatal(r.Status)
	}
}

func TestEvidenceLiveSignals(t *testing.T) {
	_, s, inc := evSetup(t)
	if err := s.Append(Finding{ID: "f1", Time: time.Now().UTC(), Host: "h", Rule: "r", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	sig := gatherEvidence(s, nil, inc, nil)
	if sig.Counts["findings_total"] != 1 || sig.Level[sigTelem] != 2 || sig.Level[sigAudit] != 2 {
		t.Fatalf("%+v", sig)
	}
	if sig.Level[sigAlerts] != 0 || sig.Level[sigWorkflow] != 1 {
		t.Fatalf("%+v", sig.Level)
	}
	store := s
	store.mu.Lock()
	inc.entries["f1"] = IncidentAction{FindingID: "f1", Status: "investigating"}
	store.mu.Unlock()
	if gatherEvidence(s, nil, inc, nil).Level[sigWorkflow] != 2 {
		t.Fatal("workflow should be met")
	}
}

func TestCertInClockMath(t *testing.T) {
	_, s, inc := evSetup(t)
	now := time.Now().UTC()
	seed := []Finding{
		{ID: "a", Time: now.Add(-1 * time.Hour), Host: "h", Rule: "r1", Severity: "high"},
		{ID: "b", Time: now.Add(-7 * time.Hour), Host: "h", Rule: "r2", Severity: "critical"},
		{ID: "c", Time: now.Add(-1 * time.Hour), Host: "h", Rule: "r3", Severity: "low"},
		{ID: "d", Time: now.Add(-2 * time.Hour), Host: "h", Rule: "r4", Severity: "high"},
	}
	for _, f := range seed {
		if err := s.Append(f); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	inc.entries["d"] = IncidentAction{FindingID: "d", Status: "resolved"}
	s.mu.Unlock()
	got := certInClock(s, inc, now)
	if len(got) != 2 {
		t.Fatalf("want 2 got %d: %+v", len(got), got)
	}
	if got[0].FindingID != "b" || !got[0].Overdue || got[0].RemainingSeconds > -3500 {
		t.Fatalf("%+v", got[0])
	}
	if got[1].FindingID != "a" || got[1].Overdue || got[1].RemainingSeconds < 5*3600-5 || got[1].RemainingSeconds > 5*3600 {
		t.Fatalf("%+v", got[1])
	}
	// overdue item means the timeliness signal is unmet
	if gatherEvidence(s, nil, inc, nil).Level[sigTimely] != 0 {
		t.Fatal("overdue should fail timeliness")
	}
	h, _, _ := evSetup(t)
	if w := evGet(h, "/v1/compliance/cert-in-clock", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"informational":true`) {
		t.Fatal(w.Body.String())
	}
}

func TestEvidenceHTMLEscaping(t *testing.T) {
	h, _, _ := evSetup(t)
	w := evGet(h, "/v1/compliance/evidence?format=html&framework=cert-in", true)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Generated at", "Limitations", "Scope", "does not certify"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	var sb strings.Builder
	err := evidenceTmpl.Execute(&sb, map[string]any{
		"Generated": "<script>alert(1)</script>", "Frameworks": []evidenceFramework{{"x", "<img src=x onerror=1>", "<b>"}},
		"Counts": []kv{{"<i>", 1}}, "Controls": []ControlResult{{ID: "<script>", Title: "\"><svg>", Status: "pass", Note: "<u>"}},
		"Limitations": []string{"<script>x</script>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") || strings.Contains(out, "<svg>") {
		t.Fatalf("unescaped output: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("expected escaped script")
	}
}

func TestEvidenceJSONPackHonesty(t *testing.T) {
	h, _, _ := evSetup(t)
	w := evGet(h, "/v1/compliance/evidence", true)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["certification"] != false || out["mode"] != "observe-only" || out["limitations"] == nil {
		t.Fatalf("%v", out)
	}
	seen := map[string]bool{}
	for _, c := range out["controls"].([]any) {
		seen[c.(map[string]any)["status"].(string)] = true
	}
	if !seen["manual"] || !seen["not_applicable"] {
		t.Fatalf("manual/not_applicable must be present: %v", seen)
	}
}
