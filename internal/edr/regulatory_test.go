// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegulatoryCatalogValid(t *testing.T) {
	rs, err := RegulatoryRegimes()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) < 20 {
		t.Fatalf("only %d regimes", len(rs))
	}
	ids := map[string]bool{}
	for _, r := range rs {
		ids[r.ID] = true
	}
	for _, want := range []string{"eu-gdpr-art33", "eu-nis2-art23", "eu-dora-major-ict", "uk-gdpr", "us-sec-8k-1-05", "us-hipaa-breach", "us-circia",
		"sg-cybersecurity-act", "sg-pdpa", "au-soci-critical", "au-ndb", "jp-appi", "in-certin-2022", "in-dpdp", "br-lgpd", "sa-nca-ecc",
		"ae-pdpl", "za-popia", "ca-pipeda", "kr-pipa", "hk-pdpo"} {
		if !ids[want] {
			t.Errorf("missing regime %s", want)
		}
	}
}

func TestRegulatoryCatalogValidationRejects(t *testing.T) {
	good := `{"regimes":[{"id":"x","jurisdiction":"J","regulator":"R","name":"N","trigger":"T","start_event":"awareness","applies_to":"A",
	"stages":[{"name":"s","hours":6,"business_days":0,"from_start":true,"description":"d"}],"source_url":"https://example.org","source_kind":"secondary",
	"last_verified":"","last_researched":"2026-11-13","verified":false,"notes":"UNVERIFIED"}]}`
	if _, err := LoadRegulatoryCatalog([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"verified without date":   strings.Replace(good, `"verified":false`, `"verified":true`, 1),
		"unverified without note": strings.Replace(good, `"notes":"UNVERIFIED"`, `"notes":"fine"`, 1),
		"http url":                strings.Replace(good, "https://example.org", "http://example.org", 1),
		"bad start":               strings.Replace(good, `"awareness"`, `"whenever"`, 1),
		"both units":              strings.Replace(good, `"business_days":0`, `"business_days":2`, 1),
		"no stages":               strings.Replace(good, `"hours":6`, `"hours":-1`, 1),
	}
	for name, doc := range bad {
		if _, err := LoadRegulatoryCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	okVerified := func(kind string) string {
		d := strings.Replace(good, `"verified":false`, `"verified":true`, 1)
		d = strings.Replace(d, `"last_verified":""`, `"last_verified":"2026-11-16"`, 1)
		return strings.Replace(d, `"source_kind":"secondary"`, `"source_kind":"`+kind+`"`, 1)
	}
	for _, kind := range []string{"official_fetched", "official_excerpt"} {
		if _, err := LoadRegulatoryCatalog([]byte(okVerified(kind))); err != nil {
			t.Errorf("verified %s rejected: %v", kind, err)
		}
	}
	if _, err := LoadRegulatoryCatalog([]byte(okVerified("secondary"))); err == nil {
		t.Error("verified entry with secondary source accepted")
	}
	dup := strings.Replace(good, `"regimes":[`, `"regimes":[`+good[strings.Index(good, "[")+1:strings.LastIndex(good, "]")]+",", 1)
	if _, err := LoadRegulatoryCatalog([]byte(dup)); err == nil {
		t.Error("duplicate id accepted")
	}
}

func TestAddBusinessDays(t *testing.T) {
	fri := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC) // Friday
	if got := addBusinessDays(fri, 3); got.Weekday() != time.Wednesday {
		t.Fatalf("got %v", got)
	}
	if got := addBusinessDays(fri, 4); !got.Equal(fri.Add(6 * 24 * time.Hour)) {
		t.Fatalf("got %v", got)
	}
}

func regSetup(t *testing.T) (http.Handler, *Store, *IncidentStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.jsonl")
	s, err := testStore(t, path, 100)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := NewIncidentStore(s)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterRegulatory(mux, evTok, s, inc)
	return mux, s, inc, path
}

func regDo(h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		r.Header.Set("Authorization", "Bearer "+evTok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRegulatoryAuth(t *testing.T) {
	h, _, _, _ := regSetup(t)
	for _, p := range []string{"/v1/regulatory/regimes", "/v1/regulatory/clocks", "/v1/regulatory/profile"} {
		if w := regDo(h, "GET", p, "", false); w.Code != 401 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	if w := regDo(h, "PUT", "/v1/regulatory/profile", `{"regimes":[]}`, false); w.Code != 401 {
		t.Fatalf("put: %d", w.Code)
	}
}

func TestRegulatoryRegimesFilter(t *testing.T) {
	h, _, _, _ := regSetup(t)
	w := regDo(h, "GET", "/v1/regulatory/regimes?jurisdiction=india", "", true)
	var out struct {
		Count         int         `json:"count"`
		Regimes       []RegRegime `json:"regimes"`
		Informational bool        `json:"informational"`
		Disclaimer    string      `json:"disclaimer"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Count != 2 || !out.Informational || !strings.Contains(out.Disclaimer, "not legal advice") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = regDo(h, "GET", "/v1/regulatory/regimes?verified=true", "", true)
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	for _, r := range out.Regimes {
		if !r.Verified {
			t.Fatalf("unverified leaked: %s", r.ID)
		}
	}
}

func TestRegulatoryProfilePersistsAndClocks(t *testing.T) {
	h, s, inc, path := regSetup(t)
	if w := regDo(h, "PUT", "/v1/regulatory/profile", `{"regimes":["nope"]}`, true); w.Code != 400 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	if w := regDo(h, "PUT", "/v1/regulatory/profile", `{"regimes":["uk-gdpr","in-certin-2022","uk-gdpr","br-lgpd","eu-nis2-art23"]}`, true); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	b, err := os.ReadFile(path + ".regulatory.json")
	if err != nil || !strings.Contains(string(b), "in-certin-2022") {
		t.Fatalf("not persisted: %v %s", err, b)
	}
	// A new service over the same store reloads the profile.
	mux2 := http.NewServeMux()
	RegisterRegulatory(mux2, evTok, s, inc)
	w := regDo(mux2, "GET", "/v1/regulatory/profile", "", true)
	if strings.Count(w.Body.String(), "uk-gdpr") != 1 {
		t.Fatalf("reload/dedupe: %s", w.Body.String())
	}

	now := time.Now().UTC()
	_ = s.Append(Finding{ID: "old", Time: now.Add(-80 * time.Hour), Host: "h", Rule: "r", Severity: "critical"})
	_ = s.Append(Finding{ID: "new", Time: now.Add(-1 * time.Hour), Host: "h", Rule: "r", Severity: "high"})
	_ = s.Append(Finding{ID: "low", Time: now, Host: "h", Rule: "r", Severity: "low"})

	w = regDo(mux2, "GET", "/v1/regulatory/clocks", "", true)
	var out struct {
		Informational bool             `json:"informational"`
		Disclaimer    string           `json:"disclaimer"`
		Regimes       []map[string]any `json:"regimes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Regimes) != 4 || !out.Informational || !strings.Contains(out.Disclaimer, "does not file") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	w = regDo(mux2, "GET", "/v1/regulatory/clocks?regime=uk-gdpr", "", true)
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Regimes) != 1 {
		t.Fatalf("%s", w.Body.String())
	}
	stage := out.Regimes[0]["stages"].([]any)[0].(map[string]any)
	inc72 := stage["incidents"].([]any)
	if len(inc72) != 2 || stage["computable"] != true {
		t.Fatalf("%v", stage)
	}
	first := inc72[0].(map[string]any)
	if first["finding_id"] != "old" || first["overdue"] != true {
		t.Fatalf("most urgent must be first and overdue: %v", first)
	}
	if second := inc72[1].(map[string]any); second["overdue"] != false || second["remaining_seconds"].(float64) < 70*3600-5 {
		t.Fatalf("%v", second)
	}

	// Resolved findings drop off.
	s.mu.Lock()
	inc.entries["old"] = IncidentAction{FindingID: "old", Status: "resolved"}
	s.mu.Unlock()
	w = regDo(mux2, "GET", "/v1/regulatory/clocks?regime=uk-gdpr", "", true)
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if n := len(out.Regimes[0]["stages"].([]any)[0].(map[string]any)["incidents"].([]any)); n != 1 {
		t.Fatalf("resolved not dropped: %d", n)
	}

	// Rule-text-only stage (NIS2 final report) is not computable; unknown regime is 400.
	w = regDo(mux2, "GET", "/v1/regulatory/clocks?regime=eu-nis2-art23", "", true)
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	st := out.Regimes[0]["stages"].([]any)
	if len(st) != 3 || st[2].(map[string]any)["computable"] != false {
		t.Fatalf("%v", st)
	}
	if w := regDo(mux2, "GET", "/v1/regulatory/clocks?regime=zzz", "", true); w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
}

func TestRegulatoryCatalogVerificationRecords(t *testing.T) {
	regs, err := RegulatoryRegimes()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range regs {
		if r.Verified && (r.LastVerified != "2026-11-16" && r.ID != "uk-gdpr" && r.ID != "us-sec-8k-1-05" && r.ID != "us-circia") {
			t.Errorf("%s: unexpected last_verified %q", r.ID, r.LastVerified)
		}
		if r.Verified && r.SourceKind == "secondary" {
			t.Errorf("%s: verified from a secondary source", r.ID)
		}
	}
	// Corrected on 2026-11-16: the Singapore final report runs from the supplementary submission, not from awareness.
	for _, r := range regs {
		if r.ID == "sg-cybersecurity-act" && r.Stages[2].FromStart {
			t.Error("sg final report must not be computed from awareness")
		}
	}
}
