// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAttackPathClassify(t *testing.T) {
	rows := []struct {
		f      APFinding
		stored bool
		want   []string
	}{
		{APFinding{ID: "cfg-iac-sg-open-admin", Title: "[fail] Remote-administration port open", Severity: "high"}, false, []string{APExposure}},
		{APFinding{ID: "cfg-iac-iam-admin-wildcard", Title: "[fail] IAM policy grants all actions", Severity: "high"}, false, []string{APPrivilege}},
		{APFinding{ID: "cfg-iac-rds-public", Title: "[fail] Database is publicly accessible", Severity: "high"}, false, []string{APExposure, APData}},
		{APFinding{ID: "cfg-advisory-cve-2022-1388", Title: "[fail] Version string in range", Severity: "critical"}, false, []string{APVuln}},
		{APFinding{ID: "cfg-iac-sg-open-admin", Title: "[pass] Remote-administration port open", Severity: "info"}, false, nil},
		{APFinding{ID: "cfg-iac-sg-open-admin", Title: "[fail] x", Severity: "info"}, false, nil},
		{APFinding{ID: "proc-odd-parent", Title: "suspicious process", Severity: "high"}, true, []string{APActive}},
		{APFinding{ID: "proc-odd-parent", Title: "suspicious process", Severity: "high"}, false, nil},
		{APFinding{ID: "x", Title: "tagged", Severity: "low", Tags: []string{"T1190"}}, true, []string{APExposure}},
		{APFinding{ID: "", Title: "", Severity: "", Tags: nil}, true, nil},
	}
	for i, r := range rows {
		got := ClassifyAPFinding(r.f, r.stored)
		if strings.Join(got, ",") != strings.Join(r.want, ",") {
			t.Errorf("row %d: got %v want %v", i, got, r.want)
		}
	}
}

func sig(host, kind, sev string) APSignal {
	return APSignal{Host: host, Kind: kind, Severity: sev, Source: kind + "-sig"}
}

func TestAttackPathScoring(t *testing.T) {
	// exposure high (24) + vuln high (20) + privilege high (20) + synergy 20 = 84
	p := ScoreAttackPaths([]APSignal{sig("h1", APExposure, "high"), sig("h1", APVuln, "high"), sig("h1", APPrivilege, "high")}, 0)
	if len(p) != 1 || p[0].Score != 84 || p[0].Level != "critical" || len(p[0].BreakPoints) != 3 {
		t.Fatalf("%+v", p)
	}
	if p[0].Title != "Internet-exposed vulnerable asset with excess privilege" {
		t.Errorf("title %q", p[0].Title)
	}
	// a single kind is not a path
	if got := ScoreAttackPaths([]APSignal{sig("h", APExposure, "critical"), sig("h", APExposure, "high")}, 0); len(got) != 0 {
		t.Errorf("single kind produced a path: %+v", got)
	}
	// privilege + data without an entry point is not a path
	if got := ScoreAttackPaths([]APSignal{sig("h", APPrivilege, "critical"), sig("h", APData, "critical")}, 0); len(got) != 0 {
		t.Errorf("no entry point should mean no path: %+v", got)
	}
	// signals on different hosts never combine
	if got := ScoreAttackPaths([]APSignal{sig("a", APExposure, "high"), sig("b", APVuln, "high")}, 0); len(got) != 0 {
		t.Errorf("cross-host combination: %+v", got)
	}
	// KEV adds a bonus; cap at 100; ordering by score then host; min score filter
	kev := sig("k", APVuln, "critical")
	kev.KEV = true
	all := ScoreAttackPaths([]APSignal{
		sig("k", APExposure, "critical"), kev, sig("k", APPrivilege, "critical"), sig("k", APData, "critical"),
		sig("m", APExposure, "low"), sig("m", APVuln, "low"),
	}, 0)
	if len(all) != 2 || all[0].Host != "k" || all[0].Score != 100 || all[1].Host != "m" {
		t.Fatalf("%+v", all)
	}
	if got := ScoreAttackPaths([]APSignal{sig("m", APExposure, "low"), sig("m", APVuln, "low")}, 50); len(got) != 0 {
		t.Errorf("min_score not applied: %+v", got)
	}
	// determinism
	a, _ := json.Marshal(ScoreAttackPaths([]APSignal{sig("z", APExposure, "high"), sig("z", APActive, "high"), sig("y", APExposure, "high"), sig("y", APVuln, "high")}, 0))
	b, _ := json.Marshal(ScoreAttackPaths([]APSignal{sig("y", APVuln, "high"), sig("y", APExposure, "high"), sig("z", APActive, "high"), sig("z", APExposure, "high")}, 0))
	if string(a) != string(b) {
		t.Errorf("ordering depends on input order:\n%s\n%s", a, b)
	}
	// empty host label is grouped, not dropped
	if got := ScoreAttackPaths([]APSignal{{Kind: APExposure, Severity: "high"}, {Kind: APVuln, Severity: "high"}}, 0); len(got) != 1 || got[0].Host != apUnspecified {
		t.Errorf("%+v", got)
	}
}

func apDo(mux *http.ServeMux, method, path, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestAttackPathHTTP(t *testing.T) {
	store := newTestStore(t)
	mux := http.NewServeMux()
	RegisterAttackPaths(mux, "tok", store)

	if c := apDo(mux, "GET", "/v1/exposure/attack-paths", "", "").Code; c != 401 {
		t.Errorf("unauthenticated GET = %d", c)
	}
	if c := apDo(mux, "POST", "/v1/exposure/attack-paths/evaluate", "", "{}").Code; c != 401 {
		t.Errorf("unauthenticated POST = %d", c)
	}
	// stored findings: exposure tag + high rule on the same host
	now := time.Now().UTC()
	for _, f := range []Finding{
		{ID: "f1", Time: now, Host: "web-1", Rule: "net-exposed-admin", Severity: "high", Description: "management interface open to internet", Tags: []string{"T1133"}},
		{ID: "f2", Time: now, Host: "web-1", Rule: "cred-dump", Severity: "critical", Description: "credential dumping tool"},
	} {
		if err := store.Append(f); err != nil {
			t.Fatal(err)
		}
	}
	w := apDo(mux, "GET", "/v1/exposure/attack-paths?min_score=10", "tok", "")
	var resp struct {
		Count int      `json:"count"`
		Paths []APPath `json:"paths"`
		Mode  string   `json:"mode"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Count != 1 || resp.Paths[0].Host != "web-1" || resp.Mode != "observe-only" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if c := apDo(mux, "GET", "/v1/exposure/attack-paths?min_score=abc", "tok", "").Code; c != 400 {
		t.Errorf("bad min_score = %d", c)
	}
	if c := apDo(mux, "GET", "/v1/exposure/attack-paths?min_score=101", "tok", "").Code; c != 400 {
		t.Errorf("out of range min_score = %d", c)
	}
	// stateless evaluate from inspector-style findings
	body := `{"findings":[
	  {"host":"app-9","id":"cfg-iac-sg-open-admin","title":"[fail] open","severity":"high"},
	  {"host":"app-9","id":"cfg-advisory-cve-2022-1388","title":"[fail] in range","severity":"critical"},
	  {"host":"app-9","id":"cfg-iac-iam-admin-wildcard","title":"[fail] admin","severity":"high"}]}`
	w = apDo(mux, "POST", "/v1/exposure/attack-paths/evaluate", "tok", body)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Count != 1 || resp.Paths[0].Score < 80 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(store.List()) != 2 {
		t.Error("evaluate must not store anything")
	}
	bad := []struct {
		body string
		code int
	}{
		{`{`, 400}, {`{"signals":[{"host":"a","kind":"bogus"}]}`, 400}, {`{"min_score":500}`, 400}, {`[]`, 400},
		{`{"signals":"x"}`, 400}, {strings.Repeat("x", apMaxBody+10), 413},
	}
	for _, b := range bad {
		if c := apDo(mux, "POST", "/v1/exposure/attack-paths/evaluate", "tok", b.body).Code; c != b.code {
			t.Errorf("body %.30q: %d want %d", b.body, c, b.code)
		}
	}
	// too many items
	var sb strings.Builder
	sb.WriteString(`{"findings":[`)
	for i := 0; i < apMaxSignals+1; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":"a"}`)
	}
	sb.WriteString("]}")
	if c := apDo(mux, "POST", "/v1/exposure/attack-paths/evaluate", "tok", sb.String()).Code; c != 400 {
		t.Errorf("too many items = %d", c)
	}
}

func TestAttackPathUsesSBOMMatches(t *testing.T) {
	mux, store := expServer(t) // registers exposure, which publishes its assets to the scorer
	RegisterAttackPaths(mux, "tok", store)
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/web1", "tok", expFixture(t, "cyclonedx.json")); w.Code != 200 {
		t.Fatalf("ingest %d %s", w.Code, w.Body.String())
	}
	if err := store.Append(Finding{ID: "x1", Time: time.Now().UTC(), Host: "web1", Rule: "lb-open", Severity: "high", Description: "service open to the internet"}); err != nil {
		t.Fatal(err)
	}
	w := expDo(mux, "GET", "/v1/exposure/attack-paths", "tok", nil)
	var resp struct {
		Paths []APPath `json:"paths"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Paths) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	p := resp.Paths[0]
	if p.Host != "web1" || p.Factors[APVuln] == 0 || p.Factors[APExposure] == 0 {
		t.Fatalf("%+v", p)
	}
	// log4j (KEV in the sample dataset) earns the KEV bonus on the vulnerable-software factor
	if p.Factors[APVuln] < apKEVBonus {
		t.Errorf("expected KEV bonus in %+v", p.Factors)
	}
}
