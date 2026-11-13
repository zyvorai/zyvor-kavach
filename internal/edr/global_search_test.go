// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func searchTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(t.TempDir()+"/f.jsonl", 20000)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSearchScoreOrdering(t *testing.T) {
	exact := searchScore("t1059", "T1059", "Command and Scripting")
	prefix := searchScore("t10", "T1059", "Command and Scripting")
	sub := searchScore("059", "T1059", "Command and Scripting")
	title := searchScore("command", "X1", "Command and Scripting")
	other := searchScore("powershell", "X1", "Y", "uses PowerShell")
	if !(exact > prefix && prefix > sub && sub > title && title > other && other > 0) {
		t.Fatalf("bad ordering %d %d %d %d %d", exact, prefix, sub, title, other)
	}
	if searchScore("zzz", "a", "b", "c") != 0 {
		t.Fatal("expected no match")
	}
	if searchScore("a.*", "abc", "abc") != 0 {
		t.Fatal("regex metacharacters must be literal")
	}
}

func TestSearchRankingAndTypes(t *testing.T) {
	if err := LoadContentPacks(); err != nil {
		t.Log(err)
	}
	st := searchTestStore(t)
	_ = st.Append(Finding{ID: "f-abc", Host: "web-01", Rule: "download-execute", Severity: "high", Description: "curl piped"})
	res := RunGlobalSearch(st, nil, "T1059", nil, 50)
	if len(res) == 0 || res[0].Type != "technique" || res[0].ID != "T1059" || res[0].Score != 100 {
		t.Fatalf("exact technique id must rank first: %+v", res)
	}
	for i := 1; i < len(res); i++ {
		if res[i].Score > res[i-1].Score {
			t.Fatal("results not sorted by score")
		}
	}
	res = RunGlobalSearch(st, nil, "web-01", map[string]bool{"host": true, "finding": true}, 10)
	types := map[string]bool{}
	for _, r := range res {
		types[r.Type] = true
		if r.Route == "" {
			t.Fatal("missing route")
		}
	}
	if !types["host"] || !types["finding"] {
		t.Fatalf("want host+finding, got %+v", res)
	}
	if got := RunGlobalSearch(st, nil, "web-01", map[string]bool{"cve": true}, 10); len(got) != 0 {
		t.Fatalf("type filter leaked: %+v", got)
	}
	if got := RunGlobalSearch(st, nil, "CVE-2023-38545", nil, 10); len(got) == 0 || got[0].Type != "cve" {
		t.Fatalf("cve lookup: %+v", got)
	}
}

func TestSearchCaps(t *testing.T) {
	st := searchTestStore(t)
	for i := 0; i < 200; i++ {
		_ = st.Append(Finding{ID: "fid-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Host: "h", Rule: "download-execute", Severity: "low"})
	}
	if got := RunGlobalSearch(st, nil, "download", map[string]bool{"finding": true}, 5); len(got) != 5 {
		t.Fatalf("limit not applied: %d", len(got))
	}
	if got := RunGlobalSearch(st, nil, "download", map[string]bool{"finding": true}, 100000); len(got) > searchMaxLimit {
		t.Fatalf("max limit exceeded: %d", len(got))
	}
	if got := RunGlobalSearch(st, nil, "x", nil, 10); len(got) != 0 {
		t.Fatal("short query must return nothing")
	}
	big := &searchCollector{q: "z"}
	big.begin("finding")
	n := 0
	for big.more() {
		n++
	}
	if n != searchMaxScanPerTyp {
		t.Fatalf("scan budget %d", n)
	}
	_ = RunGlobalSearch(st, nil, strings.Repeat("a", 5000), nil, 10) // must not blow up
}

func TestSearchCasesAndHTTP(t *testing.T) {
	st := searchTestStore(t)
	b, _ := json.Marshal([]IncCase{{ID: "case-77", Title: "Ransom incident", Status: "open", Severity: "high"}})
	if err := os.WriteFile(st.path+".cases.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterGlobalSearch(mux, "tok", st, nil)
	do := func(url, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := do("/v1/search?q=case-77", ""); rr.Code != 401 {
		t.Fatalf("auth: %d", rr.Code)
	}
	rr := do("/v1/search?q=case-77&types=case", "Bearer tok")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"route":"#/cases"`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr := do("/v1/search?q=a", "Bearer tok"); rr.Code != 400 {
		t.Fatal("short q", rr.Code)
	}
	if rr := do("/v1/search?q=abc&types=bogus", "Bearer tok"); rr.Code != 400 {
		t.Fatal("bad type", rr.Code)
	}
	if rr := do("/v1/search?q=(%5B*&limit=3", "Bearer tok"); rr.Code != 200 {
		t.Fatal("metachar query", rr.Code)
	}
}
