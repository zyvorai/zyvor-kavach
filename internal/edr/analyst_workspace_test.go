// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func wsDo(t *testing.T, method, url, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func TestWorkspaceAuth(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, c := range [][2]string{{"GET", "/v1/saved-searches"}, {"POST", "/v1/saved-searches"}, {"GET", "/v1/notes?finding_id=x"}, {"POST", "/v1/notes"}, {"DELETE", "/v1/notes?id=x"}, {"DELETE", "/v1/saved-searches?id=x"}, {"GET", "/v1/journal"}, {"GET", "/v1/journal/verify"}} {
		if code, _ := wsDo(t, c[0], srv.URL+c[1], "", "{}"); code != 401 {
			t.Fatalf("%v: %d", c, code)
		}
	}
	if code, _ := wsDo(t, "GET", srv.URL+"/v1/journal", tok, ""); code != 200 {
		t.Fatal(code)
	}
}

func TestSavedSearchesAndLimits(t *testing.T) {
	srv, _, tok := obsServer(t)
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/saved-searches", tok, `{"name":"x","scope":"bogus"}`); code != 400 {
		t.Fatal(code)
	}
	code, body := wsDo(t, "POST", srv.URL+"/v1/saved-searches", tok, `{"name":"<b>a</b>","scope":"hosts","query":"ssh"}`)
	if code != 201 || strings.Contains(body, "<b>") {
		t.Fatalf("%d %s", code, body)
	}
	for i := 1; i < maxSavedSearches; i++ {
		wsDo(t, "POST", srv.URL+"/v1/saved-searches", tok, `{"name":"n","scope":"findings"}`)
	}
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/saved-searches", tok, `{"name":"n","scope":"findings"}`); code != 400 {
		t.Fatalf("limit: %d", code)
	}
}

func TestNotesLimitsAndDelete(t *testing.T) {
	srv, _, tok := obsServer(t)
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f1","text":"`+strings.Repeat("a", 2001)+`"}`); code != 400 {
		t.Fatal(code)
	}
	code, body := wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f1","text":"<script>x</script>"}`)
	if code != 201 || strings.Contains(body, "<script>") {
		t.Fatalf("%d %s", code, body)
	}
	for i := 1; i < maxNotesPerItem; i++ {
		wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f1","text":"n"}`)
	}
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f1","text":"n"}`); code != 400 {
		t.Fatalf("limit: %d", code)
	}
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f2","text":"ok"}`); code != 201 {
		t.Fatal(code)
	}
	_, list := wsDo(t, "GET", srv.URL+"/v1/notes?finding_id=f2", tok, "")
	if !strings.Contains(list, `"author":"admin"`) {
		t.Fatal(list)
	}
	idx := strings.Index(list, `"id":"`) + 6
	id := list[idx : idx+strings.Index(list[idx:], `"`)]
	if code, _ := wsDo(t, "DELETE", srv.URL+"/v1/notes?id="+id, tok, ""); code != 204 {
		t.Fatal(code)
	}
	if code, _ := wsDo(t, "DELETE", srv.URL+"/v1/notes?id="+id, tok, ""); code != 404 {
		t.Fatal(code)
	}
}

func TestJournalPersistAndTamper(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	tok := "0123456789abcdef"
	srv := httptest.NewServer(API(tok, s))
	defer srv.Close()
	wsDo(t, "POST", srv.URL+"/v1/notes", tok, `{"finding_id":"f1","text":"one"}`)
	wsDo(t, "POST", srv.URL+"/v1/saved-searches", tok, `{"name":"s","scope":"hosts"}`)
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/journal", tok, `{"action":"alert_rule.create","target":"alr-1"}`); code != 201 {
		t.Fatal(code)
	}
	if code, _ := wsDo(t, "POST", srv.URL+"/v1/journal", tok, `{"action":"evil","target":"x"}`); code != 400 {
		t.Fatal(code)
	}
	_, v := wsDo(t, "GET", srv.URL+"/v1/journal/verify", tok, "")
	if !strings.Contains(v, `"valid":true`) || !strings.Contains(v, `"entries":3`) {
		t.Fatal(v)
	}

	// Reload from disk: state persists and chain still verifies.
	ws := NewWorkspace(s)
	if len(ws.data.Notes) != 1 || len(ws.data.Searches) != 1 || len(ws.data.Journal) != 3 {
		t.Fatalf("reload: %+v", ws.data)
	}
	if seq, _ := ws.verifyLocked(); seq != 0 {
		t.Fatal("chain should verify")
	}
	ws.data.Journal[1].Actor = "mallory"
	if seq, _ := ws.verifyLocked(); seq != 2 {
		t.Fatalf("expected break at 2, got %d", seq)
	}
	ws.data.Journal[1].Actor = "admin"
	ws.data.Journal[2].Prev = "00"
	if seq, _ := ws.verifyLocked(); seq != 3 {
		t.Fatalf("expected break at 3, got %d", seq)
	}
}
