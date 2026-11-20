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

func TestCorrelateIncidents(t *testing.T) {
	now := time.Now().UTC()
	fs := []Finding{
		{ID: "a1", Host: "h1", Rule: "x", Severity: "low", Time: now},
		{ID: "a2", Host: "h1", Rule: "y", Severity: "high", Time: now.Add(10 * time.Minute)},
		{ID: "b1", Host: "h2", Rule: "x", Severity: "low", Time: now.Add(5 * time.Hour)},
	}
	inc := CorrelateIncidents(fs, time.Hour)
	if len(inc) != 2 {
		t.Fatalf("want 2 incidents got %d", len(inc))
	}
	for _, i := range inc {
		if i.Count == 2 && i.Severity != "high" {
			t.Fatal("severity should be max")
		}
	}
}

func TestCaseLifecycle(t *testing.T) {
	store, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCaseManagement(mux, "tok", store, RegisterAnalystWorkspace(mux, "tok", store))
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w0 := httptest.NewRecorder()
	mux.ServeHTTP(w0, httptest.NewRequest("GET", "/v1/cases", nil))
	if w0.Code != 401 {
		t.Fatal("want 401")
	}
	w := do("POST", "/v1/cases", `{"title":"Beacon","severity":"high","tags":["c2"],"finding_ids":["f1"]}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var c IncCase
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	if c.SLA == nil || c.Status != "open" {
		t.Fatal("bad case")
	}
	if w := do("PATCH", "/v1/cases/"+c.ID, `{"status":"closed"}`); w.Code != 400 {
		t.Fatal("close without resolution must fail")
	}
	if w := do("PATCH", "/v1/cases/"+c.ID, `{"assignee":"ana","status":"closed","resolution":"benign"}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := do("POST", "/v1/cases/"+c.ID+"/comments", `{"text":"<b>done</b>"}`); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if w := do("GET", "/v1/cases/nope", ""); w.Code != 404 {
		t.Fatal("want 404")
	}
	md := do("GET", "/v1/cases/"+c.ID+"/export", "").Body.String()
	for _, s := range []string{"# Case", "benign", "Timeline", "Comments", "f1"} {
		if !strings.Contains(md, s) {
			t.Fatalf("export missing %q", s)
		}
	}
	if w := do("GET", "/v1/incidents/correlated", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if j := do("GET", "/v1/journal", "").Body.String(); !strings.Contains(j, "case.create") {
		t.Fatal("journal missing case.create: " + j)
	}
}
