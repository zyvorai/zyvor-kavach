package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDashboardAuthAndSummary(t *testing.T) {
	token := strings.Repeat("x", 32)
	store, err := testStore(t, filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	handler := API(token, store)
	req := httptest.NewRequest("GET", "/v1/summary", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != 401 {
		t.Fatalf("public summary: %d", resp.Code)
	}
	login := httptest.NewRequest("POST", "/v1/session", strings.NewReader(`{"token":"`+token+`"}`))
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, login)
	if resp.Code != 200 {
		t.Fatalf("login %d", resp.Code)
	}
	cookies := resp.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe session cookie: %+v", cookies)
	}
	req = httptest.NewRequest("GET", "/v1/summary", nil)
	req.AddCookie(cookies[0])
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != 200 {
		t.Fatalf("summary %d", resp.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(page.Body.String(), "Every signal. One view.") {
		t.Fatal("dashboard absent")
	}
}
func TestProcessStartPreventsPIDReuseCorrelation(t *testing.T) {
	store, _ := testStore(t, filepath.Join(t.TempDir(), "db"), 50)
	now := time.Now().UTC()
	e := Event{ID: "e1", Host: "h", PID: 500, ProcessStart: "100", Time: now, Executable: "/bin/bash", Command: "bash"}
	if _, err := store.Ingest(e); err != nil {
		t.Fatal(err)
	}
	n := NetworkEvent{ID: "n1", Host: "h", PID: 500, ProcessStart: "200", Time: now, Destination: "1.2.3.4", Verdict: "deny"}
	found, err := store.IngestNetwork(n)
	if err != nil || len(found) != 0 {
		t.Fatalf("PID reused correlation: %v %v", found, err)
	}
	n.ID = "n2"
	n.ProcessStart = "100"
	found, err = store.IngestNetwork(n)
	if err != nil || len(found) != 1 {
		t.Fatalf("expected correlation: %v %v", found, err)
	}
	// Verify JSON accepts the process start field.
	b, _ := json.Marshal(n)
	if !bytes.Contains(b, []byte("process_start")) {
		t.Fatal("process start field missing")
	}
}
