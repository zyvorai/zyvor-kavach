// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegressHTTP(t *testing.T) {
	st := newTestStore(t)
	mux := http.NewServeMux()
	s := RegisterRegression(mux, "tok", st)
	defer StopRegression()
	do := func(method, path string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/regression/status", nil))
	if w.Code != 401 {
		t.Fatalf("unauthenticated status %d", w.Code)
	}
	// the startup run (no history yet) records the first snapshot
	deadline := time.Now().Add(2 * time.Minute)
	for len(s.snapshots()) < 1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if code, m := do("GET", "/v1/regression/status"); code != 200 || m["latest"] == nil {
		t.Fatalf("status %d %v", code, m)
	}
	if code, _ := do("GET", "/v1/regression/diff"); code != 404 {
		t.Fatalf("diff with one snapshot: %d", code)
	}
	if code, m := do("POST", "/v1/regression/run"); code != 200 || m["diff"] == nil {
		t.Fatalf("run %d %v", code, m)
	}
	if code, m := do("GET", "/v1/regression/diff"); code != 200 || m["regressions"] == nil {
		t.Fatalf("diff %d", code)
	}
	if code, m := do("GET", "/v1/regression/history?limit=1"); code != 200 || m["count"].(float64) != 1 {
		t.Fatalf("history %d", code)
	}
	if code, m := do("GET", "/v1/regression/trend?window=7d"); code != 200 || len(m["points"].([]any)) != 2 {
		t.Fatalf("trend %d %v", code, m)
	}
	if code, _ := do("GET", "/v1/regression/gate?max_regressions=0"); code != 200 {
		t.Fatalf("gate %d", code)
	}
	if code, _ := do("GET", "/v1/regression/gate?min_detected=100"); code != 412 {
		t.Fatalf("gate 412: %d", code)
	}
	if code, _ := do("GET", "/v1/regression/config"); code != 200 {
		t.Fatalf("config %d", code)
	}
}
