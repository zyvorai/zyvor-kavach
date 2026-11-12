// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeITDR(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC)
	fs := []Finding{
		{ID: "f1", Time: t0, Host: "h", Rule: "x", Severity: "high", Evidence: Event{UID: 0, Command: "mimikatz sekurlsa::logonpasswords"}},
		{ID: "f2", Time: t0, Host: "h", Rule: "x", Evidence: Event{UID: 1000, Command: "GetUserSPNs.py -request"}},
	}
	evs := []IdentityEvent{
		{ID: "e1", Time: t0, User: "bob", Action: "ssh_login", SourceIP: "1.1.1.1"},
		{ID: "e2", Time: t0.Add(2 * time.Minute), User: "bob", Action: "ssh_login", SourceIP: "2.2.2.2"},
	}
	inds, risks, tl := ComputeITDR(fs, evs)
	kinds := map[string]bool{}
	for _, i := range inds {
		kinds[i.Kind] = true
	}
	for _, k := range []string{"credential-dumping", "kerberoasting", "impossible-travel", "odd-hour-login"} {
		if !kinds[k] {
			t.Fatalf("missing %s", k)
		}
	}
	if r := risks["root"]; r == nil || !r.Privileged || r.Score < 40 {
		t.Fatalf("root risk %+v", r)
	}
	if len(tl["bob"]) != 2 {
		t.Fatalf("timeline %v", tl["bob"])
	}
}

func TestITDRRoutes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterITDR(mux, "tok-itdr-123456", store)
	for _, p := range []string{"summary", "indicators", "risk", "privileged", "timeline?user=root"} {
		req := httptest.NewRequest("GET", "/v1/identity/itdr/"+p, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("%s unauth -> %d", p, rec.Code)
		}
		req.Header.Set("Authorization", "Bearer tok-itdr-123456")
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 || !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s -> %d", p, rec.Code)
		}
	}
}
