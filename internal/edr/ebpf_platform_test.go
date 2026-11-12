// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestEBPFPlatformRoutes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterEBPFPlatform(mux, "test-token-ebpf321", store, nil)

	paths := []string{
		"/v1/ebpf/status", "/v1/ebpf/health", "/v1/ebpf/coverage",
		"/v1/ebpf/capabilities", "/v1/ebpf/attachments", "/v1/ebpf/maps",
		"/v1/ebpf/census", "/v1/ebpf/summary", "/v1/ebpf/drops",
		"/v1/ebpf/events", "/v1/ebpf/processes", "/v1/ebpf/features",
		"/v1/ebpf/netra/status", "/v1/ebpf/netra/drops", "/v1/ebpf/netra/flows",
		"/v1/ebpf/netra/attachments",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer test-token-ebpf321")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}

	body, _ := json.Marshal(map[string]any{
		"lost": 2,
		"events": []map[string]any{
			{"type": "exec", "pid": 7, "comm": "curl", "path": "/usr/bin/curl"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/ebpf/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token-ebpf321")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ingest -> %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/ebpf/features/net", bytes.NewReader([]byte(`{"mode":"off"}`)))
	req.Header.Set("Authorization", "Bearer test-token-ebpf321")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("feature -> %d %s", rec.Code, rec.Body.String())
	}

	ev := listEBPFEvents("exec")
	if len(ev) == 0 {
		t.Fatal("expected exec events")
	}
	feats := EBPFFeatureList()
	if len(feats) < 10 {
		t.Fatalf("features=%d", len(feats))
	}
	st := EBPFStatus(store, nil)
	if st["enforce"] != false {
		t.Fatal("enforce must be false")
	}
}

func TestFalconModulesIncludeEBPF(t *testing.T) {
	found := false
	for _, m := range FalconModules() {
		if m.ID == "ebpf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ebpf module in FalconModules")
	}
}
