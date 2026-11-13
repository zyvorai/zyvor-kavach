package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFalconPlatformRoutes(t *testing.T) {
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	_ = store.Append(Finding{
		ID: "f1", Time: time.Now().UTC(), Host: "h1", Rule: "download-execute",
		Severity: "high", Description: "test", Evidence: Event{Host: "h1", Executable: "/tmp/a", Command: "curl|bash"},
	})
	h := APIWithCredentials(token, store, nil)
	paths := []string{
		"/v1/modules", "/v1/detections", "/v1/ioc", "/v1/ioa", "/v1/prevention/policies",
		"/v1/hosts", "/v1/host-groups", "/v1/containment", "/v1/rtr/commands", "/v1/rtr/sessions",
		"/v1/device-control", "/v1/firewall/rules", "/v1/discover/assets", "/v1/discover/apps",
		"/v1/spotlight/vulnerabilities", "/v1/overwatch/alerts", "/v1/intel/actors", "/v1/intel/indicators",
		"/v1/identity/events", "/v1/identity/entities", "/v1/ueba", "/v1/fusion/playbooks",
		"/v1/fusion/runs", "/v1/cases", "/v1/threat-graph", "/v1/audit", "/v1/reports/summary",
		"/v1/connectors", "/v1/cloud/posture", "/v1/mobile/devices",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}
	// hunt
	body, _ := json.Marshal(map[string]string{"query": "host:h1 severity:high"})
	req := httptest.NewRequest(http.MethodPost, "/v1/hunt/query", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("hunt -> %d", rec.Code)
	}
	// detection triage
	tb, _ := json.Marshal(map[string]string{"id": "det-f1", "status": "in_progress", "assignee": "analyst"})
	req = httptest.NewRequest(http.MethodPost, "/v1/detections/triage", bytes.NewReader(tb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("triage -> %d %s", rec.Code, rec.Body.String())
	}
	// RTR session + execute
	sb, _ := json.Marshal(map[string]string{"host": "h1"})
	req = httptest.NewRequest(http.MethodPost, "/v1/rtr/sessions", bytes.NewReader(sb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rtr session -> %d", rec.Code)
	}
	var sess RTRSession
	_ = json.Unmarshal(rec.Body.Bytes(), &sess)
	eb, _ := json.Marshal(map[string]string{"session_id": sess.ID, "command": "findings"})
	req = httptest.NewRequest(http.MethodPost, "/v1/rtr/execute", bytes.NewReader(eb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rtr exec -> %d %s", rec.Code, rec.Body.String())
	}
	_ = os.RemoveAll(dir)
}

func TestMapDetectionMITRE(t *testing.T) {
	d := MapDetection(Finding{ID: "x", Rule: "ransomware-burst", Severity: "high", Host: "h"})
	if d.TechniqueID != "T1486" {
		t.Fatalf("got %s", d.TechniqueID)
	}
}
