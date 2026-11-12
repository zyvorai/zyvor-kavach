package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestWorldPlatformRoutes(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	_ = store.Append(Finding{
		ID: "fw1", Time: time.Now().UTC(), Host: "h1", Rule: "lolbin-netcat-shell",
		Severity: "high", Description: "shell", Evidence: Event{Host: "h1", Executable: "/bin/nc", ParentExe: "/bin/bash", PID: 2},
		Destination: "203.0.113.9:443",
	})
	h := APIWithCredentials(token, store, nil)
	gets := []string{
		"/v1/world/modules", "/v1/storyline?id=fw1", "/v1/air/investigations",
		"/v1/network-discovery", "/v1/deception", "/v1/casb/apps", "/v1/email/threats",
		"/v1/dlp/events", "/v1/cnapp/workloads", "/v1/cnapp/misconfigs", "/v1/exposure",
		"/v1/compliance", "/v1/forensics", "/v1/fim", "/v1/persistence", "/v1/yara",
		"/v1/sigma", "/v1/watchlists", "/v1/exclusions", "/v1/rules", "/v1/sensor-health",
		"/v1/sandbox", "/v1/itsm/tickets", "/v1/notify/channels", "/v1/rbac/roles",
		"/v1/tenants", "/v1/retention", "/v1/bas", "/v1/zero-trust", "/v1/dns/threats",
		"/v1/ot/devices", "/v1/sbom", "/v1/hyperautomation/workflows", "/v1/mdr/queue",
		"/v1/enrich/geo?ip=1.2.3.4", "/v1/tls/certs", "/v1/rollback?id=fw1",
		"/v1/browser/extensions", "/v1/itdr/mfa",
	}
	for _, p := range gets {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}
	body, _ := json.Marshal(map[string]string{"query": "Findings | where Severity == \"high\""})
	req := httptest.NewRequest(http.MethodPost, "/v1/hunt/kql", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("kql -> %d %s", rec.Code, rec.Body.String())
	}
	if len(WorldModules()) < 30 {
		t.Fatalf("expected 30+ world modules, got %d", len(WorldModules()))
	}
}
