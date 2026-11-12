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

func requestM4(t *testing.T, server *httptest.Server, path, token string, payload any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
func TestAgentEnrollmentHostScopeAndRevocation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "findings.jsonl"), 20)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agents.json")
	registry, err := OpenCredentialRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	admin := "very-long-test-admin-secret"
	srv := httptest.NewServer(APIWithCredentials(admin, store, registry))
	defer srv.Close()
	res := requestM4(t, srv, "/v1/agents/enroll", "not-admin", map[string]string{"host": "node-1"})
	if res.StatusCode != 401 {
		t.Fatalf("non admin enrollment: %d", res.StatusCode)
	}
	res.Body.Close()
	res = requestM4(t, srv, "/v1/agents/enroll", admin, map[string]string{"host": "node-1"})
	if res.StatusCode != 200 {
		t.Fatalf("enroll: %d", res.StatusCode)
	}
	var credentials struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&credentials); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(credentials.Token) < 60 {
		t.Fatal("token too short")
	}
	if !registry.Verify("node-1", credentials.Token) {
		t.Fatal("issued token rejected")
	}
	event := Event{ID: "host-check", Host: "node-1", PID: 99, Time: time.Now(), Command: "test"}
	res = requestM4(t, srv, "/v1/events", credentials.Token, event)
	if res.StatusCode != 200 {
		t.Fatalf("same-host ingest: %d", res.StatusCode)
	}
	res.Body.Close()
	event.Host = "node-2"
	event.ID = "host-2"
	res = requestM4(t, srv, "/v1/events", credentials.Token, event)
	if res.StatusCode != 401 {
		t.Fatalf("cross-host ingest: %d", res.StatusCode)
	}
	res.Body.Close()
	reopened, err := OpenCredentialRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Verify("node-1", credentials.Token) {
		t.Fatal("persistence failed")
	}
	res = requestM4(t, srv, "/v1/agents/revoke", admin, map[string]string{"host": "node-1"})
	if res.StatusCode != 204 {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	res.Body.Close()
	if registry.Verify("node-1", credentials.Token) {
		t.Fatal("revoked token still accepted")
	}
	event.Host = "node-1"
	res = requestM4(t, srv, "/v1/events", credentials.Token, event)
	if res.StatusCode != 401 {
		t.Fatalf("revoked ingest: %d", res.StatusCode)
	}
	res.Body.Close()
}
func TestHostValidationAndRotation(t *testing.T) {
	r, err := OpenCredentialRegistry(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Issue("../bad"); err == nil {
		t.Fatal("accepted invalid host")
	}
	a, err := r.Issue("good-host")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Issue("good-host")
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify("good-host", a) || !r.Verify("good-host", b) {
		t.Fatal("rotation failed")
	}
}
