package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestM5HeartbeatFleetAndPersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "findings.jsonl"), 20)
	if err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, "agents.json")
	registry, err := OpenCredentialRegistry(creds)
	if err != nil {
		t.Fatal(err)
	}
	admin := "this-is-a-long-admin-secret"
	server := httptest.NewServer(APIWithCredentials(admin, store, registry))
	defer server.Close()
	token, err := registry.Issue("node-1")
	if err != nil {
		t.Fatal(err)
	}
	statuses := registry.Status(time.Now(), 90*time.Second)
	if len(statuses) != 1 || statuses[0].State != "pending" {
		t.Fatalf("pending state: %+v", statuses)
	}
	if err := SendHeartbeat(context.Background(), server.URL, "bad-token", "node-1", "proc", 0, server.Client()); err == nil {
		t.Fatal("invalid token accepted")
	}
	if err := SendHeartbeat(context.Background(), server.URL, token, "node-2", "proc", 0, server.Client()); err == nil {
		t.Fatal("cross-host token accepted")
	}
	if err := SendHeartbeat(context.Background(), server.URL, token, "node-1", "proc", 4, server.Client()); err != nil {
		t.Fatal(err)
	}
	statuses = registry.Status(time.Now(), 90*time.Second)
	if statuses[0].State != "online" || statuses[0].Queued != 4 || statuses[0].LastSeen.IsZero() {
		t.Fatalf("bad heartbeat %+v", statuses)
	}
	registry.mu.Lock()
	credential := registry.agents["node-1"]
	credential.LastSeen = time.Now().Add(-3 * time.Minute)
	registry.agents["node-1"] = credential
	registry.mu.Unlock()
	statuses = registry.Status(time.Now(), 90*time.Second)
	if statuses[0].State != "offline" {
		t.Fatalf("offline state: %+v", statuses)
	}
	if err := SendHeartbeat(context.Background(), server.URL, token, "node-1", "proc", 2, server.Client()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCredentialRegistry(creds)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status(time.Now(), 90*time.Second)[0].State != "online" {
		t.Fatal("heartbeat was not persisted")
	}
	req, _ := http.NewRequest("GET", server.URL+"/v1/fleet", nil)
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("unauthorized fleet %d", res.StatusCode)
	}
	req, _ = http.NewRequest("GET", server.URL+"/v1/fleet", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	res, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var list []AgentStatus
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(list) != 1 || list[0].Host != "node-1" {
		t.Fatalf("fleet %+v", list)
	}
	if err := registry.Revoke("node-1"); err != nil {
		t.Fatal(err)
	}
	if err := SendHeartbeat(context.Background(), server.URL, token, "node-1", "proc", 0, server.Client()); err == nil {
		t.Fatal("revoked heartbeat accepted")
	}
	if registry.Status(time.Now(), 90*time.Second)[0].State != "revoked" {
		t.Fatal("revoked status incorrect")
	}
}

func TestM5HeartbeatPayloadBoundsAndQueuePending(t *testing.T) {
	registry, err := OpenCredentialRegistry(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.Issue("host1")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Heartbeat("host1", token, "test", -1); err == nil {
		t.Fatal("negative queue allowed")
	}
	if err := registry.Heartbeat("host1", token, "test", 1000001); err == nil {
		t.Fatal("unbounded queue allowed")
	}
	q := Queue{Dir: filepath.Join(t.TempDir(), "outbox"), Limit: 10}
	n, err := q.Pending()
	if err != nil || n != 0 {
		t.Fatalf("new queue %d %v", n, err)
	}
	if err := q.Enqueue(Event{ID: "test", Host: "host1", PID: 4, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	n, err = q.Pending()
	if err != nil || n != 1 {
		t.Fatalf("queued %d %v", n, err)
	}
	// Malformed input is rejected at the API layer.
	store, _ := testStore(t, filepath.Join(t.TempDir(), "findings.jsonl"), 10)
	srv := httptest.NewServer(APIWithCredentials("a-very-long-admin-secret", store, registry))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/agents/heartbeat", bytes.NewBufferString("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("malformed heartbeat %d", res.StatusCode)
	}
}
