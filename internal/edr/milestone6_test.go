package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testAdminToken = "administrator-secret-token-for-tests"

func postJSON(t *testing.T, url, token string, obj any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(obj)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func TestFileSensorBaselineAndMassDetection(t *testing.T) {
	dir := t.TempDir()
	s := NewFileScanner(dir, "node-1")
	if events, err := s.Scan(time.Now()); err != nil || len(events) != 0 {
		t.Fatalf("baseline: %v %v", events, err)
	}
	var d FileDetections
	d.Threshold = 3
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
		events, err := s.Scan(time.Now())
		if err != nil || len(events) != 1 {
			t.Fatalf("scan %v %v", events, err)
		}
		findings := d.Observe(events[0])
		if i == 2 && (len(findings) != 1 || findings[0].Rule != "mass-file-activity") {
			t.Fatalf("expected mass activity: %+v", findings)
		}
	}
}
func TestFileIngressScopedAndDeduplicated(t *testing.T) {
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "findings"), 100)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := OpenCredentialRegistry(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := registry.Issue("node-1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(APIWithCredentials(testAdminToken, store, registry))
	defer srv.Close()
	e := FileEvent{ID: "unique-1", Host: "node-1", Time: time.Now(), Path: "/tmp/example", Operation: "modify"}
	resp := postJSON(t, srv.URL+"/v1/file-events", cred, e)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	resp = postJSON(t, srv.URL+"/v1/file-events", cred, e)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	e.Host = "other-host"
	resp = postJSON(t, srv.URL+"/v1/file-events", cred, e)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("cross host status %d", resp.StatusCode)
	}
	store2, err := testStore(t, filepath.Join(dir, "findings"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store2.seen["f:unique-1"]; !ok {
		t.Fatal("file dedupe lost on restart")
	}
}
func TestIncidentTransitionPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings")
	store, err := testStore(t, path, 50)
	if err != nil {
		t.Fatal(err)
	}
	finding := Finding{ID: "case-1", Host: "node-1", Rule: "test", Time: time.Now()}
	if err := store.Append(finding); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(API(testAdminToken, store))
	defer srv.Close()
	action := IncidentAction{FindingID: "case-1", Status: "investigating", Actor: "analyst", Note: "triage"}
	resp := postJSON(t, srv.URL+"/v1/incidents/transition", testAdminToken, action)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	restored, err := testStore(t, path, 50)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := NewIncidentStore(restored)
	if err != nil {
		t.Fatal(err)
	}
	if got := workflow.entries["case-1"].Status; got != "investigating" {
		t.Fatalf("status=%q", got)
	}
	resp = postJSON(t, srv.URL+"/v1/incidents/transition", "invalid-token", action)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("unauthorized transition accepted")
	}
}
func TestFileSpoolRetry(t *testing.T) {
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "findings"), 100)
	if err != nil {
		t.Fatal(err)
	}
	e := FileEvent{ID: "retry-file-1", Host: "node-1", Path: "/tmp/x", Time: time.Now(), Operation: "create"}
	if err := SpoolFileEvent(filepath.Join(dir, "spool"), e); err != nil {
		t.Fatal(err)
	}
	if err := FlushFileEvents(context.Background(), filepath.Join(dir, "spool"), "http://127.0.0.1:1", testAdminToken, nil); err == nil {
		t.Fatal("expected delivery error")
	}
	srv := httptest.NewServer(API(testAdminToken, store))
	defer srv.Close()
	if err := FlushFileEvents(context.Background(), filepath.Join(dir, "spool"), srv.URL, testAdminToken, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "spool"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool not cleared: %v %v", entries, err)
	}
}
func TestMutualTLSConfigurationRejectsInvalidInputs(t *testing.T) {
	if _, err := NewMutualTLSClient("", "cert-only", ""); err == nil {
		t.Fatal("expected incomplete identity rejection")
	}
	if _, err := ServerTLSConfig("/nonexistent/path"); err == nil {
		t.Fatal("expected missing CA error")
	}
}
