package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQueueRetryAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	q := Queue{Dir: filepath.Join(dir, "outbox"), Limit: 2}
	e := Event{Time: time.Now().UTC(), Host: "node1", PID: 42, Executable: "/usr/bin/bash", Command: "bash -c 'echo >/dev/tcp/127.0.0.1/4444'"}
	if err := q.Enqueue(e); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(e); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(e); err == nil {
		t.Fatal("queue bound not enforced")
	}
	store, err := NewStore(filepath.Join(dir, "findings.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef"
	srv := httptest.NewServer(API(token, store))
	defer srv.Close()
	if count, err := q.Flush(context.Background(), srv.URL, "wrong-key", nil); err == nil || count != 0 {
		t.Fatalf("expected retry on 401, got %d %v", count, err)
	}
	files, _ := os.ReadDir(q.Dir)
	if len(files) != 2 {
		t.Fatal("lost pending files")
	}
	if count, err := q.Flush(context.Background(), srv.URL, token, nil); err != nil || count != 2 {
		t.Fatalf("flush: %d %v", count, err)
	}
	want := len(Detect(e))
	if want < 1 {
		t.Fatal("fixture event produced no detections")
	}
	if len(store.List()) != want {
		t.Fatalf("expected %d findings after deduped dual flush, got %+v", want, store.List())
	}
	reopened, err := NewStore(filepath.Join(dir, "findings.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Ingest(e); err != nil || len(got) != 0 {
		t.Fatalf("duplicate after restart: %v %v", got, err)
	}
}
func TestNetworkCorrelationBothOrders(t *testing.T) {
	for _, networkFirst := range []bool{false, true} {
		store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		p := Event{ID: "proc-1", Time: now, Host: "node1", PID: 321, Executable: "/bin/echo", Command: "echo test"}
		n := NetworkEvent{ID: "net-1", Time: now.Add(time.Second), Host: "node1", PID: 321, Destination: "203.0.113.10:443", Verdict: "deny", Source: "netra"}
		if networkFirst {
			_, err = store.IngestNetwork(n)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Ingest(p)
		} else {
			_, err = store.Ingest(p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.IngestNetwork(n)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := store.List(); len(got) != 1 || got[0].Rule != "netra-denied-process" {
			t.Fatalf("order=%v findings=%v", networkFirst, got)
		}
	}
}
func TestNetworkHTTPAuthAndValidation(t *testing.T) {
	s, _ := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 10)
	srv := httptest.NewServer(API("0123456789abcdef", s))
	defer srv.Close()
	n := NetworkEvent{Time: time.Now().UTC(), Host: "node", PID: 1, Verdict: "deny"}
	b, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/network-events", strings.NewReader(string(b)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthorized network ingest allowed: %d", resp.StatusCode)
	}
}
