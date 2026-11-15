// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStopAllOrderIdempotentPanicTimeout(t *testing.T) {
	StopAllForTest()
	old := StopTimeout
	StopTimeout = 150 * time.Millisecond
	defer func() { StopTimeout = old; StopAllForTest() }()
	var order []string
	RegisterStopper("a", func(context.Context) error { order = append(order, "a"); return nil })
	RegisterStopper("hang", func(ctx context.Context) error { time.Sleep(2 * time.Second); return nil })
	RegisterStopper("panic", func(context.Context) error { panic("boom") })
	RegisterStopper("err", func(context.Context) error { return errors.New("bad") })
	RegisterStopper("d", func(context.Context) error { order = append(order, "d"); return nil })
	if ShuttingDown() {
		t.Fatal("not shutting down yet")
	}
	res := StopAll(context.Background())
	var names []string
	for _, r := range res {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, ","); got != "d,err,panic,hang,a,background-goroutines" {
		t.Fatalf("order %s", got)
	}
	if strings.Join(order, "") != "da" {
		t.Fatalf("exec order %v", order)
	}
	if !res[2].Panicked || res[2].TimedOut {
		t.Fatalf("panic not contained: %+v", res[2])
	}
	if !res[3].TimedOut || res[3].Took > time.Second {
		t.Fatalf("timeout: %+v", res[3])
	}
	if res[1].Err != "bad" {
		t.Fatalf("err: %+v", res[1])
	}
	if !ShuttingDown() {
		t.Fatal("must be shutting down")
	}
	again := StopAll(context.Background())
	if len(again) != len(res) || len(order) != 2 {
		t.Fatalf("not idempotent: %d stoppers re-run=%v", len(again), order)
	}
}

func TestReadyzFlipsWhenStopping(t *testing.T) {
	StopAllForTest()
	defer StopAllForTest()
	mux := http.NewServeMux()
	RegisterHealth(mux, nil)
	probe := func() (int, string) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code, w.Body.String()
	}
	if c, _ := probe(); c != 200 {
		t.Fatalf("ready: %d", c)
	}
	StopAll(context.Background())
	if c, b := probe(); c != 503 || !strings.Contains(b, "shutting down") {
		t.Fatalf("after stop: %d %q", c, b)
	}
}

func statusOf(t *testing.T, u string) int {
	t.Helper()
	r, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r.StatusCode
}

// TestGracefulShutdownIntegration starts the real mux with every service registered, mutates state,
// stops everything and asserts (a) goroutines return to baseline within a documented tolerance and
// (b) state files were flushed.
//
// Tolerance: baseline+4. Allowed residue is runtime/net-http internals (idle keep-alive conns,
// httptest teardown) that are not ours; a service leaking its loop goroutine would exceed this
// (there are 9 loop goroutines).
func TestGracefulShutdownIntegration(t *testing.T) {
	StopAllForTest()
	dir := t.TempDir()
	base := filepath.Join(dir, "findings.jsonl")
	store, err := NewStore(base, 1000)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv := httptest.NewServer(APIWithCredentials("test-token-123", store, nil))
	if _, err := store.Ingest(Event{Host: "h1", Time: time.Now(), PID: 10, PPID: 1, Executable: "/bin/bash", ParentExe: "/usr/sbin/sshd", Command: "bash -c id"}); err != nil {
		t.Fatal(err)
	}
	if c := statusOf(t, srv.URL+"/readyz"); c != 200 {
		t.Fatalf("readyz before: %d", c)
	}
	if n := runtime.NumGoroutine(); n <= baseline {
		t.Fatalf("services did not start goroutines (%d <= %d)", n, baseline)
	}

	start := time.Now()
	BeginShutdown()
	if c := statusOf(t, srv.URL+"/readyz"); c != 503 {
		t.Fatalf("readyz during shutdown: %d", c)
	}
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := StopAll(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
	names := map[string]bool{}
	for _, r := range res {
		names[r.Name] = true
		if r.TimedOut || r.Panicked || r.Err != "" {
			t.Errorf("stopper %s failed: %+v", r.Name, r)
		}
	}
	for _, want := range []string{"ml-behaviour", "fleet-slo", "report-sched", "scheduled-detections", "exceptions", "hunt-packs"} {
		if !names[want] {
			t.Errorf("stopper %q not registered (got %v)", want, names)
		}
	}
	for _, f := range []string{".mlbehaviour.json", sloExt, ".reportschedules.json", ".scheduled_detections.json"} {
		if _, err := os.Stat(base + f); err != nil {
			t.Errorf("state file %s not flushed: %v", f, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var n int
	for {
		http.DefaultTransport.(*http.Transport).CloseIdleConnections()
		runtime.GC()
		n = runtime.NumGoroutine()
		if n <= baseline+4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n > baseline+4 {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines %d > baseline %d + 4\n%s", n, baseline, buf[:runtime.Stack(buf, true)])
	}
	StopAllForTest()
}
