// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHelpLocal(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionLocal(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
}

func TestStatusHelpLocal(t *testing.T) {
	if err := run([]string{"status", "--help"}); err != nil {
		t.Fatal(err)
	}
}

func TestPickFlags(t *testing.T) {
	got := pickFlags([]string{"--severity", "high", "--host=box1", "--noise"}, "severity", "host")
	if got["severity"] != "high" || got["host"] != "box1" {
		t.Fatalf("pickFlags=%v", got)
	}
}

func TestCatalogHasLocalAndAPI(t *testing.T) {
	cmds := allCLICommands()
	if len(cmds) < 30 {
		t.Fatalf("expected broad catalog, got %d", len(cmds))
	}
	local := 0
	for _, c := range cmds {
		if c.Local {
			local++
		}
		if len(c.Args) == 0 {
			t.Fatalf("empty args for %s", c.Name)
		}
	}
	if local < 2 {
		t.Fatalf("expected local help commands")
	}
}

func TestCatalogCoversPublicVehiclesAndInsurance(t *testing.T) {
	want := []string{
		"sectors-public-vehicles", "sectors-city-buses", "sectors-taxis",
		"sectors-school-buses", "sectors-ferries", "sectors-gov-vehicles",
		"sectors-automotive", "sectors-manufacturing", "sectors-isro",
		"finance-insurance", "finance-insurance-lines", "finance-tpa",
		"finance-reinsurance", "finance-irdai", "finance-motor",
	}
	have := map[string]bool{}
	for _, c := range allCLICommands() {
		have[c.Name] = true
	}
	for _, name := range want {
		if !have[name] {
			t.Fatalf("catalog missing %s", name)
		}
	}
}

func TestSectorsAndFinanceCmdRouting(t *testing.T) {
	mux := http.NewServeMux()
	hits := map[string]int{}
	for _, p := range []string{
		"/v1/sectors/public-vehicles", "/v1/sectors/city-buses", "/v1/sectors/taxis-cabs",
		"/v1/sectors/ferries", "/v1/finance/insurance", "/v1/finance/irdai", "/v1/finance/motor-insurance",
	} {
		path := p
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits[path]++
			_ = json.NewEncoder(w).Encode([]map[string]any{{"ok": true}})
		})
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()

	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	t.Setenv("KAVACH_URL", ts.URL)
	t.Setenv("KAVACH_TOKEN", "test-token-admin321")
	base = ts.URL

	cases := [][]string{
		{"sectors", "public-vehicles"},
		{"sectors", "city-buses"},
		{"sectors", "taxis-cabs"},
		{"sectors", "ferries"},
		{"finance", "insurance"},
		{"finance", "irdai"},
		{"finance", "motor-insurance"},
	}
	for _, args := range cases {
		if err := run(args); err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	for _, path := range []string{
		"/v1/sectors/public-vehicles", "/v1/sectors/city-buses", "/v1/sectors/taxis-cabs",
		"/v1/sectors/ferries", "/v1/finance/insurance", "/v1/finance/irdai", "/v1/finance/motor-insurance",
	} {
		if hits[path] != 1 {
			t.Fatalf("%s hit=%d", path, hits[path])
		}
	}
}

func TestRequestAgainstMock(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/summary", func(w http.ResponseWriter, r *http.Request) {
		if ah := r.Header.Get("Authorization"); !strings.HasPrefix(ah, "Bearer ") {
			t.Errorf("missing bearer")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"findings": 3, "high": 1, "critical": 0, "hosts": 2})
	})
	mux.HandleFunc("/v1/fleet", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"host": "node-a", "online": true, "last_seen": "now"},
			{"host": "node-b", "online": false},
		})
	})
	mux.HandleFunc("/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "f1", "severity": r.URL.Query().Get("severity")}})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	t.Setenv("KAVACH_URL", ts.URL)
	t.Setenv("KAVACH_TOKEN", "test-token-admin321")
	t.Setenv("KAVACH_TLS_INSECURE", "false")
	base = ts.URL

	rep, err := collectStatusReport()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Healthy || rep.Findings != 3 || rep.FleetOnline != 1 || rep.FleetTotal != 2 {
		t.Fatalf("status report=%+v", rep)
	}

	if err := run([]string{"findings", "--severity", "high"}); err != nil {
		t.Fatal(err)
	}
	_ = os.Stdout
}

func setupMock(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	t.Setenv("KAVACH_URL", ts.URL)
	t.Setenv("KAVACH_TOKEN", "test-token")
	t.Setenv("NO_COLOR", "1")
	base = ts.URL
}

func TestAttackAndComplianceTables(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attack/matrix", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"framework": "MITRE", "covered": 1, "total": 2, "coverage_pct": 50, "observed_hits": 3,
			"tactics": []any{
				map[string]any{"tactic": "Execution", "covered": true, "hits": 3, "techniques": []any{map[string]any{"id": "T1"}}},
				map[string]any{"tactic": "Impact", "covered": false, "hits": 0, "techniques": []any{}},
			},
		})
	})
	mux.HandleFunc("/v1/compliance/score", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"overall": 85, "grade": "B", "mode": "observe-only",
			"frameworks": []any{map[string]any{"framework": "CIS", "score": 85, "grade": "B", "failing": 2}}})
	})
	setupMock(t, mux)

	var buf strings.Builder
	if err := attackCmd(&buf, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TACTIC", "Execution", "yes", "Impact", "no", "coverage 1/2"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("attack table missing %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := complianceScoreCmd(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CIS") || !strings.Contains(buf.String(), "grade B") {
		t.Fatalf("compliance table:\n%s", buf.String())
	}
	buf.Reset()
	if err := attackCmd(&buf, []string{"-o", "yaml"}); err != nil || !strings.Contains(buf.String(), "tactics:") {
		t.Fatalf("yaml: %v\n%s", err, buf.String())
	}
	if err := run([]string{"attack", "--json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := outputFormat([]string{"--output", "xml"}, "table"); err == nil {
		t.Fatal("expected bad format error")
	}
}

func TestListTableOutput(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("severity") != "high" {
			t.Errorf("severity not forwarded")
		}
		_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": "f1", "severity": "high", "host": "h1", "rule": "r1"}})
	})
	setupMock(t, mux)
	var buf strings.Builder
	if err := listCmd(&buf, "/v1/findings", []string{"--severity", "high", "-o", "table"}, "severity"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "f1") || !strings.Contains(buf.String(), "1 row(s)") {
		t.Fatalf("table:\n%s", buf.String())
	}
}

func TestWatchFilterAndReconnect(t *testing.T) {
	conns := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stream", func(w http.ResponseWriter, r *http.Request) {
		conns++
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		if conns == 1 {
			_, _ = w.Write([]byte(": connected\n\nevent: finding\ndata: {\"severity\":\"low\",\"host\":\"skip\",\"rule\":\"x\"}\n\n" +
				"event: finding\ndata: {\"severity\":\"high\",\"host\":\"h-one\",\"rule\":\"r1\",\"technique_id\":\"T1059\"}\n\n"))
			fl.Flush()
			return // close -> client must reconnect
		}
		_, _ = w.Write([]byte("event: finding\ndata: {\"severity\":\"critical\",\"host\":\"h-two\",\"rule\":\"r2\"}\n\n"))
		fl.Flush()
	})
	setupMock(t, mux)
	var buf strings.Builder
	o := watchOpts{MinSeverity: "high", MaxEvents: 2, Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	if err := watchStream(context.Background(), &buf, o); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if strings.Contains(s, "skip") || !strings.Contains(s, "h-one") || !strings.Contains(s, "h-two") || !strings.Contains(s, "CRITICAL") {
		t.Fatalf("watch output:\n%s", s)
	}
	if conns != 2 {
		t.Fatalf("conns=%d", conns)
	}
}

func TestWatchAuthFatal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stream", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	setupMock(t, mux)
	var buf strings.Builder
	if err := watchStream(context.Background(), &buf, watchOpts{Backoff: time.Millisecond}); err == nil {
		t.Fatal("expected auth error")
	}
}

func TestDoctor(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/v1/summary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) })
	setupMock(t, mux)
	var buf strings.Builder
	if err := doctorCmd(&buf); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "token accepted") {
		t.Fatalf("doctor:\n%s", buf.String())
	}

	bad := http.NewServeMux()
	bad.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	bad.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	bad.HandleFunc("/v1/summary", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	setupMock(t, bad)
	buf.Reset()
	if err := doctorCmd(&buf); err == nil || !strings.Contains(buf.String(), "FAIL") {
		t.Fatalf("expected failure:\n%s", buf.String())
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var buf strings.Builder
		if err := completionCmd(&buf, []string{sh}); err != nil || !strings.Contains(buf.String(), "watch") {
			t.Fatalf("%s: %v", sh, err)
		}
	}
	if err := completionCmd(io.Discard, []string{"csh"}); err == nil {
		t.Fatal("expected error")
	}
}
