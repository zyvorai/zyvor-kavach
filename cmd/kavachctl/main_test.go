// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
