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
