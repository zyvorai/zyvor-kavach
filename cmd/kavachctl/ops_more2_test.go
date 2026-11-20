// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func om2Run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	h, err := om2Dispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

func TestOps2(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	h := func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		omJSON(w, map[string]any{"ok": true})
	}
	for _, p := range []string{"GET /v1/identity/itdr/summary", "GET /v1/identity/itdr/indicators", "GET /v1/identity/itdr/risk",
		"GET /v1/identity/itdr/privileged", "GET /v1/identity/itdr/timeline", "GET /v1/vulns/software", "GET /v1/vulns/top",
		"GET /v1/sbom/{host}", "GET /v1/incidents/correlated", "GET /v1/cases", "GET /v1/cases/{id}", "POST /v1/cases",
		"PATCH /v1/cases/{id}", "POST /v1/cases/{id}/comments", "GET /v1/cases/{id}/export", "GET /v1/hunts/packs",
		"POST /v1/hunts/packs/{id}/run", "POST /v1/hunts/run-all", "POST /v1/hunts/schedules", "DELETE /v1/hunts/schedules",
		"GET /v1/hunts/history", "GET /v1/devices/removable", "GET /v1/ransomware/risk", "GET /v1/ransomware/host/{host}",
		"GET /v1/containers/risk", "GET /v1/lateral/edges"} {
		mux.HandleFunc(p, h)
	}
	setupMock(t, mux)
	file := filepath.Join(t.TempDir(), "s.json")
	for _, a := range [][]string{
		{"identity", "summary"}, {"identity", "indicators", "--kind", "spray"}, {"identity", "risk"}, {"identity", "privileged"},
		{"identity", "timeline", "bob"}, {"vulns", "software", "--host", "h1"}, {"vulns", "top"}, {"sbom", "h1"},
		{"sbom", "h1", "--out", file}, {"incidents", "correlated", "--window", "2h"}, {"case", "list"}, {"case", "show", "c1"},
		{"case", "create", "--title", "T"}, {"case", "update", "c1", "--status", "open"}, {"case", "comment", "c1", "hi", "there"},
		{"case", "close", "c1", "--resolution", "done"}, {"case", "export", "c1"}, {"hunt", "packs"}, {"hunt", "run", "p1"},
		{"hunt", "run-all"}, {"hunt", "schedule-add", "p1", "--interval", "60"}, {"hunt", "schedule-rm", "hs-1"},
		{"hunt", "history", "--json"}, {"hunt", "devices"}, {"ransomware", "risk"}, {"ransomware", "host", "h1"},
		{"containers", "risk"}, {"lateral"},
	} {
		if _, err := om2Run(t, a...); err != nil {
			t.Fatalf("%v: %v", a, err)
		}
	}
	all := strings.Join(got, " | ")
	for _, w := range []string{"GET /v1/identity/itdr/indicators?kind=spray", "GET /v1/identity/itdr/timeline?user=bob",
		"GET /v1/vulns/software?host=h1", "GET /v1/incidents/correlated?window=2h", "DELETE /v1/hunts/schedules?id=hs-1",
		"PATCH /v1/cases/c1", "POST /v1/cases/c1/comments"} {
		if !strings.Contains(all, w) {
			t.Errorf("missing %s in %s", w, all)
		}
	}
	if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), "true") {
		t.Fatalf("sbom file: %v", err)
	}
	if h, _ := om2Dispatch([]string{"hunt", "query", "x"}, &strings.Builder{}); h {
		t.Fatal("hunt query must fall through")
	}
	if _, err := om2Run(t, "case", "close", "c1"); err == nil {
		t.Fatal("close needs resolution")
	}
}
