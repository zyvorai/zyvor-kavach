// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"strings"
	"testing"
)

func ocRunT(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	h, err := ocDispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

func TestContentCommands(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	mux.HandleFunc("GET /v1/content/rules", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		omJSON(w, map[string]any{"count": 1, "rules": []map[string]any{{"id": "r1", "name": "Rule One", "tactic": "execution", "technique": "T1059", "severity": "high", "os": "linux", "event_type": "process"}}})
	})
	mux.HandleFunc("GET /v1/content/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{"id": r.PathValue("id"), "tests": map[string]any{"positive": []any{}}})
	})
	mux.HandleFunc("GET /v1/content/coverage", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{"total_rules": 5, "active_rules": 5, "techniques_covered_count": 2, "by_tactic": map[string]int{"execution": 3}})
	})
	setupMock(t, mux)

	out, err := ocRunT(t, "content", "list", "--severity", "high", "--event-type", "process", "--q", "one")
	if err != nil || !strings.Contains(out, "Rule One") || !strings.Contains(out, "1 rules") {
		t.Fatalf("list: %v %q", err, out)
	}
	all := strings.Join(got, " ")
	if !strings.Contains(all, "event_type=process") || !strings.Contains(all, "severity=high") {
		t.Fatalf("query not forwarded: %v", got)
	}
	if out, err = ocRunT(t, "content", "show", "r1"); err != nil || !strings.Contains(out, `"r1"`) {
		t.Fatalf("show: %v %q", err, out)
	}
	if out, err = ocRunT(t, "content", "coverage"); err != nil || !strings.Contains(out, "execution") || !strings.Contains(out, "5 total") {
		t.Fatalf("coverage: %v %q", err, out)
	}
	if _, err = ocRunT(t, "content", "show"); err == nil {
		t.Fatal("show without id must error")
	}
	if _, err = ocRunT(t, "content", "bogus"); err == nil {
		t.Fatal("bogus subcommand must error")
	}
}

func TestCatalogCoversOpsCommands(t *testing.T) {
	have := map[string]bool{}
	for _, c := range allCLICommands() {
		have[c.Name] = true
	}
	for _, n := range []string{"fleet-health", "prevalence-rare", "canary-list", "governance-inventory", "tuning-history", "digest-list",
		"identity-risk", "vulns-top", "incidents-correlated", "case-list", "hunt-packs", "ransomware-risk", "content-list", "content-show", "content-coverage"} {
		if !have[n] {
			t.Errorf("catalog missing %s", n)
		}
	}
}
