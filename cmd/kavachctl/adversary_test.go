// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"strings"
	"testing"
)

func advRunT(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	h, err := advDispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

func TestAdversaryCommands(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	mux.HandleFunc("GET /v1/adversaries", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		omJSON(w, map[string]any{"count": 1, "adversaries": []map[string]any{{"id": "apt29", "name": "APT29", "kind": "nation-state", "motivation": "espionage", "confidence": "medium", "techniques": []string{"T1078"}}}})
	})
	mux.HandleFunc("GET /v1/adversaries/coverage", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{"count": 1, "by_coverage": []map[string]any{{"id": "apt29", "name": "APT29", "coverage_pct": 75, "exact_pct": 50, "observed_hits": 3, "gaps": []string{"T1102"}}}})
	})
	mux.HandleFunc("GET /v1/adversaries/{id}", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{
			"profile":  map[string]any{"name": "APT29", "aliases": []string{"Cozy Bear"}, "kind": "nation-state", "motivation": "espionage", "confidence": "medium", "sources": []map[string]any{{"url": "https://attack.mitre.org/groups/G0016/"}}},
			"coverage": map[string]any{"total": 2, "exact": 1, "related": 0, "coverage_pct": 50, "gaps": []string{"T1102"}, "techniques": []map[string]any{{"technique": "T1078", "status": "exact", "rules": []string{"r1"}, "hits": 2}, {"technique": "T1102", "status": "gap"}}},
		})
	})
	setupMock(t, mux)

	out, err := advRunT(t, "adversary", "list", "--kind", "nation-state", "--q", "apt")
	if err != nil || !strings.Contains(out, "APT29") || !strings.Contains(out, "1 adversaries") {
		t.Fatalf("list: %v %q", err, out)
	}
	if all := strings.Join(got, " "); !strings.Contains(all, "kind=nation-state") || !strings.Contains(all, "q=apt") {
		t.Fatalf("query not forwarded: %v", got)
	}
	if out, err = advRunT(t, "adversary", "show", "apt29"); err != nil || !strings.Contains(out, "T1078") || !strings.Contains(out, "50%") || !strings.Contains(out, "attack.mitre.org") {
		t.Fatalf("show: %v %q", err, out)
	}
	if out, err = advRunT(t, "adversary", "coverage"); err != nil || !strings.Contains(out, "75%") {
		t.Fatalf("coverage: %v %q", err, out)
	}
	if out, err = advRunT(t, "adversary", "coverage", "--json"); err != nil || !strings.Contains(out, "by_coverage") {
		t.Fatalf("coverage json: %v %q", err, out)
	}
	if _, err = advRunT(t, "adversary", "show"); err == nil {
		t.Fatal("show without id should fail")
	}
	if _, err = advRunT(t, "adversary", "bogus"); err == nil {
		t.Fatal("bogus subcommand should fail")
	}
	if h, _ := advDispatch([]string{"content"}, &strings.Builder{}); h {
		t.Fatal("must not claim other groups")
	}
}
