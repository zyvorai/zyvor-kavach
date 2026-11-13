package main

import (
	"net/http"
	"strings"
	"testing"
)

func p4Mock(t *testing.T, routes map[string]map[string]any) *[]string {
	t.Helper()
	mux := http.NewServeMux()
	got := &[]string{}
	for p, body := range routes {
		body := body
		mux.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) {
			*got = append(*got, r.Method+" "+r.URL.RequestURI())
			omJSON(w, body)
		})
	}
	setupMock(t, mux)
	return got
}

func p4Run(t *testing.T, args ...string) string {
	t.Helper()
	var buf strings.Builder
	ok, err := p4Dispatch(args, &buf)
	if !ok || err != nil {
		t.Fatalf("%v: handled=%v err=%v", args, ok, err)
	}
	return buf.String()
}

func p4Has(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Fatalf("missing %q in:\n%s", s, out)
		}
	}
}

func TestProvCtl(t *testing.T) {
	env := func(m map[string]any) map[string]any {
		m["method"] = "PROV-METHOD"
		m["limitations"] = []any{"LIM-ONE", "LIM-TWO"}
		return m
	}
	got := p4Mock(t, map[string]map[string]any{
		"/v1/prov/graph": env(map[string]any{"host": "h1", "node_cap": 500, "truncated": false,
			"nodes": []any{map[string]any{"id": "n1", "kind": "process", "pid": 7, "exe": "/bin/sh"}}, "edges": []any{}, "missing": map[string]any{"unresolved_parents": 2}}),
		"/v1/prov/stories": env(map[string]any{"min_score": 2, "rarity_source": "retained-store", "stories": []any{map[string]any{"id": "s1", "host": "h1", "score": 4.5}}}),
		"/v1/prov/trace":   env(map[string]any{"finding_id": "f1", "host": "h1", "attached": false, "reason": "no pid match"}),
		"/v1/prov/status":  env(map[string]any{"hosts": []any{"h1"}, "inputs": map[string]any{"findings": 1}, "lacks": []any{"LACK-X"}, "state": "memory only"}),
	})
	out := p4Run(t, "prov", "graph", "--host", "h1", "--limit", "50")
	p4Has(t, out, "METHOD: PROV-METHOD", "LIM-ONE", "LIM-TWO", "1 nodes", "unresolved_parents")
	out = p4Run(t, "prov", "stories", "--host", "h1", "--min-score", "2")
	p4Has(t, out, "PROV-METHOD", "LIM-TWO", "s1", "not verdicts")
	out = p4Run(t, "prov", "trace", "--finding-id", "f1", "--dir", "both", "--hops", "4")
	p4Has(t, out, "LIM-ONE", "NOT attached", "no pid match")
	out = p4Run(t, "prov", "status")
	p4Has(t, out, "LACK-X", "LIM-ONE", "memory only")
	raw := p4Run(t, "prov", "status", "--json")
	p4Has(t, raw, `"state":"memory only"`)
	want := []string{"GET /v1/prov/graph?host=h1&limit=50", "GET /v1/prov/stories?host=h1&min_score=2",
		"GET /v1/prov/trace?dir=both&finding_id=f1&hops=4", "GET /v1/prov/status", "GET /v1/prov/status"}
	if strings.Join(*got, "|") != strings.Join(want, "|") {
		t.Fatalf("requests: %v", *got)
	}
	var buf strings.Builder
	if _, err := p4Dispatch([]string{"prov", "graph"}, &buf); err == nil {
		t.Fatal("graph without --host should error")
	}
}

func TestRansomCtl(t *testing.T) {
	got := p4Mock(t, map[string]map[string]any{
		"/v1/ransom/status": {"method": "RD-METHOD", "alert_rule": "RULE", "cannot_see": []any{"CANNOT-A"}, "report_only": true, "note": "heuristics"},
		"/v1/ransom/hosts": {"report_only": true, "hosts": []any{map[string]any{"host": "h1", "windows": 3, "alert_windows": 1,
			"peak": map[string]any{"level": "alert", "score": 80, "start": "2026-01-01T00:00:00Z"}}}},
		"/v1/ransom/host": {"host": "h1", "windows": []any{map[string]any{"start": "2026-01-01T00:00:00Z", "level": "watch", "score": 40, "events": 9,
			"factors": []any{map[string]any{"name": "extension_churn", "kind": "primary", "triggered": true, "detail": "D"}}}}},
	})
	out := p4Run(t, "ransom", "status")
	p4Has(t, out, "METHOD: RD-METHOD", "CANNOT-A", "RULE")
	out = p4Run(t, "ransom", "hosts")
	p4Has(t, out, "report-only", "h1", "alert", "80")
	out = p4Run(t, "ransom", "host", "--host", "h1", "--limit", "5")
	p4Has(t, out, "report-only", "extension_churn", "watch")
	p4Has(t, p4Run(t, "ransom", "hosts", "--json"), `"report_only":true`)
	want := "GET /v1/ransom/status|GET /v1/ransom/hosts|GET /v1/ransom/host?host=h1&limit=5|GET /v1/ransom/hosts"
	if strings.Join(*got, "|") != want {
		t.Fatalf("requests: %v", *got)
	}
}

func TestTTPCtl(t *testing.T) {
	cav := []any{"Similarity is NOT attribution. CAVEAT-ONE", "CAVEAT-TWO"}
	got := p4Mock(t, map[string]map[string]any{
		"/v1/ttp/similar": {"caveats": cav, "source": "techniques", "method": "TTP-METHOD", "confidence": "not_enough_evidence",
			"confidence_reason": "only 2 techniques", "distinct_techniques": 2, "profiles": 9, "observed": []any{}, "matches": []any{}},
		"/v1/ttp/next": {"caveats": cav, "source": "host", "confidence": "hint_only", "label": "Not a prediction.", "observed": []any{},
			"hints": []any{map[string]any{"technique": "T1021", "tactic": "Lateral Movement", "supporting_profiles": 3, "weight": 1.2, "commodity": true}}},
		"/v1/ttp/chains": {"caveats": cav, "host": "h1", "observed_techniques": 2, "tactics_reached": []any{"Execution"},
			"killchain_order_check": "consistent", "gaps_worth_hunting": []any{map[string]any{"tactic": "Persistence", "hunt_techniques": []any{"T1053"}}},
			"gap_note": "hunt, do not assume"},
	})
	out := p4Run(t, "ttp", "similar", "--techniques", "T1059,T1003")
	p4Has(t, out, "SIMILARITY IS NOT ATTRIBUTION", "CAVEAT-ONE", "CAVEAT-TWO", "TTP-METHOD", "not_enough_evidence", "only 2 techniques", "not enough evidence")
	out = p4Run(t, "ttp", "next", "--host", "h1")
	p4Has(t, out, "CAVEAT-TWO", "Not a prediction", "T1021", "commodity")
	out = p4Run(t, "ttp", "chains", "--host", "h1")
	p4Has(t, out, "CAVEAT-ONE", "Persistence", "T1053", "do not assume")
	p4Has(t, p4Run(t, "ttp", "similar", "--finding-ids", "a,b", "--json"), `"caveats"`)
	want := "GET /v1/ttp/similar?techniques=T1059%2CT1003|GET /v1/ttp/next?host=h1|GET /v1/ttp/chains?host=h1|GET /v1/ttp/similar?finding_ids=a%2Cb"
	if strings.Join(*got, "|") != want {
		t.Fatalf("requests: %v", *got)
	}
	var buf strings.Builder
	if _, err := p4Dispatch([]string{"ttp", "similar"}, &buf); err == nil {
		t.Fatal("no input should error")
	}
	if _, err := p4Dispatch([]string{"ttp", "similar", "--host", "h", "--techniques", "T1059"}, &buf); err == nil {
		t.Fatal("two inputs should error")
	}
}

func TestInspectSimilarCtl(t *testing.T) {
	got := p4Mock(t, map[string]map[string]any{
		"/v1/inspect/similar": {"count": 1, "mode": "observe-only", "note": "Similarity is not maliciousness.", "thresholds": map[string]any{"ctph_min_score": 40},
			"matches": []any{map[string]any{"sha256": strings.Repeat("ab", 32), "ctph_score": 77, "lsh_distance": -1, "similar": true, "basis": "ctph"}}},
	})
	out := p4Run(t, "inspect", "similar", "--sha256", strings.Repeat("ab", 32), "--limit", "3")
	p4Has(t, out, "not maliciousness", "abababababababab", "77", "ctph")
	p4Has(t, p4Run(t, "inspect", "similar", "--digest", "kavach-ctph1:x", "--json"), `"count":1`)
	want := "GET /v1/inspect/similar?limit=3&sha256=" + strings.Repeat("ab", 32) + "|GET /v1/inspect/similar?digest=kavach-ctph1%3Ax"
	if strings.Join(*got, "|") != want {
		t.Fatalf("requests: %v", *got)
	}
	var buf strings.Builder
	if _, err := p4Dispatch([]string{"inspect", "similar"}, &buf); err == nil {
		t.Fatal("missing id should error")
	}
	if ok, _ := p4Dispatch([]string{"inspect", "analyzers"}, &buf); ok {
		t.Fatal("other inspect commands must fall through")
	}
}
