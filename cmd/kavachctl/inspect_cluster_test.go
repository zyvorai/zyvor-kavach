package main

import (
	"strings"
	"testing"
)

func TestInspectClustersAndSarifCtl(t *testing.T) {
	got := p4Mock(t, map[string]map[string]any{
		"/v1/inspect/clusters": {"count": 1, "considered": 4, "singletons": 2, "min_score": 1, "mode": "observe-only", "note": "Shared evidence only",
			"clusters": []any{map[string]any{"id": "clu-abc", "size": 2, "max_score": 55, "max_level": "suspicious", "explanation": "2 reports linked",
				"shared_factors": []any{map[string]any{"factor": "url:http://203.0.113.5/x", "count": 2}},
				"members":        []any{map[string]any{"id": "insp-1", "level": "low", "kind": "file", "name": "a.exe"}}}},
			"limits_hit": []any{"clusters"}},
		"/v1/inspect/sarif": {"version": "2.1.0", "runs": []any{}},
	})
	out := p4Run(t, "inspect", "clusters", "--min-score", "2", "--limit", "5", "--kind", "file")
	p4Has(t, out, "Shared evidence only", "clu-abc", "url:http://203.0.113.5/x", "insp-1", "Limits hit: clusters")
	p4Has(t, p4Run(t, "inspect", "clusters", "--json"), `"count":1`)
	p4Has(t, p4Run(t, "inspect", "sarif", "latest"), `"version":"2.1.0"`)
	p4Run(t, "inspect", "sarif", "--sha256", "ab")
	want := "GET /v1/inspect/clusters?kind=file&limit=5&min_score=2|GET /v1/inspect/clusters|GET /v1/inspect/sarif?id=latest|GET /v1/inspect/sarif?sha256=ab"
	if strings.Join(*got, "|") != want {
		t.Fatalf("requests: %v", *got)
	}
	var buf strings.Builder
	if _, err := p4Dispatch([]string{"inspect", "sarif"}, &buf); err == nil {
		t.Fatal("sarif without an id should error")
	}
	if _, err := p4Dispatch([]string{"inspect", "clusters", "extra"}, &buf); err == nil {
		t.Fatal("stray argument should error")
	}
}
