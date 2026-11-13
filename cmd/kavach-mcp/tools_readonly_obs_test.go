// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"strings"
	"testing"
)

func obsAll() []endpointTool {
	var all []endpointTool
	for _, f := range []func() []endpointTool{provTools, ransomTools, ttpTools, inspectSimilarTools} {
		all = append(all, f()...)
	}
	return all
}

func TestObsToolsReadOnlyHonest(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	want := map[string]string{"prov_": "heuristic story ranking", "ransom_": "slow-and-low", "ttp_": "NOT attribution", "inspect_similar": "never proves"}
	if len(obsAll()) != 11 {
		t.Fatalf("expected 11 tools, got %d", len(obsAll()))
	}
	for _, tl := range obsAll() {
		if ro[tl.name] == nil {
			t.Fatalf("%s missing in read-only mode", tl.name)
		}
		if tl.method != "GET" || len(tl.pathParams) > 0 || tl.bodyFields {
			t.Fatalf("%s must be a plain GET", tl.name)
		}
		d := ro[tl.name]["description"].(string)
		for p, w := range want {
			if strings.HasPrefix(tl.name, p) && !strings.Contains(d, w) {
				t.Fatalf("%s lacks %q: %s", tl.name, w, d)
			}
		}
	}
}

func TestObsToolsRequests(t *testing.T) {
	cases := []struct{ tool, args, uri string }{
		{"prov_graph", `{"host":"h1","limit":"50"}`, "/v1/prov/graph?host=h1&limit=50"},
		{"prov_stories", `{"host":"h1","min_score":"2"}`, "/v1/prov/stories?host=h1&min_score=2"},
		{"prov_trace", `{"finding_id":"f1","dir":"both","hops":"4"}`, "/v1/prov/trace?dir=both&finding_id=f1&hops=4"},
		{"prov_status", `{}`, "/v1/prov/status"},
		{"ransom_status", `{}`, "/v1/ransom/status"},
		{"ransom_hosts", `{}`, "/v1/ransom/hosts"},
		{"ransom_host", `{"host":"h1","limit":"20"}`, "/v1/ransom/host?host=h1&limit=20"},
		{"ttp_similar", `{"techniques":"T1059,T1003.001"}`, "/v1/ttp/similar?techniques=T1059%2CT1003.001"},
		{"ttp_next", `{"host":"h1"}`, "/v1/ttp/next?host=h1"},
		{"ttp_chains", `{"host":"h1"}`, "/v1/ttp/chains?host=h1"},
		{"inspect_similar", `{"sha256":"abc","limit":"5"}`, "/v1/inspect/similar?limit=5&sha256=abc"},
	}
	for _, tc := range cases {
		c, reqs := recorder(t)
		callTool(t, c, false, tc.tool, tc.args)
		r := reqs()
		if len(r) != 1 || r[0].method != "GET" || r[0].uri != tc.uri || len(r[0].body) != 0 {
			t.Fatalf("%s: got %+v want GET %s", tc.tool, r, tc.uri)
		}
	}
}
