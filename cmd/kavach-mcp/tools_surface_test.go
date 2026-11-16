// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"strings"
	"testing"
)

func TestSurfaceToolsReadOnly(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	seen := map[string]bool{}
	for _, tl := range surfaceTools() {
		if seen[tl.name] {
			t.Fatalf("duplicate tool %s", tl.name)
		}
		seen[tl.name] = true
		if ro[tl.name] == nil {
			t.Fatalf("%s missing in read-only mode", tl.name)
		}
		if tl.method != "GET" || tl.bodyFields {
			t.Fatalf("%s must be a plain GET without body", tl.name)
		}
		if !strings.Contains(tl.description, "Read-only") {
			t.Fatalf("%s description must state read-only", tl.name)
		}
	}
	if len(seen) < 90 {
		t.Fatalf("expected the full surface set, got %d", len(seen))
	}
}

func TestSurfaceToolsRequests(t *testing.T) {
	cases := []struct{ tool, args, uri string }{
		{"kavach_events_auth", `{"host":"h1","limit":"5"}`, "/v1/events/auth?host=h1&limit=5"},
		{"kavach_regression_diff", `{"from":"1","to":"latest"}`, "/v1/regression/diff?from=1&to=latest"},
		{"kavach_guidance_get", `{"id":"a/b"}`, "/v1/guidance/a%2Fb"},
		{"kavach_sectors_scada", `{}`, "/v1/sectors/scada"},
		{"kavach_finance_core_banking", `{}`, "/v1/finance/core-banking"},
		{"kavach_ransomware_host", `{"host":"h1"}`, "/v1/ransomware/host/h1"},
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
