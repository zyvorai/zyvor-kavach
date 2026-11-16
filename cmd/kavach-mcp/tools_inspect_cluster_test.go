package main

import (
	"strings"
	"testing"
)

func TestInspectClusterToolsReadOnly(t *testing.T) {
	c, reqs := recorder(t)
	ro := listToolsJSON(t, c, false) // read-only mode: no --allow-mutations
	for _, tl := range inspectClusterTools() {
		if ro[tl.name] == nil {
			t.Fatalf("%s missing in read-only mode", tl.name)
		}
		if tl.method != "GET" || tl.bodyFields || len(tl.pathParams) > 0 {
			t.Fatalf("%s must be a plain GET", tl.name)
		}
		if d := ro[tl.name]["description"].(string); !strings.Contains(d, "Read-only") {
			t.Fatalf("%s description lacks the read-only note: %s", tl.name, d)
		}
	}
	callTool(t, c, false, "inspect_clusters", `{"min_score":"2","limit":"5","kind":"file"}`)
	callTool(t, c, false, "inspect_sarif", `{"id":"latest"}`)
	r := reqs()
	if len(r) != 2 || r[0].method != "GET" || r[0].uri != "/v1/inspect/clusters?kind=file&limit=5&min_score=2" ||
		r[1].method != "GET" || r[1].uri != "/v1/inspect/sarif?id=latest" || len(r[0].body)+len(r[1].body) != 0 {
		t.Fatalf("requests: %+v", r)
	}
}
