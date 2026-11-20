package main

import (
	"strings"
	"testing"
)

func TestPostureReportToolsReadOnly(t *testing.T) {
	for _, allow := range []bool{false, true} {
		out := listTools(t, allow)
		for _, tl := range postureReportTools() {
			if !strings.Contains(out, `"name":"`+tl.name+`"`) {
				t.Fatalf("allow=%v: %s missing", allow, tl.name)
			}
			if tl.method != "GET" {
				t.Fatalf("%s must be GET", tl.name)
			}
		}
	}
	if n := len(postureReportTools()); n != 4 {
		t.Fatalf("want 4 tools, got %d", n)
	}
}
