package main

import (
	"strings"
	"testing"
)

func TestRegulatoryToolsRegisteredReadOnly(t *testing.T) {
	for _, allow := range []bool{false, true} {
		out := listTools(t, allow)
		for _, tl := range regulatoryReadTools() {
			if !strings.Contains(out, `"name":"`+tl.name+`"`) {
				t.Fatalf("allow=%v: tool %s missing", allow, tl.name)
			}
			if tl.method != "GET" {
				t.Fatalf("%s must be read-only, got %s", tl.name, tl.method)
			}
			if !strings.Contains(tl.description, "not legal advice") {
				t.Fatalf("%s lacks disclaimer", tl.name)
			}
		}
	}
	if n := len(regulatoryReadTools()); n != 3 {
		t.Fatalf("want 3 tools, got %d", n)
	}
}
