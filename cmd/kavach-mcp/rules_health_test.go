package main

import (
	"strings"
	"testing"
)

func TestRuleHealthToolsRegisteredReadOnly(t *testing.T) {
	for _, allow := range []bool{false, true} {
		out := listTools(t, allow)
		for _, tl := range ruleHealthReadTools() {
			if !strings.Contains(out, `"name":"`+tl.name+`"`) {
				t.Fatalf("allow=%v: tool %s missing", allow, tl.name)
			}
			if tl.method != "GET" {
				t.Fatalf("%s must be read-only, got %s", tl.name, tl.method)
			}
		}
	}
	if n := len(ruleHealthReadTools()); n != 4 {
		t.Fatalf("want 4 tools, got %d", n)
	}
}
