package main

import (
	"strings"
	"testing"
)

func TestContentCustomToolsRegistered(t *testing.T) {
	for _, allow := range []bool{false, true} {
		out := listTools(t, allow)
		for _, tl := range contentCustomReadTools() {
			if !strings.Contains(out, `"name":"`+tl.name+`"`) {
				t.Fatalf("allow=%v: tool %s missing", allow, tl.name)
			}
		}
	}
	if n := len(contentCustomReadTools()); n != 2 {
		t.Fatalf("want 2 tools, got %d", n)
	}
}
