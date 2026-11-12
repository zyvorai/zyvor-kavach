package main

import (
	"strings"
	"testing"
)

func TestMore2ToolsGating(t *testing.T) {
	ro := listTools(t, false)
	rw := listTools(t, true)
	if len(more2ReadTools()) != 23|| len(more2MutateTools()) != 7 {
		t.Fatalf("unexpected tool counts %d/%d", len(more2ReadTools()), len(more2MutateTools()))
	}
	for _, tl := range more2ReadTools() {
		if tl.method != "GET" || !strings.Contains(ro, `"name":"`+tl.name+`"`) {
			t.Fatalf("read tool %s bad or missing", tl.name)
		}
	}
	for _, tl := range more2MutateTools() {
		if strings.Contains(ro, `"name":"`+tl.name+`"`) {
			t.Fatalf("mutation %s leaked", tl.name)
		}
		if !strings.Contains(rw, `"name":"`+tl.name+`"`) {
			t.Fatalf("missing mutation %s", tl.name)
		}
	}
}
