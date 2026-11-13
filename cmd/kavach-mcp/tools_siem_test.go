// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"strings"
	"testing"
)

func TestSIEMToolsReadOnlyAndRegistered(t *testing.T) {
	ro := listTools(t, false)
	if len(siemReadTools()) != 3 {
		t.Fatal("expected 3 tools")
	}
	for _, tl := range siemReadTools() {
		if tl.method != "GET" || !strings.Contains(ro, `"name":"`+tl.name+`"`) {
			t.Fatalf("tool %s bad or missing", tl.name)
		}
	}
}
