// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"strings"
	"testing"
)

func TestMLToolsAreReadOnlyGETExceptSynthesize(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	for _, tl := range mlTools() {
		if ro[tl.name] == nil {
			t.Fatalf("%s missing in read-only mode", tl.name)
		}
		if tl.method != "GET" && tl.name != "ml_synthesize" {
			t.Fatalf("%s must be GET, is %s", tl.name, tl.method)
		}
		d := ro[tl.name]["description"].(string)
		if !strings.Contains(d, "not_enough_data") || !strings.Contains(d, "statistical") {
			t.Fatalf("%s description lacks honesty note: %s", tl.name, d)
		}
		if strings.Contains(tl.path, "reset") || strings.Contains(tl.path, "replay") {
			t.Fatalf("%s exposes mutating endpoint", tl.name)
		}
	}
}
