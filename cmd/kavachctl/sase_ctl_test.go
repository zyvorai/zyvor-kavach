// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"testing"
)

func TestSaseDispatchUsageAndFallthrough(t *testing.T) {
	var out bytes.Buffer
	if h, _ := saseDispatch([]string{"zscaler", "logs"}, &out); h {
		t.Fatal("other commands must fall through")
	}
	for _, a := range [][]string{{"cloudflare"}, {"umbrella", "policy", "x"}, {"cloudflare", "logs"}, {"umbrella", "bogus", "f"}} {
		h, err := saseDispatch(a, &out)
		if !h || err == nil {
			t.Fatalf("%v: want handled usage error, got handled=%v err=%v", a, h, err)
		}
	}
	if h, err := saseDispatch([]string{"cloudflare", "logs", "/nonexistent/x.json"}, &out); !h || err == nil {
		t.Fatalf("missing file must error: %v %v", h, err)
	}
}
