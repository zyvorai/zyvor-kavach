// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZscalerDispatchUsageAndLimits(t *testing.T) {
	var out bytes.Buffer
	if h, _ := zscalerDispatch([]string{"other"}, &out); h {
		t.Fatal("handled a foreign command")
	}
	for _, args := range [][]string{{"zscaler"}, {"zscaler", "bogus"}, {"zscaler", "logs"}, {"zscaler", "policy", "a", "b"}, {"zscaler", "zdx"}} {
		if h, err := zscalerDispatch(args, &out); !h || err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: handled=%v err=%v", args, h, err)
		}
	}
	dir := t.TempDir()
	if _, err := zscalerDispatch([]string{"zscaler", "logs", filepath.Join(dir, "missing.json")}, &out); err == nil {
		t.Error("missing file accepted")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, zscalerCtlMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"logs", "policy", "zdx"} {
		if _, err := zscalerDispatch([]string{"zscaler", sub, big}, &out); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("%s: oversized file: %v", sub, err)
		}
	}
	small := filepath.Join(dir, "s.json")
	_ = os.WriteFile(small, []byte("{}"), 0o600)
	if _, err := zscalerDispatch([]string{"zscaler", "logs", small, "--work-start", "x", "--sanctioned", small}, &out); err == nil {
		t.Error("bad hour accepted")
	}
}
