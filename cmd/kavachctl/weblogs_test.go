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

func TestWebLogsDispatchLocalErrors(t *testing.T) {
	var out bytes.Buffer
	if handled, _ := webLogsDispatch([]string{"status"}, &out); handled {
		t.Fatal("unrelated command must fall through")
	}
	for _, args := range [][]string{{"web"}, {"web", "bogus"}, {"web", "analyze"}, {"authlog", "sources"}, {"authlog", "analyze", "a", "b"}} {
		handled, err := webLogsDispatch(args, &out)
		if !handled || err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%v: handled=%v err=%v", args, handled, err)
		}
	}
	if _, err := webLogsDispatch([]string{"web", "analyze", filepath.Join(t.TempDir(), "missing.log")}, &out); err == nil {
		t.Error("missing file should error")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "a.log")
	if err := os.WriteFile(log, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(bad, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := webLogsDispatch([]string{"web", "analyze", log, "--openapi", bad}, &out)
	if err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("yaml spec should be refused locally, got %v", err)
	}
}
