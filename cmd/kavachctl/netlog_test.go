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

func TestNetLogDispatchLocalErrors(t *testing.T) {
	var out bytes.Buffer
	if handled, _ := netLogDispatch([]string{"status"}, &out); handled {
		t.Fatal("unrelated command must fall through")
	}
	for _, args := range [][]string{{"netlog"}, {"netlog", "bogus"}, {"netlog", "analyze"}, {"netlog", "analyze", "a", "b"}} {
		handled, err := netLogDispatch(args, &out)
		if !handled || err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%v: handled=%v err=%v", args, handled, err)
		}
	}
	dir := t.TempDir()
	if _, err := netLogDispatch([]string{"netlog", "analyze", filepath.Join(dir, "missing.log")}, &out); err == nil {
		t.Error("missing file should error")
	}
	big := filepath.Join(dir, "big.log")
	if err := os.WriteFile(big, make([]byte, netLogCtlMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := netLogDispatch([]string{"netlog", "analyze", big}, &out); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversize file should be refused locally, got %v", err)
	}
	small := filepath.Join(dir, "a.log")
	_ = os.WriteFile(small, []byte("x\n"), 0o600)
	if _, err := netLogDispatch([]string{"netlog", "analyze", small, "--bad-nets", filepath.Join(dir, "none.txt")}, &out); err == nil {
		t.Error("missing list file should error")
	}
}
