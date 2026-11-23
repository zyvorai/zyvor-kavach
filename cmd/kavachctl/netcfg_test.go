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

func TestNetcfgDispatchLocalErrors(t *testing.T) {
	var out bytes.Buffer
	if handled, _ := netcfgDispatch([]string{"status"}, &out); handled {
		t.Fatal("unrelated command must fall through")
	}
	for _, args := range [][]string{{"netcfg"}, {"netcfg", "bogus"}, {"netcfg", "analyze"}, {"netcfg", "analyze", "a", "b"}, {"netcfg", "diff", "a"}} {
		handled, err := netcfgDispatch(args, &out)
		if !handled || err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%v: handled=%v err=%v", args, handled, err)
		}
	}
	dir := t.TempDir()
	if _, err := netcfgDispatch([]string{"netcfg", "analyze", filepath.Join(dir, "missing.conf")}, &out); err == nil {
		t.Error("missing file should error")
	}
	big := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(big, make([]byte, netcfgCtlMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := netcfgDispatch([]string{"netcfg", "analyze", big}, &out); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversize file should be refused locally, got %v", err)
	}
	if _, err := netcfgDispatch([]string{"netcfg", "diff", big, big}, &out); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversize diff input should be refused locally, got %v", err)
	}
}
