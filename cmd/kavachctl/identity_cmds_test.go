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

func TestIdentityCmdsDispatchLocalErrors(t *testing.T) {
	var out bytes.Buffer
	if handled, _ := identityCmdsDispatch([]string{"status"}, &out); handled {
		t.Fatal("unrelated command must fall through")
	}
	if handled, _ := identityCmdsDispatch(nil, &out); handled {
		t.Fatal("empty args must fall through")
	}
	for _, args := range [][]string{
		{"idplog"}, {"idplog", "bogus"}, {"idplog", "analyze"}, {"idplog", "analyze", "a", "b"},
		{"ransomlog", "analyze"}, {"ransomlog", "nope"},
		{"exploitintel", "import"}, {"exploitintel", "lookup"}, {"exploitintel", "withdraw"}, {"exploitintel", "withdraw", "other"}, {"exploitintel", "x"},
		{"tripwire", "add"}, {"tripwire", "add", "--kind", "account"}, {"tripwire", "delete"}, {"tripwire", "scan"}, {"tripwire", "zzz"},
	} {
		handled, err := identityCmdsDispatch(args, &out)
		if !handled || err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%v: handled=%v err=%v", args, handled, err)
		}
	}
	dir := t.TempDir()
	if _, err := identityCmdsDispatch([]string{"idplog", "analyze", filepath.Join(dir, "missing.jsonl")}, &out); err == nil {
		t.Error("missing file should error")
	}
	big := filepath.Join(dir, "big.jsonl")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), identityCmdsMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"idplog", "analyze", big}, {"ransomlog", "analyze", big}, {"tripwire", "scan", big}} {
		if _, err := identityCmdsDispatch(args, &out); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("%v: oversized file should be refused locally: %v", args, err)
		}
	}
}
