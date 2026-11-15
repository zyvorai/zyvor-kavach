// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGroupedCommandsPrintUsage: a grouped command with no (or an unclaimed) subcommand must print
// its usage and fail, never the misleading "unknown command".
func TestGroupedCommandsPrintUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer srv.Close()
	t.Setenv("KAVACH_URL", srv.URL)
	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	if len(groupUsage) < 7 {
		t.Fatal("groupUsage shrank")
	}
	for name, u := range groupUsage {
		if !strings.HasPrefix(u, "usage: kavachctl "+name) {
			t.Errorf("%s usage line = %q", name, u)
		}
		for _, args := range [][]string{{name}, {name, "no-such-sub"}} {
			err := run(args)
			if err == nil {
				t.Errorf("%v: want non-zero exit (error), got nil", args)
				continue
			}
			if strings.Contains(err.Error(), "unknown command") || !strings.Contains(err.Error(), "usage:") {
				t.Errorf("%v: got %q, want usage", args, err)
			}
		}
	}
}
