// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestHelpAndCompletionListCatalogCommands checks that the top-level word of
// every command registered in the catalog appears in both the --help text and
// the completion word list.
func TestHelpAndCompletionListCatalogCommands(t *testing.T) {
	t.Setenv("KAVACH_SKIP_DOTENV", "1")
	var help bytes.Buffer
	printHelp(&help)
	helpText := help.String()
	comp := map[string]bool{}
	for _, c := range topLevelCommands() {
		comp[c] = true
	}
	seen := map[string]bool{}
	for _, c := range allCLICommands() {
		top := c.Args[0]
		if strings.HasPrefix(top, "-") || seen[top] {
			continue
		}
		seen[top] = true
		if !comp[top] {
			t.Errorf("completion word list is missing %q (catalog command %s)", top, c.Name)
		}
		if !strings.Contains(helpText, top) {
			t.Errorf("--help does not mention %q (catalog command %s)", top, c.Name)
		}
	}
}
