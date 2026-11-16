// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestCompetitiveDocsMatchMatrix keeps the backlog status in
// docs/competitive-analysis.md in step with competitive_matrix.json.
func TestCompetitiveDocsMatchMatrix(t *testing.T) {
	m, err := LoadCompetitiveMatrix()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/competitive-analysis.md")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"open": "open", "partial": "partial", "implemented": "implemented", "not planned (boundary)": "not_planned"}
	docs := map[int]string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		cells := strings.Split(strings.Trim(strings.TrimSpace(ln), "|"), "|")
		if len(cells) < 10 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			continue
		}
		docs[id] = strings.ToLower(strings.TrimSpace(cells[len(cells)-1]))
	}
	for _, it := range m.Backlog {
		d, ok := docs[it.ID]
		if !ok {
			t.Errorf("item %d missing from docs table", it.ID)
			continue
		}
		if want[d] != it.Status {
			t.Errorf("item %d: docs status %q but matrix status %q", it.ID, d, it.Status)
		}
	}
	if len(docs) != len(m.Backlog) {
		t.Errorf("docs rows=%d matrix items=%d", len(docs), len(m.Backlog))
	}
}
