// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSLOFirstSampleDoesNotWriteAtStartup guards against a background sampler
// that writes its state file the instant it starts: that races with whatever
// is tearing down the store directory (a test's TempDir cleanup failed with
// "directory not empty").
func TestSLOFirstSampleDoesNotWriteAtStartup(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "findings.jsonl")
	e := newSLOEngine(base)
	t.Cleanup(func() { close(e.stop) })
	e.sample(time.Now(), []AgentStatus{{Host: "h1", State: "online", LastSeen: time.Now()}}, nil)
	if _, err := os.Stat(base + sloExt); err == nil {
		t.Fatal("the first sample must not persist; the state file should only appear after sloPersistEvery")
	}
	// A later sample past the persist interval does persist.
	e.sample(time.Now().Add(sloPersistEvery+sloStep), []AgentStatus{{Host: "h1", State: "online", LastSeen: time.Now()}}, nil)
	if _, err := os.Stat(base + sloExt); err != nil {
		t.Fatalf("a sample after the persist interval should write the state file: %v", err)
	}
}
