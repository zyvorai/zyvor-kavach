// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSimilarityAnalyzerIsWindowed checks that a large input is digested on a
// bounded prefix, says so, and finishes well inside the analyzer budget.
func TestSimilarityAnalyzerIsWindowed(t *testing.T) {
	var sim *inspectAnalyzer
	inspectMu.RLock()
	for i := range inspectAnalyzers {
		if inspectAnalyzers[i].name == "similarity" {
			a := inspectAnalyzers[i]
			sim = &a
		}
	}
	inspectMu.RUnlock()
	if sim == nil {
		t.Fatal("similarity analyzer not registered")
	}
	withAnalyzers(t, *sim)
	big := make([]byte, InspectMaxBytes)
	for i := range big {
		big[i] = byte((i*131 + i>>7) & 0xff)
	}
	start := time.Now()
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Name: "big.bin", Data: big})
	if len(r.Errors) != 0 {
		t.Fatalf("large input must not error or time out: %v (took %v)", r.Errors, time.Since(start))
	}
	found := false
	for _, l := range r.LimitsHit {
		if strings.Contains(l, "digest-window") {
			found = true
		}
	}
	if !found {
		t.Fatalf("windowing must be reported in limits_hit, got %v", r.LimitsHit)
	}
	small := make([]byte, 1<<20)
	for i := range small {
		small[i] = byte(i * 7)
	}
	r = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Name: "small.bin", Data: small})
	for _, l := range r.LimitsHit {
		if strings.Contains(l, "digest-window") {
			t.Fatalf("a small input must not be windowed: %v", r.LimitsHit)
		}
	}
}
