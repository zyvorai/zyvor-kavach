// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import "testing"

func TestMLRarityProvider(t *testing.T) {
	e := newMLEngine(nil)
	if _, ok := e.rarity("h", "/usr/bin/curl", "/bin/bash"); ok {
		t.Fatal("an empty model must have no opinion")
	}
	for i := 0; i < mlMinLineageFleet+100; i++ {
		e.learnLineage("h1", "bash", "ls")
	}
	for i := 0; i < 20; i++ {
		e.learnLineage("h1", "bash", "curl")
	}
	common, ok1 := e.rarity("h1", "/usr/bin/ls", "/bin/bash")
	rare, ok2 := e.rarity("h1", "/usr/bin/nc", "/bin/bash")
	if !ok1 || !ok2 {
		t.Fatalf("a ready model with a seen parent must have an opinion: %v %v", ok1, ok2)
	}
	if !(rare > common) || rare < 0 || rare > 1 || common < 0 {
		t.Fatalf("rare child must score above a common one and stay in 0..1: common=%.2f rare=%.2f", common, rare)
	}
	if _, ok := e.rarity("h1", "/usr/bin/nc", "/opt/never-seen-parent"); ok {
		t.Fatal("a never-seen parent must yield no opinion (documented limit)")
	}
	if _, ok := e.rarity("h1", "", "/bin/bash"); ok {
		t.Fatal("missing executable must yield no opinion")
	}
}
