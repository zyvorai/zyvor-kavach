// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import "math"

// rarity adapts the fleet process-lineage model to the priority score's rarity
// factor (MLRarityProvider). It returns 0..1 where 1 means "very surprising
// child for this parent on this fleet": surprisal bits divided by twice the
// documented novelty threshold (7 bits -> 0.5, 14 bits or more -> 1).
//
// It has no opinion (ok=false) when the model is not ready, when the parent has
// never been seen (the lineage model is conditional on the parent, so it cannot
// tell a new parent from a rare one), or when exe/parent are empty.
func (e *mlEngine) rarity(host, exe, parent string) (float64, bool) {
	child, par := mlBase(exe), mlBase(parent)
	if child == "" || par == "" {
		return 0, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st == nil || e.st.Fleet == nil || e.st.Fleet.Total < mlMinLineageFleet {
		return 0, false
	}
	bits, _, parentSeen := mlSurprisal(e.st.Fleet, par, child, mlVocab(e.st.Fleet))
	if !parentSeen {
		return 0, false
	}
	return math.Max(0, math.Min(1, bits/(2*mlSurprisalBits))), true
}
