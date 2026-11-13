package edr

// scaleN returns full normally and reduced under the race detector. Only statistical
// or size-bound tests use it; every reduction is listed in docs/testing.md.
func scaleN(full, reduced int) int {
	if raceEnabled {
		return reduced
	}
	return full
}
