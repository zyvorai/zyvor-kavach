package edr

import "testing"

// scaleN returns full normally and reduced under the race detector. Only statistical
// or size-bound tests use it; every reduction is listed in docs/testing.md.
func scaleN(full, reduced int) int {
	if raceEnabled {
		return reduced
	}
	return full
}

// testStore is NewStore plus a cleanup that stops every background worker attached to the
// store (Register* goroutines) before t.TempDir is removed, so none can write into a
// deleted or half-deleted directory.
func testStore(t testing.TB, path string, max int) (*Store, error) {
	t.Helper()
	s, err := NewStore(path, max)
	if err == nil {
		t.Cleanup(s.Close)
	}
	return s, err
}
