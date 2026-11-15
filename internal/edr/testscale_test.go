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

// testStore is NewStore plus a cleanup that runs the lifecycle registry's StopAllForTest before
// t.TempDir is removed (cleanups are LIFO and TempDir registered first). Every Register* worker
// attached to the process-global registry stops and is waited for, so none can write into a
// deleted or half-deleted directory. Tests run sequentially, so global teardown is correct.
func testStore(t testing.TB, path string, max int) (*Store, error) {
	t.Helper()
	s, err := NewStore(path, max)
	if err == nil {
		t.Cleanup(func() { StopAllForTest() })
	}
	return s, err
}
