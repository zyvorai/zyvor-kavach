//go:build !race

package edr

// raceEnabled is false without the race detector; full iteration counts run.
const raceEnabled = false
