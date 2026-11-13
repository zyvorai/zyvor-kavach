// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"sort"
	"time"
)

// Per-category telemetry inventory: which event categories actually arrive on this deployment.
// Counts come from the bounded in-memory buffers (not an all-time total), so a busy category may
// show its buffer size. Observation only.

const blindspotDefaultStaleDays = 7

// catObs is what the store holds for one event category.
type catObs struct {
	Count int
	Last  time.Time // zero when never seen
}

// CategoryState values.
const (
	catActive = "active"     // events seen within the stale window
	catStale  = "stale"      // seen, but not recently
	catNever  = "never_seen" // zero events held
)

// TelemetryCategory is one row of the inventory.
type TelemetryCategory struct {
	Category string  `json:"category"`
	Count    int     `json:"events_held"`
	LastSeen *string `json:"last_seen,omitempty"`
	AgeHours *int    `json:"age_hours,omitempty"`
	State    string  `json:"state"`
}

// telemetryCategories lists the categories the content engine can evaluate, sorted.
func telemetryCategories() []string {
	out := make([]string, 0, len(contentAllTypes))
	for k := range contentAllTypes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func categoryState(o catObs, now time.Time, stale time.Duration) string {
	if o.Count == 0 && o.Last.IsZero() {
		return catNever
	}
	if o.Last.IsZero() || now.Sub(o.Last) > stale {
		return catStale
	}
	return catActive
}

// collectCategoryObs reads counts and last-seen per category from the store and telemetry buffers.
// Safe with a nil or empty store.
func collectCategoryObs(s *Store) map[string]catObs {
	m := map[string]catObs{}
	for _, c := range telemetryCategories() {
		m[c] = catObs{}
	}
	upd := func(c string, t time.Time) {
		o := m[c]
		o.Count++
		if t.After(o.Last) {
			o.Last = t
		}
		m[c] = o
	}
	if s != nil {
		s.mu.Lock()
		for _, e := range s.recentEvents {
			upd("process", e.Time)
		}
		for _, e := range s.networkEvents {
			upd("network", e.Time)
		}
		for _, e := range s.fileEvents {
			upd("file", e.Time)
		}
		s.mu.Unlock()
	}
	defaultTelemetryMu.RLock()
	ts := DefaultTelemetry
	defaultTelemetryMu.RUnlock()
	if ts != nil {
		ts.mu.Lock()
		for typ, ring := range ts.ring {
			for _, e := range ring {
				upd(typ, e.Time)
			}
		}
		ts.mu.Unlock()
	}
	return m
}

func buildTelemetryInventory(obs map[string]catObs, now time.Time, stale time.Duration) []TelemetryCategory {
	cats := make([]string, 0, len(obs))
	for c := range obs {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	out := make([]TelemetryCategory, 0, len(cats))
	for _, c := range cats {
		o := obs[c]
		row := TelemetryCategory{Category: c, Count: o.Count, State: categoryState(o, now, stale)}
		if !o.Last.IsZero() {
			ls := o.Last.UTC().Format(time.RFC3339)
			age := int(now.Sub(o.Last).Hours())
			row.LastSeen, row.AgeHours = &ls, &age
		}
		out = append(out, row)
	}
	return out
}
