// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Ransomware heuristics are observation-only investigative signals.
// They do not prove encryption and never terminate processes.

var ransomwareExt = map[string]struct{}{
	".encrypted": {}, ".locked": {}, ".crypt": {}, ".cry": {}, ".locky": {},
	".zepto": {}, ".onion": {}, ".aaa": {}, ".abc": {}, ".xyz": {},
	".conti": {}, ".rk": {}, ".wncry": {},
}

type ransomWindow struct {
	mu     sync.Mutex
	events []FileEvent
}

var hostRansom = struct {
	mu   sync.Mutex
	byHost map[string]*ransomWindow
}{byHost: map[string]*ransomWindow{}}

func windowFor(host string) *ransomWindow {
	hostRansom.mu.Lock()
	defer hostRansom.mu.Unlock()
	w, ok := hostRansom.byHost[host]
	if !ok {
		w = &ransomWindow{}
		hostRansom.byHost[host] = w
	}
	return w
}

func RansomwareFindings(host string, events []FileEvent, now time.Time) []Finding {
	if len(events) == 0 {
		return nil
	}
	w := windowFor(host)
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-30 * time.Second)
	kept := events[:0]
	for _, e := range append(w.events, events...) {
		if e.Time.After(cutoff) {
			kept = append(kept, e)
		}
	}
	w.events = kept

	var out []Finding
	extBurst := 0
	renames := 0
	deletes := 0
	creates := 0
	for _, e := range kept {
		ext := strings.ToLower(filepath.Ext(e.Path))
		if _, ok := ransomwareExt[ext]; ok {
			extBurst++
		}
		switch e.Operation {
		case "create":
			creates++
		case "delete":
			deletes++
		case "modify":
			renames++ // metadata poller cannot see rename; treat churn as signal
		}
	}
	add := func(rule, sev, desc string) {
		out = append(out, Finding{
			ID:          host + ":" + rule + ":" + now.UTC().Format(time.RFC3339Nano),
			Time:        now.UTC(),
			Host:        host,
			Rule:        rule,
			Severity:    sev,
			Description: desc,
		})
	}
	if extBurst >= 5 {
		add("ransomware-extension-burst", "high", "Multiple files with known ransomware-style extensions appeared within 30s (investigate; not proof of encryption)")
	}
	if creates >= 20 && deletes >= 10 {
		add("ransomware-burst", "high", "High create+delete churn resembles ransomware staging (observation-only)")
	}
	if renames >= 40 {
		add("ransomware-churn", "medium", "Elevated file modify churn on canary path")
	}
	return out
}
