// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Zscaler observation summaries (detect & report only).
// Builds on existing Zscaler log parsers (NSS/LSS, policy, ZDX) and general network events.

func RegisterZscalerObservation(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/zscaler/zia", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var signals []map[string]any
		for _, f := range store.List() {
			if isZIA(f) {
				signals = append(signals, map[string]any{
					"id": f.ID, "time": f.Time, "host": f.Host,
					"rule": f.Rule, "severity": f.Severity, "description": f.Description,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"pillar":  "zia",
			"signals": len(signals),
			"recent":  signals[:min(30, len(signals))],
			"note":    "observation-only ZIA-style signals from ingested logs/findings. No live Zscaler calls.",
			"time":    time.Now().UTC(),
		})
	})

	mux.HandleFunc("GET /v1/zscaler/zpa", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var signals []map[string]any
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if isPrivate(n.Destination) || strings.Contains(strings.ToLower(n.Destination), "zpa") {
				signals = append(signals, map[string]any{
					"destination": n.Destination, "host": n.Host, "time": n.Time,
				})
			}
		}
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"pillar":  "zpa",
			"signals": len(signals),
			"samples": signals[:min(30, len(signals))],
			"note":    "observation of private or ZPA-related destinations. No access control.",
			"time":    time.Now().UTC(),
		})
	})

	mux.HandleFunc("GET /v1/zscaler/zdx", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var signals []map[string]any
		for _, f := range store.List() {
			if isZDX(f) {
				signals = append(signals, map[string]any{
					"id": f.ID, "time": f.Time, "host": f.Host,
					"rule": f.Rule, "severity": f.Severity, "description": f.Description,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"pillar":  "zdx",
			"signals": len(signals),
			"recent":  signals[:min(30, len(signals))],
			"note":    "observation-only experience signals. No probe execution or ZDX API calls.",
			"time":    time.Now().UTC(),
		})
	})

	mux.HandleFunc("GET /v1/zscaler/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"product": "kavach-zscaler-observation",
			"pillars": []string{"zia", "zpa", "zdx"},
			"note":    "high-level summaries on top of existing Zscaler log parsers. Observation-only.",
			"time":    time.Now().UTC(),
		})
	})
}

func isZIA(f Finding) bool {
	s := strings.ToLower(f.Rule + " " + f.Description)
	return strings.Contains(s, "zscaler") || strings.Contains(s, "zia") ||
		strings.Contains(s, "nss") || strings.Contains(s, "web-") ||
		strings.Contains(s, "url") || strings.Contains(s, "saas")
}

func isZDX(f Finding) bool {
	s := strings.ToLower(f.Rule + " " + f.Description)
	return strings.Contains(s, "zdx") || strings.Contains(s, "latency") ||
		strings.Contains(s, "experience") || strings.Contains(s, "probe")
}
