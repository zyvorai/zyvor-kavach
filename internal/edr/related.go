// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Related findings and simple posture snapshot.
// Helps an analyst see what else is nearby without any action being taken.

func RegisterRelated(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/related", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := r.URL.Query().Get("host")
		rule := r.URL.Query().Get("rule")
		var related []Finding
		for _, f := range store.List() {
			if host != "" && !strings.EqualFold(f.Host, host) {
				continue
			}
			if rule != "" && !strings.Contains(strings.ToLower(f.Rule), strings.ToLower(rule)) {
				continue
			}
			related = append(related, f)
			if len(related) >= 30 {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":    host,
			"rule":    rule,
			"count":   len(related),
			"related": related,
			"note":    "observation-only related findings",
			"time":    time.Now().UTC(),
		})
	})

	mux.HandleFunc("GET /v1/posture/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		high, medium, info := 0, 0, 0
		hosts := map[string]struct{}{}
		for _, f := range store.List() {
			hosts[f.Host] = struct{}{}
			switch strings.ToLower(f.Severity) {
			case "high", "critical":
				high++
			case "medium":
				medium++
			default:
				info++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hosts":  len(hosts),
			"high":   high,
			"medium": medium,
			"info":   info,
			"total":  high + medium + info,
			"note":   "simple snapshot from current findings; no live probes",
			"time":   time.Now().UTC(),
		})
	})
}
