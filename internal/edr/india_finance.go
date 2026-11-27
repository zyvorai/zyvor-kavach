// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// India-focused finance observation signals.
// Detects common UPI, IMPS, NEFT/RTGS and banking-app log patterns
// from operator-supplied events or findings. Observation-only.

func RegisterIndiaFinance(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/finance/india", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var signals []map[string]any
		for _, f := range store.List() {
			if isIndiaFinance(f) {
				signals = append(signals, map[string]any{
					"id":          f.ID,
					"time":        f.Time,
					"host":        f.Host,
					"rule":        f.Rule,
					"severity":    f.Severity,
					"description": f.Description,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"region":  "india",
			"signals": len(signals),
			"recent":  signals[:min(40, len(signals))],
			"note":    "observation-only; patterns from logs the operator supplies. Never freezes or moves money.",
			"time":    time.Now().UTC(),
		})
	})
}

func isIndiaFinance(f Finding) bool {
	s := strings.ToLower(f.Rule + " " + f.Description)
	return strings.Contains(s, "upi") || strings.Contains(s, "imps") ||
		strings.Contains(s, "neft") || strings.Contains(s, "rtgs") ||
		strings.Contains(s, "rbi") || strings.Contains(s, "irdai") ||
		strings.Contains(s, "gst") || strings.Contains(s, "ifsc") ||
		strings.Contains(s, "fin-in")
}
