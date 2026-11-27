// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Netskope-inspired observation surfaces (detect & report only).
type NetskopeApp struct {
	App      string   `json:"app"`
	Count    int      `json:"count"`
	Users    []string `json:"users,omitempty"`
	Risk     string   `json:"risk,omitempty"`
	Category string   `json:"category,omitempty"`
}

func RegisterNetskope(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/netskope/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"product": "kavach-netskope-observation",
			"pillars": []string{"casb", "swg", "dlp", "ztna", "ai", "sspm"},
			"note":    "observation-only mappings of Netskope One; see /v1/netskope/{casb,swg,dlp,ztna,ai}",
			"time":    time.Now().UTC(),
		})
	})
	// other handlers follow the same pattern as the feature branch
}
