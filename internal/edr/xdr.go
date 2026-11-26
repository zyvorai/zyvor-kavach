// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"time"
)

// Deeper Netra XDR correlation.
// GET /v1/xdr/storyline?host=... returns a simple merged timeline of
// Kavach findings + recent network events for a host.
// Observation-only; uses data already ingested.

func RegisterXDR(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/xdr/storyline", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := r.URL.Query().Get("host")
		type item struct {
			Time   time.Time `json:"time"`
			Kind   string    `json:"kind"`
			Detail string    `json:"detail"`
		}
		var timeline []item
		for _, f := range store.List() {
			if host != "" && f.Host != host {
				continue
			}
			timeline = append(timeline, item{Time: f.Time, Kind: "finding", Detail: f.Rule + ": " + f.Description})
		}
		// Network events are already in store if ingested
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if host != "" && n.Host != host {
				continue
			}
			timeline = append(timeline, item{Time: n.Time, Kind: "network", Detail: n.Destination})
		}
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":     host,
			"count":    len(timeline),
			"timeline": timeline,
			"note":     "merged Kavach findings + network events; expand with Netra poller data",
		})
	})
}
