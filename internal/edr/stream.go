// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RegisterStream serves GET /v1/stream: Server-Sent Events of newly stored findings.
func RegisterStream(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/stream", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		seen := map[string]struct{}{}
		for _, f := range store.List() {
			seen[f.ID] = struct{}{}
		}
		fmt.Fprint(w, ": connected\n\n")
		fl.Flush()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		beat := 0
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				sent := false
				for _, f := range store.List() {
					if _, dup := seen[f.ID]; dup {
						continue
					}
					seen[f.ID] = struct{}{}
					b, _ := json.Marshal(MapDetection(f))
					fmt.Fprintf(w, "event: finding\ndata: %s\n\n", b)
					sent = true
				}
				if beat++; !sent && beat%15 == 0 {
					fmt.Fprint(w, ": keepalive\n\n")
					sent = true
				}
				if sent {
					fl.Flush()
				}
			}
		}
	})
}
