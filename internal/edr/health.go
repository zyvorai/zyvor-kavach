// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"os"
)

// RegisterHealth adds unauthenticated /livez and /readyz probes.
func RegisterHealth(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ShuttingDown() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		if store != nil && store.path != "" {
			if _, err := os.Stat(store.path); err != nil && !os.IsNotExist(err) {
				http.Error(w, "store unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ready\n"))
	})
}
