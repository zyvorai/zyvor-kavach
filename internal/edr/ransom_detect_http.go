package edr

import (
	"net/http"
	"strconv"
	"strings"
)

// RegisterRansomDetect wires the metadata-only ransomware behaviour detector.
// Report-only; reads the stored FileEvents.
func RegisterRansomDetect(mux *http.ServeMux, token string, store *Store) {
	cfg := DefaultRansomDetectConfig()
	mux.HandleFunc("GET /v1/ransom/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, map[string]any{
			"method": "per-host sliding-window metadata indicators, CryptoDrop-style primary/secondary union rule",
			"window": cfg.Window.String(), "stride": cfg.Stride.String(),
			"thresholds": cfg,
			"alert_rule": "score >= alert_score AND (>=2 primary indicators OR 1 primary + >=2 secondary)",
			"primary":    []string{"extension_churn", "ransom_note_dirs", "backup_shadow_destruction", "mass_inplace_rewrite"},
			"secondary":  []string{"type_funnelling", "delete_heavy", "high_rate", "directory_breadth", "machine_pacing"},
			"cannot_see": []string{
				"file contents (so no entropy, no file-type change, no similarity hash)",
				"the writing process (PID is optional and not used for scoring)",
				"slow-and-low encryption spread over hours",
				"rename old-name (a rename event carries one path; assumed to be the new name)",
			},
			"recommended_agent_change": "add an optional per-event content entropy / magic-type field to FileEvent in the agent",
			"report_only":              true,
			"note":                     "thresholds are literature-guided heuristics tuned on synthetic traces, not fleet-fitted",
		})
	})
	mux.HandleFunc("GET /v1/ransom/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hosts := ComputeRansomHosts(store.ListFiles(), cfg)
		writeJSON(w, map[string]any{"hosts": hosts, "report_only": true})
	})
	mux.HandleFunc("GET /v1/ransom/host", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host is required", http.StatusBadRequest)
			return
		}
		var fl []FileEvent
		for _, f := range store.ListFiles() {
			if f.Host == host {
				fl = append(fl, f)
			}
		}
		if len(fl) == 0 {
			http.Error(w, "no file events for host", http.StatusNotFound)
			return
		}
		ws := ComputeRansomWindows(fl, cfg)
		limit := 500
		if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v < limit {
			limit = v
		}
		if len(ws) > limit {
			ws = ws[len(ws)-limit:]
		}
		writeJSON(w, map[string]any{"host": host, "windows": ws, "report_only": true})
	})
}
