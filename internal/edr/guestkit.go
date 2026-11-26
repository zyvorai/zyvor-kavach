// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"time"
)

// GuestKit offline VM inspection integration.
// POST /v1/guestkit/report accepts a structured summary from GuestKit
// (or any offline disk inspector) and turns it into findings + exposure signals.
// Fully offline, observation-only. Nothing is executed or fetched.

type GuestKitReport struct {
	Host     string   `json:"host"`
	OS       string   `json:"os,omitempty"`
	Packages []string `json:"packages,omitempty"`
	Users    []string `json:"users,omitempty"`
	SSHKeys  []string `json:"ssh_keys,omitempty"`
	Services []string `json:"services,omitempty"`
	Findings []struct {
		Rule        string `json:"rule"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"findings,omitempty"`
}

func RegisterGuestKit(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/guestkit/report", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
		var rep GuestKitReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil || rep.Host == "" {
			http.Error(w, "bad report", 400)
			return
		}
		count := 0
		now := time.Now().UTC()
		for _, f := range rep.Findings {
			sev := f.Severity
			if sev == "" {
				sev = "medium"
			}
			finding := Finding{
				ID:          rep.Host + ":guestkit:" + f.Rule + ":" + now.Format(time.RFC3339Nano),
				Time:        now,
				Host:        rep.Host,
				Rule:        "guestkit-" + f.Rule,
				Severity:    sev,
				Description: f.Description,
				Tags:        []string{"guestkit", "offline-vm"},
			}
			_ = store.Append(finding)
			count++
		}
		// Simple exposure signal from package count
		if len(rep.Packages) > 0 {
			_ = store.Append(Finding{
				ID:          rep.Host + ":guestkit:exposure:" + now.Format(time.RFC3339Nano),
				Time:        now,
				Host:        rep.Host,
				Rule:        "guestkit-package-count",
				Severity:    "info",
				Description: "Offline VM inspection reported packages",
				Tags:        []string{"guestkit", "exposure"},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":     rep.Host,
			"findings": count,
			"status":   "ingested",
		})
	})
}
