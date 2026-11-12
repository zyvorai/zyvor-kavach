// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ThreatActor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Motivation  string   `json:"motivation"`
	Origins     []string `json:"origins"`
	TargetSectors []string `json:"target_sectors"`
	TTPs        []string `json:"ttps"`
	Description string   `json:"description"`
}

type IntelIndicator struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	ActorID   string    `json:"actor_id,omitempty"`
	Malware   string    `json:"malware,omitempty"`
	Confidence string   `json:"confidence"`
	Published time.Time `json:"published"`
}

type OverWatchAlert struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Severity    string    `json:"severity"`
	Host        string    `json:"host"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	ActorHint   string    `json:"actor_hint,omitempty"`
	TechniqueID string    `json:"technique_id"`
	Status      string    `json:"status"`
	Source      string    `json:"source"`
}

var (
	owMu     sync.Mutex
	owAlerts = defaultOverWatch()
	actors   = defaultActors()
	intelIOC = defaultIntelIndicators()
)

func defaultActors() []ThreatActor {
	return []ThreatActor{
		{ID: "actor-fancy", Name: "Fancy Demo Bear", Aliases: []string{"DEMO-APT-1"}, Motivation: "espionage", Origins: []string{"unknown"}, TargetSectors: []string{"technology", "government"}, TTPs: []string{"T1059", "T1003", "T1071"}, Description: "Seed adversary profile for demos"},
		{ID: "actor-ransom", Name: "Conti-like Demo", Aliases: []string{"DEMO-RANSOM"}, Motivation: "financial", Origins: []string{"unknown"}, TargetSectors: []string{"healthcare", "finance"}, TTPs: []string{"T1486", "T1490"}, Description: "Ransomware affiliate seed profile"},
	}
}

func defaultIntelIndicators() []IntelIndicator {
	now := time.Now().UTC()
	return []IntelIndicator{
		{ID: "xi-1", Type: "domain", Value: "evil-c2.example", ActorID: "actor-fancy", Confidence: "high", Published: now},
		{ID: "xi-2", Type: "ipv4", Value: "203.0.113.66", ActorID: "actor-fancy", Malware: "demo-beacon", Confidence: "medium", Published: now},
		{ID: "xi-3", Type: "sha256", Value: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ActorID: "actor-ransom", Malware: "demo-locker", Confidence: "high", Published: now},
	}
}

func defaultOverWatch() []OverWatchAlert {
	return []OverWatchAlert{}
}

func RegisterOverWatch(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/overwatch/alerts", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		owMu.Lock()
		out := append([]OverWatchAlert{}, owAlerts...)
		owMu.Unlock()
		// Derive hunting alerts from high/critical findings when ledger is quiet.
		if store != nil {
			for _, f := range store.List() {
				if f.Severity != "high" && f.Severity != "critical" {
					continue
				}
				out = append(out, OverWatchAlert{
					ID: "ow-der-" + shortID(f.ID), Time: f.Time, Severity: f.Severity, Host: f.Host,
					Title: "Derived hunt: " + f.Rule, Summary: f.Description,
					TechniqueID: MapDetection(f).TechniqueID, Status: "open", Source: "derived-findings",
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/overwatch/alerts", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var a OverWatchAlert
		if json.NewDecoder(r.Body).Decode(&a) != nil || a.Title == "" {
			http.Error(w, "invalid", 400)
			return
		}
		if a.ID == "" {
			a.ID = "ow-" + time.Now().UTC().Format("20060102150405")
		}
		a.Time = time.Now().UTC()
		a.Source = "overwatch"
		if a.Status == "" {
			a.Status = "open"
		}
		owMu.Lock()
		owAlerts = append(owAlerts, a)
		owMu.Unlock()
		AppendAudit(token, "overwatch.alert", a.Title)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	})
}

func RegisterIntel(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/intel/actors", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(actors)
	})
	mux.HandleFunc("GET /v1/intel/indicators", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := strings.ToLower(r.URL.Query().Get("q"))
		out := intelIOC
		if q != "" {
			filtered := out[:0]
			for _, i := range out {
				if strings.Contains(strings.ToLower(i.Value), q) || strings.Contains(strings.ToLower(i.Malware), q) {
					filtered = append(filtered, i)
				}
			}
			out = filtered
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}
