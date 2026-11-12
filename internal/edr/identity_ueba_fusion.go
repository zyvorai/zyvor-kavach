// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IdentityEvent struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Host      string    `json:"host"`
	Action    string    `json:"action"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Severity  string    `json:"severity"`
	Rule      string    `json:"rule"`
	Detail    string    `json:"detail"`
}

type IdentityEntity struct {
	User       string  `json:"user"`
	RiskScore  int     `json:"risk_score"`
	Privileged bool    `json:"privileged"`
	LastSeen   time.Time `json:"last_seen"`
	Signals    []string `json:"signals"`
}

type UEBAScore struct {
	EntityType string    `json:"entity_type"` // user|host|process
	Entity     string    `json:"entity"`
	Score      int       `json:"score"`
	Level      string    `json:"level"`
	Factors    []string  `json:"factors"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Trigger     string   `json:"trigger"`
	Actions     []string `json:"actions"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description"`
}

type PlaybookRun struct {
	ID         string    `json:"id"`
	PlaybookID string    `json:"playbook_id"`
	TriggerRef string    `json:"trigger_ref"`
	Status     string    `json:"status"`
	Actions    []string  `json:"actions_recorded"`
	Time       time.Time `json:"time"`
	Note       string    `json:"note"`
}

var (
	idMu     sync.Mutex
	idEvents = defaultIdentityEvents()
	fusionMu sync.Mutex
	playbooks = defaultPlaybooks()
	playRuns  []PlaybookRun
)

func defaultIdentityEvents() []IdentityEvent {
	return []IdentityEvent{}
}

func defaultPlaybooks() []Playbook {
	return []Playbook{
		{ID: "pb-1", Name: "High severity notify", Trigger: "detection.severity=high", Actions: []string{"notify_siem", "create_case", "assign_analyst"}, Enabled: true, Description: "Ledger-only Fusion workflow"},
		{ID: "pb-2", Name: "Ransomware burst", Trigger: "rule=ransomware-burst", Actions: []string{"create_case", "containment_request", "overwatch_escalate"}, Enabled: true, Description: "Records containment request; does not isolate"},
		{ID: "pb-3", Name: "Identity spray", Trigger: "rule=identity-password-spray", Actions: []string{"notify_siem", "identity_review"}, Enabled: true, Description: "Identity review workflow"},
	}
}

func RegisterIdentity(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/identity/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		idMu.Lock()
		out := append([]IdentityEvent{}, idEvents...)
		idMu.Unlock()
		if len(out) == 0 && store != nil {
			for _, f := range store.List() {
				if f.Evidence.UID == 0 || strings.Contains(strings.ToLower(f.Rule), "ssh") || strings.Contains(strings.ToLower(f.Rule), "credential") {
					out = append(out, IdentityEvent{
						ID: "id-der-" + shortID(f.ID), Time: f.Time, User: fmt.Sprintf("uid:%d", f.Evidence.UID),
						Host: f.Host, Action: "process_as_identity", Severity: f.Severity,
						Rule: "identity-from-finding", Detail: f.Description,
					})
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/identity/events", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var e IdentityEvent
		if json.NewDecoder(r.Body).Decode(&e) != nil || e.User == "" {
			http.Error(w, "invalid", 400)
			return
		}
		if e.ID == "" {
			e.ID = "id-" + time.Now().UTC().Format("20060102150405.000")
		}
		e.Time = time.Now().UTC()
		idMu.Lock()
		idEvents = append(idEvents, e)
		idMu.Unlock()
		AppendAudit(token, "identity.event", e.User+":"+e.Action)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("GET /v1/identity/entities", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		byUser := map[string]*IdentityEntity{}
		idMu.Lock()
		for _, e := range idEvents {
			ent := byUser[e.User]
			if ent == nil {
				ent = &IdentityEntity{User: e.User, Signals: []string{}}
				byUser[e.User] = ent
			}
			ent.LastSeen = e.Time
			ent.Signals = append(ent.Signals, e.Rule)
			ent.RiskScore += 15
			if e.Severity == "high" || e.Severity == "critical" {
				ent.RiskScore += 20
			}
			if strings.Contains(strings.ToLower(e.User), "admin") || strings.HasPrefix(e.User, "svc-") {
				ent.Privileged = true
				ent.RiskScore += 10
			}
			if ent.RiskScore > 100 {
				ent.RiskScore = 100
			}
		}
		idMu.Unlock()
		out := make([]IdentityEntity, 0, len(byUser))
		for _, e := range byUser {
			out = append(out, *e)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func RegisterUEBA(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ueba", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		now := time.Now().UTC()
		out := []UEBAScore{}
		hostCount := map[string]int{}
		for _, f := range store.List() {
			hostCount[f.Host]++
			rs := ScoreFinding(f)
			out = append(out, UEBAScore{EntityType: "detection", Entity: f.ID, Score: rs.Score, Level: rs.Level, Factors: rs.Factors, UpdatedAt: now})
		}
		for host, n := range hostCount {
			score := n * 10
			if score > 100 {
				score = 100
			}
			level := "low"
			if score >= 70 {
				level = "critical"
			} else if score >= 40 {
				level = "high"
			} else if score >= 20 {
				level = "medium"
			}
			out = append(out, UEBAScore{EntityType: "host", Entity: host, Score: score, Level: level, Factors: []string{"finding_volume"}, UpdatedAt: now})
		}
		idMu.Lock()
		for _, e := range idEvents {
			out = append(out, UEBAScore{EntityType: "user", Entity: e.User, Score: 55, Level: "medium", Factors: []string{e.Rule}, UpdatedAt: now})
		}
		idMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func RegisterFusion(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/fusion/playbooks", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fusionMu.Lock()
		out := append([]Playbook{}, playbooks...)
		fusionMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/fusion/playbooks", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var p Playbook
		if json.NewDecoder(r.Body).Decode(&p) != nil || p.Name == "" {
			http.Error(w, "invalid", 400)
			return
		}
		if p.ID == "" {
			p.ID = "pb-" + time.Now().UTC().Format("20060102150405")
		}
		p.Enabled = true
		fusionMu.Lock()
		playbooks = append(playbooks, p)
		fusionMu.Unlock()
		AppendAudit(token, "fusion.playbook", p.Name)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("GET /v1/fusion/runs", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fusionMu.Lock()
		out := append([]PlaybookRun{}, playRuns...)
		fusionMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/fusion/runs", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			PlaybookID string `json:"playbook_id"`
			TriggerRef string `json:"trigger_ref"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.PlaybookID == "" {
			http.Error(w, "invalid", 400)
			return
		}
		fusionMu.Lock()
		var pb *Playbook
		for i := range playbooks {
			if playbooks[i].ID == body.PlaybookID {
				pb = &playbooks[i]
				break
			}
		}
		if pb == nil {
			fusionMu.Unlock()
			http.Error(w, "playbook not found", 404)
			return
		}
		run := PlaybookRun{
			ID: "run-" + time.Now().UTC().Format("20060102150405.000"),
			PlaybookID: body.PlaybookID, TriggerRef: body.TriggerRef,
			Status: "recorded", Actions: append([]string{}, pb.Actions...),
			Time: time.Now().UTC(),
			Note: "Observation-only: actions are ledgered, never enforced on hosts",
		}
		playRuns = append(playRuns, run)
		fusionMu.Unlock()
		AppendAudit(token, "fusion.run", body.PlaybookID)
		_ = store
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(run)
	})
}
