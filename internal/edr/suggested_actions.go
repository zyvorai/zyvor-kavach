// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Suggested actions / recommended containment ledger.
// Findings (or analysts) can record a structured recommendation.
// Nothing is executed. An operator or external system must act on the request.

type SuggestedAction struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	FindingID   string    `json:"finding_id,omitempty"`
	Host        string    `json:"host"`
	Action      string    `json:"action"`
	Target      string    `json:"target,omitempty"`
	Reason      string    `json:"reason"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	RequestedBy string    `json:"requested_by,omitempty"`
}

type ActionLedger struct {
	path    string
	mu      sync.Mutex
	actions []SuggestedAction
	max     int
}

func NewActionLedger(path string, max int) *ActionLedger {
	if max < 1 {
		max = 500
	}
	al := &ActionLedger{path: path, max: max}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var list []SuggestedAction
			if json.Unmarshal(b, &list) == nil {
				al.actions = list
			}
		}
	}
	return al
}

func (al *ActionLedger) save() error {
	if al.path == "" {
		return nil
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	b, err := json.MarshalIndent(al.actions, "", "  ")
	if err != nil {
		return err
	}
	tmp := al.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, al.path)
}

func (al *ActionLedger) Add(a SuggestedAction) error {
	if a.ID == "" {
		a.ID = a.Host + ":" + a.Action + ":" + time.Now().UTC().Format(time.RFC3339Nano)
	}
	if a.Time.IsZero() {
		a.Time = time.Now().UTC()
	}
	if a.Status == "" {
		a.Status = "pending"
	}
	al.mu.Lock()
	al.actions = append(al.actions, a)
	if len(al.actions) > al.max {
		al.actions = al.actions[len(al.actions)-al.max:]
	}
	al.mu.Unlock()
	return al.save()
}

func (al *ActionLedger) List(status string) []SuggestedAction {
	al.mu.Lock()
	defer al.mu.Unlock()
	if status == "" {
		out := make([]SuggestedAction, len(al.actions))
		copy(out, al.actions)
		return out
	}
	var out []SuggestedAction
	for _, a := range al.actions {
		if strings.EqualFold(a.Status, status) {
			out = append(out, a)
		}
	}
	return out
}

var globalActions *ActionLedger

func RegisterSuggestedActions(mux *http.ServeMux, token string, store *Store) {
	path := ""
	if store != nil {
		path = store.path + ".actions.json"
	}
	if v := os.Getenv("KAVACH_ACTIONS_FILE"); v != "" {
		path = v
	}
	globalActions = NewActionLedger(path, 500)

	mux.HandleFunc("GET /v1/actions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		status := r.URL.Query().Get("status")
		list := globalActions.List(status)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"actions": len(list),
			"items":   list,
			"note":    "suggested actions only; nothing is executed by Kavach",
		})
	})

	mux.HandleFunc("POST /v1/actions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var a SuggestedAction
		if json.NewDecoder(r.Body).Decode(&a) != nil || a.Host == "" || a.Action == "" {
			http.Error(w, "bad request", 400)
			return
		}
		if err := globalActions.Add(a); err != nil {
			http.Error(w, "store error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "recorded", "id": a.ID})
	})

	mux.HandleFunc("POST /v1/actions/suggest", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		count := 0
		for _, f := range store.List() {
			if f.Severity != "high" && f.Severity != "critical" {
				continue
			}
			act := suggestAction(f)
			if act.Action == "" {
				continue
			}
			act.FindingID = f.ID
			act.Host = f.Host
			act.Severity = f.Severity
			act.Reason = f.Description
			_ = globalActions.Add(act)
			count++
			if count >= 50 {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"suggested": count,
			"note":      "recorded only; review with GET /v1/actions?status=pending",
		})
	})
}

func suggestAction(f Finding) SuggestedAction {
	s := strings.ToLower(f.Rule + " " + f.Description)
	switch {
	case strings.Contains(s, "reverse-shell") || strings.Contains(s, "download-execute") || strings.Contains(s, "lolbin"):
		return SuggestedAction{Action: "isolate-host", Target: f.Host, Reason: "high-severity execution pattern"}
	case strings.Contains(s, "persistence"):
		return SuggestedAction{Action: "review-persistence", Target: f.Host}
	case strings.Contains(s, "onion") || strings.Contains(s, "tor"):
		return SuggestedAction{Action: "block-destination", Target: f.Destination}
	default:
		if f.Severity == "critical" {
			return SuggestedAction{Action: "investigate", Target: f.Host}
		}
		return SuggestedAction{}
	}
}
