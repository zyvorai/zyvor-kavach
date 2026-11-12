package edr

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func secureEqual(a, b string) bool {
	return len(b) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type IncidentAction struct {
	FindingID string    `json:"finding_id"`
	Status    string    `json:"status"`
	Note      string    `json:"note,omitempty"`
	Actor     string    `json:"actor"`
	Time      time.Time `json:"time"`
}

// IncidentStore records analyst state changes; no actions kill processes or isolate machines.
type IncidentStore struct {
	store   *Store
	path    string
	entries map[string]IncidentAction
}

func NewIncidentStore(s *Store) (*IncidentStore, error) {
	x := &IncidentStore{store: s, path: s.path + ".incidents", entries: map[string]IncidentAction{}}
	b, err := os.ReadFile(x.path)
	if errors.Is(err, os.ErrNotExist) {
		return x, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var a IncidentAction
		if json.Unmarshal([]byte(line), &a) != nil {
			return nil, fmt.Errorf("corrupt incident ledger")
		}
		x.entries[a.FindingID] = a
	}
	return x, nil
}
func (x *IncidentStore) Register(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		if !secureEqual(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), token) && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		x.store.mu.Lock()
		defer x.store.mu.Unlock()
		out := make([]map[string]any, 0, len(x.store.findings))
		for _, f := range x.store.findings {
			state, ok := x.entries[f.ID]
			if !ok {
				state = IncidentAction{FindingID: f.ID, Status: "open"}
			}
			out = append(out, map[string]any{"finding": f, "workflow": state})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/incidents/transition", func(w http.ResponseWriter, r *http.Request) {
		admin := secureEqual(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), token)
		sessionOK := validSession(r, token)
		if !admin && !sessionOK {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var change IncidentAction
		if json.NewDecoder(r.Body).Decode(&change) != nil || len(change.FindingID) > 512 || len(change.Note) > 2048 || len(change.Actor) > 128 {
			http.Error(w, "invalid action", 400)
			return
		}
		if strings.TrimSpace(change.Actor) == "" {
			if sessionOK && !admin {
				change.Actor = "console"
			} else {
				http.Error(w, "invalid action", 400)
				return
			}
		}
		switch change.Status {
		case "open", "investigating", "resolved", "false_positive":
		default:
			http.Error(w, "invalid status", 400)
			return
		}
		x.store.mu.Lock()
		defer x.store.mu.Unlock()
		exists := false
		for _, f := range x.store.findings {
			if f.ID == change.FindingID {
				exists = true
				break
			}
		}
		if !exists {
			http.Error(w, "finding not found", 404)
			return
		}
		change.Time = time.Now().UTC()
		if err := appendRecord(x.path, change); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		x.entries[change.FindingID] = change
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(change)
	})
}
