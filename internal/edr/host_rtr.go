// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HostGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	Description string   `json:"description"`
}

type ContainmentRequest struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Action    string    `json:"action"` // contain_request | lift_request
	Actor     string    `json:"actor"`
	Note      string    `json:"note"`
	Status    string    `json:"status"` // recorded (never enforced)
	Time      time.Time `json:"time"`
	Enforced  bool      `json:"enforced"`
}

type RTRSession struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Actor     string    `json:"actor"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Commands  []RTRCmd  `json:"commands,omitempty"`
}

type RTRCmd struct {
	ID       string    `json:"id"`
	Command  string    `json:"command"`
	Output   string    `json:"output"`
	Time     time.Time `json:"time"`
	ReadOnly bool      `json:"read_only"`
}

var (
	hostGroupMu sync.Mutex
	hostGroups  = []HostGroup{{ID: "hg-all", Name: "all-hosts", Hosts: []string{}, Description: "Default group"}}
	containMu   sync.Mutex
	containment []ContainmentRequest
	rtrMu       sync.Mutex
	rtrSessions = map[string]*RTRSession{}
)

var rtrAllowlist = map[string]string{
	"ps":           "List recent observed processes for host from controller store",
	"netstat":      "List recent network destinations for host from controller store",
	"findings":     "List findings for host",
	"sensor":       "Return sensor probe metadata",
	"help":         "List allowed diagnostic commands",
}

func RegisterHostMgmt(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hosts := map[string]map[string]any{}
		for _, f := range store.List() {
			h := hosts[f.Host]
			if h == nil {
				h = map[string]any{"hostname": f.Host, "findings": 0, "last_activity": f.Time, "contained": false}
				hosts[f.Host] = h
			}
			h["findings"] = h["findings"].(int) + 1
			if f.Time.After(h["last_activity"].(time.Time)) {
				h["last_activity"] = f.Time
			}
		}
		if registry != nil {
			for _, st := range registry.Status(time.Now(), 90*time.Second) {
				h := hosts[st.Host]
				if h == nil {
					h = map[string]any{"hostname": st.Host, "findings": 0}
					hosts[st.Host] = h
				}
				h["online"] = st.State == "online"
				h["state"] = st.State
				h["sensor"] = st.Sensor
				h["last_seen"] = st.LastSeen
			}
		}
		containMu.Lock()
		for _, c := range containment {
			if c.Action == "contain_request" {
				if h := hosts[c.Host]; h != nil {
					h["containment_requested"] = true
					h["contained"] = false // never enforced
				}
			}
		}
		containMu.Unlock()
		out := make([]map[string]any, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, h)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/host-groups", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hostGroupMu.Lock()
		out := append([]HostGroup{}, hostGroups...)
		hostGroupMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/host-groups", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var g HostGroup
		if json.NewDecoder(r.Body).Decode(&g) != nil || g.Name == "" {
			http.Error(w, "invalid group", 400)
			return
		}
		if g.ID == "" {
			g.ID = "hg-" + time.Now().UTC().Format("20060102150405")
		}
		hostGroupMu.Lock()
		hostGroups = append(hostGroups, g)
		hostGroupMu.Unlock()
		AppendAudit(token, "hostgroup.create", g.Name)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g)
	})
	mux.HandleFunc("GET /v1/containment", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		containMu.Lock()
		out := append([]ContainmentRequest{}, containment...)
		containMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/containment", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var req ContainmentRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Host == "" {
			http.Error(w, "invalid", 400)
			return
		}
		switch req.Action {
		case "contain_request", "lift_request":
		default:
			http.Error(w, "invalid action", 400)
			return
		}
		req.ID = "cnt-" + time.Now().UTC().Format("20060102150405.000")
		req.Time = time.Now().UTC()
		req.Status = "recorded"
		req.Enforced = false
		if req.Actor == "" {
			req.Actor = "console"
		}
		req.Note = strings.TrimSpace(req.Note + " | observation-only: network isolation is never applied by Kavach")
		containMu.Lock()
		containment = append(containment, req)
		containMu.Unlock()
		AppendAudit(token, "containment."+req.Action, req.Host)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})
}

func RegisterRTR(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/rtr/commands", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out := []map[string]string{}
		for k, v := range rtrAllowlist {
			out = append(out, map[string]string{"command": k, "description": v, "mode": "read_only"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/rtr/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rtrMu.Lock()
		out := make([]*RTRSession, 0, len(rtrSessions))
		for _, s := range rtrSessions {
			out = append(out, s)
		}
		rtrMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/rtr/sessions", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var body struct {
			Host  string `json:"host"`
			Actor string `json:"actor"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Host == "" {
			http.Error(w, "invalid", 400)
			return
		}
		if body.Actor == "" {
			body.Actor = "console"
		}
		s := &RTRSession{
			ID: "rtr-" + time.Now().UTC().Format("20060102150405.000"),
			Host: body.Host, Actor: body.Actor, Status: "open", CreatedAt: time.Now().UTC(),
		}
		rtrMu.Lock()
		rtrSessions[s.ID] = s
		rtrMu.Unlock()
		AppendAudit(token, "rtr.open", body.Host)
		_ = registry
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("POST /v1/rtr/execute", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var body struct {
			SessionID string `json:"session_id"`
			Command   string `json:"command"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.SessionID == "" || body.Command == "" {
			http.Error(w, "invalid", 400)
			return
		}
		cmd := strings.ToLower(strings.TrimSpace(body.Command))
		if _, ok := rtrAllowlist[cmd]; !ok {
			http.Error(w, "command not in read-only allowlist", 400)
			return
		}
		rtrMu.Lock()
		sess, ok := rtrSessions[body.SessionID]
		rtrMu.Unlock()
		if !ok {
			http.Error(w, "session not found", 404)
			return
		}
		out := runRTRDiag(cmd, sess.Host, store)
		entry := RTRCmd{ID: "cmd-" + time.Now().UTC().Format("150405.000"), Command: cmd, Output: out, Time: time.Now().UTC(), ReadOnly: true}
		rtrMu.Lock()
		sess.Commands = append(sess.Commands, entry)
		rtrMu.Unlock()
		AppendAudit(token, "rtr.execute", sess.Host+":"+cmd)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entry)
	})
}

func runRTRDiag(cmd, host string, store *Store) string {
	switch cmd {
	case "help":
		keys := make([]string, 0, len(rtrAllowlist))
		for k := range rtrAllowlist {
			keys = append(keys, k)
		}
		b, _ := json.Marshal(keys)
		return string(b)
	case "sensor":
		b, _ := json.Marshal(map[string]any{"backend": ProbeSensor(), "product": "kavach"})
		return string(b)
	case "findings":
		var list []Finding
		for _, f := range store.List() {
			if f.Host == host {
				list = append(list, f)
			}
		}
		b, _ := json.Marshal(list)
		return string(b)
	case "ps":
		store.mu.Lock()
		var list []Event
		for _, e := range store.recentEvents {
			if e.Host == host {
				list = append(list, e)
			}
		}
		store.mu.Unlock()
		b, _ := json.Marshal(list)
		return string(b)
	case "netstat":
		store.mu.Lock()
		var list []NetworkEvent
		for _, e := range store.networkEvents {
			if e.Host == host {
				list = append(list, e)
			}
		}
		store.mu.Unlock()
		b, _ := json.Marshal(list)
		return string(b)
	default:
		return "unsupported"
	}
}
