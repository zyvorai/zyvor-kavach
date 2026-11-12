// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IOC struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // sha256|md5|domain|ipv4|ipv6
	Value       string    `json:"value"`
	Action      string    `json:"action"` // detect_only (always; prevent refused)
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
	Enabled     bool      `json:"enabled"`
}

type IOARule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	Severity    string    `json:"severity"`
	TechniqueID string    `json:"technique_id"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type PreventionPolicy struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Mode            string   `json:"mode"` // detect_only
	MLSensitivity   string   `json:"ml_sensitivity"`
	ScriptControl   bool     `json:"script_control"`
	RansomwareGuard bool     `json:"ransomware_guard"`
	MemoryScan      bool     `json:"memory_scan"`
	IOAGroups       []string `json:"ioa_groups"`
	AssignedGroups  []string `json:"assigned_groups"`
	Note            string   `json:"note"`
}

var (
	iocMu   sync.Mutex
	iocs    = defaultIOCs()
	ioaMu   sync.Mutex
	ioas    = defaultIOAs()
	policyMu sync.Mutex
	policies = defaultPolicies()
)

func defaultIOCs() []IOC {
	now := time.Now().UTC()
	return []IOC{
		{ID: "ioc-1", Type: "domain", Value: "evil-c2.example", Action: "detect_only", Severity: "high", Description: "Known C2 domain", Source: "intel", CreatedAt: now, Enabled: true},
		{ID: "ioc-2", Type: "ipv4", Value: "203.0.113.66", Action: "detect_only", Severity: "medium", Description: "Suspicious beacon IP", Source: "overwatch", CreatedAt: now, Enabled: true},
		{ID: "ioc-3", Type: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Action: "detect_only", Severity: "low", Description: "Empty-file hash placeholder", Source: "custom", CreatedAt: now, Enabled: true},
	}
}

func defaultIOAs() []IOARule {
	now := time.Now().UTC()
	return []IOARule{
		{ID: "ioa-1", Name: "Credential dump tools", Pattern: `(mimikatz|procdump|lsass|secretsdump)`, Severity: "critical", TechniqueID: "T1003", Description: "Credential dumping IOA", Enabled: true, CreatedAt: now},
		{ID: "ioa-2", Name: "Living-off-the-land shell", Pattern: `(bash\s+-i|/dev/tcp/|nc\s+-e|powershell\s+-enc)`, Severity: "high", TechniqueID: "T1059", Description: "Interactive reverse shell patterns", Enabled: true, CreatedAt: now},
		{ID: "ioa-3", Name: "Ransomware prep", Pattern: `(vssadmin\s+delete|wbadmin\s+delete|bcdedit\s+/set)`, Severity: "critical", TechniqueID: "T1490", Description: "Shadow copy / recovery disable", Enabled: true, CreatedAt: now},
	}
}

func defaultPolicies() []PreventionPolicy {
	return []PreventionPolicy{{
		ID: "pol-default", Name: "Kavach Default (Detect)", Mode: "detect_only",
		MLSensitivity: "aggressive", ScriptControl: true, RansomwareGuard: true, MemoryScan: true,
		IOAGroups: []string{"ioa-default"}, AssignedGroups: []string{"all-hosts"},
		Note: "Observation-only — Prevent/quarantine actions are never executed",
	}}
}

func MatchIOCs(haystack string) []IOC {
	iocMu.Lock()
	defer iocMu.Unlock()
	h := strings.ToLower(haystack)
	var out []IOC
	for _, i := range iocs {
		if i.Enabled && strings.Contains(h, strings.ToLower(i.Value)) {
			out = append(out, i)
		}
	}
	return out
}

func RegisterIOC(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ioc", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		iocMu.Lock()
		out := append([]IOC{}, iocs...)
		iocMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/ioc", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var i IOC
		if json.NewDecoder(r.Body).Decode(&i) != nil || i.Value == "" || i.Type == "" {
			http.Error(w, "invalid ioc", 400)
			return
		}
		switch i.Type {
		case "sha256", "md5", "sha1", "domain", "ipv4", "ipv6":
		default:
			http.Error(w, "invalid type", 400)
			return
		}
		i.Action = "detect_only" // never prevent
		if i.Severity == "" {
			i.Severity = "medium"
		}
		i.Enabled = true
		i.CreatedAt = time.Now().UTC()
		if i.ID == "" {
			i.ID = "ioc-" + time.Now().UTC().Format("20060102150405.000")
		}
		if i.Source == "" {
			i.Source = "custom"
		}
		iocMu.Lock()
		iocs = append(iocs, i)
		iocMu.Unlock()
		AppendAudit(token, "ioc.create", i.Type+":"+i.Value)
		// Optionally emit finding when value already appears in recent events
		_ = store
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i)
	})
	mux.HandleFunc("DELETE /v1/ioc", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		id := r.URL.Query().Get("id")
		iocMu.Lock()
		kept := iocs[:0]
		for _, i := range iocs {
			if i.ID != id {
				kept = append(kept, i)
			}
		}
		iocs = kept
		iocMu.Unlock()
		AppendAudit(token, "ioc.delete", id)
		w.WriteHeader(204)
	})
}

func RegisterIOA(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ioa", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ioaMu.Lock()
		out := append([]IOARule{}, ioas...)
		ioaMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/ioa", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var rule IOARule
		if json.NewDecoder(r.Body).Decode(&rule) != nil || rule.Name == "" || rule.Pattern == "" {
			http.Error(w, "invalid ioa", 400)
			return
		}
		rule.Enabled = true
		rule.CreatedAt = time.Now().UTC()
		if rule.ID == "" {
			rule.ID = "ioa-" + time.Now().UTC().Format("20060102150405.000")
		}
		if rule.Severity == "" {
			rule.Severity = "high"
		}
		ioaMu.Lock()
		ioas = append(ioas, rule)
		ioaMu.Unlock()
		AppendAudit(token, "ioa.create", rule.Name)
		_ = store
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rule)
	})
}

func RegisterPrevention(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/prevention/policies", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		policyMu.Lock()
		out := append([]PreventionPolicy{}, policies...)
		policyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/prevention/policies", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var p PreventionPolicy
		if json.NewDecoder(r.Body).Decode(&p) != nil || p.Name == "" {
			http.Error(w, "invalid policy", 400)
			return
		}
		p.Mode = "detect_only"
		p.Note = "Observation-only — Prevent/quarantine actions are never executed"
		if p.ID == "" {
			p.ID = "pol-" + time.Now().UTC().Format("20060102150405")
		}
		policyMu.Lock()
		policies = append(policies, p)
		policyMu.Unlock()
		AppendAudit(token, "prevention.create", p.Name)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})
}
