// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Asset struct {
	Hostname     string    `json:"hostname"`
	Platform     string    `json:"platform"`
	Sensor       string    `json:"sensor"`
	Online       bool      `json:"online"`
	Apps         int       `json:"apps"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	Unmanaged    bool      `json:"unmanaged"`
	Tags         []string  `json:"tags,omitempty"`
}

type AppInventory struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Path     string `json:"path,omitempty"`
	Category string `json:"category"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	Host        string    `json:"host"`
	Product     string    `json:"product"`
	Exploited   bool      `json:"exploited_in_wild"`
	ExPRTScore  float64   `json:"exprt_score"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
}

var (
	vulnMu sync.Mutex
	vulns  = defaultVulns()
)

func defaultVulns() []Vulnerability {
	return []Vulnerability{}
}

func RegisterDiscover(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/discover/assets", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		assets := map[string]*Asset{}
		for _, f := range store.List() {
			a := assets[f.Host]
			if a == nil {
				a = &Asset{Hostname: f.Host, Platform: "linux", Sensor: "kavach", Tags: []string{"managed"}}
				assets[f.Host] = a
			}
		}
		store.mu.Lock()
		for _, e := range store.recentEvents {
			a := assets[e.Host]
			if a == nil {
				a = &Asset{Hostname: e.Host, Platform: "linux", Sensor: "kavach", Tags: []string{"managed"}}
				assets[e.Host] = a
			}
		}
		store.mu.Unlock()
		if registry != nil {
			for _, st := range registry.Status(time.Now(), 90*time.Second) {
				a := assets[st.Host]
				if a == nil {
					a = &Asset{Hostname: st.Host, Platform: "linux", Sensor: st.Sensor, Tags: []string{"managed"}}
					assets[st.Host] = a
				}
				a.Online = st.State == "online"
				a.LastSeen = st.LastSeen
				a.Sensor = st.Sensor
			}
		}
		out := make([]Asset, 0, len(assets))
		for _, a := range assets {
			out = append(out, *a)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/discover/apps", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		seen := map[string]AppInventory{}
		store.mu.Lock()
		for _, e := range store.recentEvents {
			name := filepath.Base(e.Executable)
			if name == "" || name == "-" {
				continue
			}
			key := e.Host + ":" + name
			cat := "unknown"
			low := strings.ToLower(name)
			switch {
			case strings.Contains(low, "ssh"), strings.Contains(low, "curl"), strings.Contains(low, "wget"):
				cat = "network"
			case strings.Contains(low, "python"), strings.Contains(low, "node"), strings.Contains(low, "java"):
				cat = "runtime"
			case strings.Contains(low, "bash"), strings.Contains(low, "sh"), strings.Contains(low, "zsh"):
				cat = "shell"
			}
			seen[key] = AppInventory{Name: name, Host: e.Host, Path: e.Executable, Category: cat}
		}
		store.mu.Unlock()
		// Merge SBOM components as apps when process table is quiet.
		for _, row := range Live.List("sbom") {
			comp, _ := row["component"].(string)
			host, _ := row["host"].(string)
			if comp == "" {
				continue
			}
			key := host + ":" + comp
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = AppInventory{Name: comp, Host: host, Path: fmt.Sprint(row["version"]), Category: "package"}
		}
		out := make([]AppInventory, 0, len(seen))
		for _, a := range seen {
			out = append(out, a)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func RegisterSpotlight(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	mux.HandleFunc("GET /v1/spotlight/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		sev := strings.ToLower(r.URL.Query().Get("severity"))
		vulnMu.Lock()
		out := make([]Vulnerability, 0, len(vulns))
		for _, v := range vulns {
			if sev != "" && strings.ToLower(v.Severity) != sev {
				continue
			}
			out = append(out, v)
		}
		vulnMu.Unlock()
		_ = store
		_ = registry
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/spotlight/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var v Vulnerability
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.CVE == "" {
			http.Error(w, "invalid", 400)
			return
		}
		if v.ID == "" {
			v.ID = "vuln-" + time.Now().UTC().Format("20060102150405")
		}
		v.DetectedAt = time.Now().UTC()
		vulnMu.Lock()
		vulns = append(vulns, v)
		vulnMu.Unlock()
		AppendAudit(token, "spotlight.add", v.CVE)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
}
