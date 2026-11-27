// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Netskope-inspired observation surfaces (detect & report only).
// Covers the main Netskope One pillars without any blocking, proxying or policy enforcement.

type NetskopeApp struct {
	App      string   `json:"app"`
	Count    int      `json:"count"`
	Users    []string `json:"users,omitempty"`
	Risk     string   `json:"risk,omitempty"`
	Category string   `json:"category,omitempty"`
}

func RegisterNetskope(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/netskope/casb", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		apps := map[string]*NetskopeApp{}
		store.mu.Lock()
		for _, n := range store.networkEvents {
			app := classifyApp(n.Destination)
			if app == "" {
				continue
			}
			a, ok := apps[app]
			if !ok {
				a = &NetskopeApp{App: app, Category: appCategory(app)}
				apps[app] = a
			}
			a.Count++
			a.Risk = appRisk(app, a.Count)
		}
		store.mu.Unlock()
		list := toList(apps)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"apps": len(list),
			"top":  list[:min(40, len(list))],
			"note": "observation-only CASB-style view from ingested destinations; no inline control",
		})
	})

	mux.HandleFunc("GET /v1/netskope/swg", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var risky []map[string]any
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if isWebRisky(n.Destination) {
				risky = append(risky, map[string]any{
					"destination": n.Destination,
					"host":        n.Host,
					"time":        n.Time,
					"risk":        "medium",
				})
			}
		}
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"risky_web": len(risky),
			"samples":   risky[:min(30, len(risky))],
			"note":      "heuristic web-risk signals only; no proxy or blocking",
		})
	})

	mux.HandleFunc("GET /v1/netskope/dlp", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var signals []Finding
		for _, f := range store.List() {
			if strings.Contains(strings.ToLower(f.Rule), "dlp") ||
				strings.Contains(strings.ToLower(f.Description), "sensitive") ||
				containsTag(f.Tags, "dlp") {
				signals = append(signals, f)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"signals": len(signals),
			"recent":  signals[:min(20, len(signals))],
			"note":    "observation-only; no content inspection or blocking of transfers",
		})
	})

	mux.HandleFunc("GET /v1/netskope/ztna", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var private []map[string]any
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if isPrivate(n.Destination) {
				private = append(private, map[string]any{
					"destination": n.Destination,
					"host":        n.Host,
					"time":        n.Time,
				})
			}
		}
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"private_accesses": len(private),
			"samples":          private[:min(30, len(private))],
			"note":             "observation of private-destination traffic; no access control",
		})
	})

	mux.HandleFunc("GET /v1/netskope/ai", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var ai []map[string]any
		store.mu.Lock()
		for _, n := range store.networkEvents {
			if isAI(n.Destination) {
				ai = append(ai, map[string]any{
					"destination": n.Destination,
					"host":        n.Host,
					"time":        n.Time,
					"risk":        "info",
				})
			}
		}
		store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ai_destinations": len(ai),
			"samples":         ai[:min(30, len(ai))],
			"note":            "observation of known GenAI endpoints; no prompt inspection or blocking",
		})
	})

	mux.HandleFunc("GET /v1/netskope/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"product": "kavach-netskope-observation",
			"pillars": []string{"casb", "swg", "dlp", "ztna", "ai", "sspm"},
			"note":    "all pillars are observation-only mappings of Netskope One surfaces",
			"time":    time.Now().UTC(),
		})
	})
}

func classifyApp(dest string) string {
	d := strings.ToLower(dest)
	switch {
	case strings.Contains(d, "office.com") || strings.Contains(d, "microsoft.com") || strings.Contains(d, "sharepoint") || strings.Contains(d, "outlook"):
		return "Microsoft 365"
	case strings.Contains(d, "google.com") || strings.Contains(d, "googleapis") || strings.Contains(d, "drive.google"):
		return "Google Workspace"
	case strings.Contains(d, "salesforce"):
		return "Salesforce"
	case strings.Contains(d, "slack"):
		return "Slack"
	case strings.Contains(d, "dropbox"):
		return "Dropbox"
	case strings.Contains(d, "box.com"):
		return "Box"
	case strings.Contains(d, "github.com"):
		return "GitHub"
	case strings.Contains(d, "chatgpt") || strings.Contains(d, "openai") || strings.Contains(d, "claude") || strings.Contains(d, "gemini"):
		return "GenAI"
	default:
		return ""
	}
}

func appCategory(app string) string {
	if app == "GenAI" {
		return "ai"
	}
	return "saas"
}

func appRisk(app string, count int) string {
	if app == "GenAI" && count > 10 {
		return "medium"
	}
	if count > 200 {
		return "medium"
	}
	return "info"
}

func isWebRisky(dest string) bool {
	d := strings.ToLower(dest)
	return strings.Contains(d, "pastebin") || strings.Contains(d, "anonfiles") || strings.Contains(d, ".onion") || strings.Contains(d, "tor")
}

func isPrivate(dest string) bool {
	d := strings.ToLower(dest)
	return strings.HasPrefix(d, "10.") || strings.HasPrefix(d, "192.168.") || strings.HasPrefix(d, "172.") || strings.Contains(d, "internal") || strings.Contains(d, ".local")
}

func isAI(dest string) bool {
	d := strings.ToLower(dest)
	return strings.Contains(d, "openai") || strings.Contains(d, "chatgpt") || strings.Contains(d, "claude") || strings.Contains(d, "gemini") || strings.Contains(d, "anthropic") || strings.Contains(d, "perplexity")
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func toList(m map[string]*NetskopeApp) []NetskopeApp {
	list := make([]NetskopeApp, 0, len(m))
	for _, v := range m {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	return list
}
