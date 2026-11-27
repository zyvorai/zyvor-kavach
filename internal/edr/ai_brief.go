// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Multi-finding AI brief (observation-only).
// Aggregates recent findings for a host or rule into a short structured brief.

func RegisterAIBrief(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ai/brief", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := r.URL.Query().Get("host")
		rule := r.URL.Query().Get("rule")
		var selected []Finding
		for _, f := range store.List() {
			if host != "" && !strings.EqualFold(f.Host, host) {
				continue
			}
			if rule != "" && !strings.Contains(strings.ToLower(f.Rule), strings.ToLower(rule)) {
				continue
			}
			selected = append(selected, f)
			if len(selected) >= 20 {
				break
			}
		}
		brief := buildBrief(selected, host, rule)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":  host,
			"rule":  rule,
			"count": len(selected),
			"brief": brief,
			"note":  "heuristic brief only; optional external LLM can enrich later. No actions taken.",
			"time":  time.Now().UTC(),
		})
	})
}

func buildBrief(fs []Finding, host, rule string) map[string]any {
	if len(fs) == 0 {
		return map[string]any{"summary": "No matching findings.", "severity": "info"}
	}
	sev := "info"
	rules := map[string]int{}
	for _, f := range fs {
		rules[f.Rule]++
		if f.Severity == "high" || f.Severity == "critical" {
			sev = "high"
		} else if sev != "high" && f.Severity == "medium" {
			sev = "medium"
		}
	}
	topRules := []string{}
	for r := range rules {
		topRules = append(topRules, r)
		if len(topRules) >= 5 {
			break
		}
	}
	summary := "Observed " + itoa(len(fs)) + " findings"
	if host != "" {
		summary += " on host " + host
	}
	if rule != "" {
		summary += " matching rule filter " + rule
	}
	summary += ". Highest severity: " + sev + "."
	return map[string]any{
		"summary":    summary,
		"severity":   sev,
		"top_rules":  topRules,
		"suggestion": "Review the timeline and related network or offline VM data. No containment recommended.",
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
