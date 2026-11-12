// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"sort"
)

var attackTactics = []string{
	"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
	"Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
	"Collection", "Command and Control", "Exfiltration", "Impact",
}

type ATTACKTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Rules   []string `json:"rules"`
	Hits    int      `json:"hits"`
	Covered bool     `json:"covered"`
}
type ATTACKTactic struct {
	Tactic     string            `json:"tactic"`
	Covered    bool              `json:"covered"`
	Hits       int               `json:"hits"`
	Techniques []ATTACKTechnique `json:"techniques"`
}

// BuildATTACKMatrix maps detection rules and live findings onto ATT&CK tactics. Read-only.
func BuildATTACKMatrix(findings []Finding) map[string]any {
	idx := map[string]*ATTACKTactic{}
	tech := map[string]*ATTACKTechnique{}
	order := []*ATTACKTactic{}
	for _, name := range attackTactics {
		t := &ATTACKTactic{Tactic: name, Techniques: []ATTACKTechnique{}}
		idx[name] = t
		order = append(order, t)
	}
	rules := make([]string, 0, len(ruleMITRE))
	for r := range ruleMITRE {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		m := ruleMITRE[r]
		t := idx[m.Tactic]
		if t == nil {
			continue
		}
		key := m.Tactic + "|" + m.ID
		x := tech[key]
		if x == nil {
			t.Techniques = append(t.Techniques, ATTACKTechnique{ID: m.ID, Name: m.Technique, Covered: true})
			x = &t.Techniques[len(t.Techniques)-1]
			tech[key] = x
		}
		x.Rules = append(x.Rules, r)
		t.Covered = true
	}
	// Slice growth can move elements; rebuild pointers after construction.
	tech = map[string]*ATTACKTechnique{}
	for _, t := range order {
		for i := range t.Techniques {
			tech[t.Tactic+"|"+t.Techniques[i].ID] = &t.Techniques[i]
		}
	}
	total := 0
	for _, f := range findings {
		m, ok := ruleMITRE[f.Rule]
		if !ok {
			continue
		}
		if x := tech[m.Tactic+"|"+m.ID]; x != nil {
			x.Hits++
			idx[m.Tactic].Hits++
			total++
		}
	}
	covered := 0
	for _, t := range order {
		if t.Covered {
			covered++
		}
	}
	return map[string]any{
		"framework":     "MITRE ATT&CK Enterprise",
		"tactics":       order,
		"covered":       covered,
		"total":         len(order),
		"coverage_pct":  covered * 100 / len(order),
		"observed_hits": total,
		"mode":          "observe-only",
	}
}

func RegisterATTACK(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/attack/matrix", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BuildATTACKMatrix(store.List()))
	})
}
