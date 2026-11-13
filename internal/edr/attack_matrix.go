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
	// CustomRules is the subset of Rules authored by the customer (source=custom).
	CustomRules []string `json:"custom_rules,omitempty"`
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
	// Built-in, live content-pack and enabled IOA rules (with a technique) count toward coverage.
	all := allRuleMITRE()
	rules := make([]string, 0, len(all))
	for r := range all {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	techIdx := map[string]int{}
	for _, r := range rules {
		m := all[r]
		t := idx[m.Tactic]
		if t == nil {
			continue
		}
		key := m.Tactic + "|" + m.ID
		i, seen := techIdx[key]
		if !seen {
			t.Techniques = append(t.Techniques, ATTACKTechnique{ID: m.ID, Name: m.Technique, Covered: true})
			i = len(t.Techniques) - 1
			techIdx[key] = i
		}
		// Index, not pointer: appending to t.Techniques can move earlier elements, and a stale
		// pointer would silently drop rules added to an existing technique.
		t.Techniques[i].Rules = append(t.Techniques[i].Rules, r)
		if contentIsCustom(r) {
			t.Techniques[i].CustomRules = append(t.Techniques[i].CustomRules, r)
		}
		t.Covered = true
	}
	// Slices are final now; take stable pointers for hit counting.
	for _, t := range order {
		for i := range t.Techniques {
			tech[t.Tactic+"|"+t.Techniques[i].ID] = &t.Techniques[i]
		}
	}
	total := 0
	unmappedSet := map[string]struct{}{}
	unmappedHits := 0
	// Built-in rules that can fire but have no ATT&CK entry are listed explicitly, never guessed.
	for _, r := range EmittedRuleNames {
		if _, ok := all[r]; ok {
			continue
		}
		if _, ok := mitreFor(r); ok {
			continue
		}
		switch r {
		case "custom-rule", "ioc-generic", "ioa-generic": // catalogue placeholders, not real rule ids
			continue
		}
		unmappedSet[r] = struct{}{}
	}
	for _, f := range findings {
		m, ok := all[f.Rule]
		if !ok {
			m, ok = mitreForFinding(f)
		}
		if !ok {
			unmappedSet[f.Rule] = struct{}{}
			unmappedHits++
			continue
		}
		if x := tech[m.Tactic+"|"+m.ID]; x != nil {
			x.Hits++
			idx[m.Tactic].Hits++
			total++
		}
	}
	unmapped := make([]string, 0, len(unmappedSet))
	for r := range unmappedSet {
		unmapped = append(unmapped, r)
	}
	sort.Strings(unmapped)
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
		// unmapped_rules: rules with no ATT&CK technique (built-in rules that can fire plus rule ids
		// seen in findings). They are excluded from coverage and hits rather than defaulted.
		"unmapped_rules": unmapped,
		"unmapped_hits":  unmappedHits,
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
