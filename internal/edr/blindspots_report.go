// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const blindspotCaveat = "No events received may mean none happened, not that collection is broken. " +
	"'never_seen' means zero events are held for the category; 'stale' means events were seen but not within the stale window. " +
	"Technique claims are counted from the loaded content rules only (built-in detectors are not included). " +
	"Counts come from bounded in-memory buffers."

// blindValidation is the slice of the validation lab report this view needs.
type blindValidation struct {
	Missed      []ValTechScore `json:"missed"`
	NotTestable []ValTechScore `json:"not_testable"`
}

type blindGap struct {
	Category             string   `json:"category"`
	State                string   `json:"state"`
	LastSeen             string   `json:"last_seen,omitempty"`
	RulesCannotFire      int      `json:"rules_cannot_fire"`
	TechniquesCannotFire int      `json:"techniques_cannot_fire"` // every claiming rule needs an unobserved category
	TechniquesDegraded   int      `json:"techniques_degraded"`    // some rules need this category, others can still fire
	Message              string   `json:"message"`
	RuleIDs              []string `json:"rule_ids,omitempty"`
}

type blindTech struct {
	Technique  string   `json:"technique"`
	Categories []string `json:"categories_required"`
	RuleIDs    []string `json:"rule_ids"`
	Reason     string   `json:"reason"`
}

type blindPriority struct {
	Rank               int    `json:"rank"`
	Category           string `json:"category"`
	TechniquesUnlocked int    `json:"techniques_unlocked"`
	RulesUnlocked      int    `json:"rules_unlocked"`
	Advice             string `json:"advice"`
}

func blindUniqSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// buildBlindspots joins category observation, claimed techniques and validation results.
// Rules with an empty event_type are treated as process rules.
func buildBlindspots(obs map[string]catObs, rules []ContentRule, now time.Time, stale time.Duration, val *blindValidation) map[string]any {
	state := map[string]string{}
	for c, o := range obs {
		state[c] = categoryState(o, now, stale)
	}
	stateOf := func(c string) string {
		if s, ok := state[c]; ok {
			return s
		}
		return catNever // a category the store has no record of
	}
	type techInfo struct {
		cats  map[string]bool
		rules []string
	}
	techs := map[string]*techInfo{}
	rulesByCat := map[string][]string{}
	for _, r := range rules {
		if r.Technique == "" {
			continue
		}
		cat := r.EventType
		if cat == "" {
			cat = "process"
		}
		t := techs[r.Technique]
		if t == nil {
			t = &techInfo{cats: map[string]bool{}}
			techs[r.Technique] = t
		}
		t.cats[cat] = true
		t.rules = append(t.rules, r.ID)
		rulesByCat[cat] = append(rulesByCat[cat], r.ID)
	}
	techIDs := make([]string, 0, len(techs))
	for id := range techs {
		techIDs = append(techIDs, id)
	}
	sort.Strings(techIDs)

	unobservable := []blindTech{}
	atRisk := []blindTech{}
	perCatFull := map[string]int{}
	perCatDeg := map[string]int{}
	for _, id := range techIDs {
		t := techs[id]
		cats := make([]string, 0, len(t.cats))
		for c := range t.cats {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		allNever, allBad := true, true
		for _, c := range cats {
			s := stateOf(c)
			if s != catNever {
				allNever = false
			}
			if s == catActive {
				allBad = false
			}
		}
		switch {
		case allNever:
			unobservable = append(unobservable, blindTech{id, cats, blindUniqSorted(t.rules),
				"every category this technique's rules need has zero events here"})
			for _, c := range cats {
				perCatFull[c]++
			}
		case allBad:
			atRisk = append(atRisk, blindTech{id, cats, blindUniqSorted(t.rules),
				"its categories were seen before but not within the stale window"})
		}
		// degraded: some needed category is never seen but another is not
		if !allNever {
			for _, c := range cats {
				if stateOf(c) == catNever {
					perCatDeg[c]++
				}
			}
		}
	}

	gaps := []blindGap{}
	cats := telemetryCategories()
	for c := range obs {
		cats = append(cats, c)
	}
	for _, c := range blindUniqSorted(cats) {
		s := stateOf(c)
		if s == catActive {
			continue
		}
		g := blindGap{Category: c, State: s, RulesCannotFire: len(rulesByCat[c]),
			TechniquesCannotFire: perCatFull[c], TechniquesDegraded: perCatDeg[c], RuleIDs: blindUniqSorted(rulesByCat[c])}
		if o := obs[c]; !o.Last.IsZero() {
			g.LastSeen = o.Last.UTC().Format(time.RFC3339)
		}
		if s == catNever {
			g.Message = fmt.Sprintf("no %s events received: %d rules and %d techniques cannot fire (%d more techniques lose some coverage). This may mean none happened rather than a collection fault.",
				c, g.RulesCannotFire, g.TechniquesCannotFire, g.TechniquesDegraded)
		} else {
			g.Message = fmt.Sprintf("%s events were last seen %s, outside the %dh stale window: %d rules may not be firing. Check whether collection stopped.",
				c, g.LastSeen, int(stale.Hours()), g.RulesCannotFire)
			g.TechniquesCannotFire, g.TechniquesDegraded = 0, 0
		}
		if g.RulesCannotFire == 0 && s == catNever {
			g.Message = fmt.Sprintf("no %s events received; no loaded content rule needs this category.", c)
		}
		gaps = append(gaps, g)
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].TechniquesCannotFire != gaps[j].TechniquesCannotFire {
			return gaps[i].TechniquesCannotFire > gaps[j].TechniquesCannotFire
		}
		return gaps[i].Category < gaps[j].Category
	})

	prio := []blindPriority{}
	for _, g := range gaps {
		if g.State != catNever || g.TechniquesCannotFire == 0 {
			continue
		}
		prio = append(prio, blindPriority{Category: g.Category, TechniquesUnlocked: g.TechniquesCannotFire, RulesUnlocked: g.RulesCannotFire,
			Advice: fmt.Sprintf("Enable %s telemetry collection: unlocks %d technique(s) and %d rule(s).", g.Category, g.TechniquesCannotFire, g.RulesCannotFire)})
	}
	sort.SliceStable(prio, func(i, j int) bool {
		if prio[i].TechniquesUnlocked != prio[j].TechniquesUnlocked {
			return prio[i].TechniquesUnlocked > prio[j].TechniquesUnlocked
		}
		return prio[i].RulesUnlocked > prio[j].RulesUnlocked
	})
	for i := range prio {
		prio[i].Rank = i + 1
	}
	if len(prio) > 5 {
		prio = prio[:5]
	}

	out := map[string]any{
		"mode": "observe-only", "caveat": blindspotCaveat, "stale_after_hours": int(stale.Hours()),
		"techniques_claimed": len(techs), "techniques_unobservable_count": len(unobservable),
		"techniques_unobservable": unobservable, "techniques_at_risk_stale": atRisk,
		"collection_gaps": gaps, "enable_first": prio,
		"telemetry": buildTelemetryInventory(obs, now, stale),
	}
	if val != nil {
		out["validation"] = map[string]any{"available": true, "missed": nonNil(val.Missed), "not_testable": nonNil(val.NotTestable),
			"note": "Measured by replaying synthetic scenarios; independent of which events arrive on this deployment."}
	} else {
		out["validation"] = map[string]any{"available": false, "missed": []ValTechScore{}, "not_testable": []ValTechScore{}}
	}
	return out
}

// runBlindValidation runs the embedded validation lab; nil when it cannot load. Never panics.
func runBlindValidation() (v *blindValidation) {
	defer func() {
		if recover() != nil {
			v = nil
		}
	}()
	scs, nt, err := LoadValidationScenarios()
	if err != nil && len(scs) == 0 {
		return nil
	}
	cov := BuildValidationCoverage(scs, RunValidation(scs, ValOptions{}), nt, ValOptions{})
	v = &blindValidation{}
	v.Missed, _ = cov["missed"].([]ValTechScore)
	v.NotTestable, _ = cov["not_testable"].([]ValTechScore)
	return v
}

// RegisterBlindspots mounts GET /v1/coverage/blindspots and GET /v1/coverage/telemetry.
func RegisterBlindspots(mux *http.ServeMux, token string, store *Store) {
	out := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	staleOf := func(r *http.Request) time.Duration {
		d := blindspotDefaultStaleDays
		if n, err := strconv.Atoi(r.URL.Query().Get("stale_days")); err == nil && n > 0 && n <= 3650 {
			d = n
		}
		return time.Duration(d) * 24 * time.Hour
	}
	mux.HandleFunc("GET /v1/coverage/telemetry", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		stale := staleOf(r)
		out(w, map[string]any{"mode": "observe-only", "caveat": blindspotCaveat, "stale_after_hours": int(stale.Hours()),
			"categories": buildTelemetryInventory(collectCategoryObs(store), time.Now(), stale)})
	})
	mux.HandleFunc("GET /v1/coverage/blindspots", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var val *blindValidation
		if r.URL.Query().Get("validation") != "0" {
			val = runBlindValidation()
		}
		out(w, buildBlindspots(collectCategoryObs(store), ContentRules(), time.Now(), staleOf(r), val))
	})
}

// RegisterContentVersionsAndBlindspots is the single registration hook for edr.go.
func RegisterContentVersionsAndBlindspots(mux *http.ServeMux, token string, store *Store) {
	RegisterContentVersions(mux, token, store)
	RegisterBlindspots(mux, token, store)
}
