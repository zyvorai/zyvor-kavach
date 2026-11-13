// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
)

// valDetectedFloor is the regression gate: the share of non-benign scenarios whose expectations were
// all Detected must not fall below this. Raise it when detection improves; lowering it needs a reason
// recorded in docs/research-validation-lab.md.
const valDetectedFloor = 0.60

// valFalsePositiveCeiling is the number of benign controls allowed to fire at medium or above.
const valFalsePositiveCeiling = 0

type ValTechScore struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Tactics   []string `json:"tactics"`
	Claimed   bool     `json:"claimed"`
	Status    string   `json:"status"` // detected | partial | missed | not_testable | untested
	Scenarios []string `json:"scenarios,omitempty"`
	Rules     []string `json:"rules_fired,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type ValTacticScore struct {
	Tactic      string  `json:"tactic"`
	Claimed     int     `json:"claimed"`
	Detected    int     `json:"detected"`
	Partial     int     `json:"partial"`
	Missed      int     `json:"missed"`
	NotTestable int     `json:"not_testable"`
	Untested    int     `json:"untested"`
	MeasuredPct float64 `json:"measured_pct"`
}

var valStatusRank = map[string]int{"detected": 3, "partial": 2, "missed": 1}

// RunValidation replays the given scenarios (all when ids is empty).
func RunValidation(scs []ValScenario, o ValOptions) []ValResult {
	out := make([]ValResult, 0, len(scs))
	for _, sc := range scs {
		out = append(out, ReplayScenario(sc, o))
	}
	return out
}

// BuildValidationCoverage scores every claimed technique from the replay results.
func BuildValidationCoverage(scs []ValScenario, results []ValResult, notTestable map[string]string, o ValOptions) map[string]any {
	reg := valRegistry(o)
	type claim struct {
		name    string
		tactics map[string]bool
		rules   []string
	}
	claims := map[string]*claim{}
	addClaim := func(rule, id, tactic, name string) {
		c := claims[id]
		if c == nil {
			c = &claim{name: name, tactics: map[string]bool{}}
			claims[id] = c
		}
		c.tactics[tactic] = true
		c.rules = append(c.rules, rule)
	}
	for r, m := range ruleMITRE {
		addClaim(r, m.ID, m.Tactic, m.Technique)
	}
	for _, r := range reg.rules {
		if !r.PendingTelemetry {
			n := r.TechniqueName
			if n == "" {
				n = r.Technique
			}
			addClaim(r.ID, r.Technique, r.Tactic, n)
		}
	}
	scores := map[string]*ValTechScore{}
	get := func(id string) *ValTechScore {
		s := scores[id]
		if s == nil {
			s = &ValTechScore{ID: id, Status: "untested", Tactics: []string{}}
			if c := claims[id]; c != nil {
				s.Claimed, s.Name = true, c.name
				for t := range c.tactics {
					s.Tactics = append(s.Tactics, t)
				}
				sort.Strings(s.Tactics)
			}
			scores[id] = s
		}
		return s
	}
	for id := range claims {
		get(id)
	}
	for id := range notTestable {
		s := get(id)
		s.Status, s.Reason = "not_testable", notTestable[id]
	}
	byID := map[string]ValResult{}
	for _, r := range results {
		byID[r.ID] = r
	}
	for _, sc := range scs {
		if sc.Benign {
			continue
		}
		r, ok := byID[sc.ID]
		if !ok {
			continue
		}
		for _, oc := range r.Outcomes {
			if !labTechRe.MatchString(oc.Expect) {
				continue
			}
			s := get(oc.Expect)
			s.Scenarios = append(s.Scenarios, sc.ID)
			if s.Status == "not_testable" {
				continue
			}
			if valStatusRank[oc.Status] > valStatusRank[s.Status] {
				s.Status, s.Reason = oc.Status, oc.Reason
			}
			if oc.Status == "detected" {
				s.Reason = ""
			}
			s.Rules = dedupSorted(append(s.Rules, oc.Rules...))
		}
	}
	list := make([]ValTechScore, 0, len(scores))
	for _, s := range scores {
		list = append(list, *s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

	counts := map[string]int{}
	var missed, notTest, unmeasured, partial []ValTechScore
	unclaimed := []string{}
	for _, s := range list {
		if !s.Claimed {
			if s.Status != "untested" {
				unclaimed = append(unclaimed, s.ID)
			}
			continue
		}
		counts[s.Status]++
		switch s.Status {
		case "missed":
			missed = append(missed, s)
		case "partial":
			partial = append(partial, s)
		case "not_testable":
			notTest = append(notTest, s)
		case "untested":
			unmeasured = append(unmeasured, s)
		}
	}
	claimed := 0
	for _, s := range list {
		if s.Claimed {
			claimed++
		}
	}
	pct := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a*1000/b) / 10
	}
	tested := counts["detected"] + counts["partial"] + counts["missed"]

	byTactic := []ValTacticScore{}
	for _, tac := range attackTactics {
		ts := ValTacticScore{Tactic: tac}
		for _, s := range list {
			if !s.Claimed {
				continue
			}
			in := false
			for _, t := range s.Tactics {
				if t == tac {
					in = true
				}
			}
			if !in {
				continue
			}
			ts.Claimed++
			switch s.Status {
			case "detected":
				ts.Detected++
			case "partial":
				ts.Partial++
			case "missed":
				ts.Missed++
			case "not_testable":
				ts.NotTestable++
			default:
				ts.Untested++
			}
		}
		if ts.Claimed > 0 {
			ts.MeasuredPct = pct(ts.Detected, ts.Claimed)
			byTactic = append(byTactic, ts)
		}
	}

	nonBenign, passed, benign, fp := 0, 0, 0, 0
	var failing, falsePos []string
	for _, r := range results {
		if r.Benign {
			benign++
			if r.FalsePositive {
				fp++
				falsePos = append(falsePos, r.ID)
			}
			continue
		}
		nonBenign++
		if r.Pass {
			passed++
		} else {
			failing = append(failing, r.ID)
		}
	}
	matrix := BuildATTACKMatrix(nil)
	return map[string]any{
		"note": valNote, "mode": "observe-only", "synthetic": true,
		"claimed_techniques":          claimed,
		"claimed_tactic_coverage_pct": matrix["coverage_pct"],
		"counts": map[string]int{
			"detected": counts["detected"], "partial": counts["partial"], "missed": counts["missed"],
			"not_testable": counts["not_testable"], "untested": counts["untested"],
		},
		"tested_techniques":                tested,
		"measured_detected_pct":            pct(counts["detected"], claimed),
		"measured_detected_or_partial_pct": pct(counts["detected"]+counts["partial"], claimed),
		"tested_detection_rate_pct":        pct(counts["detected"], tested),
		"scenarios": map[string]any{
			"non_benign": nonBenign, "passed": passed, "detect_rate": float64(passed) / float64(max1(nonBenign)),
			"floor": valDetectedFloor, "failing": failing,
			"benign_controls": benign, "benign_false_positives": fp, "false_positive_ids": falsePos,
		},
		"by_tactic": byTactic, "by_technique": list,
		"missed": nonNil(missed), "partial": nonNil(partial), "not_testable": nonNil(notTest),
		"claimed_not_measured": nonNil(unmeasured), "tested_but_unclaimed": unclaimed,
	}
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func nonNil(x []ValTechScore) []ValTechScore {
	if x == nil {
		return []ValTechScore{}
	}
	return x
}

func valJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// RegisterValidationLab wires the detection validation lab endpoints. POST /v1/validate/run is a
// read-only computation: it replays synthetic events in memory and records nothing. The store is
// accepted for signature symmetry with the other registrars and is deliberately never used.
func RegisterValidationLab(mux *http.ServeMux, token string, _ *Store) {
	load := func(w http.ResponseWriter) ([]ValScenario, map[string]string, bool) {
		scs, nt, err := LoadValidationScenarios()
		if err != nil && len(scs) == 0 {
			valJSON(w, 500, map[string]any{"error": "scenario pack failed to load", "note": valNote})
			return nil, nil, false
		}
		return scs, nt, true
	}
	mux.HandleFunc("GET /v1/validate/scenarios", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		scs, _, ok := load(w)
		if !ok {
			return
		}
		q := r.URL.Query()
		type row struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Kind       string   `json:"kind"`
			Platform   string   `json:"platform"`
			Techniques []string `json:"techniques,omitempty"`
			Tactics    []string `json:"tactics,omitempty"`
			Benign     bool     `json:"benign"`
			Steps      int      `json:"steps"`
		}
		out := []row{}
		for _, s := range scs {
			if k := q.Get("kind"); k != "" && s.Kind != k {
				continue
			}
			if p := q.Get("platform"); p != "" && s.Platform != p {
				continue
			}
			if t := q.Get("technique"); t != "" && !containsStr(s.Techniques, t) {
				continue
			}
			out = append(out, row{s.ID, s.Name, s.Kind, s.Platform, s.Techniques, s.Tactics, s.Benign, len(s.Steps)})
		}
		valJSON(w, 200, map[string]any{"note": valNote, "synthetic": true, "count": len(out), "scenarios": out})
	})
	mux.HandleFunc("GET /v1/validate/scenarios/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		scs, _, ok := load(w)
		if !ok {
			return
		}
		for _, s := range scs {
			if s.ID == r.PathValue("id") {
				valJSON(w, 200, map[string]any{"note": valNote, "synthetic": true, "scenario": s})
				return
			}
		}
		valJSON(w, 404, map[string]any{"error": "scenario not found", "note": valNote})
	})
	mux.HandleFunc("POST /v1/validate/run", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		scs, _, ok := load(w)
		if !ok {
			return
		}
		var req struct {
			IDs           []string `json:"ids"`
			All           bool     `json:"all"`
			IncludeCustom bool     `json:"include_custom"`
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
		if err != nil || (len(b) > 0 && json.Unmarshal(b, &req) != nil) {
			valJSON(w, 400, map[string]any{"error": "invalid json body", "note": valNote})
			return
		}
		if !req.All && len(req.IDs) == 0 {
			valJSON(w, 400, map[string]any{"error": "give ids or all=true", "note": valNote})
			return
		}
		if len(req.IDs) > valMaxScenarios {
			valJSON(w, 400, map[string]any{"error": "too many ids", "note": valNote})
			return
		}
		sel := scs
		if !req.All {
			want := map[string]bool{}
			for _, id := range req.IDs {
				want[id] = true
			}
			sel = nil
			for _, s := range scs {
				if want[s.ID] {
					sel = append(sel, s)
					delete(want, s.ID)
				}
			}
			if len(want) > 0 {
				var unk []string
				for id := range want {
					unk = append(unk, id)
				}
				sort.Strings(unk)
				valJSON(w, 404, map[string]any{"error": "unknown scenario ids", "ids": unk, "note": valNote})
				return
			}
		}
		res := RunValidation(sel, ValOptions{IncludeCustom: req.IncludeCustom})
		valJSON(w, 200, map[string]any{"note": valNote, "synthetic": true, "recorded": false, "count": len(res), "results": res})
	})
	mux.HandleFunc("GET /v1/validate/coverage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		scs, nt, ok := load(w)
		if !ok {
			return
		}
		o := ValOptions{IncludeCustom: r.URL.Query().Get("include_custom") == "true"}
		valJSON(w, 200, BuildValidationCoverage(scs, RunValidation(scs, o), nt, o))
	})
}
