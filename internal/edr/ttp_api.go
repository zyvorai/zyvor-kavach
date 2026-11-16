// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// Endpoints (read-only, authenticated):
//   GET /v1/ttp/similar?host=|finding_ids=|techniques=T1059,T1003
//   GET /v1/ttp/next?techniques=...   (or host= / finding_ids=)
//   GET /v1/ttp/chains?host=
// All responses carry "caveats". Similarity is not attribution.

type ttpObserved struct {
	ID       string    `json:"technique"`
	Name     string    `json:"name,omitempty"`
	Tactic   string    `json:"tactic,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	First    time.Time `json:"first_seen,omitempty"`
	Last     time.Time `json:"last_seen,omitempty"`
	Findings int       `json:"findings"`
}

// ttpRuleMap merges built-in and live content-pack rule mappings, as the ATT&CK matrix does.
func ttpRuleMap() map[string]struct{ Tactic, Technique, ID string } {
	return allRuleMITRE()
}

// ttpObserve derives observed techniques from findings via the ATT&CK matrix mapping.
func ttpObserve(findings []Finding, keep func(Finding) bool) []ttpObserved {
	rules := ttpRuleMap()
	idx := map[string]*ttpObserved{}
	var order []string
	for _, f := range findings {
		if keep != nil && !keep(f) {
			continue
		}
		m, ok := rules[f.Rule]
		if !ok {
			m, ok = mitreForFinding(f) // IOC id aliases and IOA tags
		}
		if !ok || m.ID == "" {
			continue
		}
		o := idx[m.ID]
		if o == nil {
			o = &ttpObserved{ID: m.ID, Name: m.Technique, Tactic: m.Tactic, Rule: f.Rule, First: f.Time, Last: f.Time}
			idx[m.ID] = o
			order = append(order, m.ID)
		}
		o.Findings++
		if f.Time.Before(o.First) {
			o.First = f.Time
		}
		if f.Time.After(o.Last) {
			o.Last = f.Time
		}
	}
	out := make([]ttpObserved, 0, len(order))
	for _, id := range order {
		out = append(out, *idx[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].First.Equal(out[j].First) {
			return out[i].First.Before(out[j].First)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func ttpSet(ids []string) map[string]struct{} {
	s := map[string]struct{}{}
	for _, id := range ids {
		s[ttpParent(id)] = struct{}{}
	}
	return s
}

// ttpInput resolves the observed techniques from the query (techniques=, finding_ids=, host=).
func ttpInput(r *http.Request, store *Store) (obs []ttpObserved, source string, errMsg string) {
	q := r.URL.Query()
	if v := q.Get("techniques"); v != "" {
		parts := strings.Split(v, ",")
		if len(parts) > 100 {
			return nil, "", "too many techniques (max 100)"
		}
		seen := map[string]bool{}
		for _, p := range parts {
			p = strings.ToUpper(strings.TrimSpace(p))
			if !adversaryTechRe.MatchString(p) {
				return nil, "", "invalid technique id: " + truncate(p, 20)
			}
			if !seen[p] {
				seen[p] = true
				obs = append(obs, ttpObserved{ID: p, Tactic: ttpTacticOf(p)})
			}
		}
		return obs, "techniques", ""
	}
	if v := q.Get("finding_ids"); v != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" && len(id) <= 128 {
				want[id] = true
			}
		}
		return ttpObserve(store.List(), func(f Finding) bool { return want[f.ID] }), "finding_ids", ""
	}
	if h := q.Get("host"); h != "" {
		if len(h) > 256 {
			return nil, "", "host too long"
		}
		return ttpObserve(store.List(), func(f Finding) bool { return f.Host == h }), "host", ""
	}
	return nil, "", "provide one of host=, finding_ids= or techniques="
}

func ttpObsIDs(obs []ttpObserved) []string {
	ids := make([]string, 0, len(obs))
	for _, o := range obs {
		ids = append(ids, o.ID)
	}
	return ids
}

type ttpMatch struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Score            float64  `json:"score"`
	TFIDFCosine      float64  `json:"tfidf_cosine"`
	WeightedJaccard  float64  `json:"weighted_jaccard"`
	Overlap          []string `json:"overlap"`
	MissingTechnique []string `json:"missing_techniques"`
}

func ttpSimilar(m *ttpModel, obs map[string]struct{}, top int) (string, string, []ttpMatch) {
	ranked := m.rank(obs)
	conf, why := m.confidence(obs, ranked)
	if conf == "not_enough_evidence" {
		return conf, why, []ttpMatch{}
	}
	out := []ttpMatch{}
	for _, s := range ranked {
		if len(out) >= top || s.Score <= 0 {
			break
		}
		out = append(out, ttpMatch{ID: s.P.ID, Name: s.P.Name, Kind: s.P.Kind, Score: ttpRound3(s.Score),
			TFIDFCosine: ttpRound3(s.Cosine), WeightedJaccard: ttpRound3(s.WJac), Overlap: s.Overlap, MissingTechnique: s.Missing})
	}
	return conf, why, out
}

func ttpRound3(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

type ttpHint struct {
	Technique string  `json:"technique"`
	Tactic    string  `json:"tactic,omitempty"`
	Support   int     `json:"supporting_profiles"`
	Weight    float64 `json:"weight"`
	Commodity bool    `json:"commodity"`
}

// ttpNext derives hunting hints: techniques that co-occur with the observed set in the best-matching
// profiles, weighted by profile score, ordered by kill-chain tactic then weight.
func ttpNext(m *ttpModel, obs map[string]struct{}, k int) []ttpHint {
	ranked := m.rank(obs)
	agg := map[string]*ttpHint{}
	for i, s := range ranked {
		if i >= 5 || s.Score <= 0 {
			break
		}
		for _, t := range s.Missing {
			h := agg[t]
			if h == nil {
				h = &ttpHint{Technique: t, Tactic: ttpTacticOf(t), Commodity: m.isCommodity(t)}
				agg[t] = h
			}
			h.Support++
			h.Weight += s.Score
		}
	}
	hints := make([]ttpHint, 0, len(agg))
	for _, h := range agg {
		h.Weight = ttpRound3(h.Weight)
		hints = append(hints, *h)
	}
	sort.Slice(hints, func(i, j int) bool {
		if hints[i].Weight != hints[j].Weight {
			return hints[i].Weight > hints[j].Weight
		}
		return hints[i].Technique < hints[j].Technique
	})
	if len(hints) > k {
		hints = hints[:k]
	}
	sort.SliceStable(hints, func(i, j int) bool {
		return ttpTacticRank(hints[i].Tactic) < ttpTacticRank(hints[j].Tactic)
	})
	return hints
}

type ttpGap struct {
	Tactic string   `json:"tactic"`
	Hunt   []string `json:"hunt_techniques"`
}

// ttpChain reports kill-chain progression for time-ordered observed techniques.
func ttpChain(m *ttpModel, obs []ttpObserved) map[string]any {
	reached := map[string]bool{}
	minR, maxR := len(attackTactics), -1
	var first, last string
	for _, o := range obs {
		if o.Tactic == "" {
			continue
		}
		reached[o.Tactic] = true
		r := ttpTacticRank(o.Tactic)
		if r < minR {
			minR, first = r, o.Tactic
		}
		if r > maxR {
			maxR, last = r, o.Tactic
		}
	}
	seen := map[string]struct{}{}
	for _, o := range obs {
		seen[ttpParent(o.ID)] = struct{}{}
	}
	gaps := []ttpGap{}
	progression := []string{}
	for i, t := range attackTactics {
		if reached[t] {
			progression = append(progression, t)
		}
		// Reconnaissance/Resource Development happen off-host, so they are never reported as gaps.
		if maxR < 0 || i <= minR || i >= maxR || reached[t] || i < ttpTacticIdx["Initial Access"] {
			continue
		}
		type cand struct {
			id string
			df int
		}
		var cs []cand
		for id, d := range m.df {
			if ttpTacticOf(id) == t {
				if _, ok := seen[id]; !ok {
					cs = append(cs, cand{id, d})
				}
			}
		}
		sort.Slice(cs, func(a, b int) bool {
			if cs[a].df != cs[b].df {
				return cs[a].df > cs[b].df
			}
			return cs[a].id < cs[b].id
		})
		g := ttpGap{Tactic: t, Hunt: []string{}}
		for j := 0; j < len(cs) && j < 4; j++ {
			g.Hunt = append(g.Hunt, cs[j].id)
		}
		gaps = append(gaps, g)
	}
	res := map[string]any{
		"sequence":              obs,
		"tactics_reached":       progression,
		"observed_techniques":   len(obs),
		"gaps_worth_hunting":    gaps,
		"gap_note":              "A gap is a tactic between the earliest and latest tactic reached with no observed technique. It may be a detection blind spot or a step the actor did not need; hunt it, do not assume it happened.",
		"killchain_order_check": ttpOrderNote(obs),
	}
	if maxR >= 0 {
		res["earliest_tactic"] = first
		res["latest_tactic"] = last
		res["progression_span"] = maxR - minR + 1
	}
	return res
}

// ttpOrderNote flags when time order contradicts the usual tactic order (not unusual; informational).
func ttpOrderNote(obs []ttpObserved) string {
	prev := -1
	for _, o := range obs {
		if o.Tactic == "" {
			continue
		}
		r := ttpTacticRank(o.Tactic)
		if r < prev {
			return "time order differs from canonical tactic order (common: tactics repeat and interleave)"
		}
		prev = r
	}
	return "time order is consistent with canonical tactic order"
}

func RegisterTTP(mux *http.ServeMux, token string, store *Store) {
	base := func(source string, obs []ttpObserved) map[string]any {
		return map[string]any{
			"caveats":  ttpCaveats,
			"mode":     "observe-only",
			"source":   source,
			"observed": obs,
			"profiles": len(ttpDefault.profiles),
		}
	}
	guard := func(w http.ResponseWriter, r *http.Request) ([]ttpObserved, string, bool) {
		if !requireAuth(w, r, token) {
			return nil, "", false
		}
		if ttpDefault == nil {
			http.Error(w, "adversary profiles unavailable", http.StatusServiceUnavailable)
			return nil, "", false
		}
		obs, src, msg := ttpInput(r, store)
		if msg != "" {
			http.Error(w, msg, http.StatusBadRequest)
			return nil, "", false
		}
		return obs, src, true
	}
	mux.HandleFunc("GET /v1/ttp/similar", func(w http.ResponseWriter, r *http.Request) {
		obs, src, ok := guard(w, r)
		if !ok {
			return
		}
		set := ttpSet(ttpObsIDs(obs))
		conf, why, matches := ttpSimilar(ttpDefault, set, 10)
		res := base(src, obs)
		res["distinct_techniques"] = len(set)
		res["confidence"] = conf
		res["confidence_reason"] = why
		res["matches"] = matches
		res["method"] = "score = mean of TF-IDF cosine and weighted Jaccard over parent-level techniques; document-frequency weights from the embedded profiles"
		writeJSON(w, res)
	})
	mux.HandleFunc("GET /v1/ttp/next", func(w http.ResponseWriter, r *http.Request) {
		obs, src, ok := guard(w, r)
		if !ok {
			return
		}
		set := ttpSet(ttpObsIDs(obs))
		res := base(src, obs)
		res["distinct_techniques"] = len(set)
		res["label"] = "Hints to hunt for, derived from co-occurrence in similar public profiles. Not a prediction."
		if len(set) < ttpMinTechniques {
			res["confidence"] = "not_enough_evidence"
			res["hints"] = []ttpHint{}
		} else {
			res["confidence"] = "hint_only"
			res["hints"] = ttpNext(ttpDefault, set, 12)
			res["hint_basis"] = "weighted by similarity of the 5 best-matching profiles; ordered by kill-chain tactic"
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("GET /v1/ttp/chains", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if ttpDefault == nil {
			http.Error(w, "adversary profiles unavailable", http.StatusServiceUnavailable)
			return
		}
		h := r.URL.Query().Get("host")
		if h == "" || len(h) > 256 {
			http.Error(w, "host= is required", http.StatusBadRequest)
			return
		}
		obs := ttpObserve(store.List(), func(f Finding) bool { return f.Host == h })
		res := ttpChain(ttpDefault, obs)
		res["caveats"] = ttpCaveats
		res["mode"] = "observe-only"
		res["host"] = h
		writeJSON(w, res)
	})
}
