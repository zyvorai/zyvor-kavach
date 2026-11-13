// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// MLRarityProvider is an optional hook for the lineage/similarity model (set by another module).
// It returns a rarity in 0..1 (1 = never seen on this fleet) for the (host, exe, parent) lineage
// and ok=false when it has no opinion. When nil or not ok, the rarity factor is omitted from the
// priority score and the remaining weights are renormalised.
var MLRarityProvider func(host, exe, parent string) (float64, bool)

// RegisterMLNet wires the network/synthesis/priority ML endpoints (all authenticated, all
// read-only): GET /v1/ml/beacons, POST /v1/ml/synthesize, GET /v1/ml/priority.
func RegisterMLNet(mux *http.ServeMux, token string, store *Store) {
	registerMLBeacons(mux, token, store)
	registerMLSynth(mux, token, store)
	registerMLPriority(mux, token, store)
}

// Priority fusion weights (documented in docs/local-models-net.md). The score is the weighted mean
// of the factors that are present, scaled to 0..100; absent factors are listed under "omitted".
var mlPriorityWeights = []struct {
	Name   string
	Weight float64
}{
	{"severity", 0.30},
	{"rarity", 0.20},
	{"beaconing", 0.20},
	{"asset_criticality", 0.15},
	{"rule_trust", 0.15},
}

type PriorityFactor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`  // 0..1, higher = more urgent
	Weight float64 `json:"weight"` // nominal weight
	Note   string  `json:"note"`
}

type PriorityResult struct {
	FindingID   string           `json:"finding_id"`
	Host        string           `json:"host"`
	Rule        string           `json:"rule"`
	Severity    string           `json:"severity"`
	Destination string           `json:"destination,omitempty"`
	Score       float64          `json:"score"` // 0..100
	Level       string           `json:"level"` // low | medium | high | critical
	Coverage    float64          `json:"coverage"`
	Factors     []PriorityFactor `json:"factors"`
	Omitted     []string         `json:"omitted"`
}

func priorityLevel(s float64) string {
	switch {
	case s >= 75:
		return "critical"
	case s >= 55:
		return "high"
	case s >= 35:
		return "medium"
	}
	return "low"
}

// priorityCtx holds per-request lookups shared across findings.
type priorityCtx struct {
	health  map[string]RuleHealth
	beacons map[string]BeaconSeries // host|destination
	assets  map[string]PostureAsset
}

func newPriorityCtx(store *Store, findings []Finding) *priorityCtx {
	c := &priorityCtx{health: map[string]RuleHealth{}, beacons: map[string]BeaconSeries{}, assets: map[string]PostureAsset{}}
	for _, h := range BuildRuleHealth(findings, nil, nil, time.Now()) {
		c.health[h.Rule] = h
	}
	series, _, _ := AnalyzeBeacons(store.networkSnapshot(), BeaconParams{MinEvents: beaconDefaultMinEvents, Allow: loadBeaconAllow(store)}, "")
	for _, s := range series {
		c.beacons[s.Host+"|"+s.Destination] = s
	}
	if p := newPostureSvc(store); p != nil {
		p.mu.Lock()
		for k, v := range p.st.Assets {
			c.assets[k] = v
		}
		p.mu.Unlock()
	}
	return c
}

func (c *priorityCtx) score(f Finding) PriorityResult {
	res := PriorityResult{FindingID: f.ID, Host: f.Host, Rule: f.Rule, Severity: f.Severity, Destination: f.Destination, Factors: []PriorityFactor{}, Omitted: []string{}}
	vals := map[string]PriorityFactor{}
	sev := map[string]float64{"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1}
	if v, ok := sev[f.Severity]; ok {
		vals["severity"] = PriorityFactor{"severity", v, 0.30, "rule severity " + f.Severity}
	}
	if h, ok := c.health[f.Rule]; ok {
		vals["rule_trust"] = PriorityFactor{"rule_trust", 1 - float64(h.NoisyScore)/100, 0.15,
			"rule noisiness " + strconv.Itoa(h.NoisyScore) + "/100 (rule health), lifecycle " + h.State + "; noisy rules rank lower"}
	}
	if FeedbackRuleTrust != nil { // analyst-derived trust, when enough verdicts exist (feedback_http.go)
		if t, ok := FeedbackRuleTrust(f.Rule); ok {
			vals["rule_trust"] = PriorityFactor{"rule_trust", clamp01(t), 0.15, "analyst verdicts: shrunk precision " + f2(t) + " for this rule (advisory)"}
		}
	}
	var rarityNote string
	if MLRarityProvider != nil {
		if v, ok := MLRarityProvider(f.Host, f.Evidence.Executable, f.Evidence.ParentExe); ok {
			vals["rarity"] = PriorityFactor{"rarity", clamp01(v), 0.20, "lineage rarity from the local similarity model"}
		} else {
			rarityNote = "rarity: the lineage model has no opinion for this process"
		}
	} else {
		rarityNote = "rarity: no lineage model registered"
	}
	var beaconNote string
	if f.Destination != "" {
		if b, ok := c.beacons[f.Host+"|"+f.Destination]; ok {
			vals["beaconing"] = PriorityFactor{"beaconing", b.Score / 100, 0.20,
				"beacon score " + f2(b.Score) + " for " + f.Destination + " (period " + f2(b.PeriodSec) + "s, " + strconv.Itoa(b.Events) + " events)"}
		} else {
			beaconNote = "beaconing: no scored series for the finding's destination (not enough data or allowlisted)"
		}
	} else {
		beaconNote = "beaconing: finding has no destination"
	}
	var assetNote string
	if a, ok := c.assets[f.Host]; ok && a.Criticality >= 1 {
		vals["asset_criticality"] = PriorityFactor{"asset_criticality", float64(a.Criticality-1) / 4, 0.15, "asset criticality " + strconv.Itoa(a.Criticality) + "/5 (posture assets)"}
	} else {
		assetNote = "asset_criticality: host not registered in /v1/posture/assets"
	}
	var sum, wsum float64
	for _, w := range mlPriorityWeights {
		if p, ok := vals[w.Name]; ok {
			res.Factors = append(res.Factors, p)
			sum += p.Value * w.Weight
			wsum += w.Weight
		}
	}
	for _, n := range []string{rarityNote, beaconNote, assetNote} {
		if n != "" {
			res.Omitted = append(res.Omitted, n)
		}
	}
	if wsum > 0 {
		res.Score = float64(int(1000*100*sum/wsum+0.5)) / 1000
	}
	res.Coverage = float64(int(wsum*100+0.5)) / 100
	res.Level = priorityLevel(res.Score)
	return res
}

func registerMLPriority(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ml/priority", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		all := store.List()
		ctx := newPriorityCtx(store, all)
		weights := map[string]float64{}
		for _, w := range mlPriorityWeights {
			weights[w.Name] = w.Weight
		}
		note := "Weighted mean of present factors scaled to 0-100; absent factors are omitted and the remaining weights renormalised. Advisory only: /v1/ai/score is unchanged."
		if id := q.Get("finding_id"); id != "" {
			for _, f := range all {
				if f.ID == id {
					customJSON(w, 200, map[string]any{"mode": "observe-only", "model": "priority-fusion-v1", "weights": weights, "note": note, "priority": ctx.score(f)})
					return
				}
			}
			customJSON(w, 404, map[string]any{"error": "finding not found"})
			return
		}
		limit := 50
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 500 {
			limit = v
		}
		out := []PriorityResult{}
		for _, f := range all {
			if h := q.Get("host"); h != "" && f.Host != h {
				continue
			}
			out = append(out, ctx.score(f))
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
		total := len(out)
		if len(out) > limit {
			out = out[:limit]
		}
		customJSON(w, 200, map[string]any{"mode": "observe-only", "model": "priority-fusion-v1", "weights": weights, "note": note, "total": total, "priorities": out})
	})
}
