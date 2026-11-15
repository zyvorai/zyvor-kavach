// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"sort"
	"sync/atomic"
	"time"
)

// Model 4: alert-fatigue advisor. Stateless (nothing persisted): it recomputes from retained
// findings (rule health) and the analyst feedback ledger on each request. It only SUGGESTS which
// rules deserve a retune; it changes no rule, lifecycle or exception.

const (
	mlFatMinHits30d   = 10   // per-rule cold-start guard
	mlFatRetuneScore  = 60.0 // score at or above which a rule is a retune candidate
	mlFatMinVerdicts  = feedbackMinVerdicts
	mlFatFPEvidenceHi = 0.5 // Wilson upper bound on precision below this = analysts mostly reject it
)

var mlFatWeights = []struct {
	Name   string
	Weight float64
}{
	{"volume_share", 0.25},
	{"host_repetition", 0.15},
	{"trend", 0.10},
	{"noisiness", 0.15},
	{"fp_evidence", 0.35},
}

// feedbackSnapshotFn returns the feedback ledger (set by RegisterFeedback).
var feedbackSnapshotFn atomic.Pointer[func() []FeedbackEntry]

func feedbackPrecisionByRule() map[string]RulePrecision {
	out := map[string]RulePrecision{}
	fn := feedbackSnapshotFn.Load()
	if fn == nil {
		return out
	}
	for _, r := range rulePrecisions(consolidate((*fn)()), feedbackMinVerdicts, feedbackReviewBelow) {
		out[r.Rule] = r
	}
	return out
}

type FatigueFactor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Weight float64 `json:"weight"`
	Note   string  `json:"note"`
}

type FatigueResult struct {
	Rule       string          `json:"rule"`
	Name       string          `json:"name,omitempty"`
	Status     string          `json:"status"` // ok | not_enough_data
	Hits30d    int             `json:"hits_30d"`
	Hits7d     int             `json:"hits_7d"`
	Hosts      int             `json:"distinct_hosts_30d"`
	Verdicts   int             `json:"decided_verdicts"`
	Score      float64         `json:"fatigue_score"`
	Coverage   float64         `json:"coverage"`
	Retune     bool            `json:"retune_candidate"`
	Factors    []FatigueFactor `json:"factors"`
	Omitted    []string        `json:"omitted"`
	Suggestion []string        `json:"suggestions"`
	Note       string          `json:"note,omitempty"`
}

func fatigueFor(h RuleHealth, fb RulePrecision) FatigueResult {
	r := FatigueResult{Rule: h.Rule, Name: h.Name, Hits30d: h.Hits30d, Hits7d: h.Hits7d, Hosts: h.DistinctHost, Verdicts: fb.Decided,
		Factors: []FatigueFactor{}, Omitted: []string{}, Suggestion: []string{}}
	if h.Hits30d < mlFatMinHits30d {
		r.Status = "not_enough_data"
		r.Note = "fewer than " + f2(mlFatMinHits30d) + " hits in 30 days; no judgement is made"
		return r
	}
	r.Status = "ok"
	vals := map[string]FatigueFactor{}
	vals["volume_share"] = FatigueFactor{"volume_share", clamp01(h.Share30d / 0.25), 0.25, "rule is " + f2(h.Share30d*100) + "% of all findings in 30 days (full at 25%)"}
	per := float64(h.Hits30d) / float64(maxInt(1, h.DistinctHost))
	vals["host_repetition"] = FatigueFactor{"host_repetition", clamp01((per - 3) / 27), 0.15, f2(per) + " hits per host in 30 days (starts at 3, full at 30)"}
	tr := map[string]float64{"up": 1, "new": 0.5, "flat": 0.3, "down": 0, "none": 0}[h.Trend]
	vals["trend"] = FatigueFactor{"trend", tr, 0.10, "7-day trend " + h.Trend}
	vals["noisiness"] = FatigueFactor{"noisiness", float64(h.NoisyScore) / 100, 0.15, "rule-health noisy score " + f2(float64(h.NoisyScore)) + "/100"}
	if fb.Status == feedbackStatusOK && fb.Shrunk != nil {
		vals["fp_evidence"] = FatigueFactor{"fp_evidence", clamp01(1 - *fb.Shrunk), 0.35,
			"analyst verdicts: shrunk precision " + f2(*fb.Shrunk) + " over " + f2(float64(fb.Decided)) + " decided findings (labelled subset, not fleet precision)"}
	} else {
		r.Omitted = append(r.Omitted, "fp_evidence: fewer than "+f2(mlFatMinVerdicts)+" decided analyst verdicts ("+f2(float64(fb.Decided))+")")
	}
	var sum, wsum float64
	for _, w := range mlFatWeights {
		if f, ok := vals[w.Name]; ok {
			r.Factors = append(r.Factors, f)
			sum += f.Value * w.Weight
			wsum += w.Weight
		}
	}
	if wsum > 0 {
		r.Score = mlRound(100*sum/wsum, 1)
	}
	r.Coverage = mlRound(wsum, 2)
	r.Retune = r.Score >= mlFatRetuneScore
	if !r.Retune {
		return r
	}
	switch {
	case fb.Status == feedbackStatusOK && fb.WilsonHi != nil && *fb.WilsonHi < mlFatFPEvidenceHi:
		r.Suggestion = append(r.Suggestion, "analysts mostly rejected this rule's findings: tighten its conditions or add a scoped exception, validate in the testing lifecycle (PUT /v1/rules/lifecycle/{id}) and replay the regression pack before re-enabling")
	case fb.Status != feedbackStatusOK:
		r.Suggestion = append(r.Suggestion, "volume looks high but there are too few analyst verdicts to call it noise: record verdicts (POST /v1/feedback) on its findings before changing it")
	}
	if h.DistinctHost <= 2 && h.Hits30d >= 30 {
		r.Suggestion = append(r.Suggestion, "hits are concentrated on "+f2(float64(h.DistinctHost))+" host(s): consider a scoped, expiring exception (POST /v1/exceptions) rather than editing the rule")
	}
	if h.Trend == "up" {
		r.Suggestion = append(r.Suggestion, "volume is rising: check for newly deployed benign software or a changed baseline before retuning")
	}
	if len(r.Suggestion) == 0 {
		r.Suggestion = append(r.Suggestion, "review the rule's most frequent matches with the detection lab (/v1/ml/synthesize can draft a tighter candidate)")
	}
	return r
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildFatigue(findings []Finding, now time.Time, fb map[string]RulePrecision) []FatigueResult {
	var out []FatigueResult
	for _, h := range BuildRuleHealth(findings, nil, nil, now) {
		if h.HitsTotal == 0 {
			continue
		}
		out = append(out, fatigueFor(h, fb[h.Rule]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Status == "ok") != (out[j].Status == "ok") {
			return out[i].Status == "ok"
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
