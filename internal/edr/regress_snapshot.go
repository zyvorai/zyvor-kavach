// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Continuous control validation: the runner replays the whole validation-lab scenario set in memory
// (side-effect free) and records a result snapshot, so a later run can be diffed against it.
// Observation only. Scenarios are Kavach's own synthetic data; see docs/regression-tracking.md.

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

const (
	regressHistoryCap  = 90
	regressContentCap  = 20 // distinct trimmed content snapshots retained for cause attribution
	regressDefaultTime = "03:00"
	regressNote        = "Synthetic data replayed in memory; measured on Kavach's own scenarios (one variant per technique); not a guarantee against real attacks. Cause attribution is a hint, not proof."
)

// RegressTactic is the measured coverage of one tactic at snapshot time.
type RegressTactic struct {
	Tactic      string  `json:"tactic"`
	Claimed     int     `json:"claimed"`
	Detected    int     `json:"detected"`
	Partial     int     `json:"partial"`
	Missed      int     `json:"missed"`
	MeasuredPct float64 `json:"measured_pct"`
}

// RegressSnapshot is the result of one full scenario run.
type RegressSnapshot struct {
	Seq         int    `json:"seq"`
	Time        string `json:"time"`
	Trigger     string `json:"trigger"` // schedule | manual | startup
	ContentHash string `json:"content_hash"`
	Build       string `json:"build,omitempty"`
	RuntimeMS   int64  `json:"runtime_ms"`
	Truncated   bool   `json:"truncated,omitempty"` // runtime bound hit; not all scenarios ran

	// Scenarios: id -> detected | partial | missed (non-benign), benign_ok | benign_fp (benign).
	Scenarios     map[string]string   `json:"scenarios"`
	ScenarioRules map[string][]string `json:"scenario_rules,omitempty"` // rule ids that fired per scenario
	Techniques    map[string]string   `json:"techniques"`               // claimed techniques: detected|partial|missed|not_testable|untested
	TechRules     map[string][]string `json:"technique_rules,omitempty"`
	Tactics       []RegressTactic     `json:"tactics"`

	MeasuredDetectedPct float64  `json:"measured_detected_pct"`
	DetectRate          float64  `json:"scenario_detect_rate"`
	BenignControls      int      `json:"benign_controls"`
	BenignFP            []string `json:"benign_false_positives"`
}

// regressContent is the trimmed content snapshot kept so a later diff can name changed rules.
type regressContent struct {
	Snap ContentSnapshot   `json:"snap"`
	Sev  map[string]string `json:"severity,omitempty"` // detection rule id -> severity
}

// RegressConfig is the operator-tunable configuration.
type RegressConfig struct {
	Enabled         bool   `json:"enabled"`
	Time            string `json:"time"`                  // HH:MM UTC
	MaxRuntimeSec   int    `json:"max_runtime_sec"`       // 5..300
	AlertMinRegress int    `json:"alert_min_regressions"` // record a finding at or above this many regressions (0 = never for regressions)
	AlertMediumAt   int    `json:"alert_medium_at"`       // severity medium at or above this many regressions
	AlertOnBenignFP bool   `json:"alert_on_benign_fp"`
}

func defaultRegressConfig() RegressConfig {
	return RegressConfig{Enabled: true, Time: regressDefaultTime, MaxRuntimeSec: 60, AlertMinRegress: 1, AlertMediumAt: 3, AlertOnBenignFP: true}
}

type regressFile struct {
	Config       RegressConfig             `json:"config"`
	Snapshots    []RegressSnapshot         `json:"snapshots"`
	Contents     map[string]regressContent `json:"contents"`
	ContentOrder []string                  `json:"content_order,omitempty"`
	NextSeq      int                       `json:"next_seq"`
}

func scenarioOutcome(r ValResult) string {
	if r.Benign {
		if r.FalsePositive {
			return "benign_fp"
		}
		return "benign_ok"
	}
	worst := 4
	for _, o := range r.Outcomes {
		if rk, ok := valStatusRank[o.Status]; ok && rk < worst {
			worst = rk
		}
	}
	switch worst {
	case 3:
		return "detected"
	case 2:
		return "partial"
	case 1:
		return "missed"
	}
	if r.Pass {
		return "detected"
	}
	return "missed"
}

// buildRegressSnapshot turns replay results into a snapshot (pure; no clock, no IO).
func buildRegressSnapshot(scs []ValScenario, results []ValResult, nt map[string]string, contentHash string) RegressSnapshot {
	cov := BuildValidationCoverage(scs, results, nt, ValOptions{})
	s := RegressSnapshot{ContentHash: contentHash, Scenarios: map[string]string{}, ScenarioRules: map[string][]string{},
		Techniques: map[string]string{}, TechRules: map[string][]string{}, BenignFP: []string{}}
	for _, r := range results {
		s.Scenarios[r.ID] = scenarioOutcome(r)
		seen := map[string]bool{}
		var rules []string
		for _, f := range r.Fired {
			if !seen[f.Rule] {
				seen[f.Rule] = true
				rules = append(rules, f.Rule)
			}
		}
		sort.Strings(rules)
		if len(rules) > 0 {
			s.ScenarioRules[r.ID] = rules
		}
		if r.Benign {
			s.BenignControls++
			if r.FalsePositive {
				s.BenignFP = append(s.BenignFP, r.ID)
			}
		}
	}
	sort.Strings(s.BenignFP)
	if t, ok := cov["by_technique"].([]ValTechScore); ok {
		for _, x := range t {
			if !x.Claimed {
				continue
			}
			s.Techniques[x.ID] = x.Status
			if len(x.Rules) > 0 {
				s.TechRules[x.ID] = x.Rules
			}
		}
	}
	if t, ok := cov["by_tactic"].([]ValTacticScore); ok {
		for _, x := range t {
			s.Tactics = append(s.Tactics, RegressTactic{x.Tactic, x.Claimed, x.Detected, x.Partial, x.Missed, x.MeasuredPct})
		}
	}
	if v, ok := cov["measured_detected_pct"].(float64); ok {
		s.MeasuredDetectedPct = v
	}
	if m, ok := cov["scenarios"].(map[string]any); ok {
		if v, ok := m["detect_rate"].(float64); ok {
			s.DetectRate = v
		}
	}
	return s
}

// trimContent keeps only the item-level data that cause attribution needs.
func trimContent(c ContentSnapshot) ContentSnapshot {
	out := ContentSnapshot{Seq: c.Seq, Time: c.Time, Build: c.Build, Hash: c.Hash, Total: c.Total, ByKind: c.ByKind}
	for _, p := range c.Packs {
		if p.Kind == "detection" || p.Kind == "bytes" || p.Kind == "scenario" {
			out.Packs = append(out.Packs, p)
		}
	}
	return out
}

func detectionSeverities() map[string]string {
	m := map[string]string{}
	for id, r := range valRegistry(ValOptions{}).byID {
		m[id] = r.Severity
	}
	return m
}

func loadRegressFile(path string) regressFile {
	f := regressFile{Config: defaultRegressConfig(), Contents: map[string]regressContent{}, NextSeq: 1}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var g regressFile
			if json.Unmarshal(b, &g) == nil {
				f = g
			}
		}
	}
	if f.Contents == nil {
		f.Contents = map[string]regressContent{}
	}
	if f.NextSeq < 1 {
		f.NextSeq = 1
	}
	for _, s := range f.Snapshots {
		if s.Seq >= f.NextSeq {
			f.NextSeq = s.Seq + 1
		}
	}
	if f.Config.Time == "" {
		f.Config = defaultRegressConfig()
	}
	return f
}

func saveRegressFile(path string, f regressFile) {
	if path == "" {
		return
	}
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func parseRegressTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}
