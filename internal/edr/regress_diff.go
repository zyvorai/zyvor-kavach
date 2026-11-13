// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// RegressChange is one scenario or technique whose outcome moved between two snapshots.
type RegressChange struct {
	Kind        string   `json:"kind"` // scenario | technique
	ID          string   `json:"id"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Rules       []string `json:"rules,omitempty"`        // rules that fired for it in the reference snapshot
	LikelyCause []string `json:"likely_cause,omitempty"` // HINT only
}

// RegressLifecycle is a rule lifecycle change (rule-health) inside the window.
type RegressLifecycle struct {
	Rule   string `json:"rule"`
	Time   string `json:"time"`
	Actor  string `json:"actor,omitempty"`
	Detail string `json:"detail"`
}

// RegressDiff compares two consecutive (or chosen) snapshots.
type RegressDiff struct {
	Note             string             `json:"note"`
	AttributionNote  string             `json:"attribution_note"`
	FromSeq          int                `json:"from_seq"`
	ToSeq            int                `json:"to_seq"`
	FromTime         string             `json:"from_time"`
	ToTime           string             `json:"to_time"`
	ContentChanged   bool               `json:"content_changed"`
	ContentDetail    bool               `json:"content_detail_available"`
	Incomplete       bool               `json:"incomplete,omitempty"` // either run hit its runtime bound
	Regressions      []RegressChange    `json:"regressions"`
	Improvements     []RegressChange    `json:"improvements"`
	ScenariosAdded   []string           `json:"scenarios_added"`
	ScenariosRemoved []string           `json:"scenarios_removed"`
	NewBenignFP      []string           `json:"new_benign_false_positives"`
	ResolvedBenignFP []string           `json:"resolved_benign_false_positives"`
	TacticDelta      []map[string]any   `json:"tactic_delta"`
	CoverageDeltaPct float64            `json:"measured_detected_pct_delta"`
	RulesAdded       []string           `json:"rules_added"`
	RulesRemoved     []string           `json:"rules_removed"`
	RulesModified    []string           `json:"rules_modified"`
	LifecycleChanges []RegressLifecycle `json:"lifecycle_changes"`
}

// regressDiffInput carries what attribution needs; both content blobs may be nil (pruned).
type regressDiffInput struct {
	Prev, Cur               RegressSnapshot
	PrevContent, CurContent *regressContent
	Lifecycle               []RegressLifecycle
}

func rankOf(s string) int { return valStatusRank[s] } // 0 for non-ranked statuses

func regressRound1(f float64) float64 { return math.Round(f*10) / 10 }

// regressDiffSnapshots is pure: no clock, no IO.
func regressDiffSnapshots(in regressDiffInput) RegressDiff {
	p, c := in.Prev, in.Cur
	d := RegressDiff{Note: regressNote,
		AttributionNote: "likely_cause is a hint derived by joining the content-version diff and rule lifecycle history with the rules that fired before; it is not proof of causation.",
		FromSeq:         p.Seq, ToSeq: c.Seq, FromTime: p.Time, ToTime: c.Time,
		ContentChanged: p.ContentHash != c.ContentHash, Incomplete: p.Truncated || c.Truncated,
		Regressions: []RegressChange{}, Improvements: []RegressChange{}, ScenariosAdded: []string{}, ScenariosRemoved: []string{},
		NewBenignFP: []string{}, ResolvedBenignFP: []string{}, TacticDelta: []map[string]any{},
		RulesAdded: []string{}, RulesRemoved: []string{}, RulesModified: []string{}, LifecycleChanges: in.Lifecycle,
		CoverageDeltaPct: regressRound1(c.MeasuredDetectedPct - p.MeasuredDetectedPct)}
	if d.LifecycleChanges == nil {
		d.LifecycleChanges = []RegressLifecycle{}
	}

	var cd *ContentDiff
	if d.ContentChanged && in.PrevContent != nil && in.CurContent != nil {
		x := diffSnapshots(in.PrevContent.Snap, in.CurContent.Snap)
		cd = &x
		d.ContentDetail = true
		for _, a := range x.Added {
			d.RulesAdded = append(d.RulesAdded, a.ID)
		}
		for _, a := range x.Removed {
			d.RulesRemoved = append(d.RulesRemoved, a.ID)
		}
		for _, a := range x.Modified {
			d.RulesModified = append(d.RulesModified, a.ID)
		}
		sort.Strings(d.RulesAdded)
		sort.Strings(d.RulesRemoved)
		sort.Strings(d.RulesModified)
	}

	attribute := func(id string, rules []string, scenarioKind bool) []string {
		return regressCauses(id, rules, scenarioKind, d, cd, in)
	}
	for id, to := range c.Scenarios {
		from, ok := p.Scenarios[id]
		if !ok {
			d.ScenariosAdded = append(d.ScenariosAdded, id)
			if to == "benign_fp" {
				d.NewBenignFP = append(d.NewBenignFP, id)
			}
			continue
		}
		switch {
		case from == "benign_ok" && to == "benign_fp":
			d.NewBenignFP = append(d.NewBenignFP, id)
		case from == "benign_fp" && to == "benign_ok":
			d.ResolvedBenignFP = append(d.ResolvedBenignFP, id)
		case rankOf(from) > 0 && rankOf(to) > 0 && rankOf(to) < rankOf(from):
			d.Regressions = append(d.Regressions, RegressChange{"scenario", id, from, to, p.ScenarioRules[id], attribute(id, p.ScenarioRules[id], true)})
		case rankOf(from) > 0 && rankOf(to) > rankOf(from):
			d.Improvements = append(d.Improvements, RegressChange{"scenario", id, from, to, c.ScenarioRules[id], attribute(id, c.ScenarioRules[id], true)})
		}
	}
	for id := range p.Scenarios {
		if _, ok := c.Scenarios[id]; !ok {
			d.ScenariosRemoved = append(d.ScenariosRemoved, id)
		}
	}
	for id, to := range c.Techniques {
		from, ok := p.Techniques[id]
		if !ok {
			continue
		}
		switch {
		case rankOf(from) > 0 && rankOf(to) > 0 && rankOf(to) < rankOf(from):
			d.Regressions = append(d.Regressions, RegressChange{"technique", id, from, to, p.TechRules[id], attribute(id, p.TechRules[id], false)})
		case rankOf(from) > 0 && rankOf(to) > rankOf(from):
			d.Improvements = append(d.Improvements, RegressChange{"technique", id, from, to, c.TechRules[id], attribute(id, c.TechRules[id], false)})
		}
	}
	prevTac := map[string]RegressTactic{}
	for _, t := range p.Tactics {
		prevTac[t.Tactic] = t
	}
	for _, t := range c.Tactics {
		if o, ok := prevTac[t.Tactic]; ok && o.MeasuredPct != t.MeasuredPct {
			d.TacticDelta = append(d.TacticDelta, map[string]any{"tactic": t.Tactic, "from_pct": o.MeasuredPct, "to_pct": t.MeasuredPct, "delta_pct": regressRound1(t.MeasuredPct - o.MeasuredPct)})
		}
	}
	for _, s := range [][]string{d.ScenariosAdded, d.ScenariosRemoved, d.NewBenignFP, d.ResolvedBenignFP} {
		sort.Strings(s)
	}
	for _, cs := range [][]RegressChange{d.Regressions, d.Improvements} {
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].Kind != cs[j].Kind {
				return cs[i].Kind < cs[j].Kind
			}
			return cs[i].ID < cs[j].ID
		})
	}
	return d
}

func regressCauses(id string, rules []string, scenarioKind bool, d RegressDiff, cd *ContentDiff, in regressDiffInput) []string {
	var out []string
	changes := map[string]ContentChange{}
	kind := map[string]string{}
	if cd != nil {
		for _, a := range cd.Removed {
			changes[a.ID], kind[a.ID] = a, "removed"
		}
		for _, a := range cd.Modified {
			changes[a.ID], kind[a.ID] = a, "modified"
		}
		for _, a := range cd.Added {
			if _, dup := changes[a.ID]; !dup {
				changes[a.ID], kind[a.ID] = a, "added"
			}
		}
	}
	sevOf := func(c *regressContent, r string) string {
		if c == nil {
			return ""
		}
		return c.Sev[r]
	}
	for _, r := range rules {
		if k, ok := kind[r]; ok {
			s := fmt.Sprintf("rule %s %s", r, k)
			if k == "modified" {
				var det []string
				if a, b := sevOf(in.PrevContent, r), sevOf(in.CurContent, r); a != "" && b != "" && a != b {
					det = append(det, fmt.Sprintf("severity %s -> %s", a, b))
				}
				for _, h := range changes[r].Highlight {
					if h != "severity" {
						det = append(det, h+" changed")
					}
				}
				if len(det) == 0 && len(changes[r].Fields) > 0 {
					det = append(det, "fields: "+strings.Join(changes[r].Fields, ","))
				}
				if len(det) > 0 {
					s += " (" + strings.Join(det, "; ") + ")"
				}
			}
			out = append(out, s)
		}
		for _, l := range d.LifecycleChanges {
			if l.Rule == r {
				out = append(out, fmt.Sprintf("rule %s lifecycle: %s", r, l.Detail))
			}
		}
	}
	if scenarioKind {
		if k, ok := kind[id]; ok && changes[id].Kind == "scenario" {
			out = append(out, fmt.Sprintf("scenario definition %s", k))
		}
	}
	if len(out) == 0 {
		switch {
		case !d.ContentChanged:
			out = append(out, "no embedded content change between the two runs; consider engine/built-in rule code or environment changes")
		case cd == nil:
			out = append(out, "embedded content changed but the per-rule content detail is no longer retained for one of the snapshots")
		default:
			out = append(out, fmt.Sprintf("embedded content changed (%d added, %d removed, %d modified) but none of the rules that fired before; possibly an indirect or built-in rule effect",
				len(cd.Added), len(cd.Removed), len(cd.Modified)))
		}
	}
	return out
}

// regressLifecycleWindow reads rule-health lifecycle history entries in (from, to].
func regressLifecycleWindow(from, to time.Time) []RegressLifecycle {
	s := ruleSvc.Load()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RegressLifecycle
	for _, h := range s.d.History {
		if h.Action == "lifecycle" && h.Time.After(from) && !h.Time.After(to) {
			out = append(out, RegressLifecycle{h.Rule, h.Time.UTC().Format(time.RFC3339), h.Actor, h.Detail})
		}
	}
	return out
}
