// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// TTP similarity model: a document-frequency weighted (TF-IDF style) technique model built from the
// embedded adversary profiles at init() time. Read-only analytics; a similarity score is a hunting
// aid and is NOT attribution. See docs/research-ttp.md for sources, evaluation and limits.

import (
	"math"
	"sort"
	"strings"
)

// ttpCaveats is attached to every /v1/ttp/* response.
var ttpCaveats = []string{
	"Similarity is NOT attribution. A high score means the observed techniques resemble a public profile, not that the same actor is responsible.",
	"TTPs are shared across actors: many groups, criminals and red teams use the same techniques, so overlap is weak evidence.",
	"Tools and techniques such as PowerShell, command shells and ingress tool transfer are commodity and appear in most profiles.",
	"Profiles are summaries of public reporting at medium confidence, incomplete and possibly stale; absent techniques are often just unreported.",
	"Adversaries can imitate other groups (false flags). Treat any ranking as a prompt to hunt and to gather stronger evidence, not as a conclusion.",
}

// ttpMinTechniques is the minimum number of distinct observed (parent-level) techniques needed to rank.
const ttpMinTechniques = 3

// ttpCommodityDF: techniques present in at least this share of profiles are treated as commodity.
const ttpCommodityDF = 0.25

type ttpProfile struct {
	ID, Name, Kind string
	Techs          map[string]struct{} // parent-level technique ids
	Raw            []string            // original ids (may include sub-techniques)
	vec            map[string]float64  // L2-normalised idf weights
}

type ttpModel struct {
	profiles []*ttpProfile
	df       map[string]int
	idf      map[string]float64
	n        int
}

var ttpDefault *ttpModel

func init() {
	list, err := Adversaries()
	if err != nil {
		return
	}
	ttpDefault = buildTTPModel(list)
}

// ttpParent rolls a sub-technique id (T1059.001) up to its parent (T1059).
func ttpParent(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

func buildTTPModel(list []AdversaryProfile) *ttpModel {
	m := &ttpModel{df: map[string]int{}, idf: map[string]float64{}, n: len(list)}
	for _, a := range list {
		p := &ttpProfile{ID: a.ID, Name: a.Name, Kind: a.Kind, Techs: map[string]struct{}{}, Raw: a.Techniques}
		for _, t := range a.Techniques {
			p.Techs[ttpParent(t)] = struct{}{}
		}
		for t := range p.Techs {
			m.df[t]++
		}
		m.profiles = append(m.profiles, p)
	}
	for t, d := range m.df {
		m.idf[t] = math.Log(float64(m.n+1)/float64(d+1)) + 1
	}
	for _, p := range m.profiles {
		p.vec = m.vector(p.Techs)
	}
	return m
}

// w is the weight of a technique; one unseen in any profile is treated as maximally rare.
func (m *ttpModel) w(t string) float64 {
	if v, ok := m.idf[t]; ok {
		return v
	}
	return math.Log(float64(m.n+1)) + 1
}

func (m *ttpModel) vector(set map[string]struct{}) map[string]float64 {
	v := map[string]float64{}
	var norm float64
	for t := range set {
		w := m.w(t)
		v[t] = w
		norm += w * w
	}
	norm = math.Sqrt(norm)
	if norm > 0 {
		for t := range v {
			v[t] /= norm
		}
	}
	return v
}

func (m *ttpModel) isCommodity(t string) bool {
	return m.n > 0 && float64(m.df[t])/float64(m.n) >= ttpCommodityDF
}

type ttpScore struct {
	P       *ttpProfile
	Cosine  float64
	WJac    float64
	Score   float64
	Overlap []string
	Missing []string // profile techniques not observed
}

// rank compares an observed parent-level set with every profile; sorted best first.
func (m *ttpModel) rank(obs map[string]struct{}) []ttpScore {
	ov := m.vector(obs)
	out := make([]ttpScore, 0, len(m.profiles))
	for _, p := range m.profiles {
		var dot, inter, union float64
		s := ttpScore{P: p}
		for t, a := range ov {
			if b, ok := p.vec[t]; ok {
				dot += a * b
			}
		}
		for t := range obs {
			w := m.w(t)
			union += w
			if _, ok := p.Techs[t]; ok {
				inter += w
				s.Overlap = append(s.Overlap, t)
			}
		}
		for t := range p.Techs {
			if _, ok := obs[t]; !ok {
				union += m.w(t)
				s.Missing = append(s.Missing, t)
			}
		}
		if union > 0 {
			s.WJac = inter / union
		}
		s.Cosine = dot
		s.Score = (s.Cosine + s.WJac) / 2
		sort.Strings(s.Overlap)
		sort.Strings(s.Missing)
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].P.ID < out[j].P.ID
	})
	return out
}

// confidence is deliberately conservative: never above "moderate", and only with enough informative
// (non-commodity) techniques, a decent score and a visible margin over the runner-up.
func (m *ttpModel) confidence(obs map[string]struct{}, ranked []ttpScore) (string, string) {
	if len(obs) < ttpMinTechniques {
		return "not_enough_evidence", "fewer than 3 distinct techniques observed (after sub-technique roll-up)"
	}
	if len(ranked) == 0 || ranked[0].Score == 0 {
		return "low", "no profile shares any observed technique"
	}
	informative := 0
	for t := range obs {
		if !m.isCommodity(t) {
			informative++
		}
	}
	top := ranked[0]
	margin := 0.0
	if len(ranked) > 1 {
		margin = top.Score - ranked[1].Score
	}
	if informative < 2 {
		return "low", "observed techniques are almost all commodity (present in >=25% of profiles)"
	}
	if informative >= 3 && len(top.Overlap) >= 4 && top.Score >= 0.45 && margin >= 0.05 {
		return "moderate", "several non-commodity techniques overlap and the top profile leads the runner-up; still not a conclusion"
	}
	return "low", "overlap is limited or several profiles score similarly"
}
