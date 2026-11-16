// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"sort"
	"strings"
)

const provLinkHops = 6 // max directed distance at which two hits are treated as one story

// reach does a bounded forward BFS over causal edges (edge direction: parent -> child,
// process -> destination/file). It records predecessor pointers so path nodes can be
// recovered. Hubs are entered but never expanded (except as the start), which is what
// keeps shared ancestors such as init or a login daemon from fusing unrelated stories.
func (g *ProvGraph) reach(start string, hops int) (dist map[string]int, pred map[string]string) {
	dist = map[string]int{start: 0}
	pred = map[string]string{}
	q := []string{start}
	for len(q) > 0 && len(dist) < provVisitCap {
		cur := q[0]
		q = q[1:]
		if dist[cur] >= hops || (cur != start && g.isHub(cur)) {
			continue
		}
		for _, ei := range g.out[cur] {
			nb := g.Edges[ei].To
			if _, ok := dist[nb]; ok {
				continue
			}
			dist[nb] = dist[cur] + 1
			pred[nb] = cur
			q = append(q, nb)
		}
	}
	return dist, pred
}

// propagate computes the HOLMES-style bounded threat score: each hit's weight flows to
// causal descendants (forward only), decaying by provDecay per hop; a node keeps the
// maximum over sources, so scores never accumulate without bound.
func (g *ProvGraph) propagate() map[string]float64 {
	score := map[string]float64{}
	for _, h := range g.hits {
		dist, _ := g.reach(h.node, provHops)
		for id, d := range dist {
			if v := h.weight * math.Pow(provDecay, float64(d)); v > score[id] {
				score[id] = v
			}
		}
	}
	return score
}

// NodeScores exposes the propagated per-node threat score (for tests and inspection).
func (g *ProvGraph) NodeScores() map[string]float64 { return g.propagate() }

// Stories returns ranked connected sub-graphs containing rule hits. Two hits belong to the
// same story when one is causally downstream of the other within provLinkHops; sibling
// relations through a common ancestor do not link them.
func (g *ProvGraph) Stories(rar *ProvRarity, minScore float64) []ProvStory {
	if len(g.hits) == 0 {
		return []ProvStory{}
	}
	n := len(g.hits)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	byNode := map[string][]int{}
	for i, h := range g.hits {
		byNode[h.node] = append(byNode[h.node], i)
	}
	// story path nodes: hit index -> nodes on paths to related downstream hits
	pathNodes := make([]map[string]bool, n)
	for i, h := range g.hits {
		pathNodes[i] = map[string]bool{h.node: true}
		dist, pred := g.reach(h.node, provLinkHops)
		for id := range dist {
			for _, j := range byNode[id] {
				if j == i {
					continue
				}
				ra, rb := find(i), find(j)
				if ra != rb {
					if ra < rb {
						parent[rb] = ra
					} else {
						parent[ra] = rb
					}
				}
				for c := id; c != ""; c = pred[c] {
					pathNodes[i][c] = true
					if c == h.node {
						break
					}
				}
			}
		}
	}
	comps := map[int][]int{}
	for i := range g.hits {
		comps[find(i)] = append(comps[find(i)], i)
	}
	node := g.propagate()
	var out []ProvStory
	for _, idxs := range comps {
		sort.Ints(idxs)
		inStory := map[string]bool{}
		for _, i := range idxs {
			for id := range pathNodes[i] {
				inStory[id] = true
			}
		}
		ids := make([]string, 0, len(inStory))
		for id := range inStory {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		hits := make([]provHit, 0, len(idxs))
		for _, i := range idxs {
			hits = append(hits, g.hits[i])
		}
		sort.SliceStable(hits, func(i, j int) bool {
			if !hits[i].time.Equal(hits[j].time) {
				return hits[i].time.Before(hits[j].time)
			}
			return hits[i].finding < hits[j].finding
		})
		st := ProvStory{Host: g.Host, Nodes: ids}
		stage := map[int]float64{}
		var seq []int
		sev := 0.0
		for _, h := range hits {
			st.Hits = append(st.Hits, ProvStoryHit{Rule: h.rule, Tactic: h.tactic, Severity: h.severity, FindingID: h.finding, Node: h.node, Time: h.time})
			// a hit inherits decayed suspicion from causal ancestors (node score excludes
			// its own full weight only when an ancestor is stronger)
			w := math.Max(h.weight, node[h.node])
			if h.tIdx >= 0 {
				if w > stage[h.tIdx] {
					stage[h.tIdx] = w
				}
				seq = append(seq, h.tIdx)
			} else if w > sev {
				sev = w // unmapped rule: severity only, no tactic credit
			}
		}
		sum := sev
		var tidx []int
		for ti, w := range stage {
			sum += w
			tidx = append(tidx, ti)
		}
		sort.Ints(tidx)
		for _, ti := range tidx {
			st.Tactics = append(st.Tactics, attackTactics[ti])
		}
		st.OrderedRun = provLIS(seq)
		mult := 1.0
		if len(tidx) > 1 {
			mult += provDiversityK * float64(len(tidx)-1)
		}
		if st.OrderedRun > 1 {
			mult *= 1 + provOrderK*float64(st.OrderedRun-1)
		}
		st.Score = round3(sum * mult)
		st.First, st.Last = hits[0].time, hits[len(hits)-1].time
		st.RarePaths = g.rarePaths(inStory, rar)
		for _, p := range st.RarePaths {
			if p.Bits > st.MaxRarity {
				st.MaxRarity = p.Bits
			}
		}
		st.MaxRarity = round3(st.MaxRarity)
		st.ID = "story-" + provID(g.Host, ids[0], strings.Join(st.Tactics, ","))
		if st.Score >= minScore {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].MaxRarity != out[j].MaxRarity {
			return out[i].MaxRarity > out[j].MaxRarity
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > provMaxStories {
		out = out[:provMaxStories]
	}
	if out == nil {
		out = []ProvStory{}
	}
	return out
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// provLIS is the longest strictly increasing subsequence length (n is small).
func provLIS(a []int) int {
	if len(a) > provMaxHits {
		a = a[:provMaxHits]
	}
	best := 0
	dp := make([]int, len(a))
	for i := range a {
		dp[i] = 1
		for j := 0; j < i; j++ {
			if a[j] < a[i] && dp[j]+1 > dp[i] {
				dp[i] = dp[j] + 1
			}
		}
		if dp[i] > best {
			best = dp[i]
		}
	}
	return best
}
