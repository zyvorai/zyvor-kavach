// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	provHops        = 3   // propagation radius from a hit
	provDecay       = 0.6 // per-hop retention of a propagated score
	provActivate    = 1.0 // propagated score needed for a node to join a story
	provHubDegree   = 25  // nodes with more edges than this are not traversed through
	provMaxHits     = 500 // hits considered per host
	provVisitCap    = 300 // nodes visited per propagation source
	provTopPaths    = 3
	provMaxStories  = 50
	provDiversityK  = 0.5  // story multiplier per extra distinct tactic
	provOrderK      = 0.25 // story multiplier per extra step in kill-chain order
	provMinRegular  = 1e-6
	provSmoothAlpha = 0.5
)

// provLineageSource lets the behaviour model supply learned parent->child exe-basename
// transition counts (count of parent->child, total children of parent). It is nil by
// default; when nil or when it reports ok=false, transitions are counted from the
// retained store. Set it from wiring code; this package does not edit the model file.
var provLineageSource func(host, parentBase, childBase string) (count, parentTotal int, ok bool)

var provSevWeight = map[string]float64{"info": 1, "low": 2, "medium": 6, "high": 8, "critical": 10}

type provHit struct {
	node     string
	rule     string
	tactic   string
	tIdx     int // kill-chain index, -1 if the rule has no ATT&CK mapping
	weight   float64
	severity string
	time     time.Time
	finding  string
}

func provTacticIndex(name string) int {
	for i, t := range attackTactics {
		if t == name {
			return i
		}
	}
	return -1
}

// provTacticOf maps a rule to its ATT&CK tactic using the built-in table, then content rules.
func provTacticOf(rule string) string {
	if m, ok := mitreFor(rule); ok {
		return m.Tactic
	}
	return ""
}

func (g *ProvGraph) attachFindings(b *provBuilder, findings []Finding) {
	var fs []Finding
	for _, f := range findings {
		if f.Host == g.Host {
			fs = append(fs, f)
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if !fs[i].Time.Equal(fs[j].Time) {
			return fs[i].Time.Before(fs[j].Time)
		}
		return fs[i].ID < fs[j].ID
	})
	if len(fs) > provMaxHits {
		g.Missing.EventsIgnoredByCaps += len(fs) - provMaxHits
		fs = fs[len(fs)-provMaxHits:]
	}
	for _, f := range fs {
		pid := f.PID
		if pid <= 0 {
			pid = f.Evidence.PID
		}
		id := ""
		if pid > 0 {
			if f.Evidence.ProcessStart != "" {
				id = b.find(g.Host, pid, f.Evidence.ProcessStart, "", f.Time)
			}
			if id == "" {
				id = b.find(g.Host, pid, "", "", f.Time)
			}
			if id == "" { // finding timestamp can precede the first poll of the process
				id = b.find(g.Host, pid, "", "", f.Time.Add(24*time.Hour))
			}
		}
		if id == "" {
			g.Missing.FindingsUnattached++
			continue
		}
		g.Nodes[id].Findings = append(g.Nodes[id].Findings, f.ID)
		tac := provTacticOf(f.Rule)
		w := provSevWeight[strings.ToLower(f.Severity)]
		if w == 0 {
			w = 2
		}
		g.hits = append(g.hits, provHit{node: id, rule: f.Rule, tactic: tac, tIdx: provTacticIndex(tac), weight: w,
			severity: f.Severity, time: f.Time, finding: f.ID})
	}
}

func (g *ProvGraph) isHub(id string) bool { return len(g.out[id])+len(g.in[id]) > provHubDegree }

func (g *ProvGraph) neighbours(id string) []string {
	var r []string
	for _, i := range g.out[id] {
		r = append(r, g.Edges[i].To)
	}
	for _, i := range g.in[id] {
		r = append(r, g.Edges[i].From)
	}
	sort.Strings(r)
	return r
}

type ProvStoryHit struct {
	Rule      string    `json:"rule"`
	Tactic    string    `json:"tactic,omitempty"`
	Severity  string    `json:"severity"`
	FindingID string    `json:"finding_id"`
	Node      string    `json:"node"`
	Time      time.Time `json:"time"`
}

type ProvPath struct {
	Bits  float64  `json:"rarity_bits"`
	Steps []string `json:"steps"`
}

type ProvStory struct {
	ID         string         `json:"id"`
	Host       string         `json:"host"`
	Score      float64        `json:"score"`
	Tactics    []string       `json:"tactics"` // kill-chain order
	OrderedRun int            `json:"kill_chain_ordered_steps"`
	Hits       []ProvStoryHit `json:"hits"`
	Nodes      []string       `json:"nodes"`
	First      time.Time      `json:"first"`
	Last       time.Time      `json:"last"`
	RarePaths  []ProvPath     `json:"rare_paths"`
	MaxRarity  float64        `json:"max_path_rarity_bits"`
}

// ---- path rarity (ProvDetector-style) ----

// ProvRarity holds transition counts: kind|src -> dst -> count.
type ProvRarity struct {
	counts map[string]map[string]int
	totals map[string]int
	vocab  map[string]map[string]struct{}
	Source string // "behaviour-model" or "retained-store"
}

func provEdgeLabel(g *ProvGraph, e ProvEdge) (key, src, dst string) {
	from, to := g.Nodes[e.From], g.Nodes[e.To]
	if from == nil || to == nil {
		return "", "", ""
	}
	src = provBase(from.Exe)
	switch e.Kind {
	case provEdgeSpawn:
		dst = provBase(to.Exe)
	case provEdgeConn:
		dst = to.Label
	default:
		dst = path.Dir(strings.ReplaceAll(to.Label, "\\", "/"))
	}
	return e.Kind + "|" + src, src, dst
}

// NewProvRarity tallies transitions over the given per-host graphs (the retained store).
func NewProvRarity(graphs []*ProvGraph) *ProvRarity {
	r := &ProvRarity{counts: map[string]map[string]int{}, totals: map[string]int{}, vocab: map[string]map[string]struct{}{}, Source: "retained-store"}
	for _, g := range graphs {
		for _, e := range g.Edges {
			k, _, dst := provEdgeLabel(g, e)
			if k == "" {
				continue
			}
			if r.counts[k] == nil {
				r.counts[k] = map[string]int{}
				r.vocab[k] = map[string]struct{}{}
			}
			r.counts[k][dst]++
			r.totals[k]++
			r.vocab[k][dst] = struct{}{}
		}
	}
	return r
}

// bits returns -log2 regularity of an edge. Store counts are leave-one-out so the edge
// being scored does not make itself look common.
func (r *ProvRarity) bits(g *ProvGraph, e ProvEdge) float64 {
	k, src, dst := provEdgeLabel(g, e)
	if k == "" {
		return 0
	}
	var cnt, tot, voc int
	if e.Kind == provEdgeSpawn && provLineageSource != nil {
		if c, t, ok := provLineageSource(g.Host, src, dst); ok {
			cnt, tot, voc = c, t, len(r.vocab[k])
			r.Source = "behaviour-model"
			return provBits(cnt, tot, voc)
		}
	}
	cnt, tot, voc = r.counts[k][dst]-1, r.totals[k]-1, len(r.vocab[k])
	if cnt < 0 {
		cnt = 0
	}
	if tot < 0 {
		tot = 0
	}
	return provBits(cnt, tot, voc)
}

func provBits(cnt, tot, voc int) float64 {
	p := (float64(cnt) + provSmoothAlpha) / (float64(tot) + provSmoothAlpha*float64(voc+1))
	if p < provMinRegular {
		p = provMinRegular
	}
	return -math.Log2(p)
}

// rarePaths returns the provProvTopPaths root-to-leaf paths within the story with the
// largest summed edge rarity (sum of -log2 regularity), as in ProvDetector's path selection.
func (g *ProvGraph) rarePaths(in map[string]bool, rar *ProvRarity) []ProvPath {
	if rar == nil {
		return []ProvPath{}
	}
	hasIn := map[string]bool{}
	for _, e := range g.Edges {
		if in[e.From] && in[e.To] {
			hasIn[e.To] = true
		}
	}
	var roots []string
	for id := range in {
		if !hasIn[id] {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	var paths []ProvPath
	budget := 5000
	var dfs func(id string, bits float64, steps []string, onPath map[string]bool)
	dfs = func(id string, bits float64, steps []string, onPath map[string]bool) {
		budget--
		if budget < 0 {
			return
		}
		leaf := true
		for _, ei := range g.out[id] {
			e := g.Edges[ei]
			if !in[e.To] || onPath[e.To] {
				continue
			}
			leaf = false
			onPath[e.To] = true
			dfs(e.To, bits+rar.bits(g, e), append(append([]string(nil), steps...), provStep(g, e)), onPath)
			delete(onPath, e.To)
		}
		if leaf && len(steps) > 0 {
			paths = append(paths, ProvPath{Bits: round3(bits), Steps: steps})
		}
	}
	for _, r := range roots {
		dfs(r, 0, nil, map[string]bool{r: true})
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Bits != paths[j].Bits {
			return paths[i].Bits > paths[j].Bits
		}
		return strings.Join(paths[i].Steps, ">") < strings.Join(paths[j].Steps, ">")
	})
	if len(paths) > provTopPaths {
		paths = paths[:provTopPaths]
	}
	if paths == nil {
		paths = []ProvPath{}
	}
	return paths
}

func provStep(g *ProvGraph, e ProvEdge) string {
	_, src, dst := provEdgeLabel(g, e)
	return e.Kind + ":" + src + "->" + dst
}
