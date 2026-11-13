// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	provTraceHopsMax = 8
	provTraceNodeCap = 200
)

// ProvSubgraph is a traced sub-graph.
type ProvSubgraph struct {
	Nodes     []*ProvNode `json:"nodes"`
	Edges     []ProvEdge  `json:"edges"`
	Truncated bool        `json:"truncated"`
}

// Trace walks causal edges from start: "back" follows edges toward their sources,
// "fwd" toward their targets, "both" does both. Bounded by hops and node cap; the visit
// order is deterministic (edges are time-sorted).
func (g *ProvGraph) Trace(start, dir string, hops, nodeCap int) ProvSubgraph {
	if hops < 1 {
		hops = 3
	}
	if hops > provTraceHopsMax {
		hops = provTraceHopsMax
	}
	if nodeCap < 1 || nodeCap > provTraceNodeCap {
		nodeCap = provTraceNodeCap
	}
	res := ProvSubgraph{Nodes: []*ProvNode{}, Edges: []ProvEdge{}}
	if g.Nodes[start] == nil {
		return res
	}
	type item struct {
		id  string
		hop int
	}
	seen := map[string]bool{start: true}
	q := []item{{start, 0}}
	edgeSet := map[int]bool{}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.hop >= hops {
			continue
		}
		var idx []int
		if dir == "back" || dir == "both" {
			idx = append(idx, g.in[cur.id]...)
		}
		if dir == "fwd" || dir == "both" {
			idx = append(idx, g.out[cur.id]...)
		}
		sort.Ints(idx)
		for _, ei := range idx {
			e := g.Edges[ei]
			nb := e.From
			if nb == cur.id {
				nb = e.To
			}
			if !seen[nb] {
				if len(seen) >= nodeCap {
					res.Truncated = true
					continue
				}
				seen[nb] = true
				q = append(q, item{nb, cur.hop + 1})
			}
			edgeSet[ei] = true
		}
	}
	for id := range seen {
		res.Nodes = append(res.Nodes, g.Nodes[id])
	}
	sort.Slice(res.Nodes, func(i, j int) bool {
		if !res.Nodes[i].First.Equal(res.Nodes[j].First) {
			return res.Nodes[i].First.Before(res.Nodes[j].First)
		}
		return res.Nodes[i].ID < res.Nodes[j].ID
	})
	for ei := range edgeSet {
		e := g.Edges[ei]
		if seen[e.From] && seen[e.To] {
			res.Edges = append(res.Edges, e)
		}
	}
	sort.Slice(res.Edges, func(i, j int) bool {
		a, b := res.Edges[i], res.Edges[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return res
}

type provSnapshot struct {
	prevSnapshot
	files []FileEvent
}

func provTake(store *Store) provSnapshot {
	sn := provSnapshot{prevSnapshot: prevTake(store)}
	if store != nil {
		sn.files = store.ListFiles()
	}
	return sn
}

func (s provSnapshot) hosts() []string {
	set := map[string]struct{}{}
	for _, e := range s.events {
		set[e.Host] = struct{}{}
	}
	for _, e := range s.network {
		set[e.Host] = struct{}{}
	}
	for _, e := range s.files {
		set[e.Host] = struct{}{}
	}
	for _, e := range s.findings {
		set[e.Host] = struct{}{}
	}
	var out []string
	for h := range set {
		if h != "" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func (s provSnapshot) graph(host string, maxNodes int) *ProvGraph {
	return BuildProvGraph(host, s.events, s.network, s.files, s.findings, maxNodes)
}

func (s provSnapshot) rarity(maxNodes int) *ProvRarity {
	var gs []*ProvGraph
	for _, h := range s.hosts() {
		gs = append(gs, s.graph(h, maxNodes))
	}
	return NewProvRarity(gs)
}

func provEnvelope(extra map[string]any) map[string]any {
	extra["method"] = provMethod
	extra["limitations"] = provLimitations
	return extra
}

func provFloat(r *http.Request, name string, def float64) float64 {
	v, err := strconv.ParseFloat(r.URL.Query().Get(name), 64)
	if err != nil || v != v || v < 0 {
		return def
	}
	return v
}

// RegisterProvenance wires the observation-only provenance-graph routes.
func RegisterProvenance(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/prov/graph", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		sn := provTake(store)
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			prevWrite(w, provEnvelope(map[string]any{"error": "host is required", "hosts": sn.hosts()}))
			return
		}
		limit := prevIntParam(r, "limit", 500, 1, provHardNodes)
		g := sn.graph(host, limit)
		prevWrite(w, provEnvelope(map[string]any{
			"host": host, "node_cap": limit, "truncated": g.Truncated,
			"nodes": g.SortedNodes(), "edges": g.Edges, "missing": g.Missing,
		}))
	})
	mux.HandleFunc("GET /v1/prov/stories", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		sn := provTake(store)
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		minScore := provFloat(r, "min_score", 1)
		hosts := sn.hosts()
		var graphs []*ProvGraph
		for _, h := range hosts {
			graphs = append(graphs, sn.graph(h, provMaxNodes))
		}
		rar := NewProvRarity(graphs)
		stories := []ProvStory{}
		for _, g := range graphs {
			if host != "" && g.Host != host {
				continue
			}
			stories = append(stories, g.Stories(rar, minScore)...)
		}
		sort.SliceStable(stories, func(i, j int) bool {
			if stories[i].Score != stories[j].Score {
				return stories[i].Score > stories[j].Score
			}
			return stories[i].ID < stories[j].ID
		})
		if len(stories) > provMaxStories {
			stories = stories[:provMaxStories]
		}
		prevWrite(w, provEnvelope(map[string]any{
			"host": host, "min_score": minScore, "rarity_source": rar.Source,
			"stories": stories,
			"scoring": map[string]any{"hops": provHops, "decay": provDecay, "hub_degree": provHubDegree,
				"severity_weights": provSevWeight, "diversity_per_extra_tactic": provDiversityK, "order_per_extra_step": provOrderK},
		}))
	})
	mux.HandleFunc("GET /v1/prov/trace", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fid := r.URL.Query().Get("finding_id")
		dir := r.URL.Query().Get("dir")
		if dir == "" {
			dir = "back"
		}
		if dir != "back" && dir != "fwd" && dir != "both" {
			http.Error(w, "dir must be back, fwd or both", http.StatusBadRequest)
			return
		}
		hops := prevIntParam(r, "hops", 3, 1, provTraceHopsMax)
		sn := provTake(store)
		var host string
		for _, f := range sn.findings {
			if f.ID == fid {
				host = f.Host
				break
			}
		}
		if fid == "" || host == "" {
			http.Error(w, "finding not found", http.StatusNotFound)
			return
		}
		g := sn.graph(host, provMaxNodes)
		start := ""
		for _, n := range g.SortedNodes() {
			for _, id := range n.Findings {
				if id == fid {
					start = n.ID
				}
			}
		}
		if start == "" {
			prevWrite(w, provEnvelope(map[string]any{"finding_id": fid, "host": host, "attached": false,
				"reason": "finding could not be attached to an observed process (no pid match)", "nodes": []*ProvNode{}, "edges": []ProvEdge{}, "missing": g.Missing}))
			return
		}
		sub := g.Trace(start, dir, hops, provTraceNodeCap)
		prevWrite(w, provEnvelope(map[string]any{"finding_id": fid, "host": host, "attached": true, "start": start,
			"dir": dir, "hops": hops, "node_cap": provTraceNodeCap, "truncated": sub.Truncated,
			"nodes": sub.Nodes, "edges": sub.Edges, "missing": g.Missing}))
	})
	mux.HandleFunc("GET /v1/prov/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		sn := provTake(store)
		withPID := 0
		for _, n := range sn.network {
			if n.PID > 0 {
				withPID++
			}
		}
		fileWriter := 0
		for _, f := range sn.files {
			if f.PID > 0 {
				fileWriter++
			}
		}
		prevWrite(w, provEnvelope(map[string]any{
			"hosts": sn.hosts(),
			"inputs": map[string]any{"process_events": len(sn.events), "network_events": len(sn.network), "network_events_with_pid": withPID,
				"file_events": len(sn.files), "file_events_with_writer_pid": fileWriter, "findings": len(sn.findings)},
			"includes": []string{"process nodes (host, pid, process_start, exe)", "parent-child spawn edges", "process->destination connect edges (PID-attributed)", "process->file edges only where FileEvent.PID is set", "findings attached to processes by pid"},
			"lacks":    []string{"file read/write/exec syscall edges", "writer attribution for most file events", "inter-process IPC / injection edges", "events outside the retained window", "short-lived processes missed by polling"},
			"state":    "memory only; rebuilt from the retained store on every request",
			"caps":     map[string]any{"input_events_per_kind": provInputCap, "default_nodes": provMaxNodes, "max_nodes": provHardNodes, "trace_hops_max": provTraceHopsMax, "trace_nodes": provTraceNodeCap},
			"lineage_source": func() string {
				if provLineageSource != nil {
					return "behaviour-model (via provLineageSource) with store fallback"
				}
				return "retained-store (provLineageSource not wired)"
			}(),
		}))
	})
}
