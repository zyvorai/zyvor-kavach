// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Provenance-graph analysis (observation only). The graph is rebuilt from the retained
// store on every request; nothing is persisted and nothing is acted upon. See
// docs/research-provenance.md for the literature this follows and where it diverges.

const (
	provInputCap  = 50000 // newest events of each kind considered
	provMaxNodes  = 2000  // default node cap for a built graph
	provHardNodes = 5000
	provCmdClip   = 200
	provKindProc  = "process"
	provKindDest  = "destination"
	provKindFile  = "file"
	provEdgeSpawn = "spawn"
	provEdgeConn  = "connect"
	provEdgeFile  = "file"
	provMethod    = "provenance graph (process tree + pid-attributed network/file edges); HOLMES-style tactic score propagation with decay; ProvDetector-style transition rarity; bounded BFS tracing"
)

// provLimitations is attached to every response.
var provLimitations = []string{
	"Process-lifetime graph built from polled process, network and file telemetry; it is not a kernel audit graph and has no read/write/exec syscall edges.",
	"File events usually carry no writer PID, so process-to-file edges exist only where FileEvent.PID is set; most file activity is unattributed and absent from the graph.",
	"Network events attach to a process only when a PID is present and a matching process was observed; unmatched ones are counted, not guessed.",
	"Parent edges need the parent process to have been observed (pid reuse is handled heuristically by exe match and time order); missing parents are counted as unresolved.",
	"Polling can miss short-lived processes, so causal chains may have gaps; a gap splits a story into pieces rather than producing a false link.",
	"Graph size, hop count and node count are capped; high-fanout nodes (shells, init, daemons) are not traversed through, to limit dependency explosion, which can split a real chain.",
	"Scores are heuristic, derived from existing rule hits and severities; they are triage ranking, not a verdict. Rarity uses retained-store transition counts (leave-one-out); on a small or attacker-dominated store the baseline itself is unreliable.",
}

type ProvNode struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Host     string    `json:"host"`
	PID      int       `json:"pid,omitempty"`
	Start    string    `json:"process_start,omitempty"`
	Exe      string    `json:"exe,omitempty"`
	Command  string    `json:"command,omitempty"`
	Label    string    `json:"label,omitempty"` // destination or file path
	First    time.Time `json:"first_seen"`
	Events   int       `json:"events,omitempty"`
	Findings []string  `json:"finding_ids,omitempty"`
}

type ProvEdge struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	Kind string    `json:"kind"`
	Time time.Time `json:"time"`
	Verd string    `json:"verdict,omitempty"`
}

// ProvGraph is one host's graph plus accounting of what could not be linked.
type ProvGraph struct {
	Host      string
	Nodes     map[string]*ProvNode
	Edges     []ProvEdge
	out, in   map[string][]int // node id -> edge indexes
	Missing   ProvMissing
	Truncated bool // the node cap dropped nodes
	hits      []provHit
}

type ProvMissing struct {
	UnresolvedParents   int `json:"unresolved_parents"`
	NetworkNoProcess    int `json:"network_events_without_process"`
	NetworkNoPID        int `json:"network_events_without_pid"`
	FileEventsTotal     int `json:"file_events_total"`
	FileEventsNoWriter  int `json:"file_events_without_writer_pid"`
	FileNoProcess       int `json:"file_events_pid_not_matched"`
	FindingsUnattached  int `json:"findings_not_attached_to_process"`
	NodesDroppedByCap   int `json:"nodes_dropped_by_cap"`
	EventsIgnoredByCaps int `json:"events_ignored_by_input_cap"`
}

func provID(parts ...string) string {
	d := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(d[:6])
}

func provBase(exe string) string {
	exe = strings.ReplaceAll(exe, "\\", "/")
	return strings.ToLower(path.Base(exe))
}

type provCand struct {
	id    string
	first time.Time
	exe   string
	start string
}

type provBuilder struct {
	g     *ProvGraph
	cands map[string][]provCand // host|pid -> candidates
}

func (b *provBuilder) procNode(host string, pid int, start, exe, cmd string, t time.Time) *ProvNode {
	key := host + "|" + strconv.Itoa(pid) + "|" + start + "|" + exe
	id := "p-" + provID(key)
	n := b.g.Nodes[id]
	if n == nil {
		c := cmd
		if len(c) > provCmdClip {
			c = strings.ToValidUTF8(c[:provCmdClip], "")
		}
		n = &ProvNode{ID: id, Kind: provKindProc, Host: host, PID: pid, Start: start, Exe: exe, Command: c, First: t}
		b.g.Nodes[id] = n
		k := host + "|" + strconv.Itoa(pid)
		b.cands[k] = append(b.cands[k], provCand{id: id, first: t, exe: exe, start: start})
	} else if t.Before(n.First) {
		n.First = t
		for i := range b.cands[host+"|"+strconv.Itoa(pid)] {
			c := &b.cands[host+"|"+strconv.Itoa(pid)][i]
			if c.id == id {
				c.first = t
			}
		}
	}
	n.Events++
	return n
}

// find resolves (host,pid[,start]) at time t to a process node id, or "".
func (b *provBuilder) find(host string, pid int, start, exeHint string, t time.Time) string {
	cs := b.cands[host+"|"+strconv.Itoa(pid)]
	var best *provCand
	for i := range cs {
		c := &cs[i]
		if start != "" {
			if c.start == start {
				return c.id
			}
			continue
		}
		if exeHint != "" && c.exe != exeHint {
			continue
		}
		if c.first.After(t) {
			continue
		}
		if best == nil || c.first.After(best.first) || (c.first.Equal(best.first) && c.id > best.id) {
			best = c
		}
	}
	if best == nil {
		return ""
	}
	return best.id
}

func (g *ProvGraph) addEdge(from, to, kind string, t time.Time, verdict string) {
	g.Edges = append(g.Edges, ProvEdge{From: from, To: to, Kind: kind, Time: t, Verd: verdict})
}

// BuildProvGraph builds the graph for one host from retained telemetry. maxNodes<=0 uses
// the default. Output is deterministic for a given input.
func BuildProvGraph(host string, events []Event, network []NetworkEvent, files []FileEvent, findings []Finding, maxNodes int) *ProvGraph {
	if maxNodes <= 0 {
		maxNodes = provMaxNodes
	}
	if maxNodes > provHardNodes {
		maxNodes = provHardNodes
	}
	g := &ProvGraph{Host: host, Nodes: map[string]*ProvNode{}}
	b := &provBuilder{g: g, cands: map[string][]provCand{}}

	var evs []Event
	for _, e := range events {
		if e.Host == host {
			evs = append(evs, e)
		}
	}
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].Time.Equal(evs[j].Time) {
			return evs[i].Time.Before(evs[j].Time)
		}
		return evs[i].PID < evs[j].PID
	})
	if len(evs) > provInputCap {
		g.Missing.EventsIgnoredByCaps += len(evs) - provInputCap
		evs = evs[len(evs)-provInputCap:]
	}
	type pe struct {
		child string
		e     Event
	}
	pending := make([]pe, 0, len(evs))
	for _, e := range evs {
		n := b.procNode(host, e.PID, e.ProcessStart, e.Executable, e.Command, e.Time)
		pending = append(pending, pe{n.ID, e})
	}
	// Parent edges after all nodes exist, so resolution is independent of event order.
	seenSpawn := map[string]bool{}
	for _, p := range pending {
		if seenSpawn[p.child] {
			continue
		}
		seenSpawn[p.child] = true
		if p.e.PPID <= 0 {
			continue
		}
		par := b.find(host, p.e.PPID, "", p.e.ParentExe, p.e.Time)
		if par == "" || par == p.child {
			g.Missing.UnresolvedParents++
			continue
		}
		g.addEdge(par, p.child, provEdgeSpawn, p.e.Time, "")
	}

	var nws []NetworkEvent
	for _, n := range network {
		if n.Host == host {
			nws = append(nws, n)
		}
	}
	sort.SliceStable(nws, func(i, j int) bool { return nws[i].Time.Before(nws[j].Time) })
	if len(nws) > provInputCap {
		g.Missing.EventsIgnoredByCaps += len(nws) - provInputCap
		nws = nws[len(nws)-provInputCap:]
	}
	for _, n := range nws {
		if n.PID <= 0 {
			g.Missing.NetworkNoPID++
			continue
		}
		pid := b.find(host, n.PID, n.ProcessStart, "", n.Time)
		if pid == "" {
			g.Missing.NetworkNoProcess++
			continue
		}
		did := "d-" + provID(host, n.Destination)
		d := g.Nodes[did]
		if d == nil {
			d = &ProvNode{ID: did, Kind: provKindDest, Host: host, Label: n.Destination, First: n.Time}
			g.Nodes[did] = d
		}
		d.Events++
		g.addEdge(pid, did, provEdgeConn, n.Time, n.Verdict)
	}

	var fls []FileEvent
	for _, f := range files {
		if f.Host == host {
			fls = append(fls, f)
		}
	}
	sort.SliceStable(fls, func(i, j int) bool { return fls[i].Time.Before(fls[j].Time) })
	if len(fls) > provInputCap {
		g.Missing.EventsIgnoredByCaps += len(fls) - provInputCap
		fls = fls[len(fls)-provInputCap:]
	}
	for _, f := range fls {
		g.Missing.FileEventsTotal++
		if f.PID <= 0 {
			g.Missing.FileEventsNoWriter++
			continue
		}
		pid := b.find(host, f.PID, "", "", f.Time)
		if pid == "" {
			g.Missing.FileNoProcess++
			continue
		}
		fid := "f-" + provID(host, f.Path)
		n := g.Nodes[fid]
		if n == nil {
			n = &ProvNode{ID: fid, Kind: provKindFile, Host: host, Label: f.Path, First: f.Time}
			g.Nodes[fid] = n
		}
		n.Events++
		g.addEdge(pid, fid, provEdgeFile, f.Time, f.Operation)
	}
	g.attachFindings(b, findings)
	g.finalize(maxNodes)
	return g
}

func (g *ProvGraph) index() {
	g.out = map[string][]int{}
	g.in = map[string][]int{}
	for i, e := range g.Edges {
		g.out[e.From] = append(g.out[e.From], i)
		g.in[e.To] = append(g.in[e.To], i)
	}
}

// finalize dedups edges, applies the node cap (finding-linked nodes and their neighbours
// first, then newest) and indexes adjacency.
func (g *ProvGraph) finalize(maxNodes int) {
	sort.SliceStable(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
	seen := map[string]bool{}
	edges := make([]ProvEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		k := e.From + ">" + e.To + ">" + e.Kind
		if seen[k] {
			continue
		}
		seen[k] = true
		edges = append(edges, e)
	}
	g.Edges = edges
	if len(g.Nodes) > maxNodes {
		keep := map[string]bool{}
		prio := map[string]bool{}
		for id, n := range g.Nodes {
			if len(n.Findings) > 0 {
				prio[id] = true
				keep[id] = true
			}
		}
		for _, e := range g.Edges {
			if prio[e.From] || prio[e.To] {
				keep[e.From], keep[e.To] = true, true
			}
		}
		ids := make([]string, 0, len(g.Nodes))
		for id := range g.Nodes {
			if !keep[id] {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool {
			a, b := g.Nodes[ids[i]], g.Nodes[ids[j]]
			if !a.First.Equal(b.First) {
				return a.First.After(b.First)
			}
			return a.ID < b.ID
		})
		room := maxNodes - len(keep)
		for i := 0; i < len(ids) && room > 0; i, room = i+1, room-1 {
			keep[ids[i]] = true
		}
		for id := range g.Nodes {
			if !keep[id] {
				delete(g.Nodes, id)
				g.Missing.NodesDroppedByCap++
			}
		}
		g.Truncated = true
		kept := make([]ProvEdge, 0, len(g.Edges))
		for _, e := range g.Edges {
			if g.Nodes[e.From] != nil && g.Nodes[e.To] != nil {
				kept = append(kept, e)
			}
		}
		g.Edges = kept
	}
	g.index()
}

// SortedNodes returns nodes in a deterministic order.
func (g *ProvGraph) SortedNodes() []*ProvNode {
	out := make([]*ProvNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].First.Equal(out[j].First) {
			return out[i].First.Before(out[j].First)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
