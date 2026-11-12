// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Observation-only prevalence and blast-radius analytics over the in-memory
// stores. No external calls; every scan is capped.

const (
	prevEventCap      = 100000
	prevMaxLimit      = 1000
	prevMaxHours      = 720
	prevMaxDepth      = 3
	prevMaxNodes      = 500
	prevMaxStr        = 256
	prevListCap       = 10
	prevSharedDestMax = 10 // destinations on more hosts than this are treated as common noise
	prevSharedExeMax  = 3  // executables on more hosts than this are not rare enough to link hosts
)

var (
	prevUUID = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	prevHex0 = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b`)
	prevHexL = regexp.MustCompile(`(?i)\b[0-9a-f]{8,}\b`)
	prevNum  = regexp.MustCompile(`\d+`)
	prevWS   = regexp.MustCompile(`\s+`)
)

// prevNormalise strips uuids, hex blobs, PIDs and other numbers from a command line.
func prevNormalise(cmd string) string {
	s := prevUUID.ReplaceAllString(cmd, "<uuid>")
	s = prevHex0.ReplaceAllString(s, "<hex>")
	s = prevHexL.ReplaceAllString(s, "<hex>")
	s = prevNum.ReplaceAllString(s, "<n>")
	s = strings.TrimSpace(prevWS.ReplaceAllString(s, " "))
	return prevClip(s)
}

func prevClip(s string) string {
	if len(s) > prevMaxStr {
		return strings.ToValidUTF8(s[:prevMaxStr], "")
	}
	return s
}

type prevSnapshot struct {
	events   []Event
	network  []NetworkEvent
	findings []Finding
}

func prevTake(store *Store) prevSnapshot {
	var sn prevSnapshot
	if store == nil {
		return sn
	}
	store.mu.Lock()
	ev, nw := store.recentEvents, store.networkEvents
	if len(ev) > prevEventCap {
		ev = ev[len(ev)-prevEventCap:]
	}
	if len(nw) > prevEventCap {
		nw = nw[len(nw)-prevEventCap:]
	}
	sn.events = append([]Event(nil), ev...)
	sn.network = append([]NetworkEvent(nil), nw...)
	store.mu.Unlock()
	sn.findings = store.List()
	return sn
}

func prevIntParam(r *http.Request, name string, def, lo, hi int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func prevWrite(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // escapes <, >, & by default
}

func prevRound(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

type prevAgg struct {
	hosts   map[string]struct{}
	uids    map[int]struct{}
	parents map[string]struct{}
	first   time.Time
	last    time.Time
	count   int
	exe     string
	cmd     string
}

func prevAdd(m map[string]*prevAgg, key, exe, cmd string, e Event) {
	a := m[key]
	if a == nil {
		a = &prevAgg{hosts: map[string]struct{}{}, uids: map[int]struct{}{}, parents: map[string]struct{}{}, first: e.Time, last: e.Time, exe: exe, cmd: cmd}
		m[key] = a
	}
	a.hosts[e.Host] = struct{}{}
	a.uids[e.UID] = struct{}{}
	if e.ParentExe != "" {
		a.parents[prevClip(e.ParentExe)] = struct{}{}
	}
	if e.Time.Before(a.first) {
		a.first = e.Time
	}
	if e.Time.After(a.last) {
		a.last = e.Time
	}
	a.count++
}

func prevSortedKeys(m map[string]struct{}, n int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// PrevalenceEntry is one executable + command-shape with fleet prevalence.
type PrevalenceEntry struct {
	Executable   string    `json:"executable"`
	CommandShape string    `json:"command_shape"`
	Hosts        int       `json:"hosts"`
	Events       int       `json:"events"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	UIDs         []int     `json:"uids"`
	Parents      []string  `json:"parents"`
}

func prevEntries(events []Event) []PrevalenceEntry {
	m := map[string]*prevAgg{}
	for _, e := range events {
		if e.Executable == "" || e.Host == "" {
			continue
		}
		exe, shape := prevClip(e.Executable), prevNormalise(e.Command)
		prevAdd(m, exe+"\x00"+shape, exe, shape, e)
	}
	out := make([]PrevalenceEntry, 0, len(m))
	for _, a := range m {
		uids := make([]int, 0, len(a.uids))
		for u := range a.uids {
			uids = append(uids, u)
		}
		sort.Ints(uids)
		if len(uids) > prevListCap {
			uids = uids[:prevListCap]
		}
		out = append(out, PrevalenceEntry{Executable: a.exe, CommandShape: a.cmd, Hosts: len(a.hosts), Events: a.count,
			FirstSeen: a.first, LastSeen: a.last, UIDs: uids, Parents: prevSortedKeys(a.parents, prevListCap)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Hosts != b.Hosts {
			return a.Hosts < b.Hosts
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		if a.Executable != b.Executable {
			return a.Executable < b.Executable
		}
		return a.CommandShape < b.CommandShape
	})
	return out
}

// PrevalenceRare is an executable seen on few hosts within the window.
type PrevalenceRare struct {
	Executable string    `json:"executable"`
	Hosts      []string  `json:"hosts"`
	HostCount  int       `json:"host_count"`
	Rarity     float64   `json:"rarity"`
	InFindings bool      `json:"in_findings"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func prevRare(sn prevSnapshot, now time.Time, hours int, fraction float64) ([]PrevalenceRare, int) {
	cut := now.Add(-time.Duration(hours) * time.Hour)
	fleet := map[string]struct{}{}
	all := map[string]map[string]struct{}{}
	win := map[string]*prevAgg{}
	for _, e := range sn.events {
		if e.Host == "" || e.Executable == "" {
			continue
		}
		fleet[e.Host] = struct{}{}
		exe := prevClip(e.Executable)
		if all[exe] == nil {
			all[exe] = map[string]struct{}{}
		}
		all[exe][e.Host] = struct{}{}
		if !e.Time.Before(cut) {
			prevAdd(win, exe, exe, "", e)
		}
	}
	inF := map[string]bool{}
	for _, f := range sn.findings {
		if f.Evidence.Executable != "" {
			inF[prevClip(f.Evidence.Executable)] = true
		}
	}
	limit := 1
	if fraction > 0 {
		if l := int(fraction * float64(len(fleet))); l > 1 {
			limit = l
		}
	}
	out := []PrevalenceRare{}
	for exe, a := range win {
		n := len(all[exe])
		if n > limit {
			continue
		}
		score := 1.0
		if len(fleet) > 1 {
			score = 1 - float64(n-1)/float64(len(fleet))
		}
		out = append(out, PrevalenceRare{Executable: exe, Hosts: prevSortedKeys(all[exe], prevListCap), HostCount: n,
			Rarity: prevRound(score), InFindings: inF[exe], FirstSeen: a.first, LastSeen: a.last})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.InFindings != b.InFindings {
			return a.InFindings
		}
		if a.Rarity != b.Rarity {
			return a.Rarity > b.Rarity
		}
		return a.Executable < b.Executable
	})
	return out, len(fleet)
}

type prevFirst struct {
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	Count     int       `json:"count"`
}

func prevFirstSeen(sn prevSnapshot, host string, cut time.Time) (exes, dests []prevFirst) {
	seenE, seenD := map[string]bool{}, map[string]bool{}
	newE, newD := map[string]*prevFirst{}, map[string]*prevFirst{}
	note := func(prior map[string]bool, fresh map[string]*prevFirst, v string, t time.Time) {
		v = prevClip(v)
		if v == "" {
			return
		}
		if t.Before(cut) {
			prior[v] = true
			return
		}
		f := fresh[v]
		if f == nil {
			fresh[v] = &prevFirst{Value: v, FirstSeen: t, Count: 1}
			return
		}
		f.Count++
		if t.Before(f.FirstSeen) {
			f.FirstSeen = t
		}
	}
	for _, e := range sn.events {
		if e.Host == host {
			note(seenE, newE, e.Executable, e.Time)
		}
	}
	for _, n := range sn.network {
		if n.Host == host {
			note(seenD, newD, n.Destination, n.Time)
		}
	}
	collect := func(prior map[string]bool, fresh map[string]*prevFirst) []prevFirst {
		out := []prevFirst{}
		for v, f := range fresh {
			if !prior[v] {
				out = append(out, *f)
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
				return out[i].FirstSeen.Before(out[j].FirstSeen)
			}
			return out[i].Value < out[j].Value
		})
		return out
	}
	return collect(seenE, newE), collect(seenD, newD)
}

// PrevalenceNode is a host in the blast-radius graph.
type PrevalenceNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	Depth int    `json:"depth"`
	Risk  int    `json:"risk"`
}

// PrevalenceEdge links two hosts with explainable reasons.
type PrevalenceEdge struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Weight  int      `json:"weight"`
	Reasons []string `json:"reasons"`
}

// PrevalenceLikely is a ranked "likely also affected" host.
type PrevalenceLikely struct {
	Host    string   `json:"host"`
	Score   float64  `json:"score"`
	Depth   int      `json:"depth"`
	Risk    int      `json:"risk"`
	Reasons []string `json:"reasons"`
}

type prevPair struct{ a, b string }

func prevMkPair(x, y string) prevPair {
	if x > y {
		x, y = y, x
	}
	return prevPair{x, y}
}

func prevBlast(sn prevSnapshot, now time.Time, host string, hours, depth int) map[string]any {
	cut := now.Add(-time.Duration(hours) * time.Hour)
	kinds := []struct {
		name   string
		weight int
		maxH   int
	}{{"shared-destination", 3, prevSharedDestMax}, {"shared-rare-executable", 4, prevSharedExeMax}, {"finding-co-occurrence", 2, prevSharedDestMax}}
	art := make([]map[string]map[string]struct{}, len(kinds))
	for i := range art {
		art[i] = map[string]map[string]struct{}{}
	}
	put := func(i int, v, h string) {
		v = prevClip(v)
		if v == "" || h == "" {
			return
		}
		if art[i][v] == nil {
			art[i][v] = map[string]struct{}{}
		}
		art[i][v][h] = struct{}{}
	}
	exeAll := map[string]map[string]struct{}{}
	for _, n := range sn.network {
		if !n.Time.Before(cut) {
			put(0, n.Destination, n.Host)
		}
	}
	for _, e := range sn.events {
		if e.Host == "" || e.Executable == "" {
			continue
		}
		exe := prevClip(e.Executable)
		if exeAll[exe] == nil {
			exeAll[exe] = map[string]struct{}{}
		}
		exeAll[exe][e.Host] = struct{}{}
		if !e.Time.Before(cut) {
			put(1, exe, e.Host)
		}
	}
	for _, f := range sn.findings {
		if !f.Time.Before(cut) {
			put(2, f.Rule, f.Host)
			put(0, f.Destination, f.Host)
		}
	}
	pairs := map[prevPair]*PrevalenceEdge{}
	for i, k := range kinds {
		for v, hs := range art[i] {
			if i == 1 {
				hs = exeAll[v] // rarity judged over full history
			}
			if len(hs) < 2 || len(hs) > k.maxH {
				continue
			}
			names := prevSortedKeys(hs, 0)
			for x := 0; x < len(names); x++ {
				for y := x + 1; y < len(names); y++ {
					p := prevMkPair(names[x], names[y])
					e := pairs[p]
					if e == nil {
						e = &PrevalenceEdge{From: p.a, To: p.b}
						pairs[p] = e
					}
					e.Weight += k.weight
					e.Reasons = append(e.Reasons, k.name+": "+v)
				}
			}
		}
	}
	adj := map[string][]string{}
	for p, e := range pairs {
		sort.Strings(e.Reasons)
		if len(e.Reasons) > prevListCap {
			e.Reasons = e.Reasons[:prevListCap]
		}
		adj[p.a] = append(adj[p.a], p.b)
		adj[p.b] = append(adj[p.b], p.a)
	}
	for h := range adj {
		sort.Strings(adj[h])
	}
	risk := map[string]int{}
	for _, r := range ComputeHostRisks(sn.findings, now) {
		risk[r.Host] = r.Risk
	}
	dep := map[string]int{host: 0}
	parent := map[string]string{}
	order := []string{host}
	truncated := false
	for qi := 0; qi < len(order); qi++ {
		cur := order[qi]
		if dep[cur] >= depth {
			continue
		}
		for _, nb := range adj[cur] {
			if _, ok := dep[nb]; ok {
				continue
			}
			if len(order) >= prevMaxNodes {
				truncated = true
				continue
			}
			dep[nb] = dep[cur] + 1
			parent[nb] = cur
			order = append(order, nb)
		}
	}
	nodes := make([]PrevalenceNode, 0, len(order))
	for _, h := range order {
		nodes = append(nodes, PrevalenceNode{ID: h, Type: "host", Label: h, Depth: dep[h], Risk: risk[h]})
	}
	edges := []PrevalenceEdge{}
	for p, e := range pairs {
		_, okA := dep[p.a]
		_, okB := dep[p.b]
		if okA && okB {
			edges = append(edges, *e)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	likely := []PrevalenceLikely{}
	for _, h := range order[1:] {
		e := pairs[prevMkPair(parent[h], h)]
		score := float64(e.Weight)/float64(dep[h]) + float64(risk[h])/100
		reasons := e.Reasons
		if dep[h] > 1 {
			reasons = append([]string{"via " + parent[h]}, reasons...)
		}
		likely = append(likely, PrevalenceLikely{Host: h, Score: prevRound(score), Depth: dep[h], Risk: risk[h], Reasons: reasons})
	}
	sort.Slice(likely, func(i, j int) bool {
		if likely[i].Score != likely[j].Score {
			return likely[i].Score > likely[j].Score
		}
		return likely[i].Host < likely[j].Host
	})
	return map[string]any{"host": host, "hours": hours, "depth": depth, "max_nodes": prevMaxNodes, "truncated": truncated,
		"nodes": nodes, "edges": edges, "likely_affected": likely}
}

// RegisterPrevalenceGraph wires the observation-only prevalence and blast-radius routes.
func RegisterPrevalenceGraph(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/prevalence/executables", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		minH := prevIntParam(r, "min_hosts", 1, 1, prevEventCap)
		maxH := prevIntParam(r, "max_hosts", 0, 0, prevEventCap)
		limit := prevIntParam(r, "limit", 100, 1, prevMaxLimit)
		out := []PrevalenceEntry{}
		for _, e := range prevEntries(prevTake(store).events) {
			if e.Hosts < minH || (maxH > 0 && e.Hosts > maxH) {
				continue
			}
			if out = append(out, e); len(out) >= limit {
				break
			}
		}
		prevWrite(w, map[string]any{"executables": out, "count": len(out)})
	})
	mux.HandleFunc("GET /v1/prevalence/rare", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hours := prevIntParam(r, "hours", 24, 1, prevMaxHours)
		frac := 0.0
		if v, err := strconv.ParseFloat(r.URL.Query().Get("fraction"), 64); err == nil && v > 0 && v <= 1 {
			frac = v
		}
		rare, fleet := prevRare(prevTake(store), time.Now().UTC(), hours, frac)
		if len(rare) > prevMaxLimit {
			rare = rare[:prevMaxLimit]
		}
		prevWrite(w, map[string]any{"hours": hours, "fleet_hosts": fleet, "rare": rare, "count": len(rare)})
	})
	mux.HandleFunc("GET /v1/prevalence/first-seen", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := prevClip(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		hours := prevIntParam(r, "hours", 24, 1, prevMaxHours)
		cut := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		exes, dests := prevFirstSeen(prevTake(store), host, cut)
		prevWrite(w, map[string]any{"host": host, "hours": hours, "new_executables": exes, "new_destinations": dests})
	})
	mux.HandleFunc("GET /v1/graph/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := prevClip(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		hours := prevIntParam(r, "hours", 24, 1, prevMaxHours)
		depth := prevIntParam(r, "depth", 2, 1, prevMaxDepth)
		prevWrite(w, prevBlast(prevTake(store), time.Now().UTC(), host, hours, depth))
	})
}
