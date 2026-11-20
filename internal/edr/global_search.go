// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Global search: one read-only endpoint that looks across every entity type
// the console knows about. Matching is plain case-insensitive substring over
// a small set of fields per entity; user input is never compiled into a
// regular expression, so there is nothing to escape or backtrack on.

const (
	searchMaxQueryLen   = 128
	searchMinQueryLen   = 2
	searchDefaultLimit  = 20
	searchMaxLimit      = 100
	searchMaxScanPerTyp = 5000 // items examined per entity type per request
	searchMaxCaseBytes  = 8 << 20
)

// SearchResult is one typed, scored hit with a console route hint.
type SearchResult struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Score    int    `json:"score"`
	Route    string `json:"route"` // console hash route, e.g. "#/cases"
}

// SearchTypes lists the valid values for the types= filter, in display order.
var SearchTypes = []string{"finding", "host", "rule", "huntpack", "query", "guidance", "technique", "cve", "ioc", "case", "saved"}

var searchRoutes = map[string]string{
	"finding": "#/detections", "host": "#/hosts", "rule": "#/content", "huntpack": "#/huntpacks",
	"query": "#/content", "guidance": "#/content", "technique": "#/content", "cve": "#/vulns",
	"ioc": "#/intel", "case": "#/cases", "saved": "#/detections",
}

// searchScore ranks a hit: exact id > id prefix > id substring > title prefix
// > title substring > other-field substring. Zero means no match. q must
// already be lower-cased.
func searchScore(q, id, title string, others ...string) int {
	lid, lt := strings.ToLower(id), strings.ToLower(title)
	switch {
	case lid == q:
		return 100
	case strings.HasPrefix(lid, q):
		return 80
	case strings.Contains(lid, q):
		return 60
	case lt == q:
		return 55
	case strings.HasPrefix(lt, q):
		return 50
	case strings.Contains(lt, q):
		return 40
	}
	for _, o := range others {
		if o != "" && strings.Contains(strings.ToLower(o), q) {
			return 20
		}
	}
	// Multi-word query: every word must appear somewhere.
	words := strings.Fields(q)
	if len(words) < 2 {
		return 0
	}
	hay := lid + " " + lt + " " + strings.ToLower(strings.Join(others, " "))
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return 0
		}
	}
	return 10
}

type searchCollector struct {
	q       string
	results []SearchResult
	typ     string
	scanned int
}

func (c *searchCollector) begin(typ string) { c.typ, c.scanned = typ, 0 }

// more reports whether the per-type scan budget allows examining another item.
func (c *searchCollector) more() bool {
	c.scanned++
	return c.scanned <= searchMaxScanPerTyp
}

func (c *searchCollector) add(id, title, sub string, others ...string) {
	if s := searchScore(c.q, id, title, others...); s > 0 {
		c.results = append(c.results, SearchResult{Type: c.typ, ID: id, Title: title, Subtitle: sub, Score: s, Route: searchRoutes[c.typ]})
	}
}

// RunGlobalSearch searches every wanted type. want nil/empty means all types.
func RunGlobalSearch(store *Store, ws *Workspace, q string, want map[string]bool, limit int) []SearchResult {
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > searchMaxQueryLen {
		q = q[:searchMaxQueryLen]
	}
	if len(q) < searchMinQueryLen {
		return []SearchResult{}
	}
	if limit <= 0 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}
	on := func(t string) bool { return len(want) == 0 || want[t] }
	c := &searchCollector{q: q}

	if store != nil && (on("finding") || on("host")) {
		fs := store.List()
		if on("finding") {
			c.begin("finding")
			for i := len(fs) - 1; i >= 0 && c.more(); i-- { // newest first
				f := fs[i]
				c.add(f.ID, f.Rule+" on "+f.Host, f.Severity+" · "+f.Description, f.Host, f.Description, f.Destination, strings.Join(f.Tags, " "))
			}
		}
		if on("host") {
			c.begin("host")
			seen := map[string]bool{}
			hosts := []string{}
			for i := len(fs) - 1; i >= 0; i-- {
				if h := fs[i].Host; h != "" && !seen[h] {
					seen[h] = true
					hosts = append(hosts, h)
				}
			}
			for _, h := range vmHosts() {
				if !seen[h] {
					seen[h] = true
					hosts = append(hosts, h)
				}
			}
			for _, h := range hosts {
				if !c.more() {
					break
				}
				c.add(h, h, "host")
			}
		}
	}
	if on("rule") {
		c.begin("rule")
		for _, r := range ContentRules() {
			if !c.more() {
				break
			}
			c.add(r.ID, r.Name, r.Severity+" · "+r.Technique+" · "+r.Tactic, r.Description, r.Technique, r.TechniqueName, r.Tactic, strings.Join(r.Tags, " "))
		}
	}
	if on("huntpack") {
		c.begin("huntpack")
		for _, p := range huntPacks {
			if !c.more() {
				break
			}
			c.add(p.ID, p.Name, p.Technique+" · "+p.Tactic, p.Technique, p.Tactic)
		}
	}
	if on("query") {
		c.begin("query")
		for _, e := range queryLibrary {
			if !c.more() {
				break
			}
			c.add(e.ID, e.Name, e.Tactic+" · "+e.Language, e.Description, e.Technique, e.Tactic, strings.Join(e.Tags, " "))
		}
	}
	if on("guidance") {
		c.begin("guidance")
		for _, g := range guidanceCatalog {
			if g.Kind != "rule" {
				continue
			}
			if !c.more() {
				break
			}
			c.add(g.ID, g.Title, "guidance", g.WhatItMeans)
		}
	}
	if on("technique") {
		c.begin("technique")
		for _, d := range techniqueDefs {
			if !c.more() {
				break
			}
			c.add(d.id, d.title, d.tactic, d.means, d.tactic)
		}
	}
	if on("cve") {
		c.begin("cve")
		adv, _ := vmLoadAdvisories()
		for _, a := range adv {
			if !c.more() {
				break
			}
			c.add(a.CVE, a.CVE+" · "+a.Package, "CVSS "+strconv.FormatFloat(a.CVSS, 'f', 1, 64), a.Package, a.Summary)
		}
	}
	if on("ioc") {
		c.begin("ioc")
		iocMu.Lock()
		list := append([]IOC{}, iocs...)
		iocMu.Unlock()
		for _, i := range list {
			if !c.more() {
				break
			}
			c.add(i.Value, i.Type+" "+i.Value, i.Severity+" · "+i.Source, i.ID, i.Description)
		}
	}
	if on("case") && store != nil && store.path != "" {
		c.begin("case")
		for _, cs := range readCasesForSearch(store.path + ".cases.json") {
			if !c.more() {
				break
			}
			c.add(cs.ID, cs.Title, cs.Status+" · "+cs.Severity, cs.Assignee, cs.IncidentID, strings.Join(cs.Tags, " "), strings.Join(cs.FindingIDs, " "))
		}
	}
	if on("saved") && ws != nil {
		c.begin("saved")
		ws.mu.Lock()
		saved := append([]SavedSearch{}, ws.data.Searches...)
		ws.mu.Unlock()
		for _, s := range saved {
			if !c.more() {
				break
			}
			c.add(s.ID, s.Name, s.Scope, s.Query)
		}
	}

	rank := map[string]int{}
	for i, t := range SearchTypes {
		rank[t] = i
	}
	sort.SliceStable(c.results, func(i, j int) bool {
		a, b := c.results[i], c.results[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Type != b.Type {
			return rank[a.Type] < rank[b.Type]
		}
		return a.ID < b.ID
	})
	if len(c.results) > limit {
		c.results = c.results[:limit]
	}
	if c.results == nil {
		return []SearchResult{}
	}
	return c.results
}

func readCasesForSearch(path string) []IncCase {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > searchMaxCaseBytes {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cs []IncCase
	if json.Unmarshal(b, &cs) != nil {
		return nil
	}
	return cs
}

// RegisterGlobalSearch serves GET /v1/search?q=&types=a,b&limit=N.
func RegisterGlobalSearch(mux *http.ServeMux, token string, store *Store, ws *Workspace) {
	mux.HandleFunc("GET /v1/search", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		qs := r.URL.Query()
		q := strings.TrimSpace(qs.Get("q"))
		if len(q) < searchMinQueryLen {
			http.Error(w, "q must be at least 2 characters", http.StatusBadRequest)
			return
		}
		valid := map[string]bool{}
		for _, t := range SearchTypes {
			valid[t] = true
		}
		want := map[string]bool{}
		if tv := strings.TrimSpace(qs.Get("types")); tv != "" {
			for _, t := range strings.Split(tv, ",") {
				t = strings.ToLower(strings.TrimSpace(t))
				if !valid[t] {
					http.Error(w, "unknown type: "+t, http.StatusBadRequest)
					return
				}
				want[t] = true
			}
		}
		limit, _ := strconv.Atoi(qs.Get("limit"))
		res := RunGlobalSearch(store, ws, q, want, limit)
		writeJSON(w, map[string]any{"query": strings.ToLower(q), "count": len(res), "results": res})
	})
}
