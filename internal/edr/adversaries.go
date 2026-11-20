// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Adversary profiles: concise, public-reporting-based summaries of well-documented threat groups and
// ransomware families, with the ATT&CK techniques publicly attributed to them. Observation only:
// Kavach does not detect "the actor"; it reports which of their publicly reported techniques the
// embedded content rules can observe, and which are gaps.

//go:embed adversaries/*.json
var adversaryFS embed.FS

type AdversarySource struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type AdversaryProfile struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Aliases          []string          `json:"aliases"`
	Kind             string            `json:"kind"` // nation-state, cybercrime, ransomware
	AttributedOrigin string            `json:"attributed_origin"`
	Motivation       string            `json:"motivation"`
	Targets          string            `json:"targets"`
	Techniques       []string          `json:"techniques"`
	Confidence       string            `json:"confidence"` // high, medium, low
	Sources          []AdversarySource `json:"sources"`
}

type adversaryPack struct {
	Pack     string             `json:"pack"`
	Profiles []AdversaryProfile `json:"profiles"`
}

var (
	adversaryIDRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	adversaryTechRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	adversaryOnce   sync.Once
	adversaryList   []AdversaryProfile
	adversaryErr    error
)

func parseAdversaryPacks(packs map[string][]byte) ([]AdversaryProfile, error) {
	names := make([]string, 0, len(packs))
	for n := range packs {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]string{}
	var out []AdversaryProfile
	for _, n := range names {
		dec := json.NewDecoder(strings.NewReader(string(packs[n])))
		dec.DisallowUnknownFields()
		var p adversaryPack
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("adversaries/%s: %w", n, err)
		}
		for _, a := range p.Profiles {
			if err := validateAdversary(a); err != nil {
				return nil, fmt.Errorf("adversaries/%s: %s: %w", n, a.ID, err)
			}
			if prev, dup := seen[a.ID]; dup {
				return nil, fmt.Errorf("adversaries/%s: duplicate id %q (also in %s)", n, a.ID, prev)
			}
			seen[a.ID] = n
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func validateAdversary(a AdversaryProfile) error {
	if !adversaryIDRe.MatchString(a.ID) || len(a.ID) > 64 {
		return fmt.Errorf("invalid id")
	}
	if a.Name == "" || a.Motivation == "" || a.Targets == "" || a.Kind == "" {
		return fmt.Errorf("name, kind, motivation and targets are required")
	}
	switch a.Confidence {
	case "high", "medium", "low":
	default:
		return fmt.Errorf("confidence must be high, medium or low")
	}
	if len(a.Techniques) == 0 {
		return fmt.Errorf("no techniques")
	}
	dup := map[string]bool{}
	for _, t := range a.Techniques {
		if !adversaryTechRe.MatchString(t) {
			return fmt.Errorf("invalid technique id %q", t)
		}
		if dup[t] {
			return fmt.Errorf("duplicate technique %q", t)
		}
		dup[t] = true
	}
	if len(a.Sources) == 0 {
		return fmt.Errorf("sources must be non-empty")
	}
	for _, s := range a.Sources {
		if s.Title == "" || !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("source needs a title and https url")
		}
	}
	return nil
}

// Adversaries returns the embedded, validated profiles sorted by id.
func Adversaries() ([]AdversaryProfile, error) {
	adversaryOnce.Do(func() {
		ents, err := adversaryFS.ReadDir("adversaries")
		if err != nil {
			adversaryErr = err
			return
		}
		packs := map[string][]byte{}
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, err := adversaryFS.ReadFile("adversaries/" + e.Name())
			if err != nil {
				adversaryErr = err
				return
			}
			packs[e.Name()] = b
		}
		adversaryList, adversaryErr = parseAdversaryPacks(packs)
	})
	return adversaryList, adversaryErr
}

type AdversaryTechCoverage struct {
	Technique string   `json:"technique"`
	Status    string   `json:"status"` // exact, related, gap
	Rules     []string `json:"rules"`
	Hits      int      `json:"hits"`
}

type AdversaryCoverage struct {
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Kind         string                  `json:"kind"`
	Techniques   []AdversaryTechCoverage `json:"techniques,omitempty"`
	Total        int                     `json:"total"`
	Exact        int                     `json:"exact"`
	Related      int                     `json:"related"`
	Gaps         []string                `json:"gaps"`
	ExactPct     int                     `json:"exact_pct"`
	CoveragePct  int                     `json:"coverage_pct"` // exact + related
	ObservedHits int                     `json:"observed_hits"`
}

func techParent(id string) string {
	if i := strings.IndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// adversaryRuleIndex maps technique id -> rule ids, and parent id -> rule ids on any sub-technique.
func adversaryRuleIndex() (exact, family map[string][]string) {
	exact, family = map[string][]string{}, map[string][]string{}
	add := func(rule, id string) {
		exact[id] = append(exact[id], rule)
		if p := techParent(id); p != id {
			family[p] = append(family[p], rule)
		}
	}
	for r, m := range ruleMITRE {
		add(r, m.ID)
	}
	for r, m := range contentMITREAll() {
		add(r, m.ID)
	}
	for _, v := range exact {
		sort.Strings(v)
	}
	for _, v := range family {
		sort.Strings(v)
	}
	return
}

func adversaryHitIndex(findings []Finding) map[string]int {
	hits := map[string]int{}
	if tactics, ok := BuildATTACKMatrix(findings)["tactics"].([]*ATTACKTactic); ok {
		for _, t := range tactics {
			for _, tc := range t.Techniques {
				hits[tc.ID] += tc.Hits
			}
		}
	}
	return hits
}

// coverageFor computes coverage of one profile. A technique is "exact" when a rule maps to that id,
// "related" when a rule maps to a sibling sub-technique of the same parent (or to its parent), else a gap.
func coverageFor(a AdversaryProfile, exact, family map[string][]string, hits map[string]int, detail bool) AdversaryCoverage {
	c := AdversaryCoverage{ID: a.ID, Name: a.Name, Kind: a.Kind, Total: len(a.Techniques), Gaps: []string{}}
	for _, t := range a.Techniques {
		tc := AdversaryTechCoverage{Technique: t, Rules: []string{}, Hits: hits[t]}
		switch {
		case len(exact[t]) > 0:
			tc.Status, tc.Rules = "exact", exact[t]
			c.Exact++
		default:
			rel := family[t] // t is a parent: rules on its sub-techniques
			if p := techParent(t); p != t {
				rel = append(append([]string{}, exact[p]...), family[p]...) // t is a sub: rules on parent or siblings
			}
			if len(rel) > 0 {
				tc.Status, tc.Rules = "related", dedupSorted(rel)
				c.Related++
			} else {
				tc.Status = "gap"
				c.Gaps = append(c.Gaps, t)
			}
		}
		c.ObservedHits += tc.Hits
		if detail {
			c.Techniques = append(c.Techniques, tc)
		}
	}
	c.ExactPct = c.Exact * 100 / c.Total
	c.CoveragePct = (c.Exact + c.Related) * 100 / c.Total
	return c
}

func dedupSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// RegisterAdversaries wires the read-only adversary profile endpoints.
func RegisterAdversaries(mux *http.ServeMux, token string, store *Store) {
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	load := func(w http.ResponseWriter) ([]AdversaryProfile, bool) {
		ps, err := Adversaries()
		if err != nil {
			http.Error(w, "adversary profiles unavailable", 500)
			return nil, false
		}
		return ps, true
	}
	const note = "Attribution reflects public reporting and is not detection of the actor; coverage means Kavach can observe the technique, not that the actor is present."
	mux.HandleFunc("GET /v1/adversaries", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ps, ok := load(w)
		if !ok {
			return
		}
		q := r.URL.Query()
		kind, tech, text := q.Get("kind"), q.Get("technique"), strings.ToLower(q.Get("q"))
		out := []AdversaryProfile{}
		for _, p := range ps {
			if kind != "" && p.Kind != kind {
				continue
			}
			if tech != "" && !containsStr(p.Techniques, tech) {
				continue
			}
			if text != "" && !strings.Contains(strings.ToLower(p.ID+" "+p.Name+" "+strings.Join(p.Aliases, " ")), text) {
				continue
			}
			out = append(out, p)
		}
		reply(w, map[string]any{"mode": "observe-only", "note": note, "count": len(out), "adversaries": out})
	})
	mux.HandleFunc("GET /v1/adversaries/coverage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ps, ok := load(w)
		if !ok {
			return
		}
		exact, family := adversaryRuleIndex()
		hits := adversaryHitIndex(store.List())
		rows := make([]AdversaryCoverage, 0, len(ps))
		for _, p := range ps {
			rows = append(rows, coverageFor(p, exact, family, hits, false))
		}
		byCov := append([]AdversaryCoverage{}, rows...)
		sort.SliceStable(byCov, func(i, j int) bool {
			if byCov[i].CoveragePct != byCov[j].CoveragePct {
				return byCov[i].CoveragePct > byCov[j].CoveragePct
			}
			return byCov[i].ID < byCov[j].ID
		})
		byHits := append([]AdversaryCoverage{}, rows...)
		sort.SliceStable(byHits, func(i, j int) bool {
			if byHits[i].ObservedHits != byHits[j].ObservedHits {
				return byHits[i].ObservedHits > byHits[j].ObservedHits
			}
			return byHits[i].ID < byHits[j].ID
		})
		reply(w, map[string]any{"mode": "observe-only", "note": note, "count": len(rows), "by_coverage": byCov, "by_observed_hits": byHits})
	})
	mux.HandleFunc("GET /v1/adversaries/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ps, ok := load(w)
		if !ok {
			return
		}
		id, _ := url.PathUnescape(r.PathValue("id"))
		for _, p := range ps {
			if p.ID == id {
				exact, family := adversaryRuleIndex()
				reply(w, map[string]any{"mode": "observe-only", "note": note, "profile": p,
					"coverage": coverageFor(p, exact, family, adversaryHitIndex(store.List()), true)})
				return
			}
		}
		http.Error(w, "adversary not found", 404)
	})
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
