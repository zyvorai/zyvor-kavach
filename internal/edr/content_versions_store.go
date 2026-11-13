// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const contentVersionsCap = 50

// highlight fields: a change here alters what fires or how loudly.
var contentHighlightFields = map[string]bool{
	"severity": true, "match": true, "event_type": true, "technique": true, "tactic": true,
	"os": true, "strings": true, "condition": true, "patterns": true, "query": true, "weight": true,
	"applies_to": true, "techniques": true, "steps": true,
}

// ContentChange is one item that differs between two snapshots.
type ContentChange struct {
	Pack      string   `json:"pack"`
	Kind      string   `json:"kind"`
	ID        string   `json:"id"`
	Fields    []string `json:"fields_changed,omitempty"`
	Highlight []string `json:"highlights,omitempty"` // severity / match-affecting fields that changed
}

// ContentDiff is the result of comparing two snapshots.
type ContentDiff struct {
	FromSeq   int             `json:"from_seq"`
	ToSeq     int             `json:"to_seq"`
	Identical bool            `json:"identical"`
	Added     []ContentChange `json:"added"`
	Removed   []ContentChange `json:"removed"`
	Modified  []ContentChange `json:"modified"`
	Packs     []string        `json:"packs_changed"`
}

type itemKey struct{ pack, id string }

func indexSnapshot(s ContentSnapshot) (map[itemKey]ContentRuleSnap, map[itemKey]string) {
	m := map[itemKey]ContentRuleSnap{}
	kind := map[itemKey]string{}
	for _, p := range s.Packs {
		for _, it := range p.Items {
			k := itemKey{p.Name, it.ID}
			m[k] = it
			kind[k] = p.Kind
		}
	}
	return m, kind
}

// diffSnapshots lists added, removed and modified items (with changed top-level fields).
func diffSnapshots(a, b ContentSnapshot) ContentDiff {
	d := ContentDiff{FromSeq: a.Seq, ToSeq: b.Seq, Added: []ContentChange{}, Removed: []ContentChange{}, Modified: []ContentChange{}, Packs: []string{}}
	ai, ak := indexSnapshot(a)
	bi, bk := indexSnapshot(b)
	packSet := map[string]bool{}
	for k, bv := range bi {
		av, ok := ai[k]
		switch {
		case !ok:
			d.Added = append(d.Added, ContentChange{Pack: k.pack, Kind: bk[k], ID: k.id})
			packSet[k.pack] = true
		case av.Hash != bv.Hash:
			c := ContentChange{Pack: k.pack, Kind: bk[k], ID: k.id}
			names := map[string]bool{}
			for f, h := range bv.Field {
				if av.Field[f] != h {
					names[f] = true
				}
			}
			for f := range av.Field {
				if _, ok := bv.Field[f]; !ok {
					names[f] = true
				}
			}
			for f := range names {
				c.Fields = append(c.Fields, f)
				if contentHighlightFields[f] {
					c.Highlight = append(c.Highlight, f)
				}
			}
			sort.Strings(c.Fields)
			sort.Strings(c.Highlight)
			d.Modified = append(d.Modified, c)
			packSet[k.pack] = true
		}
	}
	for k := range ai {
		if _, ok := bi[k]; !ok {
			d.Removed = append(d.Removed, ContentChange{Pack: k.pack, Kind: ak[k], ID: k.id})
			packSet[k.pack] = true
		}
	}
	// A pack-level hash change with no item change (metadata) still counts as a change.
	ap := map[string]string{}
	for _, p := range a.Packs {
		ap[p.Name] = p.Hash
	}
	for _, p := range b.Packs {
		if h, ok := ap[p.Name]; !ok || h != p.Hash {
			packSet[p.Name] = true
		}
		delete(ap, p.Name)
	}
	for n := range ap {
		packSet[n] = true
	}
	for n := range packSet {
		d.Packs = append(d.Packs, n)
	}
	srt := func(c []ContentChange) {
		sort.Slice(c, func(i, j int) bool {
			if c[i].Pack != c[j].Pack {
				return c[i].Pack < c[j].Pack
			}
			return c[i].ID < c[j].ID
		})
	}
	srt(d.Added)
	srt(d.Removed)
	srt(d.Modified)
	sort.Strings(d.Packs)
	d.Identical = a.Hash == b.Hash && len(d.Added)+len(d.Removed)+len(d.Modified) == 0
	return d
}

// ContentVersionStore keeps a capped snapshot history in <store>.contentversions.json.
type ContentVersionStore struct {
	mu        sync.Mutex
	path      string
	cap       int
	Snapshots []ContentSnapshot `json:"snapshots"`
	NextSeq   int               `json:"next_seq"`
}

func newContentVersionStore(path string, cap int) *ContentVersionStore {
	if cap < 1 {
		cap = contentVersionsCap
	}
	s := &ContentVersionStore{path: path, cap: cap, NextSeq: 1}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, s)
			s.path, s.cap = path, cap
			if s.NextSeq < 1 {
				s.NextSeq = 1
			}
			for _, x := range s.Snapshots {
				if x.Seq >= s.NextSeq {
					s.NextSeq = x.Seq + 1
				}
			}
		}
	}
	return s
}

// Record appends cur when it differs from the newest stored snapshot (by overall hash).
// It returns the stored (or already-latest) snapshot and whether a new one was added.
func (s *ContentVersionStore) Record(cur ContentSnapshot, now time.Time, build string) (ContentSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.Snapshots); n > 0 && s.Snapshots[n-1].Hash == cur.Hash {
		return s.Snapshots[n-1], false
	}
	cur.Seq = s.NextSeq
	s.NextSeq++
	cur.Time = now.UTC().Format(time.RFC3339)
	cur.Build = build
	s.Snapshots = append(s.Snapshots, cur)
	if len(s.Snapshots) > s.cap {
		s.Snapshots = append([]ContentSnapshot(nil), s.Snapshots[len(s.Snapshots)-s.cap:]...)
	}
	s.saveLocked()
	return cur, true
}

func (s *ContentVersionStore) saveLocked() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(struct {
		Snapshots []ContentSnapshot `json:"snapshots"`
		NextSeq   int               `json:"next_seq"`
	}{s.Snapshots, s.NextSeq})
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *ContentVersionStore) list() []ContentSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ContentSnapshot(nil), s.Snapshots...)
}

// resolve finds a snapshot by seq number, overall-hash prefix, "current" or "previous".
func resolveSnapshot(all []ContentSnapshot, ref string) (ContentSnapshot, bool) {
	if len(all) == 0 {
		return ContentSnapshot{}, false
	}
	switch ref {
	case "", "current", "latest":
		return all[len(all)-1], true
	case "previous", "prev":
		if len(all) < 2 {
			return ContentSnapshot{}, false
		}
		return all[len(all)-2], true
	}
	if n, err := strconv.Atoi(ref); err == nil {
		for _, x := range all {
			if x.Seq == n {
				return x, true
			}
		}
		return ContentSnapshot{}, false
	}
	if len(ref) >= 4 {
		for _, x := range all {
			if strings.HasPrefix(x.Hash, ref) {
				return x, true
			}
		}
	}
	return ContentSnapshot{}, false
}

func summarizeSnapshot(s ContentSnapshot, withItems bool) map[string]any {
	packs := make([]map[string]any, 0, len(s.Packs))
	for _, p := range s.Packs {
		m := map[string]any{"name": p.Name, "kind": p.Kind, "hash": p.Hash, "count": p.Count}
		if withItems {
			m["items"] = p.Items
		}
		packs = append(packs, m)
	}
	return map[string]any{"seq": s.Seq, "time": s.Time, "build": s.Build, "hash": s.Hash,
		"total_items": s.Total, "items_by_kind": s.ByKind, "packs": packs}
}

func changelogEntry(prev *ContentSnapshot, cur ContentSnapshot) map[string]any {
	e := map[string]any{"seq": cur.Seq, "time": cur.Time, "build": cur.Build, "hash": cur.Hash, "total_items": cur.Total}
	if prev == nil {
		e["summary"] = fmt.Sprintf("Initial snapshot: %d items across %d packs. No earlier snapshot to compare.", cur.Total, len(cur.Packs))
		return e
	}
	d := diffSnapshots(*prev, cur)
	hl := 0
	for _, m := range d.Modified {
		if len(m.Highlight) > 0 {
			hl++
		}
	}
	e["added"], e["removed"], e["modified"], e["packs_changed"] = len(d.Added), len(d.Removed), len(d.Modified), d.Packs
	e["modified_with_severity_or_match_change"] = hl
	e["summary"] = fmt.Sprintf("vs snapshot %d: %d added, %d removed, %d modified (%d with severity or match changes) in %d pack(s).",
		prev.Seq, len(d.Added), len(d.Removed), len(d.Modified), hl, len(d.Packs))
	return e
}

// RegisterContentVersions snapshots the embedded content at startup and mounts the read-only
// /v1/content/versions, /v1/content/changes and /v1/content/changelog endpoints.
func RegisterContentVersions(mux *http.ServeMux, token string, store *Store) {
	p := ""
	if store != nil && store.path != "" {
		p = filepath.Clean(store.path) + ".contentversions.json"
	}
	vs := newContentVersionStore(p, contentVersionsCap)
	cur, errs := buildContentSnapshot()
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "content versions: %v\n", e)
	}
	if len(errs) == 0 { // never record a partial snapshot as a "removal" of content
		vs.Record(cur, time.Now(), contentBuildString())
	}
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/content/versions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		all := vs.list()
		items := r.URL.Query().Get("items") == "1"
		rows := make([]map[string]any, 0, len(all))
		for i := len(all) - 1; i >= 0; i-- {
			rows = append(rows, summarizeSnapshot(all[i], items))
		}
		out(w, 200, map[string]any{"mode": "observe-only", "count": len(rows), "history_cap": vs.cap, "snapshots": rows,
			"note": "Newest first. A snapshot is recorded at startup only when embedded content differs from the last one."})
	})
	mux.HandleFunc("GET /v1/content/changes", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		all := vs.list()
		q := r.URL.Query()
		if len(all) == 0 {
			out(w, 200, map[string]any{"mode": "observe-only", "message": "no snapshots recorded"})
			return
		}
		fromRef, toRef := q.Get("from"), q.Get("to")
		to, ok := resolveSnapshot(all, toRef)
		if !ok {
			out(w, 404, map[string]any{"error": "unknown 'to' snapshot"})
			return
		}
		if fromRef == "" {
			// default: the snapshot immediately before 'to'
			var prev *ContentSnapshot
			for i := range all {
				if all[i].Seq == to.Seq && i > 0 {
					prev = &all[i-1]
				}
			}
			if prev == nil {
				out(w, 200, map[string]any{"mode": "observe-only", "to": summarizeSnapshot(to, false),
					"message": "no earlier snapshot", "added": []any{}, "removed": []any{}, "modified": []any{}})
				return
			}
			d := diffSnapshots(*prev, to)
			out(w, 200, map[string]any{"mode": "observe-only", "from": summarizeSnapshot(*prev, false), "to": summarizeSnapshot(to, false), "diff": d})
			return
		}
		from, ok := resolveSnapshot(all, fromRef)
		if !ok {
			out(w, 404, map[string]any{"error": "unknown 'from' snapshot"})
			return
		}
		out(w, 200, map[string]any{"mode": "observe-only", "from": summarizeSnapshot(from, false), "to": summarizeSnapshot(to, false), "diff": diffSnapshots(from, to)})
	})
	mux.HandleFunc("GET /v1/content/changelog", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		all := vs.list()
		entries := []map[string]any{}
		for i := len(all) - 1; i >= 0; i-- {
			var prev *ContentSnapshot
			if i > 0 {
				prev = &all[i-1]
			}
			entries = append(entries, changelogEntry(prev, all[i]))
		}
		msg := ""
		if len(all) <= 1 {
			msg = "no earlier snapshot"
		}
		out(w, 200, map[string]any{"mode": "observe-only", "message": msg, "count": len(entries), "changelog": entries})
	})
}
