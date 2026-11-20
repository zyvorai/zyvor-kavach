// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Detection-as-code versioning: a rule-level manifest of the embedded packs, a capped store of
// manifest snapshots (counts and hashes only) and a field-aware diff. Observation only; this
// never changes what rules fire. Complements content_versions_*.go (startup hash history).

const (
	contentSnapsCap    = 20
	contentSnapBodyCap = 4096
	contentSignKeyEnv  = "KAVACH_CONTENT_SIGN_KEY"
)

// ManifestRule is the hash identity of one rule. The four field hashes let a diff say what changed
// without storing rule bodies.
type ManifestRule struct {
	ID      string `json:"id"`
	Pack    string `json:"pack"`
	Hash    string `json:"hash"`
	Sev     string `json:"severity_hash"`
	Match   string `json:"patterns_hash"`
	Attack  string `json:"attack_hash"`
	Enabled string `json:"enabled_hash"`
}

// ManifestPack describes one embedded pack file.
type ManifestPack struct {
	File      string   `json:"file"`
	Pack      string   `json:"pack"`
	Batches   []string `json:"batches"`
	RuleCount int      `json:"rule_count"`
	SHA256    string   `json:"sha256"`
}

// ContentManifest is the generated description of the embedded detection content.
type ContentManifest struct {
	Packs     []ManifestPack `json:"packs"`
	RuleCount int            `json:"rule_count"`
	Rules     []ManifestRule `json:"rules"`
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fieldHash(v any) string    { b, _ := json.Marshal(v); return sha256Hex(b)[:12] }

// ruleEnabledState reports the lifecycle state of an embedded rule ("production" unless set).
func ruleEnabledState(id string) string {
	s := ruleSvc.Load()
	if s == nil {
		return "production"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state(id).State
}

// buildContentManifest reads the embedded packs (not custom rules) and the current lifecycle state.
func buildContentManifest() (ContentManifest, error) {
	raw, err := embeddedContentPacks()
	if err != nil {
		return ContentManifest{}, err
	}
	files := make([]string, 0, len(raw))
	for f := range raw {
		files = append(files, f)
	}
	sort.Strings(files)
	m := ContentManifest{Packs: []ManifestPack{}, Rules: []ManifestRule{}}
	for _, f := range files {
		var p contentPack
		if err := json.Unmarshal(raw[f], &p); err != nil {
			return ContentManifest{}, err
		}
		bs := map[string]bool{}
		for i := range p.Rules {
			r := &p.Rules[i]
			if r.Batch != "" {
				bs[r.Batch] = true
			}
			st := ruleEnabledState(r.ID)
			m.Rules = append(m.Rules, ManifestRule{ID: r.ID, Pack: p.Pack, Hash: ruleHash(r),
				Sev: fieldHash(r.Severity), Match: fieldHash(r.Match), Attack: fieldHash([]string{r.Tactic, r.Technique}), Enabled: fieldHash(st)})
		}
		batches := []string{}
		for b := range bs {
			batches = append(batches, b)
		}
		sort.Strings(batches)
		m.Packs = append(m.Packs, ManifestPack{File: f, Pack: p.Pack, Batches: batches, RuleCount: len(p.Rules), SHA256: sha256Hex(raw[f])})
	}
	sort.Slice(m.Rules, func(i, j int) bool { return m.Rules[i].ID < m.Rules[j].ID })
	m.RuleCount = len(m.Rules)
	return m, nil
}

// signManifest returns the sha256 of the compact manifest JSON and, when KAVACH_CONTENT_SIGN_KEY is
// set, a detached HMAC-SHA256 of that hex digest. A shared-secret integrity check, not a PKI.
func signManifest(m ContentManifest) (digest, sig string) {
	b, _ := json.Marshal(m)
	digest = sha256Hex(b)
	if k := os.Getenv(contentSignKeyEnv); k != "" {
		mac := hmac.New(sha256.New, []byte(k))
		mac.Write([]byte(digest))
		sig = hex.EncodeToString(mac.Sum(nil))
	}
	return
}

// ContentSnap is a stored manifest snapshot: counts and hashes only, no rule bodies.
type ContentSnap struct {
	Seq            int            `json:"seq"`
	Time           string         `json:"time"`
	Label          string         `json:"label,omitempty"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	PackCount      int            `json:"pack_count"`
	RuleCount      int            `json:"rule_count"`
	Packs          []ManifestPack `json:"packs"`
	Rules          []ManifestRule `json:"rules"`
}

type contentSnapStore struct {
	mu   sync.Mutex
	path string
	Next int           `json:"next_seq"`
	List []ContentSnap `json:"snapshots"`
}

func newContentSnapStore(path string) *contentSnapStore {
	s := &contentSnapStore{path: path, Next: 1}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, s)
			s.path = path
			if s.Next < 1 {
				s.Next = 1
			}
			for _, x := range s.List {
				if x.Seq >= s.Next {
					s.Next = x.Seq + 1
				}
			}
		}
	}
	return s
}

func (s *contentSnapStore) add(m ContentManifest, label string, now time.Time) ContentSnap {
	d, _ := signManifest(m)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := ContentSnap{Seq: s.Next, Time: now.UTC().Format(time.RFC3339), Label: label, ManifestSHA256: d,
		PackCount: len(m.Packs), RuleCount: m.RuleCount, Packs: m.Packs, Rules: m.Rules}
	s.Next++
	s.List = append(s.List, c)
	if len(s.List) > contentSnapsCap {
		s.List = append([]ContentSnap(nil), s.List[len(s.List)-contentSnapsCap:]...)
	}
	if s.path != "" {
		if b, err := json.Marshal(s); err == nil {
			tmp := s.path + ".tmp"
			if os.WriteFile(tmp, b, 0600) == nil {
				_ = os.Rename(tmp, s.path)
			}
		}
	}
	return c
}

func (s *contentSnapStore) get(seq int) (ContentSnap, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.List {
		if x.Seq == seq {
			return x, true
		}
	}
	return ContentSnap{}, false
}

func (s *contentSnapStore) latest() (ContentSnap, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.List) == 0 {
		return ContentSnap{}, false
	}
	return s.List[len(s.List)-1], true
}

// ManifestChange is one rule that differs between two manifests.
type ManifestChange struct {
	ID      string   `json:"id"`
	Pack    string   `json:"pack"`
	Changed []string `json:"fields_changed,omitempty"`
}

// ManifestDiff is the rule-level difference between two manifests.
type ManifestDiff struct {
	From    string           `json:"from"`
	To      string           `json:"to"`
	Same    bool             `json:"identical"`
	Added   []ManifestChange `json:"added"`
	Removed []ManifestChange `json:"removed"`
	Changed []ManifestChange `json:"changed"`
}

func diffManifestRules(from, to []ManifestRule) ManifestDiff {
	d := ManifestDiff{Added: []ManifestChange{}, Removed: []ManifestChange{}, Changed: []ManifestChange{}}
	fi := map[string]ManifestRule{}
	for _, r := range from {
		fi[r.ID] = r
	}
	seen := map[string]bool{}
	for _, b := range to {
		seen[b.ID] = true
		a, ok := fi[b.ID]
		if !ok {
			d.Added = append(d.Added, ManifestChange{ID: b.ID, Pack: b.Pack})
			continue
		}
		var ch []string
		if a.Sev != b.Sev {
			ch = append(ch, "severity")
		}
		if a.Match != b.Match {
			ch = append(ch, "patterns")
		}
		if a.Attack != b.Attack {
			ch = append(ch, "attack_mapping")
		}
		if a.Enabled != b.Enabled {
			ch = append(ch, "enabled_state")
		}
		if len(ch) == 0 && a.Hash != b.Hash {
			ch = []string{"other"}
		}
		if len(ch) > 0 {
			d.Changed = append(d.Changed, ManifestChange{ID: b.ID, Pack: b.Pack, Changed: ch})
		}
	}
	for _, a := range from {
		if !seen[a.ID] {
			d.Removed = append(d.Removed, ManifestChange{ID: a.ID, Pack: a.Pack})
		}
	}
	d.Same = len(d.Added)+len(d.Removed)+len(d.Changed) == 0
	return d
}

// RegisterContentManifest mounts /v1/content/manifest, /v1/content/snapshots and /v1/content/diff.
func RegisterContentManifest(mux *http.ServeMux, token string, store *Store) {
	p := ""
	if store != nil && store.path != "" {
		p = filepath.Clean(store.path) + ".contentsnaps.json"
	}
	ss := newContentSnapStore(p)
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/content/manifest", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		m, err := buildContentManifest()
		if err != nil {
			out(w, 500, map[string]any{"error": "manifest build failed"})
			return
		}
		digest, sig := signManifest(m)
		resp := map[string]any{"mode": "observe-only", "generated_at": time.Now().UTC().Format(time.RFC3339),
			"manifest": m, "manifest_sha256": digest, "signed": sig != ""}
		if sig != "" {
			resp["signature"] = map[string]string{"alg": "HMAC-SHA256", "over": "manifest_sha256", "value": sig}
		}
		out(w, 200, resp)
	})
	mux.HandleFunc("GET /v1/content/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ss.mu.Lock()
		rows := make([]map[string]any, 0, len(ss.List))
		for i := len(ss.List) - 1; i >= 0; i-- {
			x := ss.List[i]
			rows = append(rows, map[string]any{"seq": x.Seq, "time": x.Time, "label": x.Label,
				"manifest_sha256": x.ManifestSHA256, "pack_count": x.PackCount, "rule_count": x.RuleCount})
		}
		ss.mu.Unlock()
		out(w, 200, map[string]any{"mode": "observe-only", "cap": contentSnapsCap, "count": len(rows), "snapshots": rows})
	})
	mux.HandleFunc("POST /v1/content/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if !secureEqual(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), token) {
			out(w, 403, map[string]any{"error": "admin token required"})
			return
		}
		var in struct {
			Label string `json:"label"`
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, contentSnapBodyCap))
		if err != nil || (len(strings.TrimSpace(string(b))) > 0 && json.Unmarshal(b, &in) != nil) {
			out(w, 400, map[string]any{"error": "invalid JSON body {label}"})
			return
		}
		if len(in.Label) > 120 {
			in.Label = in.Label[:120]
		}
		m, err := buildContentManifest()
		if err != nil {
			out(w, 500, map[string]any{"error": "manifest build failed"})
			return
		}
		c := ss.add(m, in.Label, time.Now())
		out(w, 201, map[string]any{"mode": "observe-only", "seq": c.Seq, "time": c.Time, "label": c.Label,
			"manifest_sha256": c.ManifestSHA256, "pack_count": c.PackCount, "rule_count": c.RuleCount})
	})
	mux.HandleFunc("GET /v1/content/diff", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		resolve := func(ref, def string) (string, []ManifestRule, bool) {
			if ref == "" {
				ref = def
			}
			if ref == "embedded" || ref == "current" {
				m, err := buildContentManifest()
				return "embedded", m.Rules, err == nil
			}
			if ref == "latest" {
				c, ok := ss.latest()
				return "snapshot " + strconv.Itoa(c.Seq), c.Rules, ok
			}
			n, err := strconv.Atoi(ref)
			if err != nil {
				return "", nil, false
			}
			c, ok := ss.get(n)
			return "snapshot " + strconv.Itoa(n), c.Rules, ok
		}
		q := r.URL.Query()
		fl, fr, ok := resolve(q.Get("from"), "latest")
		if !ok {
			out(w, 404, map[string]any{"error": "unknown 'from' (use a snapshot seq, latest or embedded)"})
			return
		}
		tl, tr, ok := resolve(q.Get("to"), "embedded")
		if !ok {
			out(w, 404, map[string]any{"error": "unknown 'to' (use a snapshot seq, latest or embedded)"})
			return
		}
		d := diffManifestRules(fr, tr)
		d.From, d.To = fl, tl
		out(w, 200, map[string]any{"mode": "observe-only", "diff": d})
	})
}
