// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Detection rule health and lifecycle (observation only, nothing here takes an action).
//
//   - Health metrics are computed on demand from the findings the store already holds.
//   - Lifecycle state (draft|testing|production|retired) is persisted in <store>.rulelifecycle.json.
//     It only affects reporting and ordering, except "testing": hits of a testing rule are kept as
//     shadow findings and left out of the main findings list.
//   - Rule changes (custom rule put/delete, lifecycle changes) are recorded in a hash-chained history
//     in the same file, using the same hashing scheme as the analyst journal.

const (
	ruleHistoryMax = 5000
	ruleShadowMax  = 500
	ruleNoisyAt    = 60
)

var ruleStates = map[string]int{"production": 0, "testing": 1, "draft": 2, "retired": 3}

// RuleLifecycle is the persisted state of one rule.
type RuleLifecycle struct {
	Rule  string    `json:"rule"`
	State string    `json:"state"`
	Since time.Time `json:"since"`
	By    string    `json:"by"`
	Note  string    `json:"note,omitempty"`
}

// RuleHistoryEntry is one hash-chained change record.
type RuleHistoryEntry struct {
	Seq    int       `json:"seq"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Rule   string    `json:"rule"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	Prev   string    `json:"prev_hash"`
	Hash   string    `json:"hash"`
}

func ruleEntryHash(e RuleHistoryEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s\n%s", e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Actor, e.Rule, e.Action, e.Detail, e.Prev)
	return hex.EncodeToString(h.Sum(nil))
}

type ruleFile struct {
	Lifecycle map[string]RuleLifecycle `json:"lifecycle"`
	History   []RuleHistoryEntry       `json:"history"`
	Shadow    []Finding                `json:"shadow"`
}

type ruleService struct {
	mu    sync.Mutex
	path  string
	store *Store
	now   func() time.Time
	d     ruleFile
}

var ruleSvc atomic.Pointer[ruleService]

// ruleShadowed is called for every finding about to be stored. For a rule in "testing" it records
// the finding as a shadow finding and returns true so the caller skips the main list.
func ruleShadowed(f Finding) bool {
	s := ruleSvc.Load()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Lifecycle[f.Rule].State != "testing" {
		return false
	}
	s.d.Shadow = append(s.d.Shadow, f)
	if len(s.d.Shadow) > ruleShadowMax {
		s.d.Shadow = s.d.Shadow[len(s.d.Shadow)-ruleShadowMax:]
	}
	_ = s.saveLocked()
	return true
}

// ruleChanged records a custom rule create/update/delete in the history (old or new may be nil).
func ruleChanged(actor, id string, old, nw *ContentRule) {
	s := ruleSvc.Load()
	if s == nil {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case nw == nil:
		s.appendLocked(actor, id, "custom-rule.deleted", "hash="+ruleHash(old))
	case old == nil:
		s.appendLocked(actor, id, "custom-rule.created", "hash="+ruleHash(nw))
	default:
		s.appendLocked(actor, id, "custom-rule.updated", "hash="+ruleHash(nw)+" changed="+ruleDiff(old, nw))
	}
	_ = s.saveLocked()
}

func ruleHash(r *ContentRule) string {
	if r == nil {
		return ""
	}
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

func ruleDiff(a, b *ContentRule) string {
	var ma, mb map[string]json.RawMessage
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	seen := map[string]bool{}
	var keys []string
	for k := range ma {
		seen[k] = true
	}
	for k := range mb {
		seen[k] = true
	}
	for k := range seen {
		if string(ma[k]) != string(mb[k]) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "none"
	}
	return strings.Join(keys, ",")
}

// customActor names the caller for history entries (same convention as the tuning advisor).
func customActor(r *http.Request) string {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return "admin-token"
	}
	return "session"
}

func (s *ruleService) appendLocked(actor, rule, action, detail string) RuleHistoryEntry {
	e := RuleHistoryEntry{Seq: 1, Time: s.now().UTC(), Actor: actor, Rule: rule, Action: action, Detail: detail}
	if n := len(s.d.History); n > 0 {
		last := s.d.History[n-1]
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Hash = ruleEntryHash(e)
	s.d.History = append(s.d.History, e)
	if len(s.d.History) > ruleHistoryMax {
		s.d.History = s.d.History[len(s.d.History)-ruleHistoryMax:]
	}
	return e
}

// verifyLocked checks the chain links and hashes; the first retained entry is the anchor.
func (s *ruleService) verifyLocked() (bool, int) {
	for i, e := range s.d.History {
		if i > 0 && e.Prev != s.d.History[i-1].Hash {
			return false, e.Seq
		}
		if ruleEntryHash(e) != e.Hash {
			return false, e.Seq
		}
	}
	return true, 0
}

func (s *ruleService) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *ruleService) load() {
	s.d = ruleFile{Lifecycle: map[string]RuleLifecycle{}}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f ruleFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	if f.Lifecycle == nil {
		f.Lifecycle = map[string]RuleLifecycle{}
	}
	s.d = f
}

func (s *ruleService) state(id string) RuleLifecycle {
	if l, ok := s.d.Lifecycle[id]; ok {
		return l
	}
	return RuleLifecycle{Rule: id, State: "production"}
}

// RuleHealth is the computed health of one rule.
type RuleHealth struct {
	Rule         string     `json:"rule"`
	Name         string     `json:"name,omitempty"`
	Source       string     `json:"source"` // custom | embedded | builtin (seen in findings, not in the content registry)
	Severity     string     `json:"severity,omitempty"`
	State        string     `json:"state"`
	StateSince   *time.Time `json:"state_since,omitempty"`
	Hits24h      int        `json:"hits_24h"`
	Hits7d       int        `json:"hits_7d"`
	Hits30d      int        `json:"hits_30d"`
	HitsTotal    int        `json:"hits_total"`
	ShadowHits   int        `json:"shadow_hits"`
	DistinctHost int        `json:"distinct_hosts_30d"`
	LastFired    *time.Time `json:"last_fired,omitempty"`
	Trend        string     `json:"trend"` // up|down|flat|new|none (last 7d vs the 7d before)
	Share30d     float64    `json:"share_of_findings_30d"`
	NoisyScore   int        `json:"noisy_score"`
	Noisy        bool       `json:"noisy"`
	Silent       bool       `json:"silent"` // in the registry but never fired (store retention window)
}

func ruleTrend(cur, prev int) string {
	switch {
	case cur == 0 && prev == 0:
		return "none"
	case prev == 0:
		return "new"
	case float64(cur) > 1.25*float64(prev):
		return "up"
	case float64(cur) < 0.75*float64(prev):
		return "down"
	}
	return "flat"
}

// ruleNoisy scores 0-100: 50% volume (hits/day over 7d, saturating at 100/day), 30% share of all
// 30d findings (saturating at 50%), 20% repetition (30d hits per host, saturating at 100).
func ruleNoisy(h7 int, share30 float64, h30, hosts int) int {
	vol := math.Min(1, math.Log10(1+float64(h7)/7)/2)
	sh := math.Min(1, share30*2)
	rep := 0.0
	if hosts > 0 && h30 > 1 {
		rep = math.Min(1, math.Log10(float64(h30)/float64(hosts))/2)
	}
	return int(math.Round(100 * (0.5*vol + 0.3*sh + 0.2*rep)))
}

// BuildRuleHealth computes health rows from findings (main list) and shadow findings.
func BuildRuleHealth(findings, shadow []Finding, lc map[string]RuleLifecycle, now time.Time) []RuleHealth {
	type acc struct {
		h     RuleHealth
		hosts map[string]bool
		prev7 int
	}
	rows := map[string]*acc{}
	get := func(id string) *acc {
		a := rows[id]
		if a == nil {
			a = &acc{h: RuleHealth{Rule: id, Source: "builtin", State: "production", Trend: "none"}, hosts: map[string]bool{}}
			rows[id] = a
		}
		return a
	}
	if reg := contentReg.Load(); reg != nil {
		for _, r := range reg.rules {
			a := get(r.ID)
			a.h.Name, a.h.Severity, a.h.Source = r.Name, r.Severity, "embedded"
			if contentIsCustom(r.ID) {
				a.h.Source = "custom"
			}
		}
	}
	for id := range lc {
		get(id)
	}
	total30 := 0
	d1, d7, d14, d30 := now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-14*24*time.Hour), now.Add(-30*24*time.Hour)
	for _, f := range findings {
		a := get(f.Rule)
		if a.h.Severity == "" {
			a.h.Severity = f.Severity
		}
		a.h.HitsTotal++
		if a.h.LastFired == nil || f.Time.After(*a.h.LastFired) {
			t := f.Time
			a.h.LastFired = &t
		}
		if f.Time.After(d30) {
			total30++
			a.h.Hits30d++
			a.hosts[f.Host] = true
		}
		if f.Time.After(d7) {
			a.h.Hits7d++
		} else if f.Time.After(d14) {
			a.prev7++
		}
		if f.Time.After(d1) {
			a.h.Hits24h++
		}
	}
	for _, f := range shadow {
		get(f.Rule).h.ShadowHits++
	}
	out := make([]RuleHealth, 0, len(rows))
	for id, a := range rows {
		h := a.h
		if l, ok := lc[id]; ok {
			h.State = l.State
			t := l.Since
			h.StateSince = &t
		}
		h.DistinctHost = len(a.hosts)
		h.Trend = ruleTrend(h.Hits7d, a.prev7)
		if total30 > 0 {
			h.Share30d = math.Round(float64(h.Hits30d)/float64(total30)*10000) / 10000
		}
		h.NoisyScore = ruleNoisy(h.Hits7d, h.Share30d, h.Hits30d, h.DistinctHost)
		h.Noisy = h.NoisyScore >= ruleNoisyAt
		h.Silent = h.Source != "builtin" && h.HitsTotal == 0 && h.ShadowHits == 0
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ruleStates[a.State] != ruleStates[b.State] {
			return ruleStates[a.State] < ruleStates[b.State]
		}
		if a.NoisyScore != b.NoisyScore {
			return a.NoisyScore > b.NoisyScore
		}
		return a.Rule < b.Rule
	})
	return out
}

func (s *ruleService) health() []RuleHealth {
	f := s.store.List()
	s.mu.Lock()
	lc := make(map[string]RuleLifecycle, len(s.d.Lifecycle))
	for k, v := range s.d.Lifecycle {
		lc[k] = v
	}
	sh := append([]Finding(nil), s.d.Shadow...)
	s.mu.Unlock()
	return BuildRuleHealth(f, sh, lc, s.now())
}

// RegisterRuleHealth wires the rule health, lifecycle and history endpoints.
func RegisterRuleHealth(mux *http.ServeMux, token string, store *Store) {
	s := &ruleService{path: store.path + ".rulelifecycle.json", store: store, now: time.Now}
	s.load()
	ruleSvc.Store(s)
	store.OnClose(func() { ruleSvc.CompareAndSwap(s, nil) })
	s.routes(mux, token)
}

func (s *ruleService) routes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/rules/health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		rows := s.health()
		out := rows[:0:0]
		for _, h := range rows {
			if v := q.Get("state"); v != "" && h.State != v {
				continue
			}
			if v := q.Get("source"); v != "" && h.Source != v {
				continue
			}
			if q.Get("silent") == "1" && !h.Silent {
				continue
			}
			if q.Get("noisy") == "1" && !h.Noisy {
				continue
			}
			out = append(out, h)
		}
		limit := 200
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n < limit {
			limit = n
		}
		count := len(out)
		if len(out) > limit {
			out = out[:limit]
		}
		customJSON(w, 200, map[string]any{"mode": "observe-only", "count": count, "noisy_threshold": ruleNoisyAt, "rules": out})
	})
	mux.HandleFunc("GET /v1/rules/health/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		for _, h := range s.health() {
			if h.Rule == id {
				var recent []string
				fs := s.store.List()
				for i := len(fs) - 1; i >= 0 && len(recent) < 5; i-- {
					if fs[i].Rule == id {
						recent = append(recent, fs[i].ID)
					}
				}
				customJSON(w, 200, map[string]any{"mode": "observe-only", "health": h, "recent_finding_ids": recent})
				return
			}
		}
		customJSON(w, 404, map[string]any{"error": "unknown rule"})
	})
	mux.HandleFunc("GET /v1/rules/lifecycle/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		s.mu.Lock()
		l, set := s.d.Lifecycle[id]
		if !set {
			l = s.state(id)
		}
		s.mu.Unlock()
		customJSON(w, 200, map[string]any{"mode": "observe-only", "lifecycle": l, "explicit": set,
			"states": []string{"draft", "testing", "production", "retired"}})
	})
	mux.HandleFunc("PUT /v1/rules/lifecycle/{id}", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.PathValue("id")
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
		var in struct {
			State string `json:"state"`
			Note  string `json:"note"`
		}
		if err != nil || json.Unmarshal(b, &in) != nil {
			customJSON(w, 400, map[string]any{"error": "invalid JSON body {state, note}"})
			return
		}
		if _, valid := ruleStates[in.State]; !valid {
			customJSON(w, 400, map[string]any{"error": "state must be draft, testing, production or retired"})
			return
		}
		if len(in.Note) > 500 {
			in.Note = in.Note[:500]
		}
		if !s.ruleKnown(id) {
			customJSON(w, 404, map[string]any{"error": "unknown rule"})
			return
		}
		actor := tuneActor(admin)
		s.mu.Lock()
		defer s.mu.Unlock()
		old := s.state(id).State
		l := RuleLifecycle{Rule: id, State: in.State, Since: s.now().UTC(), By: actor, Note: in.Note}
		prev, had := s.d.Lifecycle[id]
		s.d.Lifecycle[id] = l
		hl := len(s.d.History)
		s.appendLocked(actor, id, "lifecycle", fmt.Sprintf("%s -> %s note=%q", old, in.State, in.Note))
		if err := s.saveLocked(); err != nil {
			if had {
				s.d.Lifecycle[id] = prev
			} else {
				delete(s.d.Lifecycle, id)
			}
			s.d.History = s.d.History[:hl]
			customJSON(w, 500, map[string]any{"error": "persist failed: " + err.Error()})
			return
		}
		customJSON(w, 200, map[string]any{"status": "saved", "mode": "observe-only", "lifecycle": l,
			"note_effect": "reporting/ordering only; testing keeps hits as shadow findings"})
	})
	mux.HandleFunc("GET /v1/rules/history/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.PathValue("id")
		s.mu.Lock()
		okc, bad := s.verifyLocked()
		var out []RuleHistoryEntry
		for _, e := range s.d.History {
			if e.Rule == id {
				out = append(out, e)
			}
		}
		s.mu.Unlock()
		if out == nil {
			out = []RuleHistoryEntry{}
		}
		customJSON(w, 200, map[string]any{"mode": "observe-only", "rule": id, "count": len(out), "chain_ok": okc, "broken_at_seq": bad, "entries": out})
	})
}

// ruleKnown: in the content registry, already has lifecycle/history, or has produced findings.
func (s *ruleService) ruleKnown(id string) bool {
	if reg := contentReg.Load(); reg != nil && reg.byID[id] != nil {
		return true
	}
	s.mu.Lock()
	_, has := s.d.Lifecycle[id]
	s.mu.Unlock()
	if has {
		return true
	}
	for _, f := range s.store.List() {
		if f.Rule == id {
			return true
		}
	}
	return false
}
