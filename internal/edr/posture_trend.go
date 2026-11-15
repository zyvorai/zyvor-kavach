// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Posture trend: periodic, counts-only snapshots of the posture numbers Kavach already computes.
// Observation-only and pull-only: nothing is sent anywhere, no finding text, host name or
// credential is ever stored, and the history is capped.

const (
	postureTrendCap        = 400
	postureDefaultInterval = 6 // hours
	postureMinInterval     = 1
	postureMaxInterval     = 168
	postureMaxDays         = 400
)

// postureFirstDelay lets all routes register before the first automatic snapshot (var for tests).
var postureFirstDelay = 15 * time.Second

// PostureSnapshot holds counts only.
type PostureSnapshot struct {
	Time            time.Time      `json:"time"`
	ComplianceScore int            `json:"compliance_score"`
	ComplianceGrade string         `json:"compliance_grade"`
	FrameworkScores map[string]int `json:"framework_scores"`
	TacticsCovered  int            `json:"attack_tactics_covered"`
	TacticsTotal    int            `json:"attack_tactics_total"`
	FindingsTotal   int            `json:"findings_total"`
	FindingsBySev   map[string]int `json:"findings_by_severity"`
	AgentsActive    int            `json:"agents_active"`
	// SLO error-budget remaining, percent; nil when no samples were judged (never estimated).
	HeartbeatBudgetPct  *float64       `json:"slo_heartbeat_budget_remaining_pct"`
	ContinuityBudgetPct *float64       `json:"slo_continuity_budget_remaining_pct"`
	RulesTotal          int            `json:"rules_total"`
	RulesSilent         int            `json:"rules_silent"`
	RulesNoisy          int            `json:"rules_noisy"`
	RulesByState        map[string]int `json:"rules_by_state"`
	Unavailable         []string       `json:"unavailable,omitempty"`
}

type postureCfg struct {
	IntervalHours int  `json:"interval_hours"`
	Enabled       bool `json:"enabled"`
}

type postureFile struct {
	Config    postureCfg        `json:"config"`
	Snapshots []PostureSnapshot `json:"snapshots"`
}

type postureEngine struct {
	mu      sync.Mutex
	path    string
	cfg     postureCfg
	snaps   []PostureSnapshot
	collect func(now time.Time) PostureSnapshot
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newPostureEngine(path string, collect func(time.Time) PostureSnapshot) *postureEngine {
	e := &postureEngine{path: path, cfg: postureCfg{IntervalHours: postureDefaultInterval, Enabled: true}, collect: collect,
		stop: make(chan struct{}), done: make(chan struct{})}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var f postureFile
			if json.Unmarshal(b, &f) == nil {
				if f.Config.IntervalHours >= postureMinInterval && f.Config.IntervalHours <= postureMaxInterval {
					e.cfg = f.Config
				}
				e.snaps = f.Snapshots
				if len(e.snaps) > postureTrendCap {
					e.snaps = e.snaps[len(e.snaps)-postureTrendCap:]
				}
			}
		}
	}
	return e
}

func (e *postureEngine) saveLocked() {
	if e.path == "" {
		return
	}
	b, err := json.Marshal(postureFile{Config: e.cfg, Snapshots: e.snaps})
	if err != nil {
		return
	}
	tmp := e.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.path)
	}
}

// Record appends a snapshot (caps history) and persists.
func (e *postureEngine) Record(s PostureSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snaps = append(e.snaps, s)
	if len(e.snaps) > postureTrendCap {
		e.snaps = append([]PostureSnapshot(nil), e.snaps[len(e.snaps)-postureTrendCap:]...)
	}
	e.saveLocked()
}

func (e *postureEngine) Snapshots() []PostureSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]PostureSnapshot(nil), e.snaps...)
}

func (e *postureEngine) Config() postureCfg {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *postureEngine) SetConfig(c postureCfg) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = c
	e.saveLocked()
}

// due reports whether the periodic snapshot should run now.
func (e *postureEngine) due(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cfg.Enabled {
		return false
	}
	if len(e.snaps) == 0 {
		return true
	}
	return now.Sub(e.snaps[len(e.snaps)-1].Time) >= time.Duration(e.cfg.IntervalHours)*time.Hour
}

func (e *postureEngine) start() {
	go func() {
		defer close(e.done)
		select {
		case <-e.stop:
			return
		case <-time.After(postureFirstDelay):
		}
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if now := time.Now().UTC(); e.due(now) {
				e.Record(e.collect(now))
			}
			select {
			case <-e.stop:
				return
			case <-t.C:
			}
		}
	}()
}

// Shutdown stops the sampler and flushes.
func (e *postureEngine) Shutdown(ctx context.Context) error {
	e.once.Do(func() { close(e.stop) })
	select {
	case <-e.done:
	case <-ctx.Done():
	}
	e.mu.Lock()
	e.saveLocked()
	e.mu.Unlock()
	return nil
}

// internalGet calls a GET route of the same API in-process with the API token. The token never
// leaves the process and is not copied into any output.
func internalGet(h http.Handler, token, path string) (map[string]any, int, []byte) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	var m map[string]any
	if rec.Code == 200 {
		_ = json.Unmarshal(body, &m)
	}
	return m, rec.Code, body
}

func numI(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func numPtr(v any) *float64 {
	if f, ok := v.(float64); ok {
		return &f
	}
	return nil
}

// collectPosture gathers one counts-only snapshot from the existing views.
func collectPosture(h http.Handler, token string, store *Store, now time.Time) PostureSnapshot {
	s := PostureSnapshot{Time: now.UTC(), FrameworkScores: map[string]int{}, FindingsBySev: map[string]int{}, RulesByState: map[string]int{}}
	if m, code, _ := internalGet(h, token, "/v1/compliance/score"); code == 200 {
		s.ComplianceScore = numI(m["overall"])
		s.ComplianceGrade, _ = m["grade"].(string)
		if fws, ok := m["frameworks"].([]any); ok {
			for _, f := range fws {
				if fm, ok := f.(map[string]any); ok {
					if id, _ := fm["id"].(string); id != "" {
						s.FrameworkScores[id] = numI(fm["score"])
					}
				}
			}
		}
		if ev, ok := m["evidence"].(map[string]any); ok {
			s.TacticsCovered, s.TacticsTotal = numI(ev["attack_tactics_covered"]), numI(ev["attack_tactics_total"])
		}
	} else {
		s.Unavailable = append(s.Unavailable, "compliance_score")
	}
	if store != nil {
		for _, f := range store.List() {
			s.FindingsTotal++
			sev := f.Severity
			switch sev {
			case "critical", "high", "medium", "low", "info":
			default:
				sev = "other"
			}
			s.FindingsBySev[sev]++
		}
	}
	if m, code, _ := internalGet(h, token, "/v1/fleet/slo"); code == 200 {
		if fl, ok := m["fleet"].(map[string]any); ok {
			s.AgentsActive = numI(fl["enrolled_active_agents"])
			if hb, ok := fl["heartbeat"].(map[string]any); ok {
				s.HeartbeatBudgetPct = numPtr(hb["error_budget_remaining_pct"])
			}
			if ct, ok := fl["continuity"].(map[string]any); ok {
				s.ContinuityBudgetPct = numPtr(ct["error_budget_remaining_pct"])
			}
		}
	} else {
		s.Unavailable = append(s.Unavailable, "fleet_slo")
	}
	if svc := ruleSvc.Load(); svc != nil {
		for _, r := range svc.health() {
			s.RulesTotal++
			s.RulesByState[r.State]++
			if r.Silent {
				s.RulesSilent++
			}
			if r.Noisy {
				s.RulesNoisy++
			}
		}
	} else {
		s.Unavailable = append(s.Unavailable, "rule_health")
	}
	return s
}

// ---- diff ----

type postureDelta struct {
	ComplianceScore int            `json:"compliance_score"`
	TacticsCovered  int            `json:"attack_tactics_covered"`
	FindingsTotal   int            `json:"findings_total"`
	FindingsBySev   map[string]int `json:"findings_by_severity"`
	FrameworkScores map[string]int `json:"framework_scores"`
	HeartbeatBudget *float64       `json:"slo_heartbeat_budget_remaining_pct"`
	Continuity      *float64       `json:"slo_continuity_budget_remaining_pct"`
	RulesSilent     int            `json:"rules_silent"`
	RulesNoisy      int            `json:"rules_noisy"`
	RulesTotal      int            `json:"rules_total"`
}

func subPtr(a, b *float64) *float64 {
	if a == nil || b == nil {
		return nil
	}
	v := *a - *b
	return &v
}

func diffPosture(from, to PostureSnapshot) postureDelta {
	d := postureDelta{
		ComplianceScore: to.ComplianceScore - from.ComplianceScore, TacticsCovered: to.TacticsCovered - from.TacticsCovered,
		FindingsTotal: to.FindingsTotal - from.FindingsTotal, FindingsBySev: map[string]int{}, FrameworkScores: map[string]int{},
		HeartbeatBudget: subPtr(to.HeartbeatBudgetPct, from.HeartbeatBudgetPct), Continuity: subPtr(to.ContinuityBudgetPct, from.ContinuityBudgetPct),
		RulesSilent: to.RulesSilent - from.RulesSilent, RulesNoisy: to.RulesNoisy - from.RulesNoisy, RulesTotal: to.RulesTotal - from.RulesTotal,
	}
	for k := range to.FindingsBySev {
		d.FindingsBySev[k] = to.FindingsBySev[k] - from.FindingsBySev[k]
	}
	for k := range from.FindingsBySev {
		d.FindingsBySev[k] = to.FindingsBySev[k] - from.FindingsBySev[k]
	}
	for k, v := range to.FrameworkScores {
		if fv, ok := from.FrameworkScores[k]; ok {
			d.FrameworkScores[k] = v - fv
		}
	}
	return d
}

// snapshotAtOrBefore returns the newest snapshot not after t.
func snapshotAtOrBefore(snaps []PostureSnapshot, t time.Time) (PostureSnapshot, bool) {
	var best PostureSnapshot
	ok := false
	for _, s := range snaps {
		if !s.Time.After(t) && (!ok || s.Time.After(best.Time)) {
			best, ok = s, true
		}
	}
	return best, ok
}

func parseDay(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t.UTC(), err == nil
}

// RegisterPostureReports wires the posture trend, executive digest and auditor bundle routes.
// All are read-only except PUT /v1/posture/trend/config (admin token).
func RegisterPostureReports(mux *http.ServeMux, token string, store *Store) {
	path := ""
	if store != nil && store.path != "" {
		path = filepath.Clean(store.path) + ".posturetrend.json"
	}
	eng := newPostureEngine(path, func(now time.Time) PostureSnapshot { return collectPosture(mux, token, store, now) })
	eng.start()
	RegisterStopper("posture-trend", eng.Shutdown)

	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/posture/trend", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		days := 30
		if v := r.URL.Query().Get("days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > postureMaxDays {
				http.Error(w, "days must be 1.."+strconv.Itoa(postureMaxDays), 400)
				return
			}
			days = n
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		rows := []PostureSnapshot{}
		for _, s := range eng.Snapshots() {
			if !s.Time.Before(cutoff) {
				rows = append(rows, s)
			}
		}
		cfg := eng.Config()
		out(w, 200, map[string]any{"mode": "observe-only", "count": len(rows), "days": days, "history_cap": postureTrendCap,
			"interval_hours": cfg.IntervalHours, "enabled": cfg.Enabled, "snapshots": rows,
			"note": "Counts only. Snapshots are taken while Kavach runs; gaps mean it was stopped. Nothing is sent anywhere."})
	})
	mux.HandleFunc("GET /v1/posture/trend/diff", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		fd, ok := parseDay(q.Get("from"))
		if !ok {
			http.Error(w, "from must be a date YYYY-MM-DD", 400)
			return
		}
		snaps := eng.Snapshots()
		var td time.Time
		if q.Get("to") == "" {
			td = time.Now().UTC()
		} else if td, ok = parseDay(q.Get("to")); !ok {
			http.Error(w, "to must be a date YYYY-MM-DD", 400)
			return
		} else {
			td = td.Add(24*time.Hour - time.Nanosecond)
		}
		if fd.After(td) {
			http.Error(w, "from must not be after to", 400)
			return
		}
		a, okA := snapshotAtOrBefore(snaps, fd.Add(24*time.Hour-time.Nanosecond))
		b, okB := snapshotAtOrBefore(snaps, td)
		if !okA || !okB {
			out(w, 404, map[string]any{"error": "no snapshot at or before the requested date", "snapshots_held": len(snaps)})
			return
		}
		out(w, 200, map[string]any{"mode": "observe-only", "from": a, "to": b, "delta": diffPosture(a, b),
			"note": "Each side is the newest snapshot at or before the end of that day (UTC); deltas are to minus from."})
	})
	mux.HandleFunc("GET /v1/posture/trend/config", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out(w, 200, eng.Config())
	})
	mux.HandleFunc("PUT /v1/posture/trend/config", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !admin {
			http.Error(w, "admin token required", http.StatusForbidden)
			return
		}
		c := eng.Config()
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), 400)
			return
		}
		if c.IntervalHours < postureMinInterval || c.IntervalHours > postureMaxInterval {
			http.Error(w, "interval_hours must be "+strconv.Itoa(postureMinInterval)+".."+strconv.Itoa(postureMaxInterval), 400)
			return
		}
		eng.SetConfig(c)
		out(w, 200, c)
	})

	registerDigestAndBundle(mux, token, store, eng)
}
