// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheduled detections (observation only): a saved search or a kavach-seq query promoted into a
// detection that runs on an interval and RECORDS findings (rule id "hunt-<id>"). Nothing here takes an
// action on a host. State lives in <store>.scheduled_detections.json.

const (
	schedMinInterval   = time.Minute
	schedMaxInterval   = 24 * time.Hour
	schedTick          = 15 * time.Second
	schedDefaultDedup  = 24 * time.Hour
	schedMaxDedup      = 30 * 24 * time.Hour
	schedDedupKeep     = 5000
	schedShadowKeep    = 100
	schedRefusedKeep   = 50
	schedMaxRuntimeCap = 30 * time.Second
	schedDefRuntime    = 5 * time.Second
	schedScanCap       = 20000
)

var (
	schedStates     = map[string]bool{"draft": true, "testing": true, "production": true, "retired": true}
	schedSeverities = map[string]bool{"info": true, "low": true, "medium": true, "high": true}
	schedTechniqueR = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

// DetSource is what a scheduled detection evaluates.
type DetSource struct {
	Kind          string `json:"kind"` // saved_search | seq
	SavedSearchID string `json:"saved_search_id,omitempty"`
	Query         string `json:"query,omitempty"` // kavach-seq query text (kind seq)
	Since         string `json:"since,omitempty"` // seq lookback, default 24h
}

// SchedDetection is one scheduled detection.
type SchedDetection struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Source         DetSource `json:"source"`
	IntervalSec    int       `json:"interval_sec"`
	Severity       string    `json:"severity"`
	Technique      string    `json:"technique,omitempty"`
	State          string    `json:"state"` // draft|testing|production|retired
	MaxMatches     int       `json:"max_matches"`
	MaxRuntimeMS   int       `json:"max_runtime_ms"`
	DedupWindowSec int       `json:"dedup_window_sec"`
	Rule           string    `json:"rule"` // hunt-<id>
	Created        time.Time `json:"created"`
	Updated        time.Time `json:"updated"`
	By             string    `json:"by"`
	LastRun        time.Time `json:"last_run,omitempty"`
}

// SchedRun is one run-history entry.
type SchedRun struct {
	Time       time.Time `json:"time"`
	DurationMS int64     `json:"duration_ms"`
	Trigger    string    `json:"trigger"` // schedule | manual | dryrun
	DryRun     bool      `json:"dry_run"`
	Scanned    int       `json:"scanned"`
	Matched    int       `json:"matched"`
	Recorded   int       `json:"recorded"` // findings added to the main list
	Shadow     int       `json:"shadow"`   // findings kept as shadow only (state testing)
	Deduped    int       `json:"deduped"`
	Suppressed int       `json:"suppressed"` // reporting suppressed by an exception
	Truncated  bool      `json:"truncated,omitempty"`
	TimedOut   bool      `json:"timed_out,omitempty"`
	Errors     []string  `json:"errors,omitempty"`
}

// HuntLimits are the configurable quotas.
type HuntLimits struct {
	MaxScheduled     int `json:"max_scheduled"`
	MaxRunsPerHour   int `json:"max_runs_per_hour"`
	MaxMatchesPerRun int `json:"max_matches_per_run"`
	HistoryRetention int `json:"history_retention"` // runs kept per detection
}

// HuntRefusal records something a quota refused.
type HuntRefusal struct {
	Time   time.Time `json:"time"`
	What   string    `json:"what"` // create|run
	ID     string    `json:"id,omitempty"`
	Reason string    `json:"reason"`
}

type schedFile struct {
	Detections []SchedDetection            `json:"detections"`
	History    map[string][]SchedRun       `json:"history"`
	Dedup      map[string]map[string]int64 `json:"dedup"` // detection -> match key -> unix seconds last reported
	Shadow     map[string][]Finding        `json:"shadow"`
	Limits     *HuntLimits                 `json:"limits,omitempty"`
	RunTimes   []time.Time                 `json:"run_times"`
	Refused    []HuntRefusal               `json:"refused"`
	RefusedN   map[string]int              `json:"refused_counts"`
	Seq        int                         `json:"seq"`
}

type schedService struct {
	mu      sync.Mutex
	path    string
	store   *Store
	ws      *Workspace
	now     func() time.Time
	d       schedFile
	running map[string]bool
	lastRun map[string]time.Time // in-memory schedule anchors (monotonic when the clock is real)
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v > 0 {
		return v
	}
	return def
}

func clampLimits(l HuntLimits) HuntLimits {
	c := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	l.MaxScheduled = c(l.MaxScheduled, 1, 500)
	l.MaxRunsPerHour = c(l.MaxRunsPerHour, 1, 3600)
	l.MaxMatchesPerRun = c(l.MaxMatchesPerRun, 1, 1000)
	l.HistoryRetention = c(l.HistoryRetention, 1, 500)
	return l
}

func envLimits() HuntLimits {
	return clampLimits(HuntLimits{
		MaxScheduled:     envInt("KAVACH_HUNT_MAX_SCHEDULED", 50),
		MaxRunsPerHour:   envInt("KAVACH_HUNT_MAX_RUNS_PER_HOUR", 120),
		MaxMatchesPerRun: envInt("KAVACH_HUNT_MAX_MATCHES_PER_RUN", 100),
		HistoryRetention: envInt("KAVACH_HUNT_HISTORY_RETENTION", 50),
	})
}

func newSchedService(store *Store, ws *Workspace, now func() time.Time) *schedService {
	s := &schedService{store: store, ws: ws, now: now, running: map[string]bool{}, lastRun: map[string]time.Time{}, stop: make(chan struct{})}
	if store != nil && store.path != "" {
		s.path = store.path + ".scheduled_detections.json"
	}
	s.load()
	t := now()
	for _, d := range s.d.Detections {
		s.lastRun[d.ID] = t // after a restart the first run is one interval away
	}
	return s
}

func (s *schedService) load() {
	s.d = schedFile{}
	if s.path != "" {
		if b, err := os.ReadFile(s.path); err == nil {
			_ = json.Unmarshal(b, &s.d)
		}
	}
	if s.d.History == nil {
		s.d.History = map[string][]SchedRun{}
	}
	if s.d.Dedup == nil {
		s.d.Dedup = map[string]map[string]int64{}
	}
	if s.d.Shadow == nil {
		s.d.Shadow = map[string][]Finding{}
	}
	if s.d.RefusedN == nil {
		s.d.RefusedN = map[string]int{}
	}
}

func (s *schedService) saveLocked() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(s.d)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *schedService) limitsLocked() HuntLimits {
	if s.d.Limits != nil {
		return clampLimits(*s.d.Limits)
	}
	return envLimits()
}

func (s *schedService) refuseLocked(what, id, reason string) {
	s.d.Refused = append(s.d.Refused, HuntRefusal{Time: s.now().UTC(), What: what, ID: id, Reason: reason})
	if len(s.d.Refused) > schedRefusedKeep {
		s.d.Refused = s.d.Refused[len(s.d.Refused)-schedRefusedKeep:]
	}
	s.d.RefusedN[what]++
	s.saveLocked()
}

func (s *schedService) runsLastHourLocked(now time.Time) int {
	cut := now.Add(-time.Hour)
	keep := s.d.RunTimes[:0]
	for _, t := range s.d.RunTimes {
		if t.After(cut) && !t.After(now.Add(time.Hour)) { // drop entries from a clock that jumped far ahead
			keep = append(keep, t)
		}
	}
	s.d.RunTimes = keep
	return len(keep)
}

func (s *schedService) find(id string) int {
	for i := range s.d.Detections {
		if s.d.Detections[i].ID == id {
			return i
		}
	}
	return -1
}

// validateDet normalises and validates a detection definition.
func (s *schedService) validateDet(d *SchedDetection, lim HuntLimits) string {
	d.Name = strings.TrimSpace(d.Name)
	d.Technique = strings.ToUpper(strings.TrimSpace(d.Technique))
	d.Severity = strings.ToLower(strings.TrimSpace(d.Severity))
	if d.State == "" {
		d.State = "draft"
	}
	if d.IntervalSec == 0 {
		d.IntervalSec = 3600
	}
	if d.MaxMatches == 0 {
		d.MaxMatches = lim.MaxMatchesPerRun
	}
	if d.MaxRuntimeMS == 0 {
		d.MaxRuntimeMS = int(schedDefRuntime / time.Millisecond)
	}
	if d.DedupWindowSec == 0 {
		d.DedupWindowSec = int(schedDefaultDedup / time.Second)
	}
	switch {
	case d.Name == "" || len(d.Name) > 120:
		return "name is required (max 120 characters)"
	case !schedSeverities[d.Severity]:
		return "severity must be info, low, medium or high (critical is not allowed for scheduled detections)"
	case d.Technique != "" && !schedTechniqueR.MatchString(d.Technique):
		return "technique must look like T1059 or T1059.004"
	case !schedStates[d.State]:
		return "state must be draft, testing, production or retired"
	case time.Duration(d.IntervalSec)*time.Second < schedMinInterval || time.Duration(d.IntervalSec)*time.Second > schedMaxInterval:
		return "interval_sec must be between 60 and 86400"
	case d.MaxMatches < 1 || d.MaxMatches > lim.MaxMatchesPerRun:
		return "max_matches must be between 1 and the configured max_matches_per_run (" + strconv.Itoa(lim.MaxMatchesPerRun) + ")"
	case time.Duration(d.MaxRuntimeMS)*time.Millisecond < 100*time.Millisecond || time.Duration(d.MaxRuntimeMS)*time.Millisecond > schedMaxRuntimeCap:
		return "max_runtime_ms must be between 100 and 30000"
	case time.Duration(d.DedupWindowSec)*time.Second < time.Minute || time.Duration(d.DedupWindowSec)*time.Second > schedMaxDedup:
		return "dedup_window_sec must be between 60 and 2592000"
	}
	switch d.Source.Kind {
	case "saved_search":
		if d.Source.SavedSearchID == "" {
			return "source.saved_search_id is required"
		}
		if s.ws != nil {
			if _, ok := s.savedSearch(d.Source.SavedSearchID); !ok {
				return "saved search not found"
			}
		}
	case "seq":
		q, perr := parseSeq(d.Source.Query)
		if perr != nil {
			return "invalid kavach-seq query: " + perr.Error()
		}
		if len(q.Problems) > 0 {
			return "kavach-seq query uses unavailable fields"
		}
		if _, err := parseSince(d.Source.Since, time.Now()); err != nil {
			return "invalid source.since (use 24h, 7d or RFC3339)"
		}
	default:
		return "source.kind must be saved_search or seq"
	}
	return ""
}

func (s *schedService) savedSearch(id string) (SavedSearch, bool) {
	if s.ws == nil {
		return SavedSearch{}, false
	}
	s.ws.mu.Lock()
	defer s.ws.mu.Unlock()
	for _, x := range s.ws.data.Searches {
		if x.ID == id {
			return x, true
		}
	}
	return SavedSearch{}, false
}

// syncLifecycleLocked mirrors the detection state into the rule lifecycle so rule health shows it.
func syncRuleLifecycle(d SchedDetection, actor string, now time.Time) {
	r := ruleSvc.Load()
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if d.State == "production" {
		delete(r.d.Lifecycle, d.Rule)
	} else {
		r.d.Lifecycle[d.Rule] = RuleLifecycle{Rule: d.Rule, State: d.State, Since: now.UTC(), By: actor, Note: "scheduled detection " + d.ID}
	}
	r.appendLocked(actor, d.Rule, "lifecycle", "scheduled detection "+d.ID+" state="+d.State)
	_ = r.saveLocked()
}

type schedMatch struct {
	Key         string
	Host        string
	Description string
	Evidence    Event
}

func (s *schedService) evalSavedSearch(ctx context.Context, d SchedDetection, max int) (matches []schedMatch, scanned int, truncated bool, err error) {
	ss, ok := s.savedSearch(d.Source.SavedSearchID)
	if !ok {
		return nil, 0, false, fmt.Errorf("saved search %q not found", d.Source.SavedSearchID)
	}
	fs := s.store.List()
	if len(fs) > schedScanCap {
		fs = fs[len(fs)-schedScanCap:]
	}
	q := strings.ToLower(strings.TrimSpace(ss.Query))
	filters := parseHuntQuery(ss.Query)
	for _, f := range fs {
		if ctx.Err() != nil {
			return matches, scanned, true, nil
		}
		if strings.HasPrefix(f.Rule, "hunt-") { // never match our own output
			continue
		}
		scanned++
		var hit bool
		switch {
		case ss.Scope == "findings" && len(filters) > 0:
			hit = matchHunt(f, filters)
		case ss.Scope == "hosts":
			hit = q != "" && strings.Contains(strings.ToLower(f.Host), q)
		default:
			blob := strings.ToLower(f.Rule + " " + f.Host + " " + f.Description + " " + f.Evidence.Executable + " " + f.Evidence.Command)
			hit = q != "" && strings.Contains(blob, q)
		}
		if !hit {
			continue
		}
		if len(matches) >= max {
			truncated = true
			break
		}
		matches = append(matches, schedMatch{Key: "f:" + f.ID, Host: f.Host, Evidence: f.Evidence,
			Description: fmt.Sprintf("Scheduled detection %q matched finding %s (%s)", d.Name, f.ID, f.Rule)})
	}
	return
}

func (s *schedService) evalSeq(ctx context.Context, d SchedDetection, max int) (matches []schedMatch, scanned int, truncated, timedOut bool, err error) {
	q, perr := parseSeq(d.Source.Query)
	if perr != nil {
		return nil, 0, false, false, perr
	}
	since, serr := parseSince(d.Source.Since, s.now())
	if serr != nil {
		return nil, 0, false, false, serr
	}
	if d.Source.Since == "" {
		since = s.now().Add(-24 * time.Hour)
	}
	events, _ := collectSeq(storeSeqSource{s.store}, q, since)
	res := runSeq(ctx, q, events, max)
	for _, c := range res.Scanned {
		scanned += c
	}
	truncated, timedOut = res.Truncated, res.TimedOut
	for _, m := range res.Matches {
		if len(matches) >= max {
			truncated = true
			break
		}
		ids := make([]string, 0, len(m.Events))
		for _, e := range m.Events {
			ids = append(ids, e.ID)
		}
		sum := sha256.Sum256([]byte(m.Key + "|" + strings.Join(ids, ",")))
		host := ""
		var first time.Time
		if len(m.Events) > 0 {
			host, first = m.Events[0].str("host"), m.Events[0].Time
		}
		matches = append(matches, schedMatch{Key: "s:" + hex.EncodeToString(sum[:8]), Host: host,
			Evidence:    Event{Time: first, Host: host, Command: "kavach-seq match, events: " + strings.Join(ids, ",")},
			Description: fmt.Sprintf("Scheduled detection %q matched a kavach-seq %s (%d events)", d.Name, q.Kind, len(m.Events))})
	}
	return
}

// run evaluates one detection. dry never records or updates dedup state. The caller must have won
// the running slot via claim.
func (s *schedService) run(parent context.Context, d SchedDetection, trigger string, dry bool) SchedRun {
	start := s.now()
	run := SchedRun{Time: start.UTC(), Trigger: trigger, DryRun: dry}
	ctx, cancel := context.WithTimeout(parent, time.Duration(d.MaxRuntimeMS)*time.Millisecond)
	defer cancel()
	s.mu.Lock()
	lim := s.limitsLocked()
	s.mu.Unlock()
	max := d.MaxMatches
	if max > lim.MaxMatchesPerRun {
		max = lim.MaxMatchesPerRun
	}
	var matches []schedMatch
	var err error
	switch d.Source.Kind {
	case "saved_search":
		matches, run.Scanned, run.Truncated, err = s.evalSavedSearch(ctx, d, max)
	case "seq":
		matches, run.Scanned, run.Truncated, run.TimedOut, err = s.evalSeq(ctx, d, max)
	}
	if err != nil {
		run.Errors = append(run.Errors, err.Error())
	}
	if ctx.Err() != nil {
		run.TimedOut = true
	}
	run.Matched = len(matches)

	win := time.Duration(d.DedupWindowSec) * time.Second
	var fresh []schedMatch
	s.mu.Lock()
	seen := s.d.Dedup[d.ID]
	for _, m := range matches {
		if t, ok := seen[m.Key]; ok && start.Sub(time.Unix(t, 0)) < win && !time.Unix(t, 0).After(start) {
			run.Deduped++
			continue
		}
		fresh = append(fresh, m)
	}
	s.mu.Unlock()

	exc := excSvc.Load()
	var shadows []Finding
	var recorded []schedMatch
	for _, m := range fresh {
		f := Finding{ID: fmt.Sprintf("%s-%s-%d", d.Rule, strings.NewReplacer(":", "").Replace(m.Key), start.Unix()),
			Time: start.UTC(), Host: m.Host, Rule: d.Rule, Severity: d.Severity, Description: m.Description,
			Evidence: m.Evidence, Tags: []string{"scheduled-detection"}}
		if d.Technique != "" {
			f.Tags = append(f.Tags, "attack:"+d.Technique)
		}
		switch {
		case d.State == "testing":
			run.Shadow++
			shadows = append(shadows, f)
		case dry:
			if exc != nil && exc.would(f) {
				run.Suppressed++
			} else {
				run.Recorded++ // would be reported
			}
		default:
			if exc != nil && exc.would(f) {
				run.Suppressed++
			} else {
				run.Recorded++
			}
			s.store.mu.Lock()
			aerr := s.store.appendFindingLocked(f)
			s.store.mu.Unlock()
			if aerr != nil {
				run.Errors = append(run.Errors, aerr.Error())
				run.Recorded--
				continue
			}
		}
		recorded = append(recorded, m)
	}
	end := s.now()
	run.DurationMS = end.Sub(start).Milliseconds()
	if dry {
		return run
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Dedup[d.ID] == nil {
		s.d.Dedup[d.ID] = map[string]int64{}
	}
	for _, m := range recorded {
		s.d.Dedup[d.ID][m.Key] = start.Unix()
	}
	s.pruneDedupLocked(d.ID, start, win)
	if len(shadows) > 0 {
		sh := append(s.d.Shadow[d.ID], shadows...)
		if len(sh) > schedShadowKeep {
			sh = sh[len(sh)-schedShadowKeep:]
		}
		s.d.Shadow[d.ID] = sh
	}
	h := append(s.d.History[d.ID], run)
	if n := s.limitsLocked().HistoryRetention; len(h) > n {
		h = h[len(h)-n:]
	}
	s.d.History[d.ID] = h
	if i := s.find(d.ID); i >= 0 {
		s.d.Detections[i].LastRun = start.UTC()
	}
	s.saveLocked()
	return run
}

func (s *schedService) pruneDedupLocked(id string, now time.Time, win time.Duration) {
	m := s.d.Dedup[id]
	for k, t := range m {
		if now.Sub(time.Unix(t, 0)) >= win {
			delete(m, k)
		}
	}
	if len(m) > schedDedupKeep {
		type kv struct {
			k string
			t int64
		}
		all := make([]kv, 0, len(m))
		for k, t := range m {
			all = append(all, kv{k, t})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
		for _, e := range all[:len(all)-schedDedupKeep] {
			delete(m, e.k)
		}
	}
}

// claim reserves the detection's single running slot and the hourly run quota.
func (s *schedService) claim(id, trigger string) (SchedDetection, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.find(id)
	if i < 0 {
		return SchedDetection{}, 404, "detection not found"
	}
	if s.running[id] {
		return SchedDetection{}, 409, "a run of this detection is already in progress"
	}
	now := s.now()
	if n, lim := s.runsLastHourLocked(now), s.limitsLocked().MaxRunsPerHour; n >= lim {
		s.refuseLocked("run", id, fmt.Sprintf("max_runs_per_hour (%d) reached", lim))
		return SchedDetection{}, 429, "max_runs_per_hour reached"
	}
	s.d.RunTimes = append(s.d.RunTimes, now)
	s.running[id] = true
	return s.d.Detections[i], 0, ""
}

func (s *schedService) release(id string) {
	s.mu.Lock()
	delete(s.running, id)
	s.mu.Unlock()
}

// runNow executes a detection once (manual or dry-run) with no overlap.
func (s *schedService) runNow(ctx context.Context, id, trigger string, dry bool) (SchedRun, int, string) {
	d, code, msg := s.claim(id, trigger)
	if code != 0 {
		return SchedRun{}, code, msg
	}
	defer s.release(id)
	if !dry && (d.State == "draft" || d.State == "retired") {
		return SchedRun{}, 409, "state " + d.State + " does not record findings; use dryrun or move to testing/production"
	}
	return s.run(ctx, d, trigger, dry), 0, ""
}

// tick runs every due production/testing detection, one at a time. now may come from a fake clock.
func (s *schedService) tick(ctx context.Context, now time.Time) {
	if x := excSvc.Load(); x != nil {
		x.flush()
	}
	s.mu.Lock()
	var due []string
	for _, d := range s.d.Detections {
		if d.State != "production" && d.State != "testing" {
			continue
		}
		last, ok := s.lastRun[d.ID]
		if !ok || now.Before(last) { // backwards clock jump: re-anchor instead of stalling
			s.lastRun[d.ID] = now
			continue
		}
		if now.Sub(last) >= time.Duration(d.IntervalSec)*time.Second {
			due = append(due, d.ID)
		}
	}
	s.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.lastRun[id] = now
		s.mu.Unlock()
		d, code, _ := s.claim(id, "schedule")
		if code != 0 {
			continue // overlap or quota: skipped (quota refusals are counted)
		}
		s.run(ctx, d, "schedule", false)
		s.release(id)
	}
}

// start launches the single bounded scheduler goroutine.
func (s *schedService) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		t := time.NewTicker(schedTick)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				s.tick(ctx, s.now())
			}
		}
	}()
}

// Shutdown stops the scheduler (waiting for the goroutine, bounded by ctx) and persists definitions.
func (s *schedService) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLocked()
	return nil
}

// Stop ends the scheduler goroutine and waits for it.
func (s *schedService) Stop() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
}
