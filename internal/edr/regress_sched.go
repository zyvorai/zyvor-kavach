// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errRegressBusy = errors.New("a regression run is already in progress")

// regressExec replays the scenarios within the bound and returns the snapshot (no seq/time yet).
type regressExec func(maxRuntime time.Duration) (RegressSnapshot, *regressContent, error)

type regressSvc struct {
	mu    sync.Mutex
	path  string
	store *Store
	f     regressFile

	now         func() time.Time
	after       func(time.Duration) <-chan time.Time
	exec        regressExec
	contentHash func() string

	running  atomic.Bool
	started  atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	wake     chan struct{}
	done     chan struct{}
}

var regressActive atomic.Pointer[regressSvc]

// StopRegression stops the regression scheduler goroutine (idempotent; waits for it to exit).
func StopRegression() {
	if s := regressActive.Load(); s != nil {
		s.Stop()
	}
}

func newRegressSvc(store *Store) *regressSvc {
	p := ""
	if store != nil && store.path != "" {
		p = filepath.Clean(store.path) + ".regression.json"
	}
	s := &regressSvc{path: p, store: store, f: loadRegressFile(p), now: time.Now, after: time.After,
		stop: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	s.exec = defaultRegressExec
	s.contentHash = func() string { c, _ := buildContentSnapshot(); return c.Hash }
	return s
}

// defaultRegressExec replays every embedded scenario in memory (embedded content only, no custom
// rules, never touching the store) and stops early when the runtime bound is hit.
func defaultRegressExec(maxRuntime time.Duration) (RegressSnapshot, *regressContent, error) {
	scs, nt, err := LoadValidationScenarios()
	if err != nil && len(scs) == 0 {
		return RegressSnapshot{}, nil, err
	}
	start := time.Now()
	results := make([]ValResult, 0, len(scs))
	ran := make([]ValScenario, 0, len(scs))
	truncated := false
	for _, sc := range scs {
		if time.Since(start) > maxRuntime {
			truncated = true
			break
		}
		results = append(results, ReplayScenario(sc, ValOptions{}))
		ran = append(ran, sc)
	}
	cs, _ := buildContentSnapshot()
	snap := buildRegressSnapshot(ran, results, nt, cs.Hash)
	snap.Truncated = truncated
	snap.Build = contentBuildString()
	snap.RuntimeMS = time.Since(start).Milliseconds()
	return snap, &regressContent{Snap: trimContent(cs), Sev: detectionSeverities()}, nil
}

func (s *regressSvc) config() RegressConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Config
}

// run executes one full run (no overlap), records the snapshot, and raises the in-Kavach finding.
func (s *regressSvc) run(trigger string) (RegressSnapshot, *RegressDiff, error) {
	if !s.running.CompareAndSwap(false, true) {
		return RegressSnapshot{}, nil, errRegressBusy
	}
	defer s.running.Store(false)
	cfg := s.config()
	snap, content, err := s.exec(time.Duration(cfg.MaxRuntimeSec) * time.Second)
	if err != nil {
		return RegressSnapshot{}, nil, err
	}
	s.mu.Lock()
	snap.Seq = s.f.NextSeq
	s.f.NextSeq++
	snap.Time = s.now().UTC().Format(time.RFC3339)
	snap.Trigger = trigger
	var prev *RegressSnapshot
	if n := len(s.f.Snapshots); n > 0 {
		p := s.f.Snapshots[n-1]
		prev = &p
	}
	s.f.Snapshots = append(s.f.Snapshots, snap)
	if len(s.f.Snapshots) > regressHistoryCap {
		s.f.Snapshots = append([]RegressSnapshot(nil), s.f.Snapshots[len(s.f.Snapshots)-regressHistoryCap:]...)
	}
	if content != nil {
		if _, ok := s.f.Contents[snap.ContentHash]; !ok {
			s.f.ContentOrder = append(s.f.ContentOrder, snap.ContentHash)
		}
		s.f.Contents[snap.ContentHash] = *content
		for len(s.f.ContentOrder) > regressContentCap {
			delete(s.f.Contents, s.f.ContentOrder[0])
			s.f.ContentOrder = s.f.ContentOrder[1:]
		}
	}
	saveRegressFile(s.path, s.f)
	s.mu.Unlock()

	var diff *RegressDiff
	if prev != nil {
		d := s.diffOf(*prev, snap)
		diff = &d
		s.maybeAlert(cfg, snap, d)
	}
	return snap, diff, nil
}

func (s *regressSvc) diffOf(prev, cur RegressSnapshot) RegressDiff {
	in := regressDiffInput{Prev: prev, Cur: cur}
	s.mu.Lock()
	if c, ok := s.f.Contents[prev.ContentHash]; ok {
		in.PrevContent = &c
	}
	if c, ok := s.f.Contents[cur.ContentHash]; ok {
		in.CurContent = &c
	}
	s.mu.Unlock()
	pt, ok1 := parseRegressTime(prev.Time)
	ct, ok2 := parseRegressTime(cur.Time)
	if ok1 && ok2 {
		in.Lifecycle = regressLifecycleWindow(pt, ct)
	}
	return regressDiffSnapshots(in)
}

// maybeAlert records an informational finding through the normal finding path. Findings in the
// store are what alert rules match on, so a rule with rule_contains "regression-detected" delivers it.
func (s *regressSvc) maybeAlert(cfg RegressConfig, cur RegressSnapshot, d RegressDiff) {
	if s.store == nil || d.Incomplete {
		return
	}
	nReg := len(d.Regressions)
	nFP := len(d.NewBenignFP)
	trigReg := cfg.AlertMinRegress > 0 && nReg >= cfg.AlertMinRegress
	trigFP := cfg.AlertOnBenignFP && nFP > 0
	if !trigReg && !trigFP {
		return
	}
	sev := "low"
	if nFP > 0 || (cfg.AlertMediumAt > 0 && nReg >= cfg.AlertMediumAt) {
		sev = "medium"
	}
	sum := map[string]any{"from_seq": d.FromSeq, "to_seq": d.ToSeq, "regressions": d.Regressions,
		"new_benign_false_positives": d.NewBenignFP, "rules_modified": d.RulesModified, "rules_removed": d.RulesRemoved,
		"measured_detected_pct_delta": d.CoverageDeltaPct, "note": regressNote}
	b, _ := json.Marshal(sum)
	if len(b) > 3000 {
		b = append(b[:3000], []byte("...")...)
	}
	t, _ := parseRegressTime(cur.Time)
	f := Finding{ID: fmt.Sprintf("regression-detected-%d", cur.Seq), Time: t, Host: "kavach-regression", Rule: "regression-detected", Severity: sev,
		Description: fmt.Sprintf("Detection regression between validation runs #%d and #%d: %d regression(s), %d new benign false positive(s). Synthetic scenarios; attribution is a hint.", d.FromSeq, d.ToSeq, nReg, nFP),
		Evidence:    Event{Time: t, Host: "kavach-regression", Executable: "kavach-regression", Command: string(b)},
		Tags:        []string{"regression", "validation-lab", "informational"}}
	s.store.mu.Lock()
	_ = s.store.appendFindingLocked(f)
	s.store.mu.Unlock()
}

// regressNextRun returns the next HH:MM UTC strictly after now.
func regressNextRun(now time.Time, hhmm string) time.Time {
	h, m := 3, 0
	if p := strings.Split(hhmm, ":"); len(p) == 2 {
		if a, e := strconv.Atoi(p[0]); e == nil {
			h = a
		}
		if a, e := strconv.Atoi(p[1]); e == nil {
			m = a
		}
	}
	n := now.UTC()
	t := time.Date(n.Year(), n.Month(), n.Day(), h, m, 0, 0, time.UTC)
	if !t.After(n) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

func validHHMM(s string) bool {
	t, err := time.Parse("15:04", s)
	return err == nil && t.Format("15:04") == s
}

// Start launches the single scheduler goroutine.
func (s *regressSvc) Start() {
	s.started.Store(true)
	go s.loop()
}

func (s *regressSvc) loop() {
	defer close(s.done)
	s.mu.Lock()
	var last string
	if n := len(s.f.Snapshots); n > 0 {
		last = s.f.Snapshots[n-1].ContentHash
	}
	enabled := s.f.Config.Enabled
	s.mu.Unlock()
	if enabled && s.contentHash() != last {
		select {
		case <-s.stop:
			return
		default:
		}
		_, _, _ = s.run("startup")
	}
	for {
		cfg := s.config()
		var timer <-chan time.Time
		if cfg.Enabled {
			now := s.now()
			timer = s.after(regressNextRun(now, cfg.Time).Sub(now))
		}
		select {
		case <-s.stop:
			return
		case <-s.wake:
		case <-timer:
			_, _, _ = s.run("schedule")
		}
	}
}

// Stop ends the scheduler goroutine and waits for it. Safe to call more than once.
func (s *regressSvc) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	if !s.started.Load() {
		return
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}

func (s *regressSvc) setConfig(c RegressConfig) {
	s.mu.Lock()
	s.f.Config = c
	saveRegressFile(s.path, s.f)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *regressSvc) snapshots() []RegressSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RegressSnapshot(nil), s.f.Snapshots...)
}
