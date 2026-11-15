// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func synthSnap(seq int, hash string, sc map[string]string, tech map[string]string) RegressSnapshot {
	return RegressSnapshot{Seq: seq, Time: time.Date(2026, 1, seq, 3, 0, 0, 0, time.UTC).Format(time.RFC3339), ContentHash: hash,
		Scenarios: sc, Techniques: tech, ScenarioRules: map[string][]string{}, TechRules: map[string][]string{}}
}

func TestRegressDiffKinds(t *testing.T) {
	p := synthSnap(1, "h", map[string]string{"a": "detected", "b": "missed", "c": "detected", "gone": "detected", "bn": "benign_ok", "bn2": "benign_fp"},
		map[string]string{"T1": "detected", "T2": "missed", "T3": "partial"})
	c := synthSnap(2, "h", map[string]string{"a": "missed", "b": "detected", "c": "partial", "new": "detected", "bn": "benign_fp", "bn2": "benign_ok"},
		map[string]string{"T1": "partial", "T2": "detected", "T3": "partial"})
	d := regressDiffSnapshots(regressDiffInput{Prev: p, Cur: c})
	ids := func(cs []RegressChange) []string {
		var o []string
		for _, x := range cs {
			o = append(o, x.Kind+":"+x.ID+":"+x.From+">"+x.To)
		}
		return o
	}
	if got := ids(d.Regressions); !reflect.DeepEqual(got, []string{"scenario:a:detected>missed", "scenario:c:detected>partial", "technique:T1:detected>partial"}) {
		t.Fatalf("regressions %v", got)
	}
	if got := ids(d.Improvements); !reflect.DeepEqual(got, []string{"scenario:b:missed>detected", "technique:T2:missed>detected"}) {
		t.Fatalf("improvements %v", got)
	}
	if !reflect.DeepEqual(d.ScenariosAdded, []string{"new"}) || !reflect.DeepEqual(d.ScenariosRemoved, []string{"gone"}) {
		t.Fatalf("added/removed %v %v", d.ScenariosAdded, d.ScenariosRemoved)
	}
	if !reflect.DeepEqual(d.NewBenignFP, []string{"bn"}) || !reflect.DeepEqual(d.ResolvedBenignFP, []string{"bn2"}) {
		t.Fatalf("fp %v %v", d.NewBenignFP, d.ResolvedBenignFP)
	}
	if d.ContentChanged || !strings.Contains(d.Regressions[0].LikelyCause[0], "no embedded content change") {
		t.Fatalf("cause %v", d.Regressions[0].LikelyCause)
	}
}

func TestRegressCauseAttribution(t *testing.T) {
	a := snapOf(t, `{"pack":"x","rules":[{"id":"r1","severity":"high","match":{"field":"f","op":"equals"}},{"id":"r2","severity":"low"},{"id":"r3","severity":"low"}]}`)
	b := snapOf(t, `{"pack":"x","rules":[{"id":"r1","severity":"medium","match":{"field":"f","op":"contains"}},{"id":"r3","severity":"low"},{"id":"r4","severity":"low"}]}`)
	p := synthSnap(1, a.Hash, map[string]string{"s1": "detected", "s2": "detected", "s3": "detected"}, map[string]string{"T1": "detected"})
	p.Time = "2026-01-01T03:00:00Z"
	p.ScenarioRules = map[string][]string{"s1": {"r1"}, "s2": {"r2"}, "s3": {"r3"}}
	p.TechRules = map[string][]string{"T1": {"r1", "r2"}}
	c := synthSnap(2, b.Hash, map[string]string{"s1": "missed", "s2": "missed", "s3": "missed"}, map[string]string{"T1": "missed"})
	c.Time = "2026-01-02T03:00:00Z"
	lc := []RegressLifecycle{{Rule: "r3", Time: "2026-01-01T12:00:00Z", Detail: "production -> retired note=\"x\""}}
	d := regressDiffSnapshots(regressDiffInput{Prev: p, Cur: c,
		PrevContent: &regressContent{Snap: a, Sev: map[string]string{"r1": "high"}},
		CurContent:  &regressContent{Snap: b, Sev: map[string]string{"r1": "medium"}}, Lifecycle: lc})
	if !d.ContentDetail || !reflect.DeepEqual(d.RulesAdded, []string{"r4"}) || !reflect.DeepEqual(d.RulesRemoved, []string{"r2"}) || !reflect.DeepEqual(d.RulesModified, []string{"r1"}) {
		t.Fatalf("content diff %+v", d)
	}
	cause := map[string]string{}
	for _, r := range d.Regressions {
		cause[r.Kind+":"+r.ID] = strings.Join(r.LikelyCause, " | ")
	}
	if g := cause["scenario:s1"]; !strings.Contains(g, "rule r1 modified") || !strings.Contains(g, "severity high -> medium") || !strings.Contains(g, "match changed") {
		t.Fatalf("s1 cause %q", g)
	}
	if g := cause["scenario:s2"]; !strings.Contains(g, "rule r2 removed") {
		t.Fatalf("s2 cause %q", g)
	}
	if g := cause["scenario:s3"]; !strings.Contains(g, "lifecycle: production -> retired") {
		t.Fatalf("s3 cause %q", g)
	}
	if g := cause["technique:T1"]; !strings.Contains(g, "r1 modified") || !strings.Contains(g, "r2 removed") {
		t.Fatalf("T1 cause %q", g)
	}
	if !strings.Contains(d.AttributionNote, "hint") {
		t.Fatal("attribution must be labelled a hint")
	}
	// content changed but unrelated rule only
	d2 := regressDiffSnapshots(regressDiffInput{Prev: p, Cur: c, PrevContent: nil, CurContent: nil})
	if !strings.Contains(d2.Regressions[0].LikelyCause[0], "no longer retained") {
		t.Fatalf("missing-detail cause %v", d2.Regressions[0].LikelyCause)
	}
}

func fakeExec(hash string, out map[string]string, calls *int) regressExec {
	return func(time.Duration) (RegressSnapshot, *regressContent, error) {
		*calls++
		return synthSnap(0, hash, out, map[string]string{}), nil, nil
	}
}

func TestRegressHistoryCapAndPersistence(t *testing.T) {
	st := newTestStore(t)
	s := newRegressSvc(st)
	calls := 0
	s.exec = fakeExec("h", map[string]string{"a": "detected"}, &calls)
	n := 0
	s.now = func() time.Time {
		n++
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Hour)
	}
	for i := 0; i < regressHistoryCap+7; i++ {
		if _, _, err := s.run("manual"); err != nil {
			t.Fatal(err)
		}
	}
	all := s.snapshots()
	if len(all) != regressHistoryCap || all[0].Seq != 8 || all[len(all)-1].Seq != regressHistoryCap+7 {
		t.Fatalf("cap: len=%d first=%d last=%d", len(all), all[0].Seq, all[len(all)-1].Seq)
	}
	s.setConfig(RegressConfig{Enabled: false, Time: "04:30", MaxRuntimeSec: 30, AlertMinRegress: 2, AlertMediumAt: 5, AlertOnBenignFP: false})
	s2 := newRegressSvc(st)
	if got := s2.snapshots(); len(got) != regressHistoryCap || got[10].Seq != all[10].Seq {
		t.Fatalf("round trip snapshots")
	}
	if c := s2.config(); c.Time != "04:30" || c.Enabled || c.AlertMinRegress != 2 {
		t.Fatalf("round trip config %+v", c)
	}
	if s2.f.NextSeq != regressHistoryCap+8 {
		t.Fatalf("next seq %d", s2.f.NextSeq)
	}
	if _, err := os.Stat(filepath.Clean(st.path) + ".regression.json"); err != nil {
		t.Fatal(err)
	}
}

func TestRegressNextRun(t *testing.T) {
	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if g := regressNextRun(now, "03:00"); !g.Equal(time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC)) {
		t.Fatal(g)
	}
	if g := regressNextRun(now, "23:15"); !g.Equal(time.Date(2026, 3, 1, 23, 15, 0, 0, time.UTC)) {
		t.Fatal(g)
	}
	if g := regressNextRun(now, "10:00"); !g.Equal(time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)) {
		t.Fatal(g)
	}
	if validHHMM("25:00") || !validHHMM("07:05") || validHHMM("7:5") {
		t.Fatal("validHHMM")
	}
}

type fakeTimer struct {
	d  time.Duration
	ch chan time.Time
}

func TestRegressSchedulerFakeClock(t *testing.T) {
	s := newRegressSvc(nil)
	now := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	calls := 0
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	timers := make(chan fakeTimer, 8)
	s.after = func(d time.Duration) <-chan time.Time {
		ft := fakeTimer{d, make(chan time.Time, 1)}
		timers <- ft
		return ft.ch
	}
	var ran = make(chan string, 8)
	s.exec = func(time.Duration) (RegressSnapshot, *regressContent, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return synthSnap(0, "h1", map[string]string{"a": "detected"}, map[string]string{}), nil, nil
	}
	s.contentHash = func() string { return "h1" }
	s.Start()
	ft := <-timers // startup run (no history) has happened before the first wait
	if ft.d != 17*time.Hour {
		t.Fatalf("first wait %v", ft.d)
	}
	if got := s.snapshots(); len(got) != 1 || got[0].Trigger != "startup" {
		t.Fatalf("startup run: %+v", got)
	}
	mu.Lock()
	now = now.Add(17 * time.Hour)
	mu.Unlock()
	ft.ch <- now
	ft2 := <-timers
	if ft2.d != 24*time.Hour {
		t.Fatalf("second wait %v", ft2.d)
	}
	got := s.snapshots()
	if len(got) != 2 || got[1].Trigger != "schedule" {
		t.Fatalf("schedule run: %+v", got)
	}
	_ = ran
	// config change re-arms the timer without running
	s.setConfig(RegressConfig{Enabled: true, Time: "11:00", MaxRuntimeSec: 60, AlertMinRegress: 1, AlertMediumAt: 3})
	ft3 := <-timers
	if ft3.d != 8*time.Hour {
		t.Fatalf("rearm wait %v", ft3.d)
	}
	if len(s.snapshots()) != 2 {
		t.Fatal("config change must not run")
	}
	s.Stop()
	s.Stop() // idempotent
	select {
	case <-s.done:
	default:
		t.Fatal("goroutine still running after Stop")
	}
}

func TestRegressStartupSkippedWhenContentUnchanged(t *testing.T) {
	st := newTestStore(t)
	s := newRegressSvc(st)
	calls := 0
	s.exec = fakeExec("same", map[string]string{"a": "detected"}, &calls)
	if _, _, err := s.run("manual"); err != nil {
		t.Fatal(err)
	}
	s.contentHash = func() string { return "same" }
	timers := make(chan fakeTimer, 2)
	s.after = func(d time.Duration) <-chan time.Time {
		ft := fakeTimer{d, make(chan time.Time)}
		timers <- ft
		return ft.ch
	}
	s.Start()
	<-timers
	s.Stop()
	if calls != 1 {
		t.Fatalf("startup ran despite unchanged content: %d", calls)
	}
}

func TestRegressNoOverlap(t *testing.T) {
	s := newRegressSvc(nil)
	gate := make(chan struct{})
	started := make(chan struct{})
	s.exec = func(time.Duration) (RegressSnapshot, *regressContent, error) {
		close(started)
		<-gate
		return synthSnap(0, "h", map[string]string{}, map[string]string{}), nil, nil
	}
	done := make(chan error)
	go func() { _, _, e := s.run("manual"); done <- e }()
	<-started
	if _, _, err := s.run("manual"); err != errRegressBusy {
		t.Fatalf("expected busy, got %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRegressAlertFinding(t *testing.T) {
	st := newTestStore(t)
	s := newRegressSvc(st)
	cur := 0
	outs := []map[string]string{
		{"a": "detected", "b": "detected", "bn": "benign_ok"},
		{"a": "missed", "b": "detected", "bn": "benign_ok"},
		{"a": "missed", "b": "missed", "bn": "benign_fp"},
	}
	s.exec = func(time.Duration) (RegressSnapshot, *regressContent, error) {
		o := outs[cur]
		cur++
		return synthSnap(0, "h", o, map[string]string{}), nil, nil
	}
	for i := 0; i < 3; i++ {
		if _, _, err := s.run("manual"); err != nil {
			t.Fatal(err)
		}
	}
	var fs []Finding
	for _, f := range st.List() {
		if f.Rule == "regression-detected" {
			fs = append(fs, f)
		}
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings got %d", len(fs))
	}
	if fs[0].Severity != "low" || fs[1].Severity != "medium" {
		t.Fatalf("severity %s %s", fs[0].Severity, fs[1].Severity)
	}
	if !strings.Contains(fs[1].Evidence.Command, "new_benign_false_positives") || !strings.Contains(fs[1].Evidence.Command, "bn") {
		t.Fatalf("evidence %s", fs[1].Evidence.Command)
	}
	// the alert dispatcher matches on the finding's rule name
	if !ruleMatches(AlertRule{RuleContains: "regression-detected", MinSeverity: "low"}, fs[0]) {
		t.Fatal("alert rule should match regression finding")
	}
}

func TestRegressGateSemantics(t *testing.T) {
	s := newRegressSvc(nil)
	if code, _ := s.gate(map[string][]string{}); code != 412 {
		t.Fatalf("empty history must fail closed, got %d", code)
	}
	p := synthSnap(1, "h", map[string]string{"a": "detected"}, map[string]string{})
	p.MeasuredDetectedPct = 60
	c := synthSnap(2, "h", map[string]string{"a": "missed"}, map[string]string{})
	c.MeasuredDetectedPct = 50
	c.BenignFP = []string{"bn"}
	s.f.Snapshots = []RegressSnapshot{p, c}
	q := func(k, v string) map[string][]string { return map[string][]string{k: {v}} }
	if code, _ := s.gate(map[string][]string{}); code != 200 {
		t.Fatalf("no thresholds -> pass, got %d", code)
	}
	if code, b := s.gate(q("min_detected", "55")); code != 412 || b["pass"] != false {
		t.Fatalf("min_detected 55: %d", code)
	}
	if code, _ := s.gate(q("min_detected", "50")); code != 200 {
		t.Fatalf("min_detected 50: %d", code)
	}
	if code, _ := s.gate(q("max_regressions", "0")); code != 412 {
		t.Fatalf("max_regressions 0: %d", code)
	}
	if code, _ := s.gate(q("max_regressions", "1")); code != 200 {
		t.Fatalf("max_regressions 1: %d", code)
	}
	if code, _ := s.gate(q("max_false_positives", "0")); code != 412 {
		t.Fatalf("max_fp 0: %d", code)
	}
	if code, _ := s.gate(q("min_detected", "abc")); code != 400 {
		t.Fatalf("bad param: %d", code)
	}
}

func TestRegressRealRunIsolation(t *testing.T) {
	st := newTestStore(t)
	before := st.List()
	var ledger []byte
	ledger, _ = os.ReadFile(st.path)
	iocBefore := len(defaultIOCs())
	s := newRegressSvc(st)
	snap, _, err := s.run("manual")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Scenarios) < 50 || snap.ContentHash == "" || len(snap.Tactics) == 0 || snap.Truncated {
		t.Fatalf("snapshot looks empty: scenarios=%d tactics=%d trunc=%v", len(snap.Scenarios), len(snap.Tactics), snap.Truncated)
	}
	if snap.MeasuredDetectedPct <= 0 || snap.BenignControls == 0 {
		t.Fatalf("no measured coverage: %+v", regressSummary(snap))
	}
	// second identical run: no regressions, no findings
	s2, d, err := s.run("manual")
	if err != nil || d == nil || len(d.Regressions) != 0 || len(d.NewBenignFP) != 0 {
		t.Fatalf("second run diff: %v %+v", err, d)
	}
	if s2.Seq != 2 {
		t.Fatalf("seq %d", s2.Seq)
	}
	after := st.List()
	if len(after) != len(before) {
		t.Fatalf("live store changed: %d -> %d", len(before), len(after))
	}
	if now, _ := os.ReadFile(st.path); string(now) != string(ledger) {
		t.Fatal("live ledger bytes changed")
	}
	if len(defaultIOCs()) != iocBefore {
		t.Fatal("IOC list changed")
	}
}

func TestRegressTruncatedRunNeverAlerts(t *testing.T) {
	st := newTestStore(t)
	s := newRegressSvc(st)
	i := 0
	s.exec = func(time.Duration) (RegressSnapshot, *regressContent, error) {
		i++
		sn := synthSnap(0, "h", map[string]string{"a": "detected"}, map[string]string{})
		if i == 2 {
			sn.Scenarios = map[string]string{"a": "missed"}
			sn.Truncated = true
		}
		return sn, nil, nil
	}
	s.run("manual")
	_, d, _ := s.run("manual")
	if !d.Incomplete || len(st.List()) != 0 {
		t.Fatalf("truncated run must be flagged and not alert: %+v findings=%d", d.Incomplete, len(st.List()))
	}
}
