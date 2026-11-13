package edr

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sloTestEngine(t *testing.T) *sloEngine {
	t.Helper()
	return newSLOEngine(filepath.Join(t.TempDir(), "f.jsonl"))
}

func sloSt(host, state string, seen time.Time) AgentStatus {
	return AgentStatus{Host: host, State: state, LastSeen: seen, Sensor: "ebpf", Queued: 2}
}

func sloFindAgent(r sloReport, h string) sloAgentView {
	for _, a := range r.Agents {
		if a.Host == h {
			return a
		}
	}
	return sloAgentView{}
}

func TestSLOHeartbeatMathFakeClock(t *testing.T) {
	e := sloTestEngine(t)
	t0 := ut(2026, 6, 1, 0, 0)
	// 100 samples: heartbeat fresh except 5 stale ones; the first 10 are before the first heartbeat
	for i := 0; i < 100; i++ {
		now := t0.Add(time.Duration(i) * sloStep)
		st := sloSt("a", "online", time.Time{})
		if i >= 10 {
			st.LastSeen = now.Add(-time.Minute)
			if i >= 50 && i < 55 {
				st.LastSeen = now.Add(-20 * time.Minute)
			}
		}
		if !e.sample(now, []AgentStatus{st}, nil) {
			t.Fatal("sample refused")
		}
	}
	end := t0.Add(99 * sloStep)
	rep := e.report(end, []AgentStatus{sloSt("a", "online", end.Add(-time.Minute))}, nil)
	hb := sloFindAgent(rep, "a").Heartbeat
	if hb.JudgedSamples != 90 || hb.GoodSamples != 85 {
		t.Fatalf("judged %d good %d", hb.JudgedSamples, hb.GoodSamples)
	}
	if hb.CompliancePct == nil || *hb.CompliancePct != 94.44 {
		t.Fatalf("compliance %v", hb.CompliancePct)
	}
	if hb.TimeOutOfSLOMin != 25 {
		t.Fatalf("out of slo %v", hb.TimeOutOfSLOMin)
	}
	// target 99%: allowed = 0.01*90*5 = 4.5 min, used 25 => budget exhausted
	if hb.BudgetMinutes != 4.5 || hb.BudgetRemainingPct == nil || *hb.BudgetRemainingPct != 0 || hb.Status != "breaching" {
		t.Fatalf("%+v", hb)
	}
	found := false
	for _, b := range rep.Breaches {
		found = found || (b.Agent == "a" && b.Indicator == "heartbeat_freshness" && b.Kind == "window_compliance")
	}
	if !found {
		t.Fatalf("breach not listed: %+v", rep.Breaches)
	}
	// duplicate sample within half a step is ignored
	if e.sample(end.Add(time.Minute), []AgentStatus{sloSt("a", "online", end)}, nil) {
		t.Fatal("duplicate sample accepted")
	}
	// a looser target meets the SLO with budget left
	c := e.Config()
	c.HeartbeatTargetPct = 90
	e.SetConfig(c, end)
	hb = sloFindAgent(e.report(end, []AgentStatus{sloSt("a", "online", end)}, nil), "a").Heartbeat
	if hb.Status != "meeting" || *hb.BudgetRemainingPct != 44.4 {
		t.Fatalf("%+v rem=%v", hb, *hb.BudgetRemainingPct)
	}
}

func TestSLORollingWindowDropsOldSamples(t *testing.T) {
	e := sloTestEngine(t)
	t0 := ut(2026, 6, 1, 0, 0)
	for i := 0; i < 48; i++ { // 4 hours, stale for the first 2
		now := t0.Add(time.Duration(i) * sloStep)
		seen := now
		if i < 24 {
			seen = now.Add(-time.Hour)
		}
		e.sample(now, []AgentStatus{sloSt("a", "online", seen)}, nil)
	}
	end := t0.Add(47 * sloStep)
	c := e.Config()
	c.WindowHours = 1
	e.SetConfig(c, end)
	hb := sloFindAgent(e.report(end, []AgentStatus{sloSt("a", "online", end)}, nil), "a").Heartbeat
	if hb.CompliancePct == nil || *hb.CompliancePct != 100 {
		t.Fatalf("1h window should be clean: %+v", hb)
	}
}

func TestSLONoDataIsHonest(t *testing.T) {
	e := sloTestEngine(t)
	now := ut(2026, 6, 1, 0, 0)
	rep := e.report(now, nil, nil)
	if len(rep.Agents) != 0 || len(rep.NotReported) == 0 {
		t.Fatalf("%+v", rep)
	}
	for _, c := range rep.Coverage {
		if c.Pct != nil || c.Status != "unknown" {
			t.Fatalf("empty fleet must not report coverage: %+v", c)
		}
	}
	// pending agent that never sent a heartbeat: not judged, flagged, footprint marked not reported
	e.sample(now, []AgentStatus{{Host: "p", State: "pending"}}, nil)
	rep = e.report(now, []AgentStatus{{Host: "p", State: "pending"}}, nil)
	a := sloFindAgent(rep, "p")
	if a.Heartbeat.CompliancePct != nil || a.Heartbeat.Status != "unknown" || a.Current != "never_seen" {
		t.Fatalf("%+v", a)
	}
	if a.Footprint["agent_cpu_percent"] != "not reported by agent" || a.Footprint["sensor"] != "not reported by agent" {
		t.Fatalf("footprint: %+v", a.Footprint)
	}
	if a.Categories["process"] != "never reported" {
		t.Fatalf("categories: %+v", a.Categories)
	}
	if a.Continuity.Status != "unknown" {
		t.Fatal("continuity with no data must be unknown")
	}
	if rep.Fleet["heartbeat"].(sloIndicator).Status != "unknown" {
		t.Fatal("fleet heartbeat must be unknown")
	}
	// revoked agents are excluded entirely
	rep = e.report(now, []AgentStatus{{Host: "r", State: "revoked"}}, nil)
	if len(rep.Agents) != 0 {
		t.Fatal("revoked agent included")
	}
}

func TestSLOContinuityGapVersusOwnRate(t *testing.T) {
	e := sloTestEngine(t)
	t0 := ut(2026, 6, 1, 0, 0)
	c := e.Config()
	c.ContinuityGapMinutes = 30 // 6 samples
	e.SetConfig(c, t0)
	var end time.Time
	for i := 0; i < 60; i++ {
		now := t0.Add(time.Duration(i) * sloStep)
		end = now
		obs := map[string]*sloObs{"busy": {counts: [3]int{3, 0, 0}}, "quiet": {}}
		if i >= 40 && i < 50 { // busy goes silent for 10 samples
			obs["busy"] = &sloObs{}
		}
		st := []AgentStatus{sloSt("busy", "online", now), sloSt("quiet", "online", now)}
		e.sample(now, st, obs)
	}
	rep := e.report(end, []AgentStatus{sloSt("busy", "online", end), sloSt("quiet", "online", end)}, nil)
	busy, quiet := sloFindAgent(rep, "busy").Continuity, sloFindAgent(rep, "quiet").Continuity
	if busy.JudgedSamples == 0 || busy.GoodSamples == busy.JudgedSamples || busy.Status != "breaching" {
		t.Fatalf("busy: %+v", busy)
	}
	// silence of 10 samples with a 6-sample window: samples 45..49 have an empty trailing window
	if busy.JudgedSamples-busy.GoodSamples != 5 {
		t.Fatalf("expected 5 gap samples, got %d", busy.JudgedSamples-busy.GoodSamples)
	}
	if quiet.JudgedSamples != 0 || quiet.Status != "unknown" {
		t.Fatalf("an agent that never sends events must not be judged: %+v", quiet)
	}
}

func TestSLOCoverageByCategory(t *testing.T) {
	e := sloTestEngine(t)
	now := ut(2026, 6, 1, 12, 0)
	sts := []AgentStatus{sloSt("a", "online", now), sloSt("b", "online", now), sloSt("c", "offline", now.Add(-time.Hour)), sloSt("d", "revoked", now)}
	obs := map[string]*sloObs{
		"a": {last: [3]time.Time{now.Add(-time.Minute), now.Add(-time.Minute), {}}},
		"b": {last: [3]time.Time{now.Add(-2 * time.Hour), {}, {}}},
	}
	rep := e.report(now, sts, obs)
	got := map[string]sloCoverage{}
	for _, c := range rep.Coverage {
		got[c.Category] = c
	}
	if got["process"].Reporting != 1 || got["process"].Enrolled != 3 || *got["process"].Pct != 33.33 || got["process"].Status != "breaching" {
		t.Fatalf("%+v", got["process"])
	}
	if got["file"].Reporting != 0 || *got["file"].Pct != 0 {
		t.Fatalf("%+v", got["file"])
	}
	if sloFindAgent(rep, "b").Categories["process"] != "silent" || sloFindAgent(rep, "c").Current != "stale" {
		t.Fatal("per-agent state wrong")
	}
	var cov, cur bool
	for _, b := range rep.Breaches {
		cov = cov || (b.Kind == "coverage" && b.Indicator == "coverage_process")
		cur = cur || (b.Agent == "c" && b.Kind == "current")
	}
	if !cov || !cur {
		t.Fatalf("breaches %+v", rep.Breaches)
	}
}

func TestSLOBoundedAndPersisted(t *testing.T) {
	e := sloTestEngine(t)
	t0 := ut(2026, 6, 1, 0, 0)
	for i := 0; i < sloMaxPoints+50; i++ {
		now := t0.Add(time.Duration(i) * sloStep)
		e.sample(now, []AgentStatus{sloSt("a", "online", now)}, nil)
	}
	if n := len(e.series["a"]); n != sloMaxPoints {
		t.Fatalf("series not bounded: %d", n)
	}
	// agent cap
	e2 := sloTestEngine(t)
	var sts []AgentStatus
	for i := 0; i < sloMaxAgents+20; i++ {
		sts = append(sts, sloSt("h"+string(rune('A'+i%26))+strings.Repeat("x", i/26), "online", t0))
	}
	e2.sample(t0, sts, nil)
	if len(e2.series) != sloMaxAgents {
		t.Fatalf("agent cap: %d", len(e2.series))
	}
	// persistence round-trip including config
	c := e.Config()
	c.WindowHours = 12
	e.SetConfig(c, t0)
	e3 := newSLOEngine(strings.TrimSuffix(e.path, sloExt))
	if e3.Config().WindowHours != 12 || len(e3.series["a"]) != sloMaxPoints {
		t.Fatalf("reload: %+v %d", e3.Config(), len(e3.series["a"]))
	}
	// corrupt file => defaults
	e4 := newSLOEngine(strings.TrimSuffix(e.path, sloExt) + "-none")
	if e4.Config() != sloDefaults() {
		t.Fatal("defaults")
	}
}

func TestSLOConfigValidation(t *testing.T) {
	if sloDefaults().validate() != "" {
		t.Fatal("defaults invalid")
	}
	for _, mut := range []func(*sloConfig){
		func(c *sloConfig) { c.HeartbeatFreshMinutes = 0 },
		func(c *sloConfig) { c.ContinuityGapMinutes = 1 },
		func(c *sloConfig) { c.HeartbeatTargetPct = 101 },
		func(c *sloConfig) { c.CoverageTargetPct = 0 },
		func(c *sloConfig) { c.WindowHours = 100 },
	} {
		c := sloDefaults()
		mut(&c)
		if c.validate() == "" {
			t.Errorf("accepted %+v", c)
		}
	}
	if d, ok := sloParseWindow("2d", time.Hour); !ok || d != 48*time.Hour {
		t.Fatal("2d")
	}
	if _, ok := sloParseWindow("100h", time.Hour); ok {
		t.Fatal("over max")
	}
	if _, ok := sloParseWindow("1m", time.Hour); ok {
		t.Fatal("under step")
	}
}

func TestSLOAPI(t *testing.T) {
	h, store, tok := rsAPI(t) // RegisterReportSched also mounts the SLO routes
	_ = store
	if rsDo(h, "GET", "/v1/fleet/slo", "", "").Code != 401 {
		t.Fatal("auth")
	}
	w := rsDo(h, "GET", "/v1/fleet/slo", tok, "")
	var rep sloReport
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rep) != nil || rep.Config != sloDefaults() {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	d := rsDo(h, "GET", "/v1/fleet/slo/definitions", tok, "")
	if d.Code != 200 || !strings.Contains(d.Body.String(), "agent_would_need_to_send") || !strings.Contains(d.Body.String(), "not reported by agent") {
		t.Fatalf("definitions: %s", d.Body)
	}
	if rsDo(h, "PUT", "/v1/fleet/slo", "", `{}`).Code != 401 {
		t.Fatal("put auth")
	}
	if c := rsDo(h, "PUT", "/v1/fleet/slo", tok, `{"window_hours":500}`).Code; c != 400 {
		t.Fatalf("invalid put %d", c)
	}
	if c := rsDo(h, "PUT", "/v1/fleet/slo", tok, `{"bogus":1}`).Code; c != 400 {
		t.Fatalf("unknown field %d", c)
	}
	p := rsDo(h, "PUT", "/v1/fleet/slo", tok, `{"heartbeat_fresh_minutes":10}`)
	var cfg sloConfig
	_ = json.Unmarshal(p.Body.Bytes(), &cfg)
	if p.Code != 200 || cfg.HeartbeatFreshMinutes != 10 || cfg.WindowHours != 24 {
		t.Fatalf("partial update should keep other fields: %d %+v", p.Code, cfg)
	}
	if rsDo(h, "GET", "/v1/fleet/slo/history?window=bad", tok, "").Code != 400 {
		t.Fatal("bad window")
	}
	if rsDo(h, "GET", "/v1/fleet/slo/history?agent=nobody", tok, "").Code != 404 {
		t.Fatal("unknown agent")
	}
	if g := rsDo(h, "GET", "/v1/fleet/slo/history?window=6h", tok, ""); g.Code != 200 || !strings.Contains(g.Body.String(), `"points"`) {
		t.Fatalf("history %d %s", g.Code, g.Body)
	}
}

func TestSLOHistory(t *testing.T) {
	e := sloTestEngine(t)
	t0 := ut(2026, 6, 1, 0, 0)
	var end time.Time
	for i := 0; i < 12; i++ {
		end = t0.Add(time.Duration(i) * sloStep)
		sts := []AgentStatus{sloSt("a", "online", end), sloSt("b", "online", end.Add(-time.Hour))}
		e.sample(end, sts, map[string]*sloObs{"a": {counts: [3]int{2, 0, 0}}})
	}
	a := e.history("a", end, 30*time.Minute)
	if len(a) != 7 || a[0].Fresh == nil || !*a[0].Fresh || *a[0].Events != 2 {
		t.Fatalf("agent history: %+v", a)
	}
	f := e.history("", end, time.Hour)
	if len(f) == 0 || f[0].Agents != 2 || f[0].FreshAgent != 1 || *f[0].FreshPct != 50 {
		t.Fatalf("fleet history: %+v", f)
	}
}
