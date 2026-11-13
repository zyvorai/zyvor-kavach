package edr

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"sync"
	"time"
)

// Fleet SLOs. Everything is derived from what agents already send: the
// heartbeat time (LastSeen), sensor name and queue depth, plus the timestamps
// of the process/network/file events the server holds per host. Nothing here
// invents agent footprint numbers; see sloNotReported for what is missing.

const (
	sloStep          = 5 * time.Minute
	sloMaxWindowH    = 72
	sloMaxAgents     = 500
	sloMaxPoints     = sloMaxWindowH * 12 // one point per step
	sloPersistEvery  = 10 * time.Minute
	sloMinBaselineK  = 2 // trailing windows of history needed before continuity is judged
	sloExt           = ".fleetslo.json"
	sloWindowDefault = 24
)

type sloConfig struct {
	HeartbeatFreshMinutes int     `json:"heartbeat_fresh_minutes"`
	HeartbeatTargetPct    float64 `json:"heartbeat_target_pct"`
	ContinuityGapMinutes  int     `json:"continuity_gap_minutes"`
	ContinuityTargetPct   float64 `json:"continuity_target_pct"`
	CoverageTargetPct     float64 `json:"coverage_target_pct"`
	WindowHours           int     `json:"window_hours"`
}

func sloDefaults() sloConfig {
	return sloConfig{HeartbeatFreshMinutes: 5, HeartbeatTargetPct: 99, ContinuityGapMinutes: 30, ContinuityTargetPct: 95, CoverageTargetPct: 90, WindowHours: sloWindowDefault}
}

func (c sloConfig) validate() string {
	switch {
	case c.HeartbeatFreshMinutes < 1 || c.HeartbeatFreshMinutes > 1440:
		return "heartbeat_fresh_minutes must be 1-1440"
	case c.ContinuityGapMinutes < 5 || c.ContinuityGapMinutes > 1440:
		return "continuity_gap_minutes must be 5-1440 (the sampling step is 5 minutes)"
	case c.HeartbeatTargetPct <= 0 || c.HeartbeatTargetPct > 100, c.ContinuityTargetPct <= 0 || c.ContinuityTargetPct > 100, c.CoverageTargetPct <= 0 || c.CoverageTargetPct > 100:
		return "target percentages must be in (0, 100]"
	case c.WindowHours < 1 || c.WindowHours > sloMaxWindowH:
		return "window_hours must be 1-72"
	}
	return ""
}

// sloPoint is one sample of one agent. F bit 1: agent has heartbeated at least
// once; bit 2: heartbeat was fresh. E: events the server holds for the host
// with a timestamp in the preceding step.
type sloPoint struct {
	T int64  `json:"t"`
	F uint8  `json:"f"`
	E uint16 `json:"e"`
}

const (
	sloFlagKnown = 1
	sloFlagFresh = 2
)

type sloObs struct {
	counts [3]int       // events in the last step: process, network, file
	last   [3]time.Time // newest event time per category
}

var sloCategories = [3]string{"process", "network", "file"}

// sloObserve scans the bounded event rings once.
func sloObserve(store *Store, now time.Time) map[string]*sloObs {
	obs := map[string]*sloObs{}
	if store == nil {
		return obs
	}
	add := func(host string, cat int, t time.Time) {
		if host == "" {
			return
		}
		o := obs[host]
		if o == nil {
			o = &sloObs{}
			obs[host] = o
		}
		if t.After(o.last[cat]) {
			o.last[cat] = t
		}
		if t.After(now.Add(-sloStep)) && !t.After(now) {
			o.counts[cat]++
		}
	}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		add(e.Host, 0, e.Time)
	}
	for _, e := range store.networkEvents {
		add(e.Host, 1, e.Time)
	}
	for _, e := range store.fileEvents {
		add(e.Host, 2, e.Time)
	}
	store.mu.Unlock()
	return obs
}

type sloEngine struct {
	mu     sync.Mutex
	path   string
	cfg    sloConfig
	series map[string][]sloPoint
	dirty  bool
	lastT  int64
	lastP  time.Time
	stop   chan struct{}
	once   sync.Once
}

func newSLOEngine(storePath string) *sloEngine {
	e := &sloEngine{path: storePath + sloExt, cfg: sloDefaults(), series: map[string][]sloPoint{}, stop: make(chan struct{})}
	if b, err := os.ReadFile(e.path); err == nil {
		var f struct {
			Config sloConfig             `json:"config"`
			Series map[string][]sloPoint `json:"series"`
		}
		if json.Unmarshal(b, &f) == nil {
			if f.Config.validate() == "" {
				e.cfg = f.Config
			}
			for h, pts := range f.Series {
				if len(e.series) >= sloMaxAgents {
					break
				}
				if len(pts) > sloMaxPoints {
					pts = pts[len(pts)-sloMaxPoints:]
				}
				e.series[h] = pts
				if n := len(pts); n > 0 && pts[n-1].T > e.lastT {
					e.lastT = pts[n-1].T
				}
			}
		}
	}
	return e
}

func (e *sloEngine) persistLocked(now time.Time) {
	_ = govWriteAtomic(e.path, map[string]any{"config": e.cfg, "series": e.series})
	e.dirty, e.lastP = false, now
}

func (e *sloEngine) Config() sloConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *sloEngine) SetConfig(c sloConfig, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = c
	e.persistLocked(now)
}

// sample records one point per enrolled, non-revoked agent. Calls closer than
// half a step to the previous sample are ignored.
func (e *sloEngine) sample(now time.Time, statuses []AgentStatus, obs map[string]*sloObs) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastT != 0 && now.Unix()-e.lastT < int64(sloStep.Seconds()/2) {
		return false
	}
	fresh := time.Duration(e.cfg.HeartbeatFreshMinutes) * time.Minute
	live := map[string]bool{}
	for _, st := range statuses {
		if st.State == "revoked" {
			continue
		}
		live[st.Host] = true
		if _, ok := e.series[st.Host]; !ok && len(e.series) >= sloMaxAgents {
			continue
		}
		p := sloPoint{T: now.Unix()}
		if !st.LastSeen.IsZero() {
			p.F |= sloFlagKnown
			if now.Sub(st.LastSeen) <= fresh {
				p.F |= sloFlagFresh
			}
		}
		if o := obs[st.Host]; o != nil {
			n := o.counts[0] + o.counts[1] + o.counts[2]
			if n > math.MaxUint16 {
				n = math.MaxUint16
			}
			p.E = uint16(n)
		}
		s := append(e.series[st.Host], p)
		if len(s) > sloMaxPoints {
			s = s[len(s)-sloMaxPoints:]
		}
		e.series[st.Host] = s
	}
	// drop series that are unenrolled/revoked and whose newest point left retention
	cut := now.Add(-sloMaxWindowH * time.Hour).Unix()
	for h, s := range e.series {
		if !live[h] && (len(s) == 0 || s[len(s)-1].T < cut) {
			delete(e.series, h)
		}
	}
	e.lastT, e.dirty = now.Unix(), true
	if now.Sub(e.lastP) >= sloPersistEvery {
		e.persistLocked(now)
	}
	return true
}

// ---------------- evaluation ----------------

type sloIndicator struct {
	Name               string   `json:"name"`
	TargetPct          float64  `json:"target_pct"`
	JudgedSamples      int      `json:"judged_samples"`
	GoodSamples        int      `json:"good_samples"`
	CompliancePct      *float64 `json:"compliance_pct"`
	TimeOutOfSLOMin    float64  `json:"time_out_of_slo_minutes"`
	BudgetMinutes      float64  `json:"error_budget_minutes"`
	BudgetRemainingPct *float64 `json:"error_budget_remaining_pct"`
	Status             string   `json:"status"` // meeting | breaching | unknown
	Note               string   `json:"note,omitempty"`
}

func sloIndicatorOf(name string, target float64, good, judged int, note string) sloIndicator {
	in := sloIndicator{Name: name, TargetPct: target, JudgedSamples: judged, GoodSamples: good, Status: "unknown", Note: note}
	if judged == 0 {
		return in
	}
	step := sloStep.Minutes()
	c := math.Round(float64(good)/float64(judged)*10000) / 100
	in.CompliancePct = &c
	bad := float64(judged-good) * step
	allowed := (1 - target/100) * float64(judged) * step
	in.TimeOutOfSLOMin, in.BudgetMinutes = bad, math.Round(allowed*10)/10
	var rem float64
	switch {
	case allowed <= 0 && bad == 0:
		rem = 100
	case allowed <= 0:
		rem = 0
	default:
		rem = math.Max(0, math.Round((allowed-bad)/allowed*1000)/10)
	}
	in.BudgetRemainingPct = &rem
	in.Status = "meeting"
	if c < target {
		in.Status = "breaching"
	}
	return in
}

func sloWindow(pts []sloPoint, now time.Time, hours int) []sloPoint {
	cut := now.Add(-time.Duration(hours) * time.Hour).Unix()
	i := sort.Search(len(pts), func(i int) bool { return pts[i].T >= cut })
	return pts[i:]
}

// sloHeartbeat: good = fresh heartbeat. Samples before the agent's first
// heartbeat are not judged (an agent that never reported has no baseline).
func sloHeartbeat(pts []sloPoint, now time.Time, c sloConfig) sloIndicator {
	good, judged := 0, 0
	for _, p := range sloWindow(pts, now, c.WindowHours) {
		if p.F&sloFlagKnown == 0 {
			continue
		}
		judged++
		if p.F&sloFlagFresh != 0 {
			good++
		}
	}
	return sloIndicatorOf("heartbeat_freshness", c.HeartbeatTargetPct, good, judged, "")
}

// sloContinuity: a sample is a gap when the agent produced no events in the
// trailing continuity window although its own earlier history says it
// normally produces at least one per window. Agents with too little history,
// or that normally send nothing, are not judged.
func sloContinuity(pts []sloPoint, now time.Time, c sloConfig) sloIndicator {
	k := (c.ContinuityGapMinutes + 4) / 5
	pre := make([]int, len(pts)+1)
	for i, p := range pts {
		pre[i+1] = pre[i] + int(p.E)
	}
	cut := now.Add(-time.Duration(c.WindowHours) * time.Hour).Unix()
	good, judged := 0, 0
	for i := range pts {
		if pts[i].T < cut || i+1 < sloMinBaselineK*k {
			continue
		}
		trailing := pre[i+1] - pre[i+1-k]
		priorN := i + 1 - k
		if priorN < k {
			continue
		}
		expected := float64(pre[priorN]) / float64(priorN) * float64(k)
		if expected < 1 {
			continue // not normally reporting: nothing to compare against
		}
		judged++
		if trailing > 0 {
			good++
		}
	}
	return sloIndicatorOf("telemetry_continuity", c.ContinuityTargetPct, good, judged,
		"gap = no events in the trailing continuity window while the agent's own history expects at least one; events are counted from the bounded in-memory rings, so busy hosts may under-count")
}

type sloAgentView struct {
	Host       string         `json:"host"`
	State      string         `json:"state"`
	LastSeen   *time.Time     `json:"last_seen,omitempty"`
	Current    string         `json:"heartbeat_current"` // fresh | stale | never_seen
	Heartbeat  sloIndicator   `json:"heartbeat"`
	Continuity sloIndicator   `json:"continuity"`
	Categories map[string]any `json:"categories"`
	Footprint  map[string]any `json:"footprint"`
	Samples    int            `json:"samples_in_window"`
}

var sloNotReported = []string{"agent_cpu_percent", "agent_rss_memory_bytes", "agent_disk_spool_bytes", "events_dropped_total",
	"agent_version", "agent_uptime_seconds", "sensor_restart_count", "per_sensor_event_rates", "kernel_ringbuffer_drops"}

type sloBreach struct {
	Agent     string  `json:"agent,omitempty"`
	Indicator string  `json:"indicator"`
	Kind      string  `json:"kind"` // window_compliance | current | coverage
	Detail    string  `json:"detail"`
	Value     float64 `json:"value,omitempty"`
}

type sloCoverage struct {
	Category  string   `json:"category"`
	Reporting int      `json:"agents_reporting"`
	Enrolled  int      `json:"agents_enrolled"`
	Pct       *float64 `json:"coverage_pct"`
	TargetPct float64  `json:"target_pct"`
	Status    string   `json:"status"`
}

type sloReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Config      sloConfig      `json:"targets"`
	Fleet       map[string]any `json:"fleet"`
	Coverage    []sloCoverage  `json:"coverage"`
	Agents      []sloAgentView `json:"agents"`
	Breaches    []sloBreach    `json:"breaches"`
	NotReported []string       `json:"not_reported_by_agent"`
	Notes       []string       `json:"notes"`
}

func sloPct(good, total int) *float64 {
	if total == 0 {
		return nil
	}
	v := math.Round(float64(good)/float64(total)*10000) / 100
	return &v
}

func (e *sloEngine) report(now time.Time, statuses []AgentStatus, obs map[string]*sloObs) sloReport {
	e.mu.Lock()
	cfg := e.cfg
	series := make(map[string][]sloPoint, len(e.series))
	for h, s := range e.series {
		series[h] = s // points are append-only copies; slices are not mutated in place
	}
	e.mu.Unlock()
	rep := sloReport{GeneratedAt: now.UTC(), Config: cfg, Agents: []sloAgentView{}, Breaches: []sloBreach{}, NotReported: sloNotReported,
		Notes: []string{"Indicators use only data agents already send: heartbeat time, sensor, queue depth, and event timestamps held by the server.",
			"Series are sampled every 5 minutes in memory (max 72h, 500 agents) and persisted at most every 10 minutes; a server restart leaves a gap that is not counted against agents."}}
	fresh := time.Duration(cfg.HeartbeatFreshMinutes) * time.Minute
	gap := time.Duration(cfg.ContinuityGapMinutes) * time.Minute
	var hbGood, hbJudged, ctGood, ctJudged, active, curFresh int
	catRep := [3]int{}
	for _, st := range statuses {
		if st.State == "revoked" {
			continue
		}
		active++
		pts := series[st.Host]
		v := sloAgentView{Host: st.Host, State: st.State, Current: "never_seen", Categories: map[string]any{}, Samples: len(sloWindow(pts, now, cfg.WindowHours))}
		if !st.LastSeen.IsZero() {
			ls := st.LastSeen
			v.LastSeen = &ls
			if now.Sub(ls) <= fresh {
				v.Current = "fresh"
				curFresh++
			} else {
				v.Current = "stale"
			}
		}
		v.Heartbeat, v.Continuity = sloHeartbeat(pts, now, cfg), sloContinuity(pts, now, cfg)
		hbGood += v.Heartbeat.GoodSamples
		hbJudged += v.Heartbeat.JudgedSamples
		ctGood += v.Continuity.GoodSamples
		ctJudged += v.Continuity.JudgedSamples
		o := obs[st.Host]
		for i, name := range sloCategories {
			switch {
			case o == nil || o.last[i].IsZero():
				v.Categories[name] = "never reported"
			case now.Sub(o.last[i]) <= gap:
				v.Categories[name] = "reporting"
				catRep[i]++
			default:
				v.Categories[name] = "silent"
			}
		}
		v.Footprint = map[string]any{"queued_items": st.Queued, "sensor": orNotReported(st.Sensor)}
		for _, n := range sloNotReported {
			v.Footprint[n] = "not reported by agent"
		}
		if v.Current != "fresh" {
			rep.Breaches = append(rep.Breaches, sloBreach{Agent: st.Host, Indicator: "heartbeat_freshness", Kind: "current", Detail: "heartbeat is " + v.Current})
		}
		for _, in := range []sloIndicator{v.Heartbeat, v.Continuity} {
			if in.Status == "breaching" {
				rep.Breaches = append(rep.Breaches, sloBreach{Agent: st.Host, Indicator: in.Name, Kind: "window_compliance",
					Detail: "compliance below target over the rolling window", Value: *in.CompliancePct})
			}
		}
		rep.Agents = append(rep.Agents, v)
	}
	for i, name := range sloCategories {
		c := sloCoverage{Category: name, Reporting: catRep[i], Enrolled: active, Pct: sloPct(catRep[i], active), TargetPct: cfg.CoverageTargetPct, Status: "unknown"}
		if c.Pct != nil {
			c.Status = "meeting"
			if *c.Pct < cfg.CoverageTargetPct {
				c.Status = "breaching"
				rep.Breaches = append(rep.Breaches, sloBreach{Indicator: "coverage_" + name, Kind: "coverage", Detail: "share of enrolled agents reporting " + name + " telemetry is below target", Value: *c.Pct})
			}
		}
		rep.Coverage = append(rep.Coverage, c)
	}
	rep.Fleet = map[string]any{
		"enrolled_active_agents": active, "agents_with_fresh_heartbeat_now": curFresh,
		"heartbeat":  sloIndicatorOf("heartbeat_freshness", cfg.HeartbeatTargetPct, hbGood, hbJudged, "pooled over all agent samples in the window"),
		"continuity": sloIndicatorOf("telemetry_continuity", cfg.ContinuityTargetPct, ctGood, ctJudged, "pooled over judged agent samples in the window"),
	}
	return rep
}

func orNotReported(s string) string {
	if s == "" {
		return "not reported by agent"
	}
	return s
}

type sloHistPoint struct {
	T          int64    `json:"t"`
	Fresh      *bool    `json:"heartbeat_fresh,omitempty"`
	Events     *int     `json:"events,omitempty"`
	Agents     int      `json:"agents,omitempty"`
	FreshAgent int      `json:"agents_fresh,omitempty"`
	FreshPct   *float64 `json:"fresh_pct,omitempty"`
}

// history returns stored points for one agent, or a fleet aggregate when
// agent is empty.
func (e *sloEngine) history(agent string, now time.Time, window time.Duration) []sloHistPoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	cut := now.Add(-window).Unix()
	out := []sloHistPoint{}
	if agent != "" {
		for _, p := range e.series[agent] {
			if p.T < cut {
				continue
			}
			hp := sloHistPoint{T: p.T}
			if p.F&sloFlagKnown != 0 {
				f := p.F&sloFlagFresh != 0
				hp.Fresh = &f
			}
			ev := int(p.E)
			hp.Events = &ev
			out = append(out, hp)
		}
		return out
	}
	type agg struct{ n, fresh int }
	by := map[int64]*agg{}
	for _, s := range e.series {
		for _, p := range s {
			if p.T < cut || p.F&sloFlagKnown == 0 {
				continue
			}
			a := by[p.T]
			if a == nil {
				a = &agg{}
				by[p.T] = a
			}
			a.n++
			if p.F&sloFlagFresh != 0 {
				a.fresh++
			}
		}
	}
	for t, a := range by {
		out = append(out, sloHistPoint{T: t, Agents: a.n, FreshAgent: a.fresh, FreshPct: sloPct(a.fresh, a.n)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

func (e *sloEngine) hasAgent(h string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.series[h]
	return ok
}
