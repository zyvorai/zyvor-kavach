// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Fleet health diagnostics. Strictly read-only: Kavach observes agent
// liveness and data flow and describes what an operator could check; it never
// acts on a host.

const (
	fleetHOnlineAfter  = 90 * time.Second // matches /v1/agents and /v1/fleet
	fleetHBlindAfter   = time.Hour        // heartbeat fresh but no events this long => sensor blind suspicion
	fleetHBacklogWarn  = 100              // queued items considered a backlog
	fleetHDefaultStale = 15               // minutes
	fleetHMaxStale     = 10080            // one week
)

// Score factor weights (sum 100).
var fleetHWeights = []struct {
	Name   string
	Weight int
	Desc   string
}{
	{"heartbeat_online", 40, "share of active (non-revoked) agents with a heartbeat in the last 90s"},
	{"data_flowing", 25, "share of active agents whose host has reported events"},
	{"strong_sensor", 15, "share of active agents on the eBPF sensor rather than /proc polling"},
	{"backlog_healthy", 10, "share of active agents with a queue of at most 100 items"},
	{"no_shadow_hosts", 10, "enrolled hosts divided by enrolled plus shadow hosts"},
}

type fleetHFactor struct {
	Name   string  `json:"name"`
	Weight int     `json:"weight"`
	Ratio  float64 `json:"ratio"`
	Points float64 `json:"points"`
	Desc   string  `json:"description"`
}

type fleetHAgent struct {
	Host                 string     `json:"host"`
	State                string     `json:"state"`
	LastSeen             *time.Time `json:"last_seen,omitempty"`
	HeartbeatAgeSeconds  *int64     `json:"heartbeat_age_seconds,omitempty"`
	Sensor               string     `json:"sensor,omitempty"`
	SensorKind           string     `json:"sensor_kind"` // ebpf | proc-poll | unknown
	Queued               int        `json:"queued"`
	BacklogHigh          bool       `json:"backlog_high"`
	LastEvent            *time.Time `json:"last_event,omitempty"`
	EventAgeSeconds      *int64     `json:"event_age_seconds,omitempty"`
	NeverReportedEvents  bool       `json:"never_reported_events"`
	SensorBlindSuspected bool       `json:"sensor_blind_suspected"`
	Findings             int        `json:"findings"`
	Version              string     `json:"version"`
	VersionDrift         string     `json:"version_drift"`
	Flags                []string   `json:"flags"`
}

type fleetHSeen struct {
	lastEvent time.Time
	findings  int
}

// fleetHObserved merges per-host activity from findings and process, network
// and file events held by the store.
func fleetHObserved(store *Store) map[string]*fleetHSeen {
	seen := map[string]*fleetHSeen{}
	if store == nil {
		return seen
	}
	get := func(h string) *fleetHSeen {
		s := seen[h]
		if s == nil {
			s = &fleetHSeen{}
			seen[h] = s
		}
		return s
	}
	touch := func(h string, t time.Time) {
		if h == "" {
			return
		}
		s := get(h)
		if t.After(s.lastEvent) {
			s.lastEvent = t
		}
	}
	for _, f := range store.List() {
		touch(f.Host, f.Time)
		if f.Host != "" {
			get(f.Host).findings++
		}
	}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		touch(e.Host, e.Time)
	}
	for _, n := range store.networkEvents {
		touch(n.Host, n.Time)
	}
	for _, fe := range store.fileEvents {
		touch(fe.Host, fe.Time)
	}
	store.mu.Unlock()
	return seen
}

func fleetHSensorKind(sensor string) string {
	s := strings.ToLower(sensor)
	switch {
	case strings.Contains(s, "ebpf"):
		return "ebpf"
	case strings.Contains(s, "proc"):
		return "proc-poll"
	}
	return "unknown"
}

func fleetHAgentFor(st AgentStatus, seen map[string]*fleetHSeen, now time.Time) fleetHAgent {
	a := fleetHAgent{Host: st.Host, State: st.State, Sensor: st.Sensor, SensorKind: fleetHSensorKind(st.Sensor),
		Queued: st.Queued, BacklogHigh: st.Queued > fleetHBacklogWarn, Flags: []string{},
		Version: "not reported", VersionDrift: "unknown (agents do not report a version in heartbeats)"}
	if !st.LastSeen.IsZero() {
		ls := st.LastSeen
		age := int64(now.Sub(ls).Seconds())
		a.LastSeen, a.HeartbeatAgeSeconds = &ls, &age
	}
	if s := seen[st.Host]; s != nil {
		a.Findings = s.findings
		if !s.lastEvent.IsZero() {
			le := s.lastEvent
			age := int64(now.Sub(le).Seconds())
			a.LastEvent, a.EventAgeSeconds = &le, &age
		}
	}
	active := st.State != "revoked"
	if active && a.LastEvent == nil {
		a.NeverReportedEvents = true
		a.Flags = append(a.Flags, "never_reported_events")
	}
	if active && st.State == "online" && a.LastEvent != nil && now.Sub(*a.LastEvent) > fleetHBlindAfter {
		a.SensorBlindSuspected = true
		a.Flags = append(a.Flags, "sensor_blind_suspected")
	}
	if active && a.SensorKind == "proc-poll" {
		a.Flags = append(a.Flags, "weaker_polling_sensor")
	}
	if active && a.BacklogHigh {
		a.Flags = append(a.Flags, "backlog_high")
	}
	if st.State == "offline" {
		a.Flags = append(a.Flags, "heartbeat_stale")
	}
	if st.State == "pending" {
		a.Flags = append(a.Flags, "never_heartbeated")
	}
	return a
}

type fleetHReport struct {
	Score          int            `json:"score"`
	Factors        []fleetHFactor `json:"factors"`
	Agents         []fleetHAgent  `json:"agents"`
	Counts         map[string]int `json:"counts"`
	ShadowHosts    []string       `json:"shadow_hosts"`
	GapHistoryNote string         `json:"heartbeat_gap_history_note"`
	GeneratedAt    time.Time      `json:"generated_at"`
}

func fleetHBuild(store *Store, registry *CredentialRegistry, now time.Time) fleetHReport {
	var statuses []AgentStatus
	if registry != nil {
		statuses = registry.Status(now, fleetHOnlineAfter)
	}
	seen := fleetHObserved(store)
	enrolled := map[string]bool{}
	rep := fleetHReport{Agents: []fleetHAgent{}, Factors: []fleetHFactor{}, ShadowHosts: []string{}, GeneratedAt: now.UTC(),
		GapHistoryNote: "Heartbeat gap history is not stored; heartbeat age is derived from the last heartbeat time only."}
	counts := map[string]int{"enrolled": len(statuses), "active": 0, "online": 0, "offline": 0, "pending": 0, "revoked": 0,
		"ebpf": 0, "proc_poll": 0, "never_reported_events": 0, "sensor_blind_suspected": 0, "backlog_high": 0}
	var nOnline, nData, nStrong, nBacklogOK int
	for _, st := range statuses {
		enrolled[st.Host] = true
		a := fleetHAgentFor(st, seen, now)
		rep.Agents = append(rep.Agents, a)
		counts[st.State]++
		if st.State == "revoked" {
			continue
		}
		counts["active"]++
		if st.State == "online" {
			nOnline++
		}
		if !a.NeverReportedEvents {
			nData++
		} else {
			counts["never_reported_events"]++
		}
		if a.SensorBlindSuspected {
			counts["sensor_blind_suspected"]++
		}
		if a.BacklogHigh {
			counts["backlog_high"]++
		} else {
			nBacklogOK++
		}
		switch a.SensorKind {
		case "ebpf":
			nStrong++
			counts["ebpf"]++
		case "proc-poll":
			counts["proc_poll"]++
		}
	}
	for h := range seen {
		if !enrolled[h] {
			rep.ShadowHosts = append(rep.ShadowHosts, h)
		}
	}
	sort.Strings(rep.ShadowHosts)
	counts["shadow_hosts"] = len(rep.ShadowHosts)
	rep.Counts = counts

	active := counts["active"]
	ratio := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return float64(n) / float64(d)
	}
	ratios := []float64{ratio(nOnline, active), ratio(nData, active), ratio(nStrong, active), ratio(nBacklogOK, active),
		ratio(len(statuses), len(statuses)+len(rep.ShadowHosts))}
	total := 0.0
	for i, w := range fleetHWeights {
		pts := float64(w.Weight) * ratios[i]
		total += pts
		rep.Factors = append(rep.Factors, fleetHFactor{Name: w.Name, Weight: w.Weight, Ratio: float64(int(ratios[i]*1000+0.5)) / 1000,
			Points: float64(int(pts*10+0.5)) / 10, Desc: w.Desc})
	}
	if active == 0 {
		total = 0 // no active agents: nothing is covered
	}
	rep.Score = int(total + 0.5)
	return rep
}

// fleetHStale lists active agents whose last heartbeat is older than cutoff,
// and separately those that have never sent a heartbeat.
func fleetHStale(registry *CredentialRegistry, now time.Time, cutoff time.Duration) (stale, neverSeen []fleetHAgent) {
	stale, neverSeen = []fleetHAgent{}, []fleetHAgent{}
	if registry == nil {
		return
	}
	for _, st := range registry.Status(now, fleetHOnlineAfter) {
		if st.State == "revoked" {
			continue
		}
		a := fleetHAgent{Host: st.Host, State: st.State, Sensor: st.Sensor, SensorKind: fleetHSensorKind(st.Sensor), Queued: st.Queued, Flags: []string{}}
		if st.LastSeen.IsZero() {
			neverSeen = append(neverSeen, a)
			continue
		}
		ls := st.LastSeen
		age := int64(now.Sub(ls).Seconds())
		a.LastSeen, a.HeartbeatAgeSeconds = &ls, &age
		if now.Sub(ls) > cutoff {
			stale = append(stale, a)
		}
	}
	return
}

func fleetHRecommendations(a fleetHAgent, enrolled bool) []string {
	r := []string{}
	if !enrolled {
		return append(r, "This host appears in findings or events but has no enrolled agent. Confirm whether it should be covered and, if so, ask the owner to enroll an agent.")
	}
	if a.State == "revoked" {
		return append(r, "The agent credential is revoked. If the host should be monitored, an administrator can enroll it again.")
	}
	for _, f := range a.Flags {
		switch f {
		case "never_heartbeated":
			r = append(r, "The agent has never sent a heartbeat. Check that the agent is installed and that its service is running and can reach the Kavach server.")
		case "heartbeat_stale":
			r = append(r, "The heartbeat is stale. Check the agent service on the host and its network path to the Kavach server.")
		case "never_reported_events":
			r = append(r, "No events from this host have been received. Check the agent service logs and that its collectors are enabled.")
		case "sensor_blind_suspected":
			r = append(r, "Heartbeats continue but no events have arrived recently, which may mean the sensor is blind. Check the sensor and collector logs on the host; a genuinely idle host is also possible.")
		case "weaker_polling_sensor":
			r = append(r, "The host uses /proc polling, which can miss short-lived processes. Consider reviewing whether the eBPF sensor is supported on this kernel.")
		case "backlog_high":
			r = append(r, fmt.Sprintf("The agent reports %d queued items. Check connectivity and server load, since events may be delayed.", a.Queued))
		}
	}
	if len(r) == 0 {
		r = append(r, "No issues observed. Keep monitoring.")
	}
	return r
}

func fleetHGauges(store *Store, registry *CredentialRegistry, now time.Time) string {
	rep := fleetHBuild(store, registry, now)
	stale, _ := fleetHStale(registry, now, fleetHDefaultStale*time.Minute)
	var b strings.Builder
	b.WriteString("# HELP kavach_fleet_coverage_score Fleet coverage score 0-100.\n# TYPE kavach_fleet_coverage_score gauge\n")
	fmt.Fprintf(&b, "kavach_fleet_coverage_score %d\n", rep.Score)
	b.WriteString("# HELP kavach_fleet_stale_agents Agents with no heartbeat for 15 minutes.\n# TYPE kavach_fleet_stale_agents gauge\n")
	fmt.Fprintf(&b, "kavach_fleet_stale_agents %d\n", len(stale))
	return b.String()
}

// RegisterFleetHealth mounts read-only fleet diagnostics.
func RegisterFleetHealth(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/fleet/health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, fleetHBuild(store, registry, time.Now()))
	})
	mux.HandleFunc("GET /v1/fleet/coverage-gaps", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rep := fleetHBuild(store, registry, time.Now())
		noData, weak := []string{}, []string{}
		for _, a := range rep.Agents {
			if a.State == "revoked" {
				continue
			}
			if a.NeverReportedEvents {
				noData = append(noData, a.Host)
			}
			if a.SensorKind == "proc-poll" {
				weak = append(weak, a.Host)
			}
		}
		writeJSON(w, map[string]any{"shadow_hosts": rep.ShadowHosts, "agents_without_data": noData, "agents_on_polling_sensor": weak,
			"note": "Shadow hosts appear in findings or events but have no enrolled agent."})
	})
	mux.HandleFunc("GET /v1/fleet/stale", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		mins := fleetHDefaultStale
		if q := r.URL.Query().Get("minutes"); q != "" {
			n, err := strconv.Atoi(q)
			if err != nil || n < 1 || n > fleetHMaxStale {
				http.Error(w, "minutes must be 1-10080", http.StatusBadRequest)
				return
			}
			mins = n
		}
		stale, never := fleetHStale(registry, time.Now(), time.Duration(mins)*time.Minute)
		writeJSON(w, map[string]any{"minutes": mins, "stale": stale, "never_seen": never})
	})
	mux.HandleFunc("GET /v1/fleet/health/{host}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := r.PathValue("host")
		now := time.Now()
		rep := fleetHBuild(store, registry, now)
		for _, a := range rep.Agents {
			if a.Host == host {
				writeJSON(w, map[string]any{"enrolled": true, "agent": a, "recommendations": fleetHRecommendations(a, true), "heartbeat_gap_history_note": rep.GapHistoryNote})
				return
			}
		}
		if s := fleetHObserved(store)[host]; s != nil {
			a := fleetHAgent{Host: host, State: "not_enrolled", SensorKind: "unknown", Findings: s.findings, Flags: []string{"shadow_host"}}
			if !s.lastEvent.IsZero() {
				le := s.lastEvent
				age := int64(now.Sub(le).Seconds())
				a.LastEvent, a.EventAgeSeconds = &le, &age
			}
			writeJSON(w, map[string]any{"enrolled": false, "agent": a, "recommendations": fleetHRecommendations(a, false)})
			return
		}
		http.Error(w, "unknown host", http.StatusNotFound)
	})
}
