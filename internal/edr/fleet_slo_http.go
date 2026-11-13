package edr

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func sloParseWindow(s string, def time.Duration) (time.Duration, bool) {
	if s == "" {
		return def, true
	}
	var d time.Duration
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, false
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, false
		}
	}
	if d < sloStep || d > sloMaxWindowH*time.Hour {
		return 0, false
	}
	return d, true
}

func sloDefinitions() map[string]any {
	return map[string]any{
		"sampling": "every 5 minutes, one point per enrolled non-revoked agent; rolling window configurable 1-72h",
		"indicators": []map[string]string{
			{"name": "heartbeat_freshness", "definition": "A sample is good when the agent's last heartbeat is no older than heartbeat_fresh_minutes at sampling time. Samples before the agent's first heartbeat are not judged.", "source": "enrollment registry last_seen"},
			{"name": "telemetry_continuity", "definition": "A sample is a gap when the agent produced no process/network/file events in the trailing continuity_gap_minutes although its own earlier history in the series expects at least one per window. Needs at least two windows of history; agents that normally send nothing are not judged.", "source": "event timestamps held per host"},
			{"name": "coverage", "definition": "For each telemetry category (process, network, file), the share of enrolled non-revoked agents with an event of that category inside the last continuity_gap_minutes.", "source": "event timestamps held per host"},
		},
		"error_budget":             "allowed bad time = (1 - target) x judged time in the window; time out of SLO = bad samples x 5 minutes; remaining budget = (allowed - used) / allowed, floored at 0.",
		"not_reported_by_agent":    sloNotReported,
		"agent_would_need_to_send": "Add these fields to the agent heartbeat to enable footprint SLOs: CPU percent, resident memory, spool/queue bytes, dropped-event counter, agent version, uptime, sensor restart count, per-sensor event counters, kernel ring-buffer drop counter. Until then they are reported as 'not reported by agent' and no value is estimated.",
		"defaults":                 sloDefaults(),
		"limits":                   map[string]any{"max_agents": sloMaxAgents, "max_window_hours": sloMaxWindowH, "step_minutes": 5},
	}
}

// RegisterFleetSLO mounts the fleet SLO endpoints and starts the sampler.
func RegisterFleetSLO(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	eng := newSLOEngine(store.path)
	statuses := func(now time.Time) []AgentStatus {
		if registry == nil {
			return nil
		}
		return registry.Status(now, fleetHOnlineAfter)
	}
	store.goBG(func(stop <-chan struct{}) {
		t := time.NewTicker(sloStep)
		defer t.Stop()
		for {
			now := time.Now()
			eng.sample(now, statuses(now), sloObserve(store, now))
			select {
			case <-stop:
				return
			case <-eng.stop:
				return
			case <-t.C:
			}
		}
	})
	out := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/fleet/slo", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		now := time.Now()
		out(w, eng.report(now, statuses(now), sloObserve(store, now)))
	})
	mux.HandleFunc("PUT /v1/fleet/slo", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !admin {
			http.Error(w, "admin token required", http.StatusForbidden)
			return
		}
		c := eng.Config() // omitted fields keep their current value
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), 400)
			return
		}
		if msg := c.validate(); msg != "" {
			http.Error(w, msg, 400)
			return
		}
		eng.SetConfig(c, time.Now())
		out(w, c)
	})
	mux.HandleFunc("GET /v1/fleet/slo/definitions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		out(w, sloDefinitions())
	})
	mux.HandleFunc("GET /v1/fleet/slo/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		win, ok := sloParseWindow(q.Get("window"), 24*time.Hour)
		if !ok {
			http.Error(w, "window must be a duration between 5m and 72h (e.g. 6h, 2d)", 400)
			return
		}
		agent := q.Get("agent")
		if agent != "" && !eng.hasAgent(agent) {
			http.Error(w, "no SLO history for that agent", 404)
			return
		}
		out(w, map[string]any{"agent": agent, "window": win.String(), "step_seconds": int(sloStep.Seconds()), "points": eng.history(agent, time.Now(), win)})
	})
}
