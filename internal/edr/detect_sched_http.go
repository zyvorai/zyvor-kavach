// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

var schedSvc atomic.Pointer[schedService]

// StopScheduledDetections stops the scheduler goroutine (call on server shutdown). Safe to call twice.
func StopScheduledDetections() {
	if s := schedSvc.Load(); s != nil {
		s.Stop()
	}
}

// RegisterScheduledDetections wires scheduled detections, hunt quotas and rule exceptions. Everything
// here observes and reports; nothing blocks, kills or contains.
func RegisterScheduledDetections(mux *http.ServeMux, token string, store *Store, ws *Workspace) {
	path := ""
	if store.path != "" {
		path = store.path + ".exceptions.json"
	}
	exc := newExceptionService(path, time.Now)
	excSvc.Store(exc)
	registerExceptionRoutes(mux, token, exc)
	s := newSchedService(store, ws, time.Now)
	schedSvc.Store(s)
	s.routes(mux, token)
	s.start()
}

type detInput struct {
	Name           *string    `json:"name"`
	Source         *DetSource `json:"source"`
	IntervalSec    *int       `json:"interval_sec"`
	Severity       *string    `json:"severity"`
	Technique      *string    `json:"technique"`
	State          *string    `json:"state"`
	MaxMatches     *int       `json:"max_matches"`
	MaxRuntimeMS   *int       `json:"max_runtime_ms"`
	DedupWindowSec *int       `json:"dedup_window_sec"`
}

func (in detInput) apply(d *SchedDetection) {
	if in.Name != nil {
		d.Name = *in.Name
	}
	if in.Source != nil {
		d.Source = *in.Source
	}
	if in.IntervalSec != nil {
		d.IntervalSec = *in.IntervalSec
	}
	if in.Severity != nil {
		d.Severity = *in.Severity
	}
	if in.Technique != nil {
		d.Technique = *in.Technique
	}
	if in.State != nil {
		d.State = *in.State
	}
	if in.MaxMatches != nil {
		d.MaxMatches = *in.MaxMatches
	}
	if in.MaxRuntimeMS != nil {
		d.MaxRuntimeMS = *in.MaxRuntimeMS
	}
	if in.DedupWindowSec != nil {
		d.DedupWindowSec = *in.DedupWindowSec
	}
}

func (s *schedService) routes(mux *http.ServeMux, token string) {
	adminOrSession := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		admin, ok := requireAdminOrSession(w, r, token)
		return wsActor(admin), ok
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		if json.NewDecoder(r.Body).Decode(v) != nil {
			detErr(w, 400, "invalid json body")
			return false
		}
		return true
	}

	mux.HandleFunc("GET /v1/detections/scheduled", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out := append([]SchedDetection{}, s.d.Detections...)
		detReply(w, 200, map[string]any{"detections": out, "count": len(out), "limits": s.limitsLocked(),
			"semantics": "scheduled detections record findings; they never block, kill or contain anything"})
	})
	mux.HandleFunc("POST /v1/detections/scheduled", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := adminOrSession(w, r)
		if !ok {
			return
		}
		var in detInput
		if !decode(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		lim := s.limitsLocked()
		if len(s.d.Detections) >= lim.MaxScheduled {
			s.refuseLocked("create", "", fmt.Sprintf("max_scheduled (%d) reached", lim.MaxScheduled))
			detErr(w, 429, "max_scheduled detections reached")
			return
		}
		d := SchedDetection{}
		in.apply(&d)
		if msg := s.validateDet(&d, lim); msg != "" {
			detErr(w, 400, msg)
			return
		}
		s.d.Seq++
		now := s.now().UTC()
		d.ID, d.Rule, d.Created, d.Updated, d.By = fmt.Sprintf("sd-%d", s.d.Seq), "", now, now, actor
		d.Rule = "hunt-" + d.ID
		s.d.Detections = append(s.d.Detections, d)
		s.lastRun[d.ID] = s.now()
		s.saveLocked()
		AppendAudit(token, "detection.scheduled.create", d.ID)
		syncRuleLifecycle(d, actor, now)
		detReply(w, 201, d)
	})
	mux.HandleFunc("GET /v1/detections/scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		i := s.find(r.PathValue("id"))
		if i < 0 {
			detErr(w, 404, "detection not found")
			return
		}
		id := s.d.Detections[i].ID
		detReply(w, 200, map[string]any{"detection": s.d.Detections[i], "running": s.running[id],
			"shadow_findings": s.d.Shadow[id], "dedup_keys": len(s.d.Dedup[id])})
	})
	mux.HandleFunc("PUT /v1/detections/scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := adminOrSession(w, r)
		if !ok {
			return
		}
		var in detInput
		if !decode(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		i := s.find(r.PathValue("id"))
		if i < 0 {
			detErr(w, 404, "detection not found")
			return
		}
		d := s.d.Detections[i]
		in.apply(&d)
		if msg := s.validateDet(&d, s.limitsLocked()); msg != "" {
			detErr(w, 400, msg)
			return
		}
		now := s.now().UTC()
		stateChanged := d.State != s.d.Detections[i].State
		d.Updated, d.By = now, actor
		s.d.Detections[i] = d
		if in.IntervalSec != nil {
			s.lastRun[d.ID] = s.now()
		}
		s.saveLocked()
		AppendAudit(token, "detection.scheduled.update", d.ID)
		if stateChanged {
			syncRuleLifecycle(d, actor, now)
		}
		detReply(w, 200, d)
	})
	mux.HandleFunc("DELETE /v1/detections/scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := adminOrSession(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		i := s.find(r.PathValue("id"))
		if i < 0 {
			detErr(w, 404, "detection not found")
			return
		}
		d := s.d.Detections[i]
		s.d.Detections = append(s.d.Detections[:i:i], s.d.Detections[i+1:]...)
		delete(s.d.History, d.ID)
		delete(s.d.Dedup, d.ID)
		delete(s.d.Shadow, d.ID)
		delete(s.lastRun, d.ID)
		s.saveLocked()
		AppendAudit(token, "detection.scheduled.delete", d.ID)
		_ = actor
		detReply(w, 200, map[string]any{"deleted": d.ID, "findings_already_recorded_kept": true})
	})
	post := func(suffix, trigger string, dry bool) {
		mux.HandleFunc("POST /v1/detections/scheduled/{id}/"+suffix, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := adminOrSession(w, r); !ok {
				return
			}
			res, code, msg := s.runNow(r.Context(), r.PathValue("id"), trigger, dry)
			if code != 0 {
				detErr(w, code, msg)
				return
			}
			out := map[string]any{"run": res, "dry_run": dry}
			if dry {
				out["note"] = "dry run: nothing was recorded; 'recorded' is what WOULD be reported"
			}
			detReply(w, 200, out)
		})
	}
	post("dryrun", "dryrun", true)
	post("run", "manual", false)
	mux.HandleFunc("GET /v1/detections/scheduled/{id}/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		id := r.PathValue("id")
		if s.find(id) < 0 {
			detErr(w, 404, "detection not found")
			return
		}
		h := append([]SchedRun{}, s.d.History[id]...)
		detReply(w, 200, map[string]any{"id": id, "history": h, "retention": s.limitsLocked().HistoryRetention})
	})

	mux.HandleFunc("GET /v1/hunts/limits", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		lim := s.limitsLocked()
		recent := append([]HuntRefusal{}, s.d.Refused...)
		detReply(w, 200, map[string]any{
			"limits":  lim,
			"usage":   map[string]any{"scheduled_detections": len(s.d.Detections), "runs_last_hour": s.runsLastHourLocked(s.now())},
			"refused": map[string]any{"counts": s.d.RefusedN, "recent": recent},
			"env":     []string{"KAVACH_HUNT_MAX_SCHEDULED", "KAVACH_HUNT_MAX_RUNS_PER_HOUR", "KAVACH_HUNT_MAX_MATCHES_PER_RUN", "KAVACH_HUNT_HISTORY_RETENTION"},
		})
	})
	mux.HandleFunc("PUT /v1/hunts/limits", func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !isAdmin {
			detErr(w, 403, "admin token required to change hunt limits")
			return
		}
		var in struct {
			MaxScheduled     *int `json:"max_scheduled"`
			MaxRunsPerHour   *int `json:"max_runs_per_hour"`
			MaxMatchesPerRun *int `json:"max_matches_per_run"`
			HistoryRetention *int `json:"history_retention"`
		}
		if !decode(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		l := s.limitsLocked()
		for _, p := range []struct {
			v   *int
			dst *int
			lo  int
			hi  int
			n   string
		}{{in.MaxScheduled, &l.MaxScheduled, 1, 500, "max_scheduled"}, {in.MaxRunsPerHour, &l.MaxRunsPerHour, 1, 3600, "max_runs_per_hour"},
			{in.MaxMatchesPerRun, &l.MaxMatchesPerRun, 1, 1000, "max_matches_per_run"}, {in.HistoryRetention, &l.HistoryRetention, 1, 500, "history_retention"}} {
			if p.v == nil {
				continue
			}
			if *p.v < p.lo || *p.v > p.hi {
				detErr(w, 400, fmt.Sprintf("%s must be between %d and %d", p.n, p.lo, p.hi))
				return
			}
			*p.dst = *p.v
		}
		s.d.Limits = &l
		for id, h := range s.d.History { // apply retention now
			if len(h) > l.HistoryRetention {
				s.d.History[id] = h[len(h)-l.HistoryRetention:]
			}
		}
		s.saveLocked()
		AppendAudit(token, "hunt.limits.update", fmt.Sprintf("%+v", l))
		detReply(w, 200, map[string]any{"limits": l})
	})
}
