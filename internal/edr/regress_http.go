// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func regressSummary(s RegressSnapshot) map[string]any {
	nonBenign, passed := 0, 0
	for _, v := range s.Scenarios {
		switch v {
		case "benign_ok", "benign_fp":
		case "detected":
			nonBenign++
			passed++
		default:
			nonBenign++
		}
	}
	return map[string]any{"seq": s.Seq, "time": s.Time, "trigger": s.Trigger, "content_hash": s.ContentHash, "build": s.Build,
		"runtime_ms": s.RuntimeMS, "truncated": s.Truncated, "scenarios": len(s.Scenarios), "non_benign": nonBenign, "detected": passed,
		"measured_detected_pct": s.MeasuredDetectedPct, "scenario_detect_rate": s.DetectRate,
		"benign_controls": s.BenignControls, "benign_false_positives": s.BenignFP, "tactics": s.Tactics}
}

func regressJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func resolveRegressRef(all []RegressSnapshot, ref string) (RegressSnapshot, bool) {
	n := len(all)
	if n == 0 {
		return RegressSnapshot{}, false
	}
	switch ref {
	case "", "latest", "current":
		return all[n-1], true
	case "previous":
		if n < 2 {
			return RegressSnapshot{}, false
		}
		return all[n-2], true
	}
	if q, err := strconv.Atoi(ref); err == nil {
		for _, x := range all {
			if x.Seq == q {
				return x, true
			}
		}
	}
	return RegressSnapshot{}, false
}

func parseRegressWindow(v string) time.Duration {
	if v == "" {
		return 30 * 24 * time.Hour
	}
	if strings.HasSuffix(v, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return 0
}

// RegisterRegression wires continuous control validation: scheduler, history, diff, trend, gate.
// Observation only: it replays synthetic scenarios in memory and records a finding only for regressions.
func RegisterRegression(mux *http.ServeMux, token string, store *Store) *regressSvc {
	s := newRegressSvc(store)
	regressActive.Store(s)
	s.Start()
	RegisterStopper("regression", func(ctx context.Context) error { StopRegression(); return nil })

	mux.HandleFunc("GET /v1/regression/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		all := s.snapshots()
		cfg := s.config()
		out := map[string]any{"note": regressNote, "mode": "observe-only", "config": cfg, "running": s.running.Load(),
			"snapshots": len(all), "history_cap": regressHistoryCap}
		if cfg.Enabled {
			out["next_run"] = regressNextRun(s.now(), cfg.Time).Format(time.RFC3339)
		}
		if n := len(all); n > 0 {
			out["latest"] = regressSummary(all[n-1])
			out["content_changed_since_latest"] = s.contentHash() != all[n-1].ContentHash
			if n > 1 {
				d := s.diffOf(all[n-2], all[n-1])
				out["latest_diff"] = map[string]any{"from_seq": d.FromSeq, "to_seq": d.ToSeq, "regressions": len(d.Regressions),
					"improvements": len(d.Improvements), "new_benign_false_positives": len(d.NewBenignFP)}
			}
		}
		regressJSON(w, 200, out)
	})

	mux.HandleFunc("GET /v1/regression/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		limit := 30
		if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
			limit = v
		}
		if limit > regressHistoryCap {
			limit = regressHistoryCap
		}
		all := s.snapshots()
		out := []map[string]any{}
		for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
			out = append(out, regressSummary(all[i]))
		}
		regressJSON(w, 200, map[string]any{"note": regressNote, "count": len(out), "total": len(all), "history": out})
	})

	mux.HandleFunc("GET /v1/regression/diff", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		all := s.snapshots()
		from, ok1 := resolveRegressRef(all, defStr(q.Get("from"), "previous"))
		to, ok2 := resolveRegressRef(all, defStr(q.Get("to"), "latest"))
		if !ok1 || !ok2 {
			regressJSON(w, 404, map[string]any{"error": "need two snapshots (or unknown from/to seq)", "snapshots": len(all), "note": regressNote})
			return
		}
		if from.Seq >= to.Seq {
			regressJSON(w, 400, map[string]any{"error": "from must be older than to", "note": regressNote})
			return
		}
		regressJSON(w, 200, s.diffOf(from, to))
	})

	mux.HandleFunc("GET /v1/regression/trend", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		win := parseRegressWindow(r.URL.Query().Get("window"))
		if win == 0 {
			regressJSON(w, 400, map[string]any{"error": "window must be like 7d, 30d or 72h"})
			return
		}
		cut := s.now().Add(-win)
		points := []map[string]any{}
		tac := map[string][]map[string]any{}
		for _, x := range s.snapshots() {
			t, ok := parseRegressTime(x.Time)
			if !ok || t.Before(cut) {
				continue
			}
			points = append(points, map[string]any{"seq": x.Seq, "time": x.Time, "measured_detected_pct": x.MeasuredDetectedPct,
				"scenario_detect_rate": x.DetectRate, "benign_false_positives": len(x.BenignFP), "truncated": x.Truncated})
			for _, tc := range x.Tactics {
				tac[tc.Tactic] = append(tac[tc.Tactic], map[string]any{"seq": x.Seq, "time": x.Time, "measured_pct": tc.MeasuredPct})
			}
		}
		regressJSON(w, 200, map[string]any{"note": regressNote, "window": win.String(), "points": points, "by_tactic": tac})
	})

	mux.HandleFunc("POST /v1/regression/run", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		snap, diff, err := s.run("manual")
		if err == errRegressBusy {
			regressJSON(w, 409, map[string]any{"error": err.Error()})
			return
		}
		if err != nil {
			regressJSON(w, 500, map[string]any{"error": "scenario run failed", "note": regressNote})
			return
		}
		regressJSON(w, 200, map[string]any{"note": regressNote, "snapshot": regressSummary(snap), "diff": diff})
	})

	mux.HandleFunc("GET /v1/regression/config", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		regressJSON(w, 200, s.config())
	})
	mux.HandleFunc("PUT /v1/regression/config", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		in := struct {
			Enabled         *bool   `json:"enabled"`
			Time            *string `json:"time"`
			MaxRuntimeSec   *int    `json:"max_runtime_sec"`
			AlertMinRegress *int    `json:"alert_min_regressions"`
			AlertMediumAt   *int    `json:"alert_medium_at"`
			AlertOnBenignFP *bool   `json:"alert_on_benign_fp"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			regressJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		c := s.config()
		if in.Enabled != nil {
			c.Enabled = *in.Enabled
		}
		if in.Time != nil {
			if !validHHMM(*in.Time) {
				regressJSON(w, 400, map[string]any{"error": "time must be HH:MM (UTC)"})
				return
			}
			c.Time = *in.Time
		}
		if in.MaxRuntimeSec != nil {
			if *in.MaxRuntimeSec < 5 || *in.MaxRuntimeSec > 300 {
				regressJSON(w, 400, map[string]any{"error": "max_runtime_sec must be 5..300"})
				return
			}
			c.MaxRuntimeSec = *in.MaxRuntimeSec
		}
		if in.AlertMinRegress != nil {
			if *in.AlertMinRegress < 0 || *in.AlertMinRegress > 1000 {
				regressJSON(w, 400, map[string]any{"error": "alert_min_regressions must be 0..1000"})
				return
			}
			c.AlertMinRegress = *in.AlertMinRegress
		}
		if in.AlertMediumAt != nil {
			if *in.AlertMediumAt < 0 || *in.AlertMediumAt > 1000 {
				regressJSON(w, 400, map[string]any{"error": "alert_medium_at must be 0..1000"})
				return
			}
			c.AlertMediumAt = *in.AlertMediumAt
		}
		if in.AlertOnBenignFP != nil {
			c.AlertOnBenignFP = *in.AlertOnBenignFP
		}
		s.setConfig(c)
		regressJSON(w, 200, c)
	})

	mux.HandleFunc("GET /v1/regression/gate", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		code, body := s.gate(r.URL.Query())
		regressJSON(w, code, body)
	})
	return s
}

func defStr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// gate evaluates the latest snapshot: 200 on pass, 412 on fail (or when there is nothing to judge).
func (s *regressSvc) gate(q map[string][]string) (int, map[string]any) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	type check struct {
		Name string  `json:"name"`
		Want float64 `json:"want"`
		Got  float64 `json:"got"`
		OK   bool    `json:"ok"`
	}
	var minDet, maxReg, maxFP *float64
	for k, dst := range map[string]**float64{"min_detected": &minDet, "max_regressions": &maxReg, "max_false_positives": &maxFP} {
		if v := get(k); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || (k == "min_detected" && f > 100) {
				return 400, map[string]any{"error": "invalid " + k, "pass": false}
			}
			*dst = &f
		}
	}
	all := s.snapshots()
	if len(all) == 0 {
		return 412, map[string]any{"pass": false, "reason": "no regression run recorded yet; POST /v1/regression/run first", "note": regressNote}
	}
	cur := all[len(all)-1]
	regs, newFP := 0, 0
	if len(all) > 1 {
		d := s.diffOf(all[len(all)-2], cur)
		regs, newFP = len(d.Regressions), len(d.NewBenignFP)
	}
	checks := []check{}
	pass := true
	add := func(c check) {
		checks = append(checks, c)
		pass = pass && c.OK
	}
	if minDet != nil {
		add(check{"min_detected_pct", *minDet, cur.MeasuredDetectedPct, cur.MeasuredDetectedPct >= *minDet})
	}
	if maxReg != nil {
		add(check{"max_regressions", *maxReg, float64(regs), float64(regs) <= *maxReg})
	}
	if maxFP != nil {
		add(check{"max_false_positives", *maxFP, float64(len(cur.BenignFP)), float64(len(cur.BenignFP)) <= *maxFP})
	}
	body := map[string]any{"pass": pass, "checks": checks, "snapshot_seq": cur.Seq, "snapshot_time": cur.Time,
		"measured_detected_pct": cur.MeasuredDetectedPct, "regressions": regs, "new_benign_false_positives": newFP,
		"benign_false_positives": len(cur.BenignFP), "truncated": cur.Truncated, "note": regressNote}
	if cur.Truncated {
		body["warning"] = "latest run hit its runtime bound; results are incomplete"
	}
	if pass {
		return 200, body
	}
	return 412, body
}
