// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func registerMLExtHTTP(mux *http.ServeMux, token string, store *Store, eng *mlExtEngine) {
	limitOf := func(r *http.Request, def, max int) int {
		if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
			if v > max {
				return max
			}
			return v
		}
		return def
	}
	q := func(r *http.Request, k string) string { return strings.TrimSpace(r.URL.Query().Get(k)) }
	mux.HandleFunc("GET /v1/ml/dns", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, eng.dnsView(q(r, "host"), limitOf(r, 20, 200)))
	})
	mux.HandleFunc("GET /v1/ml/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, eng.userView(q(r, "user"), limitOf(r, 20, 200)))
	})
	mux.HandleFunc("GET /v1/ml/peers", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, eng.peerView(q(r, "host"), limitOf(r, 20, 200)))
	})
	mux.HandleFunc("GET /v1/ml/fatigue", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rows := buildFatigue(store.List(), time.Now(), feedbackPrecisionByRule())
		res := map[string]any{"method": mlMethod, "model": "alert-fatigue-v1", "mode": "observe-only",
			"min_hits_30d": mlFatMinHits30d, "retune_score_threshold": mlFatRetuneScore, "min_verdicts": mlFatMinVerdicts,
			"note": "Advisory: suggests rules to review; changes nothing. Feedback verdicts are a labelled subset chosen by analysts, not fleet precision."}
		weights := map[string]float64{}
		for _, w := range mlFatWeights {
			weights[w.Name] = w.Weight
		}
		res["weights"] = weights
		ready, cands := 0, 0
		for _, x := range rows {
			if x.Status == "ok" {
				ready++
			}
			if x.Retune {
				cands++
			}
		}
		res["rules_evaluated"], res["rules_with_enough_data"], res["retune_candidates"] = len(rows), ready, cands
		if ready == 0 {
			res["status"] = "not_enough_data"
		} else {
			res["status"] = "ok"
		}
		if rule := q(r, "rule"); rule != "" {
			for _, x := range rows {
				if x.Rule == rule {
					res["rule"] = x
					writeJSON(w, res)
					return
				}
			}
			customJSON(w, 404, map[string]any{"error": "rule has no findings"})
			return
		}
		if r.URL.Query().Get("candidates") == "1" {
			f := rows[:0:0]
			for _, x := range rows {
				if x.Retune {
					f = append(f, x)
				}
			}
			rows = f
		}
		if lim := limitOf(r, 25, 200); len(rows) > lim {
			rows = rows[:lim]
		}
		res["rules"] = rows
		writeJSON(w, res)
	})
}
