// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func mlRound(f float64, d int) float64 {
	p := math.Pow(10, float64(d))
	return math.Round(f*p) / p
}

type mlTransition struct {
	Parent        string  `json:"parent"`
	Child         string  `json:"child"`
	Count         int     `json:"count"`
	Surprisal     float64 `json:"surprisal_bits"`
	FleetSurprise float64 `json:"fleet_surprisal_bits"`
	Novel         bool    `json:"novel"`
	ParentSeen    bool    `json:"parent_seen"`
}

// lineage returns the ranked transitions for a scope ("" = fleet).
func (e *mlEngine) lineage(host string, limit int) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	scope, min := e.st.Fleet, mlMinLineageFleet
	name := "fleet"
	if host != "" {
		name = "host"
		scope = e.st.Hosts[host]
	}
	res := map[string]any{"method": mlMethod, "scope": name, "host": host, "min_samples": min,
		"surprisal_threshold_bits": mlSurprisalBits, "smoothing": mlSmoothing}
	if host != "" {
		res["min_samples"] = mlMinLineageHost
		min = mlMinLineageHost
	}
	n := 0
	if scope != nil {
		n = scope.Total
	}
	res["sample_count"] = n
	res["fleet_sample_count"] = e.st.Fleet.Total
	if scope == nil || n < min {
		res["status"] = "not_enough_data"
		res["transitions"] = []mlTransition{}
		return res
	}
	vs, vf := mlVocab(scope), mlVocab(e.st.Fleet)
	var out []mlTransition
	for p, row := range scope.P {
		for c, cnt := range row {
			b, _, _ := mlSurprisal(scope, p, c, vs)
			fb, _, ps := mlSurprisal(e.st.Fleet, p, c, vf)
			out = append(out, mlTransition{Parent: p, Child: c, Count: cnt, Surprisal: mlRound(b, 2), FleetSurprise: mlRound(fb, 2), Novel: b >= mlSurprisalBits, ParentSeen: ps})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Surprisal != out[j].Surprisal {
			return out[i].Surprisal > out[j].Surprisal
		}
		if out[i].Parent != out[j].Parent {
			return out[i].Parent < out[j].Parent
		}
		return out[i].Child < out[j].Child
	})
	if len(out) > limit {
		out = out[:limit]
	}
	res["status"] = "ok"
	res["transitions"] = out
	return res
}

func (e *mlEngine) similar(q, host string) map[string]any {
	qv := mlFeaturize(q, 0)
	nb := mlNearestExemplars(qv, 5)
	res := map[string]any{"method": mlMethod, "ngram": "char 3-5, feature hashing 2^14, cosine", "threshold": mlSimThreshold,
		"exemplar_count": len(mlExemplars), "exemplar_neighbours": nb}
	best := 0.0
	if len(nb) > 0 {
		best = nb[0].Similarity
	}
	res["similar_to_known_bad"] = best >= mlSimThreshold
	if host == "" {
		res["history"] = map[string]any{"status": "not_requested", "note": "pass host= to compare with that host's own history"}
		return res
	}
	e.mu.Lock()
	h := e.st.Hist[host]
	var sims []float64
	n := 0
	if h != nil {
		n = len(h.Vecs)
		for _, v := range h.Vecs {
			sims = append(sims, mlCosine(qv, v))
		}
	}
	seen := 0
	if h != nil {
		seen = h.Seen
	}
	e.mu.Unlock()
	hist := map[string]any{"host": host, "sample_count": n, "commands_seen": seen, "min_samples": mlHistMin}
	if n < mlHistMin {
		hist["status"] = "not_enough_data"
	} else {
		sort.Sort(sort.Reverse(sort.Float64Slice(sims)))
		top := sims
		if len(top) > 3 {
			top = top[:3]
		}
		for i := range top {
			top[i] = mlRound(top[i], 3)
		}
		hist["status"] = "ok"
		hist["nearest_similarities"] = top
		hist["familiar"] = top[0] >= 0.9
	}
	res["history"] = hist
	return res
}

func (e *mlEngine) status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	maxHist := 0
	for _, h := range e.st.Hist {
		if len(h.Vecs) > maxHist {
			maxHist = len(h.Vecs)
		}
	}
	baseHosts, readyHosts := 0, 0
	for _, hb := range e.st.Base {
		baseHosts++
		for _, m := range hb.M {
			if m.Closed >= mlMinHostHours {
				readyHosts++
				break
			}
		}
	}
	return map[string]any{
		"method":         mlMethod,
		"learned_events": e.st.Learned,
		"updated":        e.st.Updated,
		"models": map[string]any{
			"lineage": map[string]any{"sample_count": e.st.Fleet.Total, "hosts": len(e.st.Hosts), "edges": e.st.Fleet.Edges,
				"min_samples_fleet": mlMinLineageFleet, "min_samples_host": mlMinLineageHost, "ready": e.st.Fleet.Total >= mlMinLineageFleet,
				"status": mlReady(e.st.Fleet.Total >= mlMinLineageFleet)},
			"command_similarity": map[string]any{"exemplar_count": len(mlExemplars), "history_hosts": len(e.st.Hist),
				"largest_history": maxHist, "min_history": mlHistMin, "ready": len(mlExemplars) > 0, "status": mlReady(len(mlExemplars) > 0)},
			"baselines": map[string]any{"hosts": baseHosts, "hosts_ready": readyHosts, "min_closed_hours": mlMinHostHours,
				"min_slot_samples": mlMinSlotN, "ready": readyHosts > 0, "status": mlReady(readyHosts > 0)},
		},
	}
}

func mlReady(ok bool) string {
	if ok {
		return "ok"
	}
	return "not_enough_data"
}

func (e *mlEngine) baseline(host string, store *Store, now time.Time) map[string]any {
	res := map[string]any{"method": mlMethod, "host": host, "z_threshold": mlZThreshold,
		"min_closed_hours": mlMinHostHours, "min_slot_samples": mlMinSlotN, "ewma_alpha": mlAlpha}
	e.mu.Lock()
	hb := e.st.Base[host]
	slot := mlSlotOf(now.Unix() / 3600)
	metrics := map[string]any{}
	if hb != nil {
		for _, name := range mlMetrics {
			m := hb.M[name]
			if m == nil {
				continue
			}
			s := m.Slots[slot]
			row := map[string]any{"closed_hours": m.Closed, "slot_samples": s.N, "slot": slot, "anomalous_hours": m.Anomalies,
				"slot_mean": mlRound(s.Mean, 2), "slot_sd": mlRound(mlSD(s), 2)}
			if m.Closed < mlMinHostHours || s.N < mlMinSlotN {
				row["status"] = "not_enough_data"
			} else {
				row["status"] = "ok"
			}
			if m.LastHour != 0 || m.Closed > 0 {
				lz := map[string]any{"hour_start": time.Unix(m.LastHour*3600, 0).UTC(), "count": m.LastCount}
				if m.LastZOK {
					lz["z"] = mlRound(m.LastZ, 2)
					lz["anomalous"] = m.LastZ >= mlZThreshold
				} else {
					lz["status"] = "not_enough_data"
				}
				row["last_closed_hour"] = lz
			}
			if m.OpenHas {
				open := map[string]any{"hour_start": time.Unix(m.OpenHour*3600, 0).UTC(), "count": m.OpenCount, "partial": true}
				if z, ok := mlZ(m, mlSlotOf(m.OpenHour), m.OpenCount); ok {
					open["z"] = mlRound(z, 2)
				} else {
					open["status"] = "not_enough_data"
				}
				row["open_hour"] = open
			}
			metrics[name] = row
		}
	}
	e.mu.Unlock()
	res["metrics"] = metrics
	if hb == nil {
		res["status"] = "not_enough_data"
	} else {
		res["status"] = "ok"
	}
	// First-seen data reused from the prevalence graph (executables / destinations new in the last 24h).
	if store != nil {
		exes, dests := prevFirstSeen(prevTake(store), host, now.Add(-24*time.Hour))
		clip := func(v []prevFirst) []prevFirst {
			if len(v) > 5 {
				return v[:5]
			}
			return v
		}
		res["first_seen_24h"] = map[string]any{"new_executables": len(exes), "new_destinations": len(dests),
			"top_new_executables": clip(exes), "top_new_destinations": clip(dests), "source": "prevalence_graph"}
	}
	return res
}

// RegisterMLBehaviour wires the fleet-learned local behaviour models and starts the incremental learner.
func RegisterMLBehaviour(mux *http.ServeMux, token string, store *Store) {
	eng := newMLEngine(store)
	go eng.run()
	MLRarityProvider = eng.rarity // feeds the lineage model into /v1/ml/priority
	mux.HandleFunc("GET /v1/ml/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, eng.status())
	})
	mux.HandleFunc("GET /v1/ml/lineage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		limit := 20
		if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
			limit = v
		}
		if limit > 100 {
			limit = 100
		}
		writeJSON(w, eng.lineage(strings.TrimSpace(r.URL.Query().Get("host")), limit))
	})
	mux.HandleFunc("GET /v1/ml/similar", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" || len(q) > mlMaxQuery {
			http.Error(w, "q (a command line, 1-2048 bytes) is required", http.StatusBadRequest)
			return
		}
		writeJSON(w, eng.similar(q, strings.TrimSpace(r.URL.Query().Get("host"))))
	})
	mux.HandleFunc("GET /v1/ml/baseline", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host is required", http.StatusBadRequest)
			return
		}
		writeJSON(w, eng.baseline(host, store, time.Now().UTC()))
	})
	mux.HandleFunc("POST /v1/ml/reset", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		eng.reset()
		writeJSON(w, map[string]any{"method": mlMethod, "status": "reset"})
	})
	mux.HandleFunc("POST /v1/ml/learn/replay", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		n := eng.replay()
		writeJSON(w, map[string]any{"method": mlMethod, "status": "replayed", "events_replayed": n, "source": "retained store"})
	})
}
