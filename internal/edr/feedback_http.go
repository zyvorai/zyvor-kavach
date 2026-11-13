// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

// FeedbackRuleTrust, when set (RegisterFeedback does), returns an analyst-derived
// trust in a rule: the shrunk precision, only when the rule has at least the
// minimum number of decided verdicts. The priority score uses it in place of
// the noisiness-based trust and falls back to it otherwise.
type feedbackTrustFn func(rule string) (float64, bool)

var feedbackRuleTrust atomic.Pointer[feedbackTrustFn]

// setFeedbackRuleTrust installs fn (nil clears) and returns an owner-checked clear func.
func setFeedbackRuleTrust(fn feedbackTrustFn) (clear func()) {
	if fn == nil {
		feedbackRuleTrust.Store(nil)
		return func() {}
	}
	p := &fn
	feedbackRuleTrust.Store(p)
	return func() { feedbackRuleTrust.CompareAndSwap(p, nil) }
}

func (s *feedbackSvc) ruleTrust(rule string) (float64, bool) {
	labels := consolidate(s.snapshot())
	for _, r := range rulePrecisions(labels, feedbackMinVerdicts, feedbackReviewBelow) {
		if r.Rule == rule && r.Status == feedbackStatusOK {
			return *r.Shrunk, true
		}
	}
	return 0, false
}

func fbRedactHost(token, host string) string {
	h := sha256.Sum256([]byte("kavach-feedback|" + token + "|" + host))
	return "host-" + hex.EncodeToString(h[:6])
}

func fbIntParam(r *http.Request, name string, def, lo, hi int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil && v >= lo && v <= hi {
		return v
	}
	return def
}

func fbFloatParam(r *http.Request, name string, def float64) float64 {
	if v, err := strconv.ParseFloat(r.URL.Query().Get(name), 64); err == nil && v > 0 && v < 1 {
		return v
	}
	return def
}

type fbCount struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

func fbTopRules(m map[string]int, n int) []fbCount {
	out := []fbCount{}
	for k, v := range m {
		out = append(out, fbCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Rule < out[j].Rule
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// RegisterFeedback wires the analyst feedback loop. Recording needs auth; every
// other endpoint is a read. Nothing here edits rules, suppressions or hosts.
func RegisterFeedback(mux *http.ServeMux, token string, store *Store) *feedbackSvc {
	svc := newFeedbackSvc(store)
	store.OnClose(setFeedbackRuleTrust(svc.ruleTrust))

	mux.HandleFunc("POST /v1/feedback", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var in struct {
			FindingID string `json:"finding_id"`
			Verdict   string `json:"verdict"`
			Note      string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if !validVerdicts[in.Verdict] {
			http.Error(w, "verdict must be true_positive, false_positive, benign_expected or needs_more_data", 400)
			return
		}
		note := cleanText(in.Note, true)
		if len(note) > maxFeedbackNote {
			http.Error(w, "note too long", 400)
			return
		}
		var f *Finding
		for _, x := range store.List() {
			if x.ID == in.FindingID {
				x := x
				f = &x
				break
			}
		}
		if f == nil || in.FindingID == "" {
			http.Error(w, "unknown finding_id", 404)
			return
		}
		svc.mu.Lock()
		e, err := svc.appendLocked(FeedbackEntry{Time: time.Now(), FindingID: f.ID, Verdict: in.Verdict, Note: note,
			Actor: wsActor(admin), Rule: f.Rule, Host: f.Host, FindingTime: f.Time})
		svc.mu.Unlock()
		if err != nil {
			http.Error(w, "could not persist feedback", 500)
			return
		}
		wsJSON(w, 201, e)
	})

	mux.HandleFunc("GET /v1/feedback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		limit := fbIntParam(r, "limit", 100, 1, 1000)
		out := []FeedbackEntry{}
		all := svc.snapshot()
		for i := len(all) - 1; i >= 0 && len(out) < limit; i-- { // newest first
			e := all[i]
			if v := q.Get("finding_id"); v != "" && e.FindingID != v {
				continue
			}
			if v := q.Get("rule"); v != "" && e.Rule != v {
				continue
			}
			if v := q.Get("host"); v != "" && e.Host != v {
				continue
			}
			out = append(out, e)
		}
		wsJSON(w, 200, map[string]any{"entries": out})
	})

	mux.HandleFunc("GET /v1/feedback/verify", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		all := svc.snapshot()
		seq, why := verifyFeedbackChain(all)
		wsJSON(w, 200, map[string]any{"ok": seq == 0, "entries": len(all), "first_broken_seq": seq, "reason": why})
	})

	mux.HandleFunc("GET /v1/feedback/rules", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		minN := fbIntParam(r, "min_verdicts", feedbackMinVerdicts, 1, 1000)
		below := fbFloatParam(r, "review_below", feedbackReviewBelow)
		rules := rulePrecisions(consolidate(svc.snapshot()), minN, below)
		ranked, notEnough, review := []RulePrecision{}, []RulePrecision{}, []string{}
		for _, x := range rules {
			if x.Status == feedbackStatusOK {
				ranked = append(ranked, x)
				if x.Review {
					review = append(review, x.Rule)
				}
			} else {
				notEnough = append(notEnough, x)
			}
		}
		sort.Slice(ranked, func(i, j int) bool {
			if *ranked[i].Shrunk != *ranked[j].Shrunk {
				return *ranked[i].Shrunk > *ranked[j].Shrunk
			}
			return ranked[i].Rule < ranked[j].Rule
		})
		vol := append([]RulePrecision{}, rules...)
		sort.Slice(vol, func(i, j int) bool {
			if vol[i].Decided != vol[j].Decided {
				return vol[i].Decided > vol[j].Decided
			}
			return vol[i].Rule < vol[j].Rule
		})
		byVol := []fbCount{}
		for _, x := range vol {
			byVol = append(byVol, fbCount{x.Rule, x.Decided})
		}
		sort.Strings(review)
		wsJSON(w, 200, map[string]any{
			"method": map[string]any{
				"observed":       "true_positive / (true_positive + false_positive + benign_expected), one count per finding",
				"interval":       "Wilson score, 95%",
				"shrunk":         "posterior mean under Beta(1,1) prior: (k+1)/(n+2)",
				"min_verdicts":   minN,
				"review_below":   below,
				"review_meaning": "the whole 95% interval is below review_below; a prompt for a human to look, never an action",
			},
			"ranked_by_shrunk_precision": ranked,
			"not_enough_verdicts":        notEnough,
			"ranked_by_verdict_volume":   byVol,
			"review_candidates":          review,
			"advisory_only":              true,
		})
	})

	mux.HandleFunc("GET /v1/feedback/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		days := fbIntParam(r, "days", 7, 1, 365)
		entries := svc.snapshot()
		labels := consolidate(entries)
		counts := map[string]int{VerdictTruePositive: 0, VerdictFalsePositive: 0, VerdictBenignExpected: 0, VerdictNeedsMoreData: 0}
		for _, e := range entries { // raw entries, including superseded ones
			counts[e.Verdict]++
		}
		latest := map[string]int{VerdictTruePositive: 0, VerdictFalsePositive: 0, VerdictBenignExpected: 0, VerdictNeedsMoreData: 0}
		fp, tp := map[string]int{}, map[string]int{}
		var lagSum float64
		var lagN int
		for _, l := range labels {
			for _, v := range l.Verdicts {
				latest[v]++
			}
			switch l.Label {
			case "negative":
				fp[l.Rule]++
			case "positive":
				tp[l.Rule]++
			}
			if d := l.FirstVerdict.Sub(l.FindingTime).Seconds(); d >= 0 {
				lagSum += d
				lagN++
			}
		}
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		recent, covered := 0, 0
		for _, f := range store.List() {
			if f.Time.After(cutoff) {
				recent++
				if _, ok := labels[f.ID]; ok {
					covered++
				}
			}
		}
		out := map[string]any{
			"entries_total":            len(entries),
			"findings_with_verdict":    len(labels),
			"counts_all_entries":       counts,
			"counts_latest_per_actor":  latest,
			"recent_days":              days,
			"recent_findings":          recent,
			"recent_findings_covered":  covered,
			"top_false_positive_rules": fbTopRules(fp, 5),
			"top_true_positive_rules":  fbTopRules(tp, 5),
			"note":                     "coverage is the share of recent findings with any verdict; analysts label a biased subset, so rates are not fleet-wide precision",
		}
		if recent > 0 {
			out["verdict_coverage"] = float64(covered) / float64(recent)
		} else {
			out["verdict_coverage"] = nil
		}
		if lagN > 0 {
			out["mean_seconds_to_first_verdict"] = lagSum / float64(lagN)
		} else {
			out["mean_seconds_to_first_verdict"] = nil
		}
		wsJSON(w, 200, out)
	})

	// POST because it produces a bulk artefact; it changes no state.
	mux.HandleFunc("POST /v1/feedback/export", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		redact := r.URL.Query().Get("redact") == "1"
		entries := svc.snapshot()
		labels := consolidate(entries)
		if redact {
			for i := range entries {
				entries[i].Host = fbRedactHost(token, entries[i].Host)
				entries[i].Note = ""
			}
			for _, l := range labels {
				l.Host = fbRedactHost(token, l.Host)
			}
		}
		ls := make([]*FindingLabel, 0, len(labels))
		for _, l := range labels {
			ls = append(ls, l)
		}
		sort.Slice(ls, func(i, j int) bool { return ls[i].FindingID < ls[j].FindingID })
		seq, _ := verifyFeedbackChain(svc.snapshot())
		w.Header().Set("Content-Disposition", `attachment; filename="kavach-feedback-labels.json"`)
		wsJSON(w, 200, map[string]any{
			"generated":  time.Now().UTC(),
			"redacted":   redact,
			"chain_ok":   seq == 0,
			"label_rule": "positive = true_positive; negative = false_positive or benign_expected; needs_more_data abstains; ties are contested",
			"labels":     ls,
			"entries":    entries,
			"caveat":     "analyst labels are noisy and cover a biased subset of findings",
		})
	})
	return svc
}
