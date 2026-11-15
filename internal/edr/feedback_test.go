// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func fbEntries(rule string, k, n int) []FeedbackEntry {
	var es []FeedbackEntry
	for i := 0; i < n; i++ {
		v := VerdictFalsePositive
		if i < k {
			v = VerdictTruePositive
		}
		es = append(es, FeedbackEntry{FindingID: fmt.Sprintf("%s-%d", rule, i), Verdict: v, Actor: "admin", Rule: rule, Time: time.Now()})
	}
	return es
}

func TestFeedbackHTTPFlow(t *testing.T) {
	srv, store, tok := obsServer(t)
	now := time.Now().UTC()
	for i, rule := range []string{"r1", "r1", "r2"} {
		if err := store.Append(Finding{ID: fmt.Sprintf("f%d", i), Time: now.Add(-time.Minute), Host: "h" + rule, Rule: rule, Severity: "high"}); err != nil {
			t.Fatal(err)
		}
	}
	post := func(tk, body string) (int, string) { return wsDo(t, "POST", srv.URL+"/v1/feedback", tk, body) }
	if c, _ := post("", `{}`); c != 401 {
		t.Fatal(c)
	}
	for _, p := range []string{"/v1/feedback", "/v1/feedback/rules", "/v1/feedback/summary", "/v1/feedback/verify"} {
		if c, _ := wsDo(t, "GET", srv.URL+p, "", ""); c != 401 {
			t.Fatal(p, c)
		}
	}
	if c, _ := wsDo(t, "POST", srv.URL+"/v1/feedback/export", "", ""); c != 401 {
		t.Fatal(c)
	}
	if c, _ := post(tok, `{"finding_id":"f0","verdict":"bogus"}`); c != 400 {
		t.Fatal(c)
	}
	if c, _ := post(tok, `{"finding_id":"nope","verdict":"true_positive"}`); c != 404 {
		t.Fatal(c)
	}
	c, body := post(tok, `{"finding_id":"f0","verdict":"false_positive","note":"<b>scanner</b>"}`)
	if c != 201 || strings.Contains(body, "<b>") || !strings.Contains(body, `"actor":"admin"`) || !strings.Contains(body, `"rule":"r1"`) {
		t.Fatal(c, body)
	}
	// retraction is a new verdict; the old one stays in the log
	post(tok, `{"finding_id":"f0","verdict":"true_positive"}`)
	_, body = wsDo(t, "GET", srv.URL+"/v1/feedback?finding_id=f0", tok, "")
	var list struct{ Entries []FeedbackEntry }
	_ = json.Unmarshal([]byte(body), &list)
	if len(list.Entries) != 2 || list.Entries[0].Verdict != VerdictTruePositive || list.Entries[1].Verdict != VerdictFalsePositive {
		t.Fatalf("%+v", list.Entries)
	}
	_, body = wsDo(t, "GET", srv.URL+"/v1/feedback?host=hr2", tok, "")
	if !strings.Contains(body, `"entries":[]`) {
		t.Fatal(body)
	}
	post(tok, `{"finding_id":"f2","verdict":"needs_more_data"}`)
	_, body = wsDo(t, "GET", srv.URL+"/v1/feedback/summary", tok, "")
	var sum map[string]any
	_ = json.Unmarshal([]byte(body), &sum)
	if sum["findings_with_verdict"].(float64) != 2 || sum["recent_findings"].(float64) != 3 || math.Abs(sum["verdict_coverage"].(float64)-2.0/3) > 1e-9 {
		t.Fatal(body)
	}
	if sum["mean_seconds_to_first_verdict"] == nil {
		t.Fatal(body)
	}
	// 2 decided findings for r1 at most: below the minimum, so no point estimate
	_, body = wsDo(t, "GET", srv.URL+"/v1/feedback/rules", tok, "")
	if !strings.Contains(body, "not_enough_verdicts") || strings.Contains(body, "observed_precision") {
		t.Fatal(body)
	}
	_, body = wsDo(t, "POST", srv.URL+"/v1/feedback/export?redact=1", tok, "")
	if strings.Contains(body, "hr1") || strings.Contains(body, "scanner") || !strings.Contains(body, "host-") {
		t.Fatal(body)
	}
	_, body = wsDo(t, "POST", srv.URL+"/v1/feedback/export", tok, "")
	if !strings.Contains(body, "hr1") {
		t.Fatal(body)
	}
	_, body = wsDo(t, "GET", srv.URL+"/v1/feedback/verify", tok, "")
	if !strings.Contains(body, `"ok":true`) {
		t.Fatal(body)
	}
	// persistence
	if n := len(newFeedbackSvc(store).data.Entries); n != 3 {
		t.Fatal(n)
	}
}

func TestFeedbackChainTamperDetection(t *testing.T) {
	s := &feedbackSvc{path: t.TempDir() + "/fb.json"}
	for _, e := range fbEntries("r", 3, 6) {
		if _, err := s.appendLocked(e); err != nil {
			t.Fatal(err)
		}
	}
	if seq, _ := verifyFeedbackChain(s.data.Entries); seq != 0 {
		t.Fatal(seq)
	}
	mut := func(f func(es []FeedbackEntry)) int {
		es := s.snapshot()
		f(es)
		seq, _ := verifyFeedbackChain(es)
		return seq
	}
	if mut(func(es []FeedbackEntry) { es[2].Verdict = VerdictTruePositive; es[2].Note = "x" }) != 3 {
		t.Fatal("edit not detected")
	}
	if mut(func(es []FeedbackEntry) { es[1].Rule = "other" }) != 2 {
		t.Fatal("rule edit not detected")
	}
	if mut(func(es []FeedbackEntry) { es[3], es[4] = es[4], es[3] }) == 0 {
		t.Fatal("reorder not detected")
	}
	es := s.snapshot()
	if seq, _ := verifyFeedbackChain(append(es[:2:2], es[3:]...)); seq == 0 {
		t.Fatal("deletion not detected")
	}
	// a recomputed hash on a mid entry still breaks the next link
	if mut(func(es []FeedbackEntry) { es[2].Verdict = VerdictFalsePositive; es[2].Hash = feedbackHash(es[2]) }) == 0 {
		t.Fatal("rehash not detected")
	}
	// append-only: append never changes earlier entries
	before := s.snapshot()
	_, _ = s.appendLocked(FeedbackEntry{FindingID: "z", Verdict: VerdictNeedsMoreData, Actor: "admin", Rule: "r"})
	after := s.snapshot()
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("earlier entry changed")
		}
	}
}

func TestFeedbackLatestPerActorAndConsensus(t *testing.T) {
	es := []FeedbackEntry{
		{FindingID: "a", Verdict: VerdictFalsePositive, Actor: "admin", Rule: "r"},
		{FindingID: "a", Verdict: VerdictTruePositive, Actor: "admin", Rule: "r"}, // supersedes
		{FindingID: "b", Verdict: VerdictTruePositive, Actor: "admin", Rule: "r"},
		{FindingID: "b", Verdict: VerdictBenignExpected, Actor: "session", Rule: "r"}, // tie
		{FindingID: "c", Verdict: VerdictNeedsMoreData, Actor: "admin", Rule: "r"},
		{FindingID: "d", Verdict: VerdictTruePositive, Actor: "admin", Rule: "r"},
		{FindingID: "d", Verdict: VerdictNeedsMoreData, Actor: "admin", Rule: "r"}, // retraction
	}
	l := consolidate(es)
	want := map[string]string{"a": "positive", "b": "contested", "c": "undecided", "d": "undecided"}
	for k, v := range want {
		if l[k].Label != v {
			t.Fatalf("%s: %s want %s", k, l[k].Label, v)
		}
	}
}

func TestFeedbackNotEnoughVerdicts(t *testing.T) {
	for n := 0; n < feedbackMinVerdicts; n++ {
		r := rulePrecisions(consolidate(fbEntries("r", 0, n)), feedbackMinVerdicts, feedbackReviewBelow)
		for _, x := range r {
			if x.Status != feedbackStatusTooFew || x.Observed != nil || x.Shrunk != nil || x.Review {
				t.Fatalf("n=%d %+v", n, x)
			}
		}
	}
	r := rulePrecisions(consolidate(fbEntries("r", 5, 5)), 5, 0.25)
	if r[0].Status != "ok" || *r[0].Observed != 1 || *r[0].Shrunk >= 1 {
		t.Fatalf("%+v", r[0])
	}
	if lo, hi := wilson95(0, 0); lo != 0 || hi != 1 {
		t.Fatal(lo, hi)
	}
}

// Synthetic evaluation. Labels are drawn from a known precision with no analyst
// noise, so these numbers are optimistic; see docs/research-feedback.md.
func TestFeedbackEvalWilsonCoverage(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	const trials = 20000
	for _, n := range []int{10, 30, 100} {
		var sum float64
		for _, p := range []float64{0.95, 0.5, 0.1} {
			cov := 0
			for i := 0; i < trials; i++ {
				k := 0
				for j := 0; j < n; j++ {
					if rng.Float64() < p {
						k++
					}
				}
				if lo, hi := wilson95(k, n); lo <= p && p <= hi {
					cov++
				}
			}
			c := float64(cov) / trials
			sum += c
			t.Logf("EVAL wilson coverage n=%d p=%.2f: %.4f", n, p, c)
			if c < 0.90 || c > 0.99 {
				t.Fatalf("coverage %v out of range n=%d p=%v", c, n, p)
			}
		}
		if mean := sum / 3; n >= 30 && (mean < 0.935 || mean > 0.97) {
			t.Fatalf("mean coverage %v n=%d", mean, n)
		}
	}
}

func TestFeedbackEvalShrinkageVsRaw(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	const trials = 20000
	ps := []float64{0.95, 0.5, 0.1}
	for _, n := range []int{5, 10, 30} {
		var rawAll, shrAll float64
		for _, p := range ps {
			var raw, shr float64
			for i := 0; i < trials; i++ {
				k := 0
				for j := 0; j < n; j++ {
					if rng.Float64() < p {
						k++
					}
				}
				d := float64(k)/float64(n) - p
				raw += d * d
				e := shrunkPrecision(k, n) - p
				shr += e * e
			}
			raw, shr = raw/trials, shr/trials
			rawAll += raw
			shrAll += shr
			t.Logf("EVAL mse n=%d p=%.2f raw=%.4f shrunk=%.4f", n, p, raw, shr)
		}
		t.Logf("EVAL mse n=%d mean over rules raw=%.4f shrunk=%.4f", n, rawAll/3, shrAll/3)
		if n <= 10 && shrAll >= rawAll {
			t.Fatalf("shrinkage did not beat raw on average at n=%d", n)
		}
	}
}

func TestFeedbackEvalReviewFlagging(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	const trials = 20000
	for _, c := range []struct {
		p       float64
		n       int
		maxRate float64 // required upper bound for good rules; -1 = report only
	}{{0.95, 10, 0.001}, {0.95, 30, 0.001}, {0.5, 20, 0.02}, {0.5, 40, 0.01}, {0.1, 10, -1}, {0.1, 20, -1}, {0.1, 40, -1}} {
		flags := 0
		for i := 0; i < trials; i++ {
			k := 0
			for j := 0; j < c.n; j++ {
				if rng.Float64() < c.p {
					k++
				}
			}
			if _, hi := wilson95(k, c.n); hi < feedbackReviewBelow {
				flags++
			}
		}
		rate := float64(flags) / trials
		t.Logf("EVAL review-flag rate p=%.2f n=%d: %.4f", c.p, c.n, rate)
		if c.maxRate >= 0 && rate > c.maxRate {
			t.Fatalf("false flag rate %v for p=%v n=%v", rate, c.p, c.n)
		}
	}
}
