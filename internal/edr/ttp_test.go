// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestTTPModelBuilt(t *testing.T) {
	if ttpDefault == nil || ttpDefault.n < 100 {
		t.Fatalf("model not built: %+v", ttpDefault)
	}
	if ttpParent("T1059.001") != "T1059" || ttpParent("T1003") != "T1003" {
		t.Fatal("roll-up")
	}
	if ttpDefault.idf["T1059"] >= ttpDefault.idf["T1486"] {
		t.Fatal("commodity technique must weigh less than a rarer one")
	}
	if !ttpDefault.isCommodity("T1059") || ttpDefault.isCommodity("T1486") {
		t.Fatal("commodity classification")
	}
}

func TestTTPNotEnoughEvidence(t *testing.T) {
	m := ttpDefault
	for _, ids := range [][]string{{}, {"T1059"}, {"T1059", "T1105"}, {"T1059.001", "T1059.003", "T1105"}} {
		set := ttpSet(ids)
		if len(set) >= ttpMinTechniques {
			continue
		}
		conf, _, matches := ttpSimilar(m, set, 5)
		if conf != "not_enough_evidence" || len(matches) != 0 {
			t.Fatalf("%v: %s %v", ids, conf, matches)
		}
	}
	// Three commodity-only techniques rank but never above low.
	conf, _, _ := ttpSimilar(m, ttpSet([]string{"T1059", "T1105", "T1566"}), 5)
	if conf != "low" {
		t.Fatalf("commodity-only confidence %s", conf)
	}
}

func TestTTPEndpoints(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now()
	_ = s.Append(Finding{ID: "a1", Time: now.Add(-3 * time.Minute), Host: "h1", Rule: "download-execute", Severity: "high"})
	_ = s.Append(Finding{ID: "a2", Time: now.Add(-2 * time.Minute), Host: "h1", Rule: "shell-network-redirection", Severity: "high"})
	_ = s.Append(Finding{ID: "a3", Time: now.Add(-1 * time.Minute), Host: "h1", Rule: "ransomware-burst", Severity: "high"})
	if r, _ := get(t, srv.URL+"/v1/ttp/similar?host=h1", ""); r.StatusCode != 401 {
		t.Fatal("must require auth")
	}
	for _, u := range []string{"/v1/ttp/similar?techniques=T1059,T1003,T1021,T1486", "/v1/ttp/similar?host=h1", "/v1/ttp/next?techniques=T1566,T1059,T1003", "/v1/ttp/chains?host=h1"} {
		r, body := get(t, srv.URL+u, tok)
		if r.StatusCode != 200 {
			t.Fatalf("%s: %d %s", u, r.StatusCode, body)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		if c, _ := m["caveats"].([]any); len(c) < 4 {
			t.Fatalf("%s: caveats missing", u)
		}
		if strings.Contains(strings.ToLower(body), "attributed"+" to") {
			t.Fatalf("%s: forbidden phrase", u)
		}
	}
	_, body := get(t, srv.URL+"/v1/ttp/similar?techniques=T1059,T1105", tok)
	if !strings.Contains(body, `"not_enough_evidence"`) {
		t.Fatalf("expected not_enough_evidence: %s", body)
	}
	_, body = get(t, srv.URL+"/v1/ttp/chains?host=h1", tok)
	var ch struct {
		Sequence []struct{ Technique string }
		Earliest string   `json:"earliest_tactic"`
		Latest   string   `json:"latest_tactic"`
		Gaps     []ttpGap `json:"gaps_worth_hunting"`
	}
	if err := json.Unmarshal([]byte(body), &ch); err != nil {
		t.Fatal(err)
	}
	if len(ch.Sequence) != 3 || ch.Sequence[0].Technique != "T1204.002" || ch.Earliest != "Execution" || ch.Latest != "Impact" || len(ch.Gaps) == 0 {
		t.Fatalf("chain: %s", body)
	}
	if r, _ := get(t, srv.URL+"/v1/ttp/similar?techniques=bogus", tok); r.StatusCode != 400 {
		t.Fatal("bad technique id must be 400")
	}
	if r, _ := get(t, srv.URL+"/v1/ttp/similar", tok); r.StatusCode != 400 {
		t.Fatal("missing input must be 400")
	}
}

func TestTTPNextHints(t *testing.T) {
	hints := ttpNext(ttpDefault, ttpSet([]string{"T1566", "T1059", "T1003"}), 12)
	if len(hints) == 0 {
		t.Fatal("no hints")
	}
	prev := -1
	for _, h := range hints {
		r := ttpTacticRank(h.Tactic)
		if r < prev {
			t.Fatalf("hints not in kill-chain order: %+v", hints)
		}
		prev = r
		if h.Technique == "T1566" || h.Technique == "T1059" || h.Technique == "T1003" {
			t.Fatal("observed technique suggested")
		}
	}
}

// ttpEvalHoldout removes 30-50% of each profile's parent techniques, queries with the rest and records the
// rank of the true profile (ties count against it). The profiles are both training and test data.
func ttpEvalHoldout(m *ttpModel, seed int64, trials int) (n, top1, top3, top5 int, confusion map[string]int, conf map[string]int) {
	rng := rand.New(rand.NewSource(seed))
	confusion = map[string]int{}
	conf = map[string]int{}
	for _, p := range m.profiles {
		ts := sortedKeysSet(p.Techs)
		if len(ts) < 6 {
			continue
		}
		for k := 0; k < trials; k++ {
			rng.Shuffle(len(ts), func(i, j int) { ts[i], ts[j] = ts[j], ts[i] })
			frac := 0.3 + 0.2*rng.Float64()
			drop := int(float64(len(ts))*frac + 0.5)
			keep := ts[drop:]
			if len(keep) < ttpMinTechniques {
				continue
			}
			obs := ttpSet(keep)
			ranked := m.rank(obs)
			var truth float64
			for _, s := range ranked {
				if s.P == p {
					truth = s.Score
				}
			}
			rank := 0
			for _, s := range ranked {
				if s.Score >= truth {
					rank++
				}
			}
			n++
			if rank <= 1 {
				top1++
			} else {
				confusion[p.ID+" -> "+ranked[0].P.ID]++
			}
			if rank <= 3 {
				top3++
			}
			if rank <= 5 {
				top5++
			}
			c, _ := m.confidence(obs, ranked)
			conf[c]++
			if rank <= 1 {
				conf[c+"_top1_correct"]++
			}
		}
	}
	return
}

func sortedKeysSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTTPEvaluation(t *testing.T) {
	m := ttpDefault
	n, t1, t3, t5, confusion, conf := ttpEvalHoldout(m, 42, 20)
	pct := func(x int) string { return fmt.Sprintf("%.1f%%", 100*float64(x)/float64(n)) }
	t.Logf("HOLDOUT seed=42 queries=%d profiles=%d top1=%s top3=%s top5=%s confidence=%v", n, m.n, pct(t1), pct(t3), pct(t5), conf)
	type kv struct {
		k string
		v int
	}
	var cf []kv
	for k, v := range confusion {
		cf = append(cf, kv{k, v})
	}
	sort.Slice(cf, func(i, j int) bool {
		if cf[i].v != cf[j].v {
			return cf[i].v > cf[j].v
		}
		return cf[i].k < cf[j].k
	})
	for i := 0; i < len(cf) && i < 12; i++ {
		t.Logf("CONFUSION %s x%d", cf[i].k, cf[i].v)
	}
	if n < 500 || float64(t5)/float64(n) < 0.5 {
		t.Fatalf("model regressed: n=%d top5=%d", n, t5)
	}

	// Negatives: random technique sets (uniform over the technique vocabulary).
	rng := rand.New(rand.NewSource(7))
	var vocab []string
	for k := range m.df {
		vocab = append(vocab, k)
	}
	sort.Strings(vocab)
	moderate, lowOverlap, total := 0, 0, 0
	var topScores []float64
	for i := 0; i < 500; i++ {
		k := 3 + rng.Intn(6)
		set := map[string]struct{}{}
		for len(set) < k {
			set[vocab[rng.Intn(len(vocab))]] = struct{}{}
		}
		r := m.rank(set)
		c, _ := m.confidence(set, r)
		total++
		if c == "moderate" {
			moderate++
		}
		if len(r[0].Overlap) <= 2 {
			lowOverlap++
		}
		topScores = append(topScores, r[0].Score)
	}
	sort.Float64s(topScores)
	t.Logf("RANDOM uniform sets=%d moderate=%d top_overlap<=2: %d median_top_score=%.3f p95=%.3f", total, moderate, lowOverlap, topScores[len(topScores)/2], topScores[len(topScores)*95/100])

	// Commodity-only sets.
	for _, ids := range [][]string{{"T1059", "T1105"}, {"T1059"}, {"T1059", "T1105", "T1566"}, {"T1059", "T1105", "T1204", "T1078"}} {
		set := ttpSet(ids)
		r := m.rank(set)
		c, _ := m.confidence(set, r)
		t.Logf("COMMODITY %v confidence=%s top_score=%.3f top=%s", ids, c, r[0].Score, r[0].P.ID)
		if len(set) < 3 && c != "not_enough_evidence" {
			t.Fatalf("%v: %s", ids, c)
		}
		if c == "moderate" {
			t.Fatalf("%v must not be moderate", ids)
		}
	}
}
