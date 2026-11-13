// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

var beaconT0 = time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)

func secs(x float64) time.Duration { return time.Duration(x * float64(time.Second)) }

// Synthetic fixtures. All deterministic (seeded).
func fixFixed(r *rand.Rand, n int) []time.Time {
	p := []float64{30, 60, 300, 900}[r.Intn(4)]
	t := beaconT0
	out := []time.Time{}
	for i := 0; i < n; i++ {
		out = append(out, t.Add(secs(r.NormFloat64()*0.3))) // ~0.3s clock/network noise
		t = t.Add(secs(p))
	}
	return out
}

// jittered: period P, each sleep uniform in P*(1-j)..P*(1+j).
func fixJitter(r *rand.Rand, n int, j float64) []time.Time {
	p := []float64{60, 300, 600}[r.Intn(3)]
	t := beaconT0
	out := []time.Time{t}
	for i := 1; i < n; i++ {
		t = t.Add(secs(p * (1 + j*(2*r.Float64()-1))))
		out = append(out, t)
	}
	return out
}

// human: sessions of 3..15 requests 1..6s apart separated by heavy-tailed (lognormal) pauses.
func fixHuman(r *rand.Rand, n int) []time.Time {
	t := beaconT0
	out := []time.Time{}
	for len(out) < n {
		k := 3 + r.Intn(13)
		for i := 0; i < k && len(out) < n; i++ {
			out = append(out, t)
			t = t.Add(secs(1 + 5*r.Float64()))
		}
		t = t.Add(secs(math.Exp(5.5 + 1.2*r.NormFloat64())))
	}
	return out
}

func fixPoisson(r *rand.Rand, n int) []time.Time {
	mean := []float64{20, 60, 300}[r.Intn(3)]
	t := beaconT0
	out := []time.Time{}
	for i := 0; i < n; i++ {
		out = append(out, t)
		t = t.Add(secs(r.ExpFloat64() * mean))
	}
	return out
}

type beaconRates struct{ detect, total int }

func (b beaconRates) rate() float64 { return float64(b.detect) / float64(b.total) }

func runBeaconFixture(gen func(r *rand.Rand) []time.Time, trials int, seed int64) (beaconRates, float64, float64) {
	r := rand.New(rand.NewSource(seed))
	var br beaconRates
	minS, maxS := 101.0, -1.0
	sum := 0.0
	for i := 0; i < trials; i++ {
		s := AnalyzeBeacon("h", "198.51.100.7:443", gen(r), 8)
		br.total++
		if s.Score >= beaconSuspectScore {
			br.detect++
		}
		sum += s.Score
		minS, maxS = math.Min(minS, s.Score), math.Max(maxS, s.Score)
	}
	return br, sum / float64(trials), minS
}

func nRange(r *rand.Rand) int { return 20 + r.Intn(81) } // 20..100 events

// TestBeaconEvaluation records detection / false-positive rates on 300 trials per class and fails
// on regression. Recorded numbers live in docs/local-models-net.md.
func TestBeaconEvaluation(t *testing.T) {
	const trials = 300
	cases := []struct {
		name   string
		gen    func(r *rand.Rand) []time.Time
		beacon bool
		bound  float64 // min detection rate (beacon) or max FP rate (benign)
	}{
		{"fixed period", func(r *rand.Rand) []time.Time { return fixFixed(r, nRange(r)) }, true, 0.99},
		{"jitter 10%", func(r *rand.Rand) []time.Time { return fixJitter(r, nRange(r), 0.10) }, true, 0.99},
		{"jitter 25%", func(r *rand.Rand) []time.Time { return fixJitter(r, nRange(r), 0.25) }, true, 0.97},
		{"jitter 50%", func(r *rand.Rand) []time.Time { return fixJitter(r, nRange(r), 0.50) }, true, 0.95},
		{"human bursty", func(r *rand.Rand) []time.Time { return fixHuman(r, nRange(r)) }, false, 0.01},
		{"poisson", func(r *rand.Rand) []time.Time { return fixPoisson(r, nRange(r)) }, false, 0.01},
	}
	for i, c := range cases {
		br, mean, minS := runBeaconFixture(c.gen, trials, int64(100+i))
		t.Logf("%-14s trials=%d flagged=%d rate=%.3f meanScore=%.1f minScore=%.1f", c.name, br.total, br.detect, br.rate(), mean, minS)
		if c.beacon && br.rate() < c.bound {
			t.Errorf("%s: detection rate %.3f below %.2f", c.name, br.rate(), c.bound)
		}
		if !c.beacon && br.rate() > c.bound {
			t.Errorf("%s: false-positive rate %.3f above %.2f", c.name, br.rate(), c.bound)
		}
	}
}

func TestBeaconGuardsAndFactors(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	short := AnalyzeBeacon("h", "d:1", fixFixed(r, 5), 8)
	if short.Status != "not_enough_data" || short.Score != 0 {
		t.Fatalf("short series must be not_enough_data: %+v", short)
	}
	s := AnalyzeBeacon("h", "d:1", fixFixed(r, 40), 8)
	if s.Level != "high" || len(s.Factors) < 4 || len(s.Histogram) != beaconHistBins || s.PeriodSec <= 0 {
		t.Fatalf("fixed beacon should be high with factors/histogram: %+v", s)
	}
	if s.Autocorr < 0.5 {
		t.Fatalf("autocorrelation of a fixed beacon should be high: %v", s.Autocorr)
	}
	// 3 events in one instant (burst) must not score.
	same := []time.Time{beaconT0, beaconT0, beaconT0, beaconT0, beaconT0, beaconT0, beaconT0, beaconT0, beaconT0}
	if b := AnalyzeBeacon("h", "d:1", same, 8); b.Score != 0 {
		t.Fatalf("zero-interval burst must score 0: %v", b.Score)
	}
}

func TestBeaconAllowlist(t *testing.T) {
	p := BeaconParams{Allow: defaultBeaconAllow}
	for _, d := range []string{"pool.ntp.org:123", "10.1.1.1:123", "127.0.0.1:8080", "d1abc.cloudfront.net:443", "localhost:80"} {
		if ok, _ := beaconAllowed(d, p); !ok {
			t.Errorf("%s should be allowlisted", d)
		}
	}
	for _, d := range []string{"198.51.100.7:443", "evil-cloudfront.net.example.org:443", "10.2.3.4:443"} {
		if ok, _ := beaconAllowed(d, p); ok {
			t.Errorf("%s must not be allowlisted", d)
		}
	}
	p.ExcludePrivate = true
	if ok, _ := beaconAllowed("10.2.3.4:443", p); !ok {
		t.Error("private range should be excluded with the flag")
	}
}
