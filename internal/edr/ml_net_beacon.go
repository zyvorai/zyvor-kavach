// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Beaconing detection: statistical, local and explainable. For every (host, destination) pair the
// retained NetworkEvent timestamps are turned into inter-arrival intervals and scored for
// regularity. No network, no LLM, no state written. Observation only. See docs/local-models-net.md.

const (
	beaconDefaultMinEvents = 8
	beaconMaxSeries        = 20000
	beaconHistBins         = 12
	beaconSuspectScore     = 60.0
	beaconHighScore        = 80.0
)

// BeaconFactor is one named, weighted contribution to the score.
type BeaconFactor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`  // 0..1
	Weight float64 `json:"weight"` // weight in the additive part; 1 for multipliers
	Note   string  `json:"note"`
}

// BeaconHistBin is one interval-histogram bucket (seconds).
type BeaconHistBin struct {
	LoSec float64 `json:"lo_sec"`
	HiSec float64 `json:"hi_sec"`
	Count int     `json:"count"`
}

// BeaconSeries is the analysis of one (host, destination) series.
type BeaconSeries struct {
	Host        string          `json:"host"`
	Destination string          `json:"destination"`
	Status      string          `json:"status"` // scored | not_enough_data
	Events      int             `json:"events"`
	First       time.Time       `json:"first"`
	Last        time.Time       `json:"last"`
	MeanSec     float64         `json:"mean_sec"`
	MedianSec   float64         `json:"median_sec"`
	CV          float64         `json:"cv"`
	JitterRatio float64         `json:"jitter_ratio"` // MAD / median
	BurstB      float64         `json:"burstiness"`   // Goh-Barabasi (sigma-mu)/(sigma+mu), -1 regular .. 1 bursty
	PeriodSec   float64         `json:"period_sec"`   // dominant period (histogram mode refined by median)
	Autocorr    float64         `json:"autocorr"`     // normalised autocorrelation of the binned series at the period lag
	Score       float64         `json:"score"`        // 0..100
	Level       string          `json:"level"`        // none | suspect | high
	Factors     []BeaconFactor  `json:"factors"`
	Histogram   []BeaconHistBin `json:"histogram"`
}

// BeaconParams tunes one analysis run.
type BeaconParams struct {
	MinEvents      int
	ExcludePrivate bool
	Allow          []string // destination host suffixes / exact names / ":port" entries
}

func beaconMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// AnalyzeBeacon scores one timestamp series. Pure function, used by the endpoint and tests.
//
// Score (0..100) = 100 * clamp01( (0.50*regularity + 0.35*concentration + 0.15*periodicity)
// * (1 - max(0, B)) * confidence )
//
//	regularity    = clamp01((1.0 - rcv)/0.8), rcv = 1.4826*MAD/median (robust CV: <=0.2 -> 1.0,
//	                a +-50% uniform jitter gives rcv ~0.37 -> 0.79, Poisson gives rcv ~1.0 -> 0)
//	concentration = clamp01((f - 0.35)/0.65), f = share of intervals within [0.5, 1.5] x median
//	                (Poisson ~0.35 -> 0, any jitter up to +-50% -> 1)
//	periodicity   = clamp01(autocorrelation at the period lag of the event-count series)
//	B             = Goh-Barabasi burstiness; bursty human traffic (B>0) is penalised linearly
//	confidence    = clamp01(n / 20) so short series cannot reach the top of the scale
func AnalyzeBeacon(host, dest string, ts []time.Time, minEvents int) BeaconSeries {
	if minEvents < 4 {
		minEvents = beaconDefaultMinEvents
	}
	t := append([]time.Time(nil), ts...)
	sort.Slice(t, func(i, j int) bool { return t[i].Before(t[j]) })
	s := BeaconSeries{Host: host, Destination: dest, Events: len(t), Level: "none", Factors: []BeaconFactor{}, Histogram: []BeaconHistBin{}}
	if len(t) > 0 {
		s.First, s.Last = t[0], t[len(t)-1]
	}
	if len(t) < minEvents {
		s.Status = "not_enough_data"
		return s
	}
	iv := make([]float64, 0, len(t)-1)
	for i := 1; i < len(t); i++ {
		iv = append(iv, t[i].Sub(t[i-1]).Seconds())
	}
	var sum float64
	for _, x := range iv {
		sum += x
	}
	s.MeanSec = sum / float64(len(iv))
	s.MedianSec = beaconMedian(iv)
	var ss float64
	for _, x := range iv {
		ss += (x - s.MeanSec) * (x - s.MeanSec)
	}
	sd := math.Sqrt(ss / float64(len(iv)))
	if s.MeanSec > 0 {
		s.CV = sd / s.MeanSec
		s.BurstB = (sd - s.MeanSec) / (sd + s.MeanSec)
	}
	dev := make([]float64, len(iv))
	for i, x := range iv {
		dev[i] = math.Abs(x - s.MedianSec)
	}
	mad := beaconMedian(dev)
	if s.MedianSec > 0 {
		s.JitterRatio = mad / s.MedianSec
	}
	s.Status = "scored"
	if s.MedianSec <= 0 { // most events in the same instant: a burst, not a beacon
		s.Histogram = beaconHist(iv, 0)
		return s
	}
	s.Histogram = beaconHist(iv, s.MedianSec)
	s.PeriodSec = beaconPeriod(iv, s.MedianSec)
	s.Autocorr = beaconAutocorr(t, s.PeriodSec)

	rcv := 1.4826 * s.JitterRatio
	reg := clamp01((1.0 - rcv) / 0.8)
	in := 0
	for _, x := range iv {
		if x >= 0.5*s.MedianSec && x <= 1.5*s.MedianSec {
			in++
		}
	}
	frac := float64(in) / float64(len(iv))
	conc := clamp01((frac - 0.35) / 0.65)
	per := clamp01(s.Autocorr)
	pen := 1 - math.Max(0, s.BurstB)
	conf := clamp01(float64(len(t)) / 20)
	s.Factors = []BeaconFactor{
		{"regularity", reg, 0.50, "robust CV " + f2(rcv) + " (1.4826*MAD/median); jitter ratio " + f2(s.JitterRatio)},
		{"concentration", conc, 0.35, f2(frac*100) + "% of intervals within +-50% of the median"},
		{"periodicity", per, 0.15, "autocorrelation " + f2(s.Autocorr) + " at the " + f2(s.PeriodSec) + "s lag"},
		{"burstiness_penalty", pen, 1, "burstiness B=" + f2(s.BurstB) + "; multiplier " + f2(pen)},
		{"confidence", conf, 1, strconv.Itoa(len(t)) + " events; full confidence at 20"},
	}
	s.Score = math.Round(1000*100*clamp01((0.50*reg+0.35*conc+0.15*per)*pen*conf)) / 1000
	switch {
	case s.Score >= beaconHighScore:
		s.Level = "high"
	case s.Score >= beaconSuspectScore:
		s.Level = "suspect"
	}
	return s
}

func clamp01(x float64) float64 { return math.Max(0, math.Min(1, x)) }
func f2(x float64) string       { return strconv.FormatFloat(math.Round(x*100)/100, 'f', -1, 64) }

// beaconHist builds a fixed-bin histogram over [0, 3*median] (last bin collects the tail).
func beaconHist(iv []float64, med float64) []BeaconHistBin {
	hi := 3 * med
	if hi <= 0 {
		hi = 1
	}
	w := hi / beaconHistBins
	bins := make([]BeaconHistBin, beaconHistBins)
	for i := range bins {
		bins[i] = BeaconHistBin{LoSec: math.Round(float64(i)*w*1000) / 1000, HiSec: math.Round(float64(i+1)*w*1000) / 1000}
	}
	for _, x := range iv {
		i := int(x / w)
		if i >= beaconHistBins {
			i = beaconHistBins - 1
		}
		bins[i].Count++
	}
	return bins
}

// beaconPeriod: histogram mode (bin width median/10) refined by the median of intervals in the
// modal bin and its neighbours.
func beaconPeriod(iv []float64, med float64) float64 {
	w := med / 10
	if w <= 0 {
		return med
	}
	cnt := map[int]int{}
	best, bi := 0, 0
	for _, x := range iv {
		if x > 5*med {
			continue
		}
		cnt[int(x/w)]++
	}
	for b, c := range cnt {
		if c > best || (c == best && b < bi) {
			best, bi = c, b
		}
	}
	var near []float64
	for _, x := range iv {
		if b := int(x / w); b >= bi-1 && b <= bi+1 {
			near = append(near, x)
		}
	}
	if len(near) == 0 {
		return med
	}
	return beaconMedian(near)
}

// beaconAutocorr bins the events into period/4 slots and returns the largest normalised
// autocorrelation within one slot of the period lag.
func beaconAutocorr(t []time.Time, period float64) float64 {
	if period <= 0 || len(t) < 4 {
		return 0
	}
	span := t[len(t)-1].Sub(t[0]).Seconds()
	slot := period / 4
	if span/slot > 8192 {
		slot = span / 8192
	}
	n := int(span/slot) + 1
	x := make([]float64, n)
	for _, e := range t {
		x[int(e.Sub(t[0]).Seconds()/slot)]++
	}
	var mean float64
	for _, v := range x {
		mean += v
	}
	mean /= float64(n)
	var den float64
	for _, v := range x {
		den += (v - mean) * (v - mean)
	}
	if den == 0 {
		return 0
	}
	lag := int(math.Round(period / slot))
	best := 0.0
	for l := lag - 1; l <= lag+1; l++ {
		if l < 1 || l >= n {
			continue
		}
		var num float64
		for i := 0; i+l < n; i++ {
			num += (x[i] - mean) * (x[i+l] - mean)
		}
		if c := num / den; c > best {
			best = c
		}
	}
	return best
}

// defaultBeaconAllow lists destinations that are periodic for benign reasons (time sync, OS
// updates, CDNs, connectivity checks). Editable: add entries to <store>.beacon_allowlist.json as a
// JSON array of strings. An entry is a host suffix ("ntp.org"), an exact host, or ":port".
var defaultBeaconAllow = []string{
	":123", "ntp.org", "time.apple.com", "time.windows.com", "time.google.com", "time.cloudflare.com",
	"windowsupdate.com", "update.microsoft.com", "swscan.apple.com", "mesu.apple.com", "archive.ubuntu.com",
	"security.ubuntu.com", "deb.debian.org", "ocsp.apple.com", "ocsp.digicert.com", "ocsp.pki.goog",
	"cloudfront.net", "akamaiedge.net", "akamaized.net", "fastly.net", "gvt1.com",
	"connectivitycheck.gstatic.com", "captive.apple.com", "msftconnecttest.com",
}

func beaconSplitDest(dest string) (host, port string) {
	if h, p, err := net.SplitHostPort(dest); err == nil {
		return strings.ToLower(strings.Trim(h, "[]")), p
	}
	return strings.ToLower(dest), ""
}

func beaconAllowed(dest string, p BeaconParams) (bool, string) {
	host, port := beaconSplitDest(dest)
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true, "loopback"
		}
		if p.ExcludePrivate && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return true, "private range"
		}
	} else if host == "localhost" {
		return true, "loopback"
	}
	for _, a := range p.Allow {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
		case strings.HasPrefix(a, ":"):
			if port == a[1:] {
				return true, "allowlist " + a
			}
		case host == a || strings.HasSuffix(host, "."+a):
			return true, "allowlist " + a
		}
	}
	return false, ""
}

func loadBeaconAllow(store *Store) []string {
	out := append([]string(nil), defaultBeaconAllow...)
	if store != nil && store.path != "" {
		if b, err := os.ReadFile(store.path + ".beacon_allowlist.json"); err == nil {
			var extra []string
			if json.Unmarshal(b, &extra) == nil {
				out = append(out, extra...)
			}
		}
	}
	return out
}

func (s *Store) networkSnapshot() []NetworkEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]NetworkEvent(nil), s.networkEvents...)
}

// AnalyzeBeacons groups the events per (host, destination) and returns scored series (best first),
// the number of series skipped as benign periodic destinations and the not-enough-data count.
func AnalyzeBeacons(events []NetworkEvent, p BeaconParams, host string) (series []BeaconSeries, excluded, short int) {
	type key struct{ h, d string }
	groups := map[key][]time.Time{}
	for _, e := range events {
		if e.Destination == "" || e.Time.IsZero() || (host != "" && e.Host != host) {
			continue
		}
		k := key{e.Host, e.Destination}
		if len(groups) >= beaconMaxSeries && groups[k] == nil {
			continue
		}
		groups[k] = append(groups[k], e.Time)
	}
	for k, ts := range groups {
		if ok, _ := beaconAllowed(k.d, p); ok {
			excluded++
			continue
		}
		s := AnalyzeBeacon(k.h, k.d, ts, p.MinEvents)
		if s.Status == "not_enough_data" {
			short++
			continue
		}
		series = append(series, s)
	}
	sort.Slice(series, func(i, j int) bool {
		if series[i].Score != series[j].Score {
			return series[i].Score > series[j].Score
		}
		if series[i].Host != series[j].Host {
			return series[i].Host < series[j].Host
		}
		return series[i].Destination < series[j].Destination
	})
	return
}

func registerMLBeacons(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ml/beacons", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		p := BeaconParams{MinEvents: beaconDefaultMinEvents, ExcludePrivate: q.Get("exclude_private") == "1" || q.Get("exclude_private") == "true", Allow: loadBeaconAllow(store)}
		if v, err := strconv.Atoi(q.Get("min_events")); err == nil && v >= 4 && v <= 100000 {
			p.MinEvents = v
		}
		limit := 20
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
			limit = v
		}
		minScore := 0.0
		if v, err := strconv.ParseFloat(q.Get("min_score"), 64); err == nil {
			minScore = v
		}
		all, excluded, short := AnalyzeBeacons(store.networkSnapshot(), p, q.Get("host"))
		out := []BeaconSeries{}
		for _, s := range all {
			if s.Score >= minScore && len(out) < limit {
				out = append(out, s)
			}
		}
		customJSON(w, 200, map[string]any{
			"mode": "observe-only", "model": "statistical-beacon-v1", "min_events": p.MinEvents,
			"suspect_score": beaconSuspectScore, "high_score": beaconHighScore,
			"series_scored": len(all), "not_enough_data": short, "excluded_benign_periodic": excluded,
			"exclude_private": p.ExcludePrivate, "suspects": out,
		})
	})
}
