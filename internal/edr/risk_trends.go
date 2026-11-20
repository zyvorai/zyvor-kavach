// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	riskHalfLife   = 72 * time.Hour // finding weight halves every 72h
	riskScale      = 2.0            // saturation constant for the 0-100 mapping
	riskTopRules   = 5
	riskGaugeHosts = 20
)

// HostRisk is the per-host risk rollup.
type HostRisk struct {
	Host     string      `json:"host"`
	Rank     int         `json:"rank"`
	Risk     int         `json:"risk"`
	Band     string      `json:"band"`
	Findings int         `json:"findings"`
	LastSeen time.Time   `json:"last_seen"`
	TopRules []RuleCount `json:"top_rules"`
}

// RuleCount is a rule with its occurrence count.
type RuleCount struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// DecayWeight returns 0.5^(age/halfLife); non-positive ages clamp to 1.
func DecayWeight(age time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	return math.Pow(0.5, float64(age)/float64(riskHalfLife))
}

// RiskBand maps a 0-100 risk to low/medium/high/critical.
func RiskBand(r int) string {
	switch {
	case r >= 75:
		return "critical"
	case r >= 50:
		return "high"
	case r >= 25:
		return "medium"
	}
	return "low"
}

func topRules(m map[string]int, n int) []RuleCount {
	out := make([]RuleCount, 0, len(m))
	for r, c := range m {
		out = append(out, RuleCount{r, c})
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

// ComputeHostRisks ranks hosts by time-decayed, severity-weighted findings.
// Each finding contributes ScoreFinding(f).Score/100 * decay; the sum s maps
// to risk = 100*(1-exp(-s/riskScale)), so risk is bounded and monotonic.
func ComputeHostRisks(findings []Finding, now time.Time) []HostRisk {
	type acc struct {
		sum   float64
		n     int
		last  time.Time
		rules map[string]int
	}
	hosts := map[string]*acc{}
	for _, f := range findings {
		a := hosts[f.Host]
		if a == nil {
			a = &acc{rules: map[string]int{}}
			hosts[f.Host] = a
		}
		a.sum += float64(ScoreFinding(f).Score) / 100 * DecayWeight(now.Sub(f.Time))
		a.n++
		a.rules[f.Rule]++
		if f.Time.After(a.last) {
			a.last = f.Time
		}
	}
	out := make([]HostRisk, 0, len(hosts))
	for h, a := range hosts {
		r := int(math.Round(100 * (1 - math.Exp(-a.sum/riskScale))))
		out = append(out, HostRisk{Host: h, Risk: r, Band: RiskBand(r), Findings: a.n, LastSeen: a.last.UTC(), TopRules: topRules(a.rules, riskTopRules)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Host < out[j].Host
	})
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// riskGauges renders kavach_host_risk for the top riskGaugeHosts hosts only.
func riskGauges(store *Store, now time.Time) string {
	var b strings.Builder
	b.WriteString("# HELP kavach_host_risk Host risk 0-100 (top 20 hosts only).\n# TYPE kavach_host_risk gauge\n")
	if store == nil {
		return b.String()
	}
	hr := ComputeHostRisks(store.List(), now)
	if len(hr) > riskGaugeHosts {
		hr = hr[:riskGaugeHosts]
	}
	for _, h := range hr {
		fmt.Fprintf(&b, "kavach_host_risk{host=%q} %d\n", h.Host, h.Risk)
	}
	return b.String()
}

// TrendBucket is one time bucket of finding counts.
type TrendBucket struct {
	Start    time.Time      `json:"start"`
	Total    int            `json:"total"`
	Severity map[string]int `json:"severity"`
}

// TrendReport is the /v1/trends payload.
type TrendReport struct {
	Days          int           `json:"days"`
	Bucket        string        `json:"bucket"`
	From          time.Time     `json:"from"`
	To            time.Time     `json:"to"`
	Buckets       []TrendBucket `json:"buckets"`
	Total         int           `json:"total"`
	PreviousTotal int           `json:"previous_total"`
	Delta         int           `json:"delta"`
	DeltaPct      float64       `json:"delta_pct"`
	TopRules      []RuleCount   `json:"top_rules"`
}

var sevKeys = []string{"low", "medium", "high", "critical"}

// ComputeTrends buckets findings (UTC-aligned). The window ends at the end of
// the bucket containing now; the previous period is the equal-length window before.
func ComputeTrends(findings []Finding, now time.Time, days int, bucket string) TrendReport {
	step := 24 * time.Hour
	if bucket == "hour" {
		step = time.Hour
	}
	end := now.UTC().Truncate(step).Add(step)
	span := time.Duration(days) * 24 * time.Hour
	start := end.Add(-span)
	prev := start.Add(-span)
	n := int(span / step)
	rep := TrendReport{Days: days, Bucket: bucket, From: start, To: end, Buckets: make([]TrendBucket, n)}
	for i := range rep.Buckets {
		s := map[string]int{}
		for _, k := range sevKeys {
			s[k] = 0
		}
		rep.Buckets[i] = TrendBucket{Start: start.Add(time.Duration(i) * step), Severity: s}
	}
	rules := map[string]int{}
	for _, f := range findings {
		t := f.Time.UTC()
		switch {
		case !t.Before(start) && t.Before(end):
			i := int(t.Sub(start) / step)
			sv := strings.ToLower(f.Severity)
			if _, ok := rep.Buckets[i].Severity[sv]; !ok {
				sv = "low"
			}
			rep.Buckets[i].Severity[sv]++
			rep.Buckets[i].Total++
			rep.Total++
			rules[f.Rule]++
		case !t.Before(prev) && t.Before(start):
			rep.PreviousTotal++
		}
	}
	rep.Delta = rep.Total - rep.PreviousTotal
	if rep.PreviousTotal > 0 {
		rep.DeltaPct = math.Round(float64(rep.Delta)/float64(rep.PreviousTotal)*1000) / 10
	}
	rep.TopRules = topRules(rules, riskTopRules)
	return rep
}

// RegisterRiskTrends serves GET /v1/risk/hosts, /v1/risk/summary and /v1/trends (read-only).
func RegisterRiskTrends(mux *http.ServeMux, token string, store *Store) {
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/risk/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, map[string]any{"hosts": ComputeHostRisks(store.List(), time.Now()), "half_life_hours": riskHalfLife.Hours()})
	})
	mux.HandleFunc("GET /v1/risk/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		hr := ComputeHostRisks(store.List(), time.Now())
		bands := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
		sum, max := 0, 0
		for _, h := range hr {
			bands[h.Band]++
			sum += h.Risk
			if h.Risk > max {
				max = h.Risk
			}
		}
		// Fleet index: blend of mean and worst host so one hot host is not averaged away.
		idx := 0
		if len(hr) > 0 {
			idx = int(math.Round(0.5*float64(sum)/float64(len(hr)) + 0.5*float64(max)))
		}
		writeJSON(w, map[string]any{"fleet_risk_index": idx, "band": RiskBand(idx), "hosts": len(hr), "bands": bands})
	})
	mux.HandleFunc("GET /v1/trends", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		days := 7
		switch r.URL.Query().Get("days") {
		case "", "7":
		case "14":
			days = 14
		case "30":
			days = 30
		default:
			http.Error(w, "days must be 7, 14 or 30", http.StatusBadRequest)
			return
		}
		bucket := r.URL.Query().Get("bucket")
		if bucket == "" {
			bucket = "day"
		}
		if bucket != "hour" && bucket != "day" {
			http.Error(w, "bucket must be hour or day", http.StatusBadRequest)
			return
		}
		writeJSON(w, ComputeTrends(store.List(), time.Now(), days, bucket))
	})
}
