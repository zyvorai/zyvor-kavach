// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecayMath(t *testing.T) {
	if DecayWeight(0) != 1 || DecayWeight(-time.Hour) != 1 {
		t.Fatal("no decay at age<=0")
	}
	if math.Abs(DecayWeight(riskHalfLife)-0.5) > 1e-9 || math.Abs(DecayWeight(2*riskHalfLife)-0.25) > 1e-9 {
		t.Fatal("half-life wrong")
	}
	now := time.Now()
	f := Finding{Host: "a", Rule: "x", Severity: "high", Time: now}
	old := f
	old.Time = now.Add(-10 * 24 * time.Hour)
	fresh := ComputeHostRisks([]Finding{f}, now)[0].Risk
	aged := ComputeHostRisks([]Finding{old}, now)[0].Risk
	if !(fresh > aged) || fresh > 100 {
		t.Fatalf("fresh %d aged %d", fresh, aged)
	}
}

func TestRankingAndBands(t *testing.T) {
	now := time.Now()
	var fs []Finding
	for i := 0; i < 6; i++ {
		fs = append(fs, Finding{Host: "hot", Rule: "download-execute", Severity: "high", Time: now})
	}
	fs = append(fs, Finding{Host: "cool", Rule: "r", Severity: "low", Time: now}, Finding{Host: "hot", Rule: "r", Severity: "low", Time: now})
	hr := ComputeHostRisks(fs, now)
	if hr[0].Host != "hot" || hr[0].Rank != 1 || hr[1].Rank != 2 || hr[0].TopRules[0].Rule != "download-execute" {
		t.Fatalf("%+v", hr)
	}
	if RiskBand(24) != "low" || RiskBand(25) != "medium" || RiskBand(50) != "high" || RiskBand(75) != "critical" {
		t.Fatal("bands")
	}
}

func TestBucketBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC)
	mk := func(tm time.Time, sev string) Finding { return Finding{Host: "h", Rule: "r", Severity: sev, Time: tm} }
	fs := []Finding{
		mk(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), "high"),     // first instant of today's bucket
		mk(time.Date(2026, 11, 11, 23, 59, 59, 0, time.UTC), "low"),   // last instant of yesterday
		mk(time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), "medium"),    // window start (7d ending 13th)
		mk(time.Date(2026, 11, 5, 23, 59, 59, 0, time.UTC), "medium"), // previous period
		mk(time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), "medium"),   // previous period start
		mk(time.Date(2026, 10, 29, 23, 0, 0, 0, time.UTC), "medium"),  // before previous
	}
	r := ComputeTrends(fs, now, 7, "day")
	if len(r.Buckets) != 7 || r.Total != 3 || r.PreviousTotal != 2 || r.Delta != 1 || r.DeltaPct != 50 {
		t.Fatalf("%+v", r)
	}
	if r.Buckets[6].Severity["high"] != 1 || r.Buckets[5].Severity["low"] != 1 || r.Buckets[0].Severity["medium"] != 1 {
		t.Fatalf("%+v", r.Buckets)
	}
	if h := ComputeTrends(nil, now, 7, "hour"); len(h.Buckets) != 168 {
		t.Fatal(len(h.Buckets))
	}
}

func TestRiskEndpointsEmptyAndAuth(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, p := range []string{"/v1/risk/hosts", "/v1/risk/summary", "/v1/trends"} {
		if r, _ := get(t, srv.URL+p, ""); r.StatusCode != 401 {
			t.Fatalf("%s auth: %d", p, r.StatusCode)
		}
	}
	_, body := get(t, srv.URL+"/v1/risk/summary", tok)
	var sum struct {
		Idx   int            `json:"fleet_risk_index"`
		Hosts int            `json:"hosts"`
		Bands map[string]int `json:"bands"`
	}
	if err := json.Unmarshal([]byte(body), &sum); err != nil || sum.Idx != 0 || sum.Hosts != 0 || len(sum.Bands) != 4 {
		t.Fatalf("%v %s", err, body)
	}
	if _, b := get(t, srv.URL+"/v1/risk/hosts", tok); !strings.Contains(b, `"hosts":[]`) {
		t.Fatal(b)
	}
	r, b := get(t, srv.URL+"/v1/trends?days=14&bucket=day", tok)
	if r.StatusCode != 200 || !strings.Contains(b, `"total":0`) {
		t.Fatal(r.StatusCode, b)
	}
	if r, _ := get(t, srv.URL+"/v1/trends?days=3", tok); r.StatusCode != 400 {
		t.Fatal("bad days")
	}
	if r, _ := get(t, srv.URL+"/v1/trends?bucket=week", tok); r.StatusCode != 400 {
		t.Fatal("bad bucket")
	}
}

func TestHostRiskGaugeBounded(t *testing.T) {
	now := time.Now()
	s, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		h := fmt.Sprintf("host%02d", i)
		if err := s.Append(Finding{ID: h, Host: h, Rule: "r", Severity: "high", Time: now}); err != nil {
			t.Fatal(err)
		}
	}
	out := riskGauges(s, now)
	if n := strings.Count(out, "kavach_host_risk{"); n != 20 {
		t.Fatalf("gauge hosts %d", n)
	}
}
