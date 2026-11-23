// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func authRec(t time.Time, user, ip, outcome string, extra map[string]any) map[string]any {
	m := map[string]any{"time": t.Format(time.RFC3339), "user": user, "ip": ip, "outcome": outcome}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestAuthNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		why  string
		succ bool
	}{
		{"basic", `{"time":"2026-11-12T10:00:00Z","user":"Bob","ip":"1.2.3.4","outcome":"success"}`, "", true},
		{"okta-like", `{"published":"2026-11-12T10:00:00Z","actor":{"alternateId":"a@x.org"},"client":{"ipAddress":"1.2.3.4"},"result":"FAILURE"}`, "", false},
		{"bool success", `{"@timestamp":"2026-11-12T10:00:00Z","user":{"name":"u"},"source":{"ip":"1.2.3.4"},"success":false}`, "", false},
		{"entra-like", `{"createdDateTime":"2026-11-12T10:00:00Z","userPrincipalName":"u@x.org","ipAddress":"1.2.3.4","status":"200"}`, "", true},
		{"no time", `{"user":"u","ip":"1.2.3.4","outcome":"success"}`, "no parseable timestamp", false},
		{"no ip", `{"time":"2026-11-12T10:00:00Z","user":"u","outcome":"success"}`, "missing user or source ip", false},
		{"unknown outcome", `{"time":"2026-11-12T10:00:00Z","user":"u","ip":"1.2.3.4","outcome":"maybe"}`, "unknown outcome", false},
	}
	for _, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.in), &m); err != nil {
			t.Fatal(err)
		}
		r, why := NormalizeAuthRecord(m)
		if why != c.why || (why == "" && r.Success != c.succ) {
			t.Errorf("%s: why=%q success=%v", c.name, why, r.Success)
		}
	}
	// passwords and unknown fields are never read into the record
	var m map[string]any
	_ = json.Unmarshal([]byte(`{"time":"2026-11-12T10:00:00Z","user":"u","ip":"1.2.3.4","outcome":"failure","password":"hunter2","lat":"999","lon":"5"}`), &m)
	r, _ := NormalizeAuthRecord(m)
	if r.HasGeo {
		t.Error("out-of-range coordinates accepted")
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "hunter2") {
		t.Error("password captured")
	}
}

func TestAuthHaversine(t *testing.T) {
	if d := authHaversineKm(52.52, 13.40, 40.71, -74.00); math.Abs(d-6385) > 60 {
		t.Errorf("Berlin-NYC = %.0f km", d)
	}
	if d := authHaversineKm(10, 10, 10, 10); d != 0 {
		t.Errorf("same point = %v", d)
	}
}

func TestAuthCredentialStuffing(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var recs []map[string]any
	for i := 0; i < 120; i++ { // 30 users, 40 sources, 3 failures per source
		recs = append(recs, authRec(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("user%d@x.org", i%30), fmt.Sprintf("192.0.2.%d", i%40), "failure", nil))
	}
	rep, fs := AnalyzeAuthLogs(recs, "")
	if rep.ByRule["auth-an-credential-stuffing"] != 1 || rep.Failures != 120 || rep.Users != 30 || rep.Sources != 40 {
		t.Fatalf("report %+v", rep)
	}
	if len(fs) == 0 || fs[0].Host != "auth:logs" {
		t.Fatalf("findings %+v", fs)
	}
	// the same volume from 2 sources is a brute-force by few clients, not stuffing
	var few []map[string]any
	for i := 0; i < 120; i++ {
		few = append(few, authRec(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("user%d@x.org", i%30), fmt.Sprintf("192.0.2.%d", i%2), "failure", nil))
	}
	rep, _ = AnalyzeAuthLogs(few, "")
	if rep.ByRule["auth-an-credential-stuffing"] != 0 {
		t.Errorf("stuffing from 2 sources: %v", rep.ByRule)
	}
}

func TestAuthDistributedAccountAttackAndVelocity(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var recs []map[string]any
	for i := 0; i < 12; i++ {
		recs = append(recs, authRec(base.Add(time.Duration(i)*10*time.Second), "ceo@x.org", fmt.Sprintf("198.51.100.%d", i+1), "failure", nil))
	}
	for i := 0; i < 130; i++ {
		recs = append(recs, authRec(base.Add(time.Duration(i)*300*time.Millisecond), "svc@x.org", "203.0.113.9", "failure", nil))
	}
	rep, _ := AnalyzeAuthLogs(recs, "")
	if rep.ByRule["auth-an-distributed-account-attack"] != 1 || rep.ByRule["auth-an-high-velocity"] != 1 {
		t.Fatalf("by_rule %v", rep.ByRule)
	}
	if len(rep.TopSources) == 0 || rep.TopSources[0].IP != "203.0.113.9" {
		t.Errorf("top sources %+v", rep.TopSources)
	}
}

func TestAuthSuccessAfterFailures(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var recs []map[string]any
	for i := 0; i < 6; i++ {
		recs = append(recs, authRec(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("u%d@x.org", i%4), "203.0.113.9", "failure", nil))
	}
	recs = append(recs, authRec(base.Add(30*time.Second), "u1@x.org", "203.0.113.9", "success", nil))
	// a user who fat-fingers their own password once then succeeds is fine
	recs = append(recs, authRec(base.Add(time.Minute), "me@x.org", "198.51.100.1", "failure", nil), authRec(base.Add(70*time.Second), "me@x.org", "198.51.100.1", "success", nil))
	rep, fs := AnalyzeAuthLogs(recs, "auth:idp")
	if rep.ByRule["auth-an-success-after-failures"] != 1 || len(fs) != 1 || fs[0].Severity != "high" || fs[0].Host != "auth:idp" {
		t.Fatalf("by_rule=%v findings=%d", rep.ByRule, len(fs))
	}
	if !strings.Contains(fs[0].Evidence.Command, "u1@x.org") {
		t.Errorf("evidence %q", fs[0].Evidence.Command)
	}
}

func TestAuthImpossibleTravel(t *testing.T) {
	base := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	geo := func(lat, lon float64, c string) map[string]any {
		return map[string]any{"lat": lat, "lon": lon, "country": c}
	}
	cases := []struct {
		name string
		recs []map[string]any
		rule string
	}{
		{"berlin to new york in 20 min", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE")),
			authRec(base.Add(20*time.Minute), "carol", "203.0.113.77", "success", geo(40.71, -74.0, "US"))}, "auth-an-impossible-travel"},
		{"berlin to new york in 12 h is plausible", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE")),
			authRec(base.Add(12*time.Hour), "carol", "203.0.113.77", "success", geo(40.71, -74.0, "US"))}, ""},
		{"nearby cities fast is fine", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE")),
			authRec(base.Add(5*time.Minute), "carol", "203.0.113.77", "success", geo(52.4, 13.0, "DE"))}, ""},
		{"same ip never alerts", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE")),
			authRec(base.Add(time.Minute), "carol", "198.51.100.20", "success", geo(40.71, -74.0, "US"))}, ""},
		{"country only, 30 min", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", map[string]any{"country": "DE"}),
			authRec(base.Add(30*time.Minute), "carol", "203.0.113.77", "success", map[string]any{"country": "US"})}, "auth-an-country-change-fast"},
		{"country only, 3 h", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", map[string]any{"country": "DE"}),
			authRec(base.Add(3*time.Hour), "carol", "203.0.113.77", "success", map[string]any{"country": "US"})}, ""},
		{"failures are ignored", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE")),
			authRec(base.Add(time.Minute), "carol", "203.0.113.77", "failure", geo(40.71, -74.0, "US"))}, ""},
		{"no geo at all", []map[string]any{
			authRec(base, "carol", "198.51.100.20", "success", nil),
			authRec(base.Add(time.Minute), "carol", "203.0.113.77", "success", nil)}, ""},
		{"out of order input is sorted", []map[string]any{
			authRec(base.Add(20*time.Minute), "carol", "203.0.113.77", "success", geo(40.71, -74.0, "US")),
			authRec(base, "carol", "198.51.100.20", "success", geo(52.52, 13.40, "DE"))}, "auth-an-impossible-travel"},
	}
	for _, c := range cases {
		rep, _ := AnalyzeAuthLogs(c.recs, "")
		got := ""
		for r := range rep.ByRule {
			got = r
		}
		if got != c.rule || len(rep.ByRule) > 1 {
			t.Errorf("%s: by_rule=%v want %q", c.name, rep.ByRule, c.rule)
		}
	}
}

func TestAuthFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth/auth_sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := authUnwrap(raw)
	if err != nil || len(recs) != 4 {
		t.Fatalf("unwrap %d %v", len(recs), err)
	}
	rep, fs := AnalyzeAuthLogs(recs, "")
	if rep.ByRule["auth-an-impossible-travel"] != 1 || len(fs) != 1 || rep.GeoRecords != 2 {
		t.Fatalf("report %+v", rep)
	}
}

func TestAuthUnwrapShapes(t *testing.T) {
	rec := `{"time":"2026-11-12T10:00:00Z","user":"u","ip":"1.2.3.4","outcome":"failure"}`
	for name, body := range map[string]string{
		"array":   `[` + rec + `]`,
		"wrapper": `{"events":[` + rec + `]}`,
		"logs":    `{"logs":[` + rec + `]}`,
		"single":  rec,
		"jsonl":   rec + "\n" + rec,
	} {
		recs, err := authUnwrap([]byte(body))
		if err != nil || len(recs) == 0 || recs[0] == nil {
			t.Errorf("%s: %v %v", name, recs, err)
		}
	}
	if _, err := authUnwrap([]byte("\n\n")); err == nil {
		t.Error("blank body accepted")
	}
	recs, _ := authUnwrap([]byte(rec + "\nnot json\n" + strings.Repeat("x", webLineMax+1)))
	if len(recs) != 3 || recs[1] != nil || recs[2] != nil {
		t.Errorf("bad lines should become nil records: %v", recs)
	}
}

func TestAuthHostileInput(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var recs []map[string]any
	recs = append(recs, nil, map[string]any{}, map[string]any{"time": strings.Repeat("9", 500), "user": "u", "ip": "1.1.1.1", "outcome": "failure"})
	recs = append(recs, authRec(base, strings.Repeat("U", 100000)+"\x00\n", "1.1.1.1\r\n", "failure", map[string]any{"lat": math.NaN(), "country": strings.Repeat("Z", 5000)}))
	nested := map[string]any{}
	cur := nested
	for i := 0; i < 5000; i++ {
		n := map[string]any{}
		cur["a"] = n
		cur = n
	}
	recs = append(recs, authRec(base, "deep", "2.2.2.2", "success", map[string]any{"geo": nested}))
	for i := 0; i < 30000; i++ {
		recs = append(recs, authRec(base.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("u%d", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "failure", nil))
	}
	start := time.Now()
	rep, _ := AnalyzeAuthLogs(recs, "")
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	if rep.Rejected != 3 || rep.Parsed != 30002 {
		t.Errorf("rejected=%d parsed=%d errors=%v", rep.Rejected, rep.Parsed, rep.Errors)
	}
}

func TestAuthLogsHTTP(t *testing.T) {
	h := telHandler(t)
	body := `{"time":"2026-11-12T08:00:00Z","user":"carol","ip":"198.51.100.20","outcome":"success","lat":52.52,"lon":13.4}` + "\n" +
		`{"time":"2026-11-12T08:10:00Z","user":"carol","ip":"203.0.113.77","outcome":"success","lat":40.71,"lon":-74}` + "\n"
	if w := telDo(h, "POST", "/v1/auth/logs", body, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", w.Code)
	}
	w := telDo(h, "POST", "/v1/auth/logs?host=IdP", body, "tok")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var rep AuthReport
	_ = json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.Findings != 1 || rep.ByRule["auth-an-impossible-travel"] != 1 {
		t.Fatalf("report %+v", rep)
	}
	if g := telDo(h, "GET", "/v1/findings", "", "tok"); !strings.Contains(g.Body.String(), "auth-an-impossible-travel") || !strings.Contains(g.Body.String(), "auth:idp") {
		t.Errorf("not stored: %.200s", g.Body.String())
	}
	for _, c := range []struct {
		body string
		code int
	}{{"", 400}, {"[]", 400}, {`[{"x":1}]`, 400}, {strings.Repeat("a", webBodyMax+1), 413}} {
		if w := telDo(h, "POST", "/v1/auth/logs", c.body, "tok"); w.Code != c.code {
			t.Errorf("%.20q -> %d want %d", c.body, w.Code, c.code)
		}
	}
	big := strings.Repeat(`{"a":1}`+"\n", authLogMax+1)
	if len(big) <= webBodyMax {
		if w := telDo(h, "POST", "/v1/auth/logs", big, "tok"); w.Code != 413 {
			t.Errorf("record cap -> %d", w.Code)
		}
	}
}
