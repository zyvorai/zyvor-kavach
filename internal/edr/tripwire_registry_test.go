// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func twReset(t *testing.T) {
	t.Helper()
	twReg.load(filepath.Join(t.TempDir(), "x.tripwires.json"))
	t.Cleanup(func() { twReg.load("") })
}

func TestTripwireValidation(t *testing.T) {
	twReset(t)
	cases := []struct {
		kind, match, label string
		ok                 bool
	}{
		{"account", "svc-backup-old", "honey admin", true},
		{"account", `CORP\Svc-Honey`, "domain form", true},
		{"account", "ab", "too short", false},
		{"account", strings.Repeat("a", 200), "too long", false},
		{"ip", "198.51.100.77", "decoy host", true},
		{"ip", "2001:db8::1", "v6", true},
		{"ip", "not-an-ip", "bad", false},
		{"value", "AKIAZZZZEXAMPLEDECOY", "fake key", true},
		{"value", "abc", "short value", false},
		{"hostname", "payroll-db.corp.example", "decoy name", true},
		{"path", "/backup-admin-old/", "decoy path", true},
		{"bogus", "whatever-value", "x", false},
		{"value", "valid-looking-value", "", false},
		{"account", "svc-backup-old", "duplicate", false},
	}
	for _, c := range cases {
		_, err := twReg.Add(c.kind, c.match, c.label, "")
		if (err == nil) != c.ok {
			t.Errorf("%s %q: err=%v want ok=%v", c.kind, c.match, err, c.ok)
		}
	}
	twReset(t)
	for i := 0; i < twMaxSubstring; i++ {
		if _, err := twReg.Add("value", fmt.Sprintf("decoy-value-%04d", i), "l", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := twReg.Add("value", "decoy-value-extra", "l", ""); err == nil {
		t.Error("substring limit not enforced")
	}
}

func TestTripwireScan(t *testing.T) {
	twReset(t)
	for _, d := range [][3]string{{"account", "svc-backup-old", "honey admin"}, {"ip", "198.51.100.77", "decoy host"}, {"value", "AKIAZZZZEXAMPLEDECOY", "fake key"},
		{"hostname", "payroll-db.corp.example", "decoy dns"}, {"path", "/backup-admin-old/", "decoy path"}} {
		if _, err := twReg.Add(d[0], d[1], d[2], ""); err != nil {
			t.Fatal(err)
		}
	}
	ts := "2026-11-12T10:00:00Z"
	cases := []struct {
		name string
		rec  map[string]any
		rule string
		sev  string
	}{
		{"okta honey login failure", map[string]any{"eventType": "user.session.start", "published": ts, "actor": map[string]any{"alternateId": "svc-backup-old@corp.example"}, "outcome": map[string]any{"result": "FAILURE"}, "client": map[string]any{"ipAddress": "203.0.113.5"}}, "tripwire-account-used", "high"},
		{"entra honey login success", map[string]any{"createdDateTime": ts, "userPrincipalName": "Svc-Backup-Old@corp.example", "ipAddress": "203.0.113.5", "status": map[string]any{"errorCode": float64(0)}, "result": "success"}, "tripwire-account-used", "critical"},
		{"windows domain form", map[string]any{"time": ts, "user": `CORP\SVC-BACKUP-OLD`, "outcome": "success"}, "tripwire-account-used", "critical"},
		{"decoy ip as destination", map[string]any{"time": ts, "src_ip": "10.0.0.5", "dest_ip": "198.51.100.77"}, "tripwire-decoy-touched", "high"},
		{"canary value in a command", map[string]any{"time": ts, "command": "aws configure set aws_access_key_id AKIAZZZZEXAMPLEDECOY"}, "tripwire-value-seen", "high"},
		{"decoy dns name", map[string]any{"time": ts, "query": "PAYROLL-DB.corp.example", "client_ip": "10.1.1.1"}, "tripwire-decoy-touched", "high"},
		{"decoy path in web log", map[string]any{"time": ts, "remote_addr": "203.0.113.9", "request": "GET /backup-admin-old/ HTTP/1.1"}, "tripwire-decoy-touched", "high"},
		{"plain text line", map[string]any{"_line": `203.0.113.9 - - [12/Nov/2026] "GET /backup-admin-old/x HTTP/1.1" 404 0`}, "tripwire-decoy-touched", "high"},
	}
	for _, c := range cases {
		rep, fs := twScan([]map[string]any{c.rec}, "test", "")
		if len(fs) != 1 || fs[0].Rule != c.rule || fs[0].Severity != c.sev || rep.Matched != 1 {
			t.Errorf("%s: %+v", c.name, fs)
			continue
		}
		if strings.Contains(fs[0].Description+fs[0].Evidence.Command, "AKIAZZZZEXAMPLEDECOY") {
			t.Errorf("%s: value leaked into the finding", c.name)
		}
	}
	for name, rec := range map[string]map[string]any{
		"other account":       {"time": ts, "user": "svc-backup-new"},
		"account in message":  {"time": ts, "message": "svc-backup-old was mentioned in a ticket"},
		"account in ip field": {"time": ts, "src_ip": "svc-backup-old"},
		"near ip":             {"time": ts, "src_ip": "198.51.100.7"},
		"unrelated":           {"time": ts, "user": "alice", "path": "/index.html"},
		"similar path":        {"time": ts, "request": "GET /backup-admin/ HTTP/1.1"},
		"empty":               {},
		"user key but number": {"time": ts, "user": float64(5)},
	} {
		if _, fs := twScan([]map[string]any{rec}, "test", ""); len(fs) != 0 {
			t.Errorf("%s: unexpected %+v", name, fs)
		}
	}
	twReg.mu.Lock()
	hits := 0
	for _, d := range twReg.defs {
		hits += d.Hits
	}
	twReg.mu.Unlock()
	if hits < len(cases) {
		t.Errorf("hits %d", hits)
	}
}

func TestTripwireCoalesceAndCaps(t *testing.T) {
	twReset(t)
	_, _ = twReg.Add("account", "svc-honey", "h", "")
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var recs []map[string]any
	for i := 0; i < 5; i++ {
		recs = append(recs, map[string]any{"time": base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339), "user": "svc-honey", "ip": "203.0.113.5", "outcome": "failure"})
	}
	if rep, fs := twScan(recs, "auth", ""); len(fs) != 1 || rep.Matched != 5 {
		t.Errorf("same source within 10 minutes should coalesce: %d findings, %d matched", len(fs), rep.Matched)
	}
	recs = nil
	for i := 0; i < 200; i++ {
		recs = append(recs, map[string]any{"time": base.Format(time.RFC3339), "user": "svc-honey", "ip": fmt.Sprintf("10.0.%d.%d", i/250, i%250)})
	}
	if _, fs := twScan(recs, "auth", ""); len(fs) != twFindCap {
		t.Errorf("cap: %d", len(fs))
	}
}

func TestTripwireHostile(t *testing.T) {
	twReset(t)
	_, _ = twReg.Add("account", "svc-honey", "h", "")
	_, _ = twReg.Add("value", "decoy-secret-value", "v", "")
	_, _ = twReg.Add("hostname", "decoy.example.org", "d", "")
	nested := map[string]any{}
	cur := nested
	for i := 0; i < 5000; i++ {
		n := map[string]any{}
		cur["a"] = n
		cur = n
	}
	recs := []map[string]any{nil, {}, {"user": strings.Repeat("A", 1<<20) + "svc-honey", "time": "x"}, {"deep": nested, "user": "svc-honey"},
		{"command": strings.Repeat("decoy-secret-valu", 100000)}}
	for i := 0; i < 30000; i++ {
		recs = append(recs, map[string]any{"time": "2026-11-12T10:00:00Z", "user": fmt.Sprintf("u%d", i), "message": strings.Repeat("x", 500) + fmt.Sprint(i), "f1": "a", "f2": "b", "ip": "1.2.3.4"})
	}
	start := time.Now()
	rep, fs := twScan(recs, "auth", "")
	if time.Since(start) > 6*time.Second {
		t.Fatalf("too slow: %s", time.Since(start))
	}
	if rep.Matched < 1 || len(fs) < 1 {
		t.Errorf("expected the deep-nested honey account to match: %+v", rep)
	}
	for _, f := range fs {
		if strings.ContainsAny(f.Description, "\x00\n") || len(f.Description) > 600 {
			t.Errorf("description %q", f.Description)
		}
	}
	recs = twRecords([]byte("not json\n" + strings.Repeat("y", webLineMax*2) + "\n\n"))
	if len(recs) != 2 || len(recs[1]["_line"].(string)) > webLineMax {
		t.Errorf("text records %d", len(recs))
	}
	if r := twRecords([]byte(`{"a":1}`)); len(r) != 1 || r[0]["a"] == nil {
		t.Errorf("json records %+v", r)
	}
}

func TestTripwireRulesRegistered(t *testing.T) {
	for _, a := range twRules {
		if m, ok := ruleMITRE[a.ID]; !ok || m.ID != a.TechID {
			t.Errorf("%s not registered", a.ID)
		}
		if _, ok := ResolveGuidance(a.ID); !ok {
			t.Errorf("no guidance for %s", a.ID)
		}
	}
}

func TestTripwireHTTPAndIngestHook(t *testing.T) {
	h := telHandler(t)
	t.Cleanup(func() { twReg.load("") })
	post := func(body string) map[string]any {
		w := telDo(h, "POST", "/v1/deception/tripwires", body, "tok")
		if w.Code != 201 {
			t.Fatalf("create %d %s", w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	if w := telDo(h, "POST", "/v1/deception/tripwires", `{"kind":"account","match":"svc-honey","label":"x"}`, ""); w.Code != 401 {
		t.Fatalf("unauth %d", w.Code)
	}
	acc := post(`{"kind":"account","match":"svc-honey","label":"honey admin"}`)
	val := post(`{"kind":"value","match":"AKIAZZZZEXAMPLEDECOY","label":"fake key"}`)
	if !strings.HasPrefix(val["match"].(string), "akia") || strings.Contains(val["match"].(string), "decoy") {
		t.Errorf("value should be masked in responses: %v", val["match"])
	}
	if g := telDo(h, "GET", "/v1/deception/tripwires", "", "tok"); g.Code != 200 || strings.Contains(g.Body.String(), "ezzzz") || !strings.Contains(g.Body.String(), "honey admin") {
		t.Errorf("list %d %s", g.Code, g.Body.String())
	}
	body := `{"time":"2026-11-12T08:00:00Z","user":"svc-honey","ip":"203.0.113.5","outcome":"failure"}`
	w := telDo(h, "POST", "/v1/auth/logs", body, "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"tripwire_hits":1`) {
		t.Fatalf("auth hook %d %s", w.Code, w.Body.String())
	}
	if g := telDo(h, "GET", "/v1/findings", "", "tok"); !strings.Contains(g.Body.String(), "tripwire-account-used") {
		t.Errorf("tripwire finding not stored")
	}
	w = telDo(h, "POST", "/v1/deception/tripwires/scan?source=proxy", "GET /x?k=AKIAZZZZEXAMPLEDECOY\nnothing here\n", "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"matched_records":1`) {
		t.Errorf("scan %d %s", w.Code, w.Body.String())
	}
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"POST", "/v1/deception/tripwires", `{"kind":"bogus","match":"abcdefg","label":"x"}`, 400},
		{"POST", "/v1/deception/tripwires", `not json`, 400},
		{"POST", "/v1/deception/tripwires", `{"kind":"account","match":"svc-honey","label":"dup"}`, 409},
		{"POST", "/v1/deception/tripwires/scan", "", 400},
		{"DELETE", "/v1/deception/tripwires/nope", "", 404},
	} {
		if w := telDo(h, c.method, c.path, c.body, "tok"); w.Code != c.code {
			t.Errorf("%s %s -> %d want %d", c.method, c.path, w.Code, c.code)
		}
	}
	if w := telDo(h, "DELETE", "/v1/deception/tripwires/"+acc["id"].(string), "", "tok"); w.Code != 200 {
		t.Errorf("delete %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/auth/logs", body, "tok"); strings.Contains(w.Body.String(), "tripwire_hits") {
		t.Errorf("deleted tripwire still matches")
	}
}
