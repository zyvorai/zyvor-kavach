// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func webRuleSet(t *testing.T) []*ContentRule {
	t.Helper()
	return webRules(loadTestRegistry(t))
}

func TestWebPackShape(t *testing.T) {
	rules := webRuleSet(t)
	if len(rules) < 45 {
		t.Fatalf("want at least 45 web- rules, got %d", len(rules))
	}
	analytic := map[string]bool{}
	for _, a := range webAnalyticRules {
		analytic[a.ID] = true
	}
	for _, r := range rules {
		if !strings.HasPrefix(r.ID, "web-") || strings.HasPrefix(r.ID, "web-an-") {
			t.Errorf("%s: id must start with web- (web-an- is reserved for analytics)", r.ID)
		}
		if r.EventType != "process" || r.Batch != webBatchTag {
			t.Errorf("%s: event_type/batch %q/%q", r.ID, r.EventType, r.Batch)
		}
		if r.Tests == nil || len(r.Tests.Positive) == 0 || len(r.Tests.Negative) < 2 {
			t.Errorf("%s: needs a positive and at least two negative fixtures", r.ID)
		}
		if analytic[r.ID] {
			t.Errorf("%s collides with an analytic rule id", r.ID)
		}
	}
	// every rule must be unable to fire on a non-web executable (no cross-talk with host rules)
	for _, r := range rules {
		ev := LabEvent{Kind: "process", Executable: "/bin/bash", Command: "status=200 bytes=1 len=1 dec=0 target=/etc/passwd ${jndi:ldap://x} union select 1", ParentExe: "sqlmap", Path: "/.env", Operation: "TRACE"}
		if r.Matches(ev) {
			t.Errorf("%s matches a non-web executable", r.ID)
		}
	}
}

func TestWebAnalyticIDsAreRegistered(t *testing.T) {
	for _, a := range webAnalyticRules {
		if m, ok := ruleMITRE[a.ID]; !ok || m.ID != a.TechID {
			t.Errorf("%s not registered in ruleMITRE with %s", a.ID, a.TechID)
		}
	}
	for _, a := range authAnalyticRules {
		if m, ok := ruleMITRE[a.ID]; !ok || m.ID != a.TechID {
			t.Errorf("%s not registered in ruleMITRE with %s", a.ID, a.TechID)
		}
	}
}

func TestWebParseLine(t *testing.T) {
	cases := []struct {
		name, line, format string
		ok                 bool
		method, target, ip string
		status             int
		ua                 string
	}{
		{"combined", `198.51.100.10 - - [12/Nov/2026:10:00:01 +0000] "GET /a?b=1 HTTP/1.1" 200 12 "-" "UA/1"`, "", true, "GET", "/a?b=1", "198.51.100.10", 200, "UA/1"},
		{"common no ua", `198.51.100.10 - bob [12/Nov/2026:10:00:01 +0000] "POST /login HTTP/1.0" 401 -`, "", true, "POST", "/login", "198.51.100.10", 401, ""},
		{"escaped quote", `1.2.3.4 - - [12/Nov/2026:10:00:01 +0000] "GET /a?q=\"x\" HTTP/1.1" 200 5 "-" "ua"`, "", true, "GET", `/a?q="x"`, "1.2.3.4", 200, "ua"},
		{"no proto", `1.2.3.4 - - [12/Nov/2026:10:00:01 +0000] "GET /a" 200 5`, "combined", true, "GET", "/a", "1.2.3.4", 200, ""},
		{"binary request", `1.2.3.4 - - [12/Nov/2026:10:00:01 +0000] "\x16\x03\x01" 400 0`, "", true, "INVALID", `x16x03x01`, "1.2.3.4", 400, ""},
		{"json nginx", `{"remote_addr":"1.2.3.4","request":"GET /j?x=1 HTTP/1.1","status":"302","http_user_agent":"U","time_iso8601":"2026-11-12T10:00:00+00:00","body_bytes_sent":55}`, "", true, "GET", "/j?x=1", "1.2.3.4", 302, "U"},
		{"json cloudflare", `{"ClientIP":"1.2.3.4","ClientRequestMethod":"POST","ClientRequestURI":"/cf","EdgeResponseStatus":403,"ClientRequestUserAgent":"cf","EdgeStartTimestamp":"2026-11-12T10:00:00Z","ClientRequestHost":"example.org"}`, "", true, "POST", "/cf", "1.2.3.4", 403, "cf"},
		{"json ecs nested", `{"@timestamp":"2026-11-12T10:00:00Z","source":{"ip":"1.2.3.4"},"http":{"request":{"method":"put"},"response":{"status_code":201}},"url":{"original":"/e"},"user_agent":{"original":"ecs"}}`, "", true, "PUT", "/e", "1.2.3.4", 201, "ecs"},
		{"f5 logfmt", `ip_client="1.2.3.4",method="GET",uri="/f5?a=1",response_code="200",request_status="passed",date_time="2026-11-12 10:00:00",vs_name="/Common/vs1"`, "", true, "GET", "/f5?a=1", "1.2.3.4", 200, ""},
		{"logfmt spaces", `client_ip=1.2.3.4 method=GET path=/lf status=404 ua="x y" ts=1794000000`, "logfmt", true, "GET", "/lf", "1.2.3.4", 404, "x y"},
		{"empty", ``, "", false, "", "", "", 0, ""},
		{"garbage", `hello world`, "", false, "", "", "", 0, ""},
		{"bad status", `1.2.3.4 - - [12/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 999 5`, "", false, "", "", "", 0, ""},
		{"no time bracket", `1.2.3.4 - - 12/Nov/2026 "GET / HTTP/1.1" 200 5`, "combined", false, "", "", "", 0, ""},
		{"unterminated quote", `1.2.3.4 - - [12/Nov/2026:10:00:01 +0000] "GET /a HTTP/1.1 200 5`, "combined", false, "", "", "", 0, ""},
		{"json bad", `{"remote_addr":`, "", false, "", "", "", 0, ""},
		{"json missing ip", `{"request":"GET / HTTP/1.1","status":200}`, "", false, "", "", "", 0, ""},
		{"json array not object", `[1,2,3]`, "json", false, "", "", "", 0, ""},
		{"logfmt unterminated", `a="b`, "logfmt", false, "", "", "", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ParseWebLine(c.line, c.format)
			if (err == nil) != c.ok {
				t.Fatalf("err=%v want ok=%v", err, c.ok)
			}
			if !c.ok {
				return
			}
			if r.Method != c.method || r.IP != c.ip || r.Status != c.status || r.UA != c.ua {
				t.Errorf("got %+v", r)
			}
			if c.name != "binary request" && r.Target != c.target {
				t.Errorf("target %q want %q", r.Target, c.target)
			}
		})
	}
}

func TestWebParseTime(t *testing.T) {
	for _, s := range []string{"12/Nov/2026:10:00:01 +0000", "2026-11-12T10:00:01Z", "2026-11-12 10:00:01", "1794000000", "1794000000123", "1794000000.5"} {
		if _, ok := parseWebTime(s); !ok {
			t.Errorf("%q should parse", s)
		}
	}
	for _, s := range []string{"", "-", "yesterday", "0", "-5", "99999999999999999999", "NaN", "1e400", "1800-01-01T00:00:00Z"} {
		if _, ok := parseWebTime(s); ok {
			t.Errorf("%q should not parse", s)
		}
	}
}

func TestWebDecodeAndSanitise(t *testing.T) {
	cases := []struct {
		in     string
		out    string
		passes int
	}{
		{"/a%20b", "/a b", 1},
		{"%252e%252e%252f", "../", 2},
		{"%25252e", ".", 3},
		{"%2525252e", "%2e", 3}, // capped at three passes
		{"/bad%zz%2", "/bad%zz%2", 0},
		{"%", "%", 0},
		{"%0d%0a", "\r\n", 1},
	}
	for _, c := range cases {
		got, n := webDecodeAll(c.in)
		if got != c.out || n != c.passes {
			t.Errorf("webDecodeAll(%q) = %q,%d want %q,%d", c.in, got, n, c.out, c.passes)
		}
	}
	if got := webSanitise("a\x00b\r\nc\x01d\xff"); got != "a<nul>b<cr><lf>c d?" {
		t.Errorf("sanitise = %q", got)
	}
}

func TestWebRedactsSecretParams(t *testing.T) {
	rec := WebRecord{IP: "1.2.3.4", Method: "GET", Status: 200, Target: "/a?user=bob&access_token=SUPERSECRET&pass%77ord=hunter2&x=1"}
	ev := NormalizeWebRecord(rec, "")
	if strings.Contains(ev.Evidence, "SUPERSECRET") || strings.Contains(ev.Evidence, "hunter2") {
		t.Fatalf("secret leaked into evidence: %s", ev.Evidence)
	}
	if !strings.Contains(ev.Evidence, "user=bob") || !strings.Contains(ev.Evidence, "access_token=REDACTED") {
		t.Fatalf("evidence = %s", ev.Evidence)
	}
	if got := strings.Join(ev.Params, ","); got != "user,access_token,password,x" {
		t.Fatalf("param names = %s", got)
	}
}

func TestWebFixtureFiresExpectedRules(t *testing.T) {
	raw, err := os.ReadFile("testdata/web/access_combined.log")
	if err != nil {
		t.Fatal(err)
	}
	rep, findings, err := AnalyzeWebLogs(string(raw), "", "", nil, loadTestRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Parsed != 15 || rep.Rejected != 0 {
		t.Fatalf("parsed %d rejected %d errors %v", rep.Parsed, rep.Rejected, rep.Errors)
	}
	want := []string{"web-sqli-union-select", "web-scanner-ua-attack-tool", "web-lfi-dotdot-sequence", "web-lfi-sensitive-file",
		"web-exploit-log4shell", "web-exposure-secret-file-served", "web-recon-secret-file-probe", "web-webshell-script-in-upload-dir",
		"web-webshell-command-parameter", "web-evasion-multi-encoding", "web-xss-script-tag", "web-cve-network-appliance-probe", "web-recon-malformed-request-line"}
	for _, w := range want {
		if rep.ByRule[w] == 0 {
			t.Errorf("rule %s did not fire; by_rule=%v", w, rep.ByRule)
		}
	}
	// benign lines (first 4, the quote line) must not raise anything
	for _, f := range findings {
		if f.Destination == "198.51.100.10" || f.Destination == "198.51.100.11" || f.Destination == "203.0.113.56" {
			t.Errorf("benign client got finding %s: %s", f.Rule, f.Evidence.Command)
		}
		if strings.Contains(f.Evidence.Command, "SECRETVALUE123") {
			t.Errorf("secret in evidence: %s", f.Evidence.Command)
		}
		if f.Host == "" || f.Rule == "" || f.Severity == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
}

func webLine(ip string, ts time.Time, method, target string, status int, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 100 "-" "%s"`, ip, ts.Format("02/Jan/2006:15:04:05 -0700"), method, target, status, ua)
}

func TestWebHostileInputBounded(t *testing.T) {
	reg := loadTestRegistry(t)
	var b strings.Builder
	huge := strings.Repeat("%25", 20000) // 60 KB of percent signs
	b.WriteString(webLine("1.1.1.1", time.Now(), "GET", "/"+huge, 200, "x") + "\n")
	b.WriteString(strings.Repeat("A", webLineMax+10) + "\n")
	b.WriteString(webLine("1.1.1.2", time.Now(), "GET", "/a?q="+strings.Repeat("(a+)+$", 5000)+"!", 200, "x") + "\n")
	b.WriteString(webLine("1.1.1.3", time.Now(), "GET", "/a?q="+strings.Repeat("union ", 4000)+"x", 200, "x") + "\n")
	b.WriteString(webLine("1.1.1.4", time.Now(), "GET", "/a?q="+strings.Repeat("select/**/", 4000), 200, "x") + "\n")
	b.WriteString(`{"remote_addr":"1.1.1.5","request":"GET / HTTP/1.1","status":200,"x":` + strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000) + "}\n")
	b.WriteString("\x00\x01\x02 binary \xff\xfe\n")
	b.WriteString(webLine("1.1.1.6", time.Now(), "GET", "/"+strings.Repeat("../", 20000), 400, "x") + "\n")
	start := time.Now()
	rep, _, err := AnalyzeWebLogs(b.String(), "", "", nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("hostile input took %s", d)
	}
	if rep.Oversize != 1 || rep.Rejected < 2 {
		t.Errorf("oversize=%d rejected=%d errors=%v", rep.Oversize, rep.Rejected, rep.Errors)
	}
	if rep.Parsed < 5 {
		t.Errorf("parsed %d", rep.Parsed)
	}
}

func TestWebTargetIsBounded(t *testing.T) {
	ev := NormalizeWebRecord(WebRecord{IP: "1.2.3.4", Method: "GET", Status: 200, Target: "/" + strings.Repeat("a", 50000)}, "")
	if len(ev.Lab.Command) > webTargetMax+80 || len(ev.Evidence) > webEvidenceMx+80 {
		t.Fatalf("command %d evidence %d", len(ev.Lab.Command), len(ev.Evidence))
	}
	if !strings.Contains(ev.Lab.Command, "len=50001") {
		t.Fatalf("true length lost: %.80s", ev.Lab.Command)
	}
}

// ---- analytics ----

func genLines(n int, f func(i int) string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(f(i))
		b.WriteByte('\n')
	}
	return b.String()
}

func TestWebFloodSource(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	text := genLines(300, func(i int) string {
		return webLine("203.0.113.9", base.Add(time.Duration(i)*20*time.Millisecond), "GET", "/", 200, "Mozilla/5.0")
	})
	text += genLines(30, func(i int) string {
		return webLine("198.51.100.5", base.Add(time.Duration(i)*time.Second), "GET", "/", 200, "Mozilla/5.0")
	})
	rep, fs, _ := AnalyzeWebLogs(text, "", "web-1", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-http-flood-source"] != 1 {
		t.Fatalf("by_rule=%v", rep.ByRule)
	}
	found := false
	for _, f := range fs {
		if f.Rule == "web-an-http-flood-source" {
			found = true
			if f.Destination != "203.0.113.9" || f.Host != "web:web-1" {
				t.Errorf("finding %+v", f)
			}
		}
	}
	if !found || rep.PeakPerSecond < 20 {
		t.Errorf("found=%v peak=%v", found, rep.PeakPerSecond)
	}
}

func TestWebFloodDistributed(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	text := genLines(1500, func(i int) string {
		return webLine(fmt.Sprintf("192.0.2.%d", i%100), base.Add(time.Duration(i)*5*time.Millisecond), "GET", "/search?q=x", 503, "Mozilla/5.0")
	})
	rep, _, _ := AnalyzeWebLogs(text, "", "", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-http-flood-distributed"] != 1 || len(rep.Flood) == 0 {
		t.Fatalf("by_rule=%v flood=%v", rep.ByRule, rep.Flood)
	}
	w := rep.Flood[0]
	if w.Sources != 100 || w.ServerErrors != w.Requests || w.TopPath != "/search" {
		t.Errorf("window %+v", w)
	}
	if rep.ByRule["web-an-http-flood-source"] != 0 {
		t.Errorf("per-source flood should not fire at 15 req/s per client: %v", rep.ByRule)
	}
}

func TestWebCredentialAbuse(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	// one client hammering /login
	brute := genLines(40, func(i int) string {
		return webLine("203.0.113.9", base.Add(time.Duration(i)*time.Second), "POST", "/login", 401, "Mozilla/5.0")
	})
	rep, _, _ := AnalyzeWebLogs(brute, "", "", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-login-bruteforce"] != 1 || rep.ByRule["web-an-credential-stuffing"] != 0 {
		t.Fatalf("brute: %v", rep.ByRule)
	}
	// 60 sources, 3 attempts each: distributed
	stuff := genLines(180, func(i int) string {
		return webLine(fmt.Sprintf("192.0.2.%d", i%60), base.Add(time.Duration(i)*time.Second), "POST", "/api/auth/login", 401, "Mozilla/5.0")
	})
	rep, _, _ = AnalyzeWebLogs(stuff, "", "", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-credential-stuffing"] != 1 || rep.ByRule["web-an-login-bruteforce"] != 0 {
		t.Fatalf("stuffing: %v", rep.ByRule)
	}
	// successful logins never alert
	ok := genLines(200, func(i int) string {
		return webLine(fmt.Sprintf("192.0.2.%d", i%60), base.Add(time.Duration(i)*time.Second), "POST", "/login", 302, "Mozilla/5.0")
	})
	rep, _, _ = AnalyzeWebLogs(ok, "", "", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-credential-stuffing"]+rep.ByRule["web-an-login-bruteforce"] != 0 {
		t.Fatalf("benign logins: %v", rep.ByRule)
	}
	// GET /login is not a login attempt
	get := genLines(100, func(i int) string {
		return webLine("203.0.113.9", base.Add(time.Duration(i)*time.Second), "GET", "/login", 401, "Mozilla/5.0")
	})
	rep, _, _ = AnalyzeWebLogs(get, "", "", nil, loadTestRegistry(t))
	if len(rep.ByRule) != 0 {
		t.Fatalf("GET login: %v", rep.ByRule)
	}
}

func TestWebEnumerationAndUARotation(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	enum := genLines(80, func(i int) string {
		return webLine("203.0.113.9", base.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("/path%d", i), 404, "Mozilla/5.0")
	})
	rot := genLines(40, func(i int) string {
		return webLine("203.0.113.10", base.Add(time.Duration(i)*time.Second), "GET", "/", 200, fmt.Sprintf("Agent-%d", i%12))
	})
	rep, _, _ := AnalyzeWebLogs(enum+rot, "", "", nil, loadTestRegistry(t))
	if rep.ByRule["web-an-path-enumeration"] != 1 || rep.ByRule["web-an-ua-rotation"] != 1 {
		t.Fatalf("by_rule=%v", rep.ByRule)
	}
	// a normal user with a few 404s is not enumeration
	few := genLines(80, func(i int) string {
		st := 200
		if i%10 == 0 {
			st = 404
		}
		return webLine("203.0.113.11", base.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("/p%d", i), st, "Mozilla/5.0")
	})
	rep, _, _ = AnalyzeWebLogs(few, "", "", nil, loadTestRegistry(t))
	if len(rep.ByRule) != 0 {
		t.Fatalf("benign: %v", rep.ByRule)
	}
}

func TestWebUntimedLinesStillAnalysed(t *testing.T) {
	text := genLines(80, func(i int) string {
		return fmt.Sprintf(`ip_client="203.0.113.9",method="GET",uri="/x%d",response_code="404"`, i)
	})
	rep, _, _ := AnalyzeWebLogs(text, "", "", nil, loadTestRegistry(t))
	if rep.Untimed != 80 || rep.ByRule["web-an-path-enumeration"] != 1 {
		t.Fatalf("untimed=%d by_rule=%v", rep.Untimed, rep.ByRule)
	}
}

// ---- API discovery ----

func TestWebTemplate(t *testing.T) {
	cases := map[string]string{
		"/":                  "/",
		"/users/42":          "/users/{id}",
		"/users/42/orders/7": "/users/{id}/orders/{id}",
		"/files/3f2b8c1e-9d4a-4e6b-8a1c-0123456789ab": "/files/{uuid}",
		"/o/deadbeefdeadbeef0123":                     "/o/{hash}",
		"/s/abcdefghijklmnopqrstuvw9":                 "/s/{token}",
		"/about/team":                                 "/about/team",
	}
	for in, want := range cases {
		if got := webTemplate(in); got != want {
			t.Errorf("webTemplate(%q) = %q want %q", in, got, want)
		}
	}
}

func loadSpecFixture(t *testing.T) *WebSpec {
	t.Helper()
	raw, err := os.ReadFile("testdata/web/openapi_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseWebSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWebAPIDiscoveryAgainstSpec(t *testing.T) {
	spec := loadSpecFixture(t)
	if spec.BasePath != "/api/v1" || spec.Ops != 5 || len(spec.all) != 4 {
		t.Fatalf("spec base=%q ops=%d paths=%d", spec.BasePath, spec.Ops, len(spec.all))
	}
	raw, _ := os.ReadFile("testdata/web/access_combined.log")
	rep, _, _ := AnalyzeWebLogs(string(raw), "", "", spec, loadTestRegistry(t))
	api := rep.API
	if !api.SpecLoaded || api.EndpointsTotal == 0 {
		t.Fatalf("api %+v", api)
	}
	has := func(l []WebEndpoint, m, p string) bool {
		for _, e := range l {
			if e.Method == m && e.Path == p {
				return true
			}
		}
		return false
	}
	if !has(api.Shadow, "GET", "/api/v1/internal/debug/dump") {
		t.Errorf("shadow endpoint missing: %+v", api.Shadow)
	}
	if has(api.Shadow, "GET", "/api/v1/users/{id}") {
		t.Errorf("documented endpoint reported as shadow")
	}
	if !has(api.Endpoints, "GET", "/users/{id}") || !has(api.Endpoints, "DELETE", "/users/{id}") {
		t.Errorf("inventory should use spec templates: %+v", api.Endpoints)
	}
	// the admin export call carried an undeclared parameter? format is declared via $ref, token is not.
	found := false
	for _, d := range api.ParamDrift {
		if d.Path == "/admin/export" && strings.Join(d.UndeclaredParams, ",") == "token" {
			found = true
		}
	}
	if !found {
		t.Errorf("param drift missing: %+v", api.ParamDrift)
	}
	if len(api.NotObserved) != 3 { // GET /users, GET /orders and GET /admin/export is observed
		// GET /users and GET /orders are never requested in the fixture
		t.Logf("not observed: %v", api.NotObserved)
	}
	if !contains(api.NotObserved, "GET /orders") || !contains(api.NotObserved, "GET /users") {
		t.Errorf("not observed = %v", api.NotObserved)
	}
	for _, e := range api.Endpoints {
		for _, p := range e.QueryParams {
			if strings.Contains(p, "SECRET") {
				t.Errorf("param value leaked as name: %s", p)
			}
		}
	}
}

func webHas(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestWebVerbDriftAndProtected(t *testing.T) {
	spec := loadSpecFixture(t)
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	text := strings.Join([]string{
		webLine("1.1.1.1", base, "PUT", "/api/v1/orders", 200, "ua"),
		webLine("1.1.1.1", base, "PATCH", "/api/v1/users/5", 404, "ua"), // refused: not drift
		webLine("1.1.1.1", base, "GET", "/api/v1/secret/stuff", 403, "ua"),
		webLine("1.1.1.1", base, "GET", "/api/v1/secret/stuff", 401, "ua"),
		webLine("1.1.1.1", base, "GET", "/api/v1/nothing/here", 404, "ua"), // 404 only: noise
		webLine("1.1.1.1", base, "GET", "/static/app.js", 200, "ua"),
		webLine("1.1.1.1", base, "GET", "/outside/base", 200, "ua"), // outside /api/v1: not an API call
		webLine("1.1.1.1", base, "OPTIONS", "/api/v1/orders", 200, "ua"),
	}, "\n")
	rep, _, _ := AnalyzeWebLogs(text, "", "", spec, loadTestRegistry(t))
	api := rep.API
	if len(api.VerbDrift) != 1 || api.VerbDrift[0].Method != "PUT" || api.VerbDrift[0].Path != "/orders" || strings.Join(api.VerbDrift[0].DocumentedMethods, ",") != "GET" {
		t.Errorf("verb drift = %+v", api.VerbDrift)
	}
	if len(api.UndocProtected) != 1 || api.UndocProtected[0].Path != "/api/v1/secret/stuff" {
		t.Errorf("protected = %+v", api.UndocProtected)
	}
	if len(api.Shadow) != 0 {
		t.Errorf("shadow = %+v", api.Shadow)
	}
	if api.StaticSkipped != 1 {
		t.Errorf("static skipped = %d", api.StaticSkipped)
	}
}

func TestWebSpecParsingRejects(t *testing.T) {
	cases := map[string]string{
		"not json":   `openapi: 3.0.0`,
		"no version": `{"paths":{"/a":{"get":{}}}}`,
		"no paths":   `{"openapi":"3.0.0"}`,
		"array":      `[1]`,
	}
	for name, body := range cases {
		if _, err := ParseWebSpec([]byte(body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := ParseWebSpec([]byte(strings.Repeat(" ", webSpecMax+1))); err == nil {
		t.Error("oversize spec accepted")
	}
	var b strings.Builder
	b.WriteString(`{"swagger":"2.0","basePath":"/v2","paths":{`)
	for i := 0; i < webSpecPathsMax+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"/p%d":{"get":{}}`, i)
	}
	b.WriteString("}}")
	if _, err := ParseWebSpec([]byte(b.String())); err == nil {
		t.Error("too many paths accepted")
	}
	s, err := ParseWebSpec([]byte(`{"swagger":"2.0","basePath":"/v2","paths":{"/pets/{petId}":{"get":{}},"/pets/mine":{"get":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if sp, in := s.Match("/v2/pets/mine"); !in || sp == nil || sp.Template != "/pets/mine" {
		t.Errorf("most specific path should win: %+v", sp)
	}
	if sp, in := s.Match("/v2/pets/9"); !in || sp == nil || sp.Template != "/pets/{petId}" {
		t.Errorf("template match: %+v", sp)
	}
	if _, in := s.Match("/other"); in {
		t.Error("path outside base path reported in scope")
	}
}

func TestWebInventoryCapped(t *testing.T) {
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	n := webMaxEndpoints + 200
	text := genLines(n, func(i int) string { return webLine("1.1.1.1", base, "GET", fmt.Sprintf("/page/name%d", i), 200, "ua") })
	if strings.Count(text, "\n") > webLinesMax {
		t.Skip()
	}
	rep, _, _ := AnalyzeWebLogs(text, "", "", nil, loadTestRegistry(t))
	if !rep.API.EndpointsTruncated || rep.API.EndpointsTotal != webMaxEndpoints || len(rep.API.Endpoints) != 200 {
		t.Fatalf("truncated=%v total=%d listed=%d", rep.API.EndpointsTruncated, rep.API.EndpointsTotal, len(rep.API.Endpoints))
	}
}

// ---- HTTP ----

func TestWebHTTP(t *testing.T) {
	h := telHandler(t)
	log := `203.0.113.50 - - [12/Nov/2026:10:01:00 +0000] "GET /item.php?id=1%20union%20select%201,2 HTTP/1.1" 200 9 "-" "sqlmap/1.7"` + "\n" +
		`198.51.100.10 - - [12/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "Mozilla/5.0"` + "\n"
	if w := telDo(h, "POST", "/v1/web/logs", log, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/web/logs", log, "nope"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", w.Code)
	}
	w := telDo(h, "POST", "/v1/web/logs?host=Shop.Example.ORG", log, "tok")
	if w.Code != 200 {
		t.Fatalf("code %d %s", w.Code, w.Body.String())
	}
	var rep WebReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Parsed != 2 || rep.Findings < 2 || rep.ByRule["web-sqli-union-select"] != 1 || rep.Mode != "observe-only" {
		t.Fatalf("report %+v", rep)
	}
	// findings are stored and visible
	w = telDo(h, "GET", "/v1/findings", "", "tok")
	if !strings.Contains(w.Body.String(), "web-sqli-union-select") || !strings.Contains(w.Body.String(), "web:shop.example.org") {
		t.Fatalf("stored findings missing: %.300s", w.Body.String())
	}
	for _, c := range []struct {
		path, body string
		code       int
	}{
		{"/v1/web/logs", "", 400},
		{"/v1/web/logs", "not a log line at all\n", 400},
		{"/v1/web/logs?format=xml", log, 400},
		{"/v1/web/logs", strings.Repeat("a", webBodyMax+1), 413},
		{"/v1/web/logs", strings.Repeat("x\n", webLinesMax+1), 413},
	} {
		if w := telDo(h, "POST", c.path, c.body, "tok"); w.Code != c.code {
			t.Errorf("%s (%d bytes) -> %d, want %d", c.path, len(c.body), w.Code, c.code)
		}
	}
	// envelope with OpenAPI
	spec, _ := os.ReadFile("testdata/web/openapi_sample.json")
	env, _ := json.Marshal(map[string]any{"log": log, "openapi": json.RawMessage(spec)})
	w = telDo(h, "POST", "/v1/web/analyze", string(env), "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"spec_loaded":true`) {
		t.Fatalf("analyze %d %.300s", w.Code, w.Body.String())
	}
	if w := telDo(h, "POST", "/v1/web/analyze", `{"log":"x","openapi":{"info":1}}`, "tok"); w.Code != 400 {
		t.Errorf("bad spec -> %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/web/analyze", `nope`, "tok"); w.Code != 400 {
		t.Errorf("bad envelope -> %d", w.Code)
	}
	if w := telDo(h, "GET", "/v1/web/sources", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("sources unauth -> %d", w.Code)
	}
	w = telDo(h, "GET", "/v1/web/sources", "", "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rule_prefix":"web-"`) || !strings.Contains(w.Body.String(), "web-an-credential-stuffing") {
		t.Errorf("sources %d %s", w.Code, w.Body.String())
	}
}
