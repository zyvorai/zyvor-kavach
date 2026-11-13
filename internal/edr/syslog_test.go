package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type sysCap struct {
	mu  sync.Mutex
	evs []SyslogEvent
}

func (c *sysCap) sink(e SyslogEvent) { c.mu.Lock(); c.evs = append(c.evs, e); c.mu.Unlock() }
func (c *sysCap) n() int             { c.mu.Lock(); defer c.mu.Unlock(); return len(c.evs) }

func startSys(t *testing.T, listen, allow string, tune func(*SyslogConfig)) (*SyslogListener, *sysCap) {
	t.Helper()
	cfg, err := ParseSyslogConfig(listen, allow)
	if err != nil {
		t.Fatal(err)
	}
	if tune != nil {
		tune(cfg)
	}
	c := &sysCap{}
	l := NewSyslogListener(cfg, c.sink)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l, c
}

func addrOf(l *SyslogListener, proto string) string {
	for _, a := range l.Addrs() {
		if strings.HasPrefix(a, proto+":") {
			return a[len(proto)+1:]
		}
	}
	return ""
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

const sshLine = "<38>Nov 13 10:00:01 gw1 sshd[812]: Accepted publickey for alice from 198.51.100.7 port 51234 ssh2"

func TestSyslogConfigRefusals(t *testing.T) {
	if _, err := ParseSyslogConfig("udp:127.0.0.1:514", ""); err == nil || !strings.Contains(err.Error(), "empty source allowlist") {
		t.Fatalf("empty allowlist must refuse: %v", err)
	}
	for _, bad := range []string{"udp:514", "tcp::514", "514", "ftp:1.2.3.4:5", ""} {
		if _, err := ParseSyslogConfig(bad, "10.0.0.0/8"); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, err := ParseSyslogConfig("udp:127.0.0.1:514", "not-a-cidr"); err == nil {
		t.Error("bad allowlist entry must refuse")
	}
	// Start refuses tls without cert.
	cfg, _ := ParseSyslogConfig("tls:127.0.0.1:0", "127.0.0.1")
	if err := NewSyslogListener(cfg, nil).Start(); err == nil {
		t.Error("tls without cert must refuse")
	}
}

func TestSyslogUDPAndTCPFraming(t *testing.T) {
	l, c := startSys(t, "udp:127.0.0.1:0,tcp:127.0.0.1:0", "127.0.0.1", nil)
	uc, _ := net.Dial("udp", addrOf(l, "udp"))
	defer uc.Close()
	_, _ = uc.Write([]byte(sshLine))
	tc, _ := net.Dial("tcp", addrOf(l, "tcp"))
	// newline framing, CRLF tolerated
	_, _ = tc.Write([]byte(sshLine + "\r\n"))
	// octet counting
	oc := "<38>Nov 13 10:00:02 gw1 sshd[812]: Failed password for bob from 198.51.100.8 port 22 ssh2"
	_, _ = tc.Write([]byte(fmt.Sprintf("%d %s", len(oc), oc)))
	// a line starting with digits that is not octet-counting
	_, _ = tc.Write([]byte("2024-11-13 not syslog at all\n"))
	waitFor(t, func() bool { return c.n() >= 3 && l.Status().Unparsed >= 1 })
	st := l.Status()
	if st.Received != 4 || st.ParsedBy["rfc3164"] != 3 || st.Unparsed != 1 {
		t.Fatalf("status %+v", st)
	}
	if s := l.Samples(); len(s) != 1 || !strings.HasPrefix(s[0], "2024-11-13") {
		t.Fatalf("samples %v", s)
	}
	tc.Close()
	// no response is ever written back: UDP read must time out
	_ = uc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := uc.Read(make([]byte, 64)); err == nil {
		t.Fatalf("listener wrote %d bytes back", n)
	}
}

func TestSyslogNoWriteBackTCP(t *testing.T) {
	l, c := startSys(t, "tcp:127.0.0.1:0", "127.0.0.1", nil)
	tc, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer tc.Close()
	_, _ = tc.Write([]byte(sshLine + "\n"))
	waitFor(t, func() bool { return c.n() == 1 })
	_ = tc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := tc.Read(make([]byte, 64)); err == nil {
		t.Fatalf("wrote back %d bytes", n)
	}
}

func TestSyslogOversize(t *testing.T) {
	l, c := startSys(t, "udp:127.0.0.1:0,tcp:127.0.0.1:0", "127.0.0.1", nil)
	big := "<13>" + strings.Repeat("A", syslogMaxMsg+10)
	uc, _ := net.Dial("udp", addrOf(l, "udp"))
	defer uc.Close()
	_, _ = uc.Write([]byte(big)) // may be refused by OS (EMSGSIZE) on some stacks; TCP path asserts below
	tc, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer tc.Close()
	_, _ = tc.Write([]byte(big + "\n" + sshLine + "\n")) // oversize line dropped, next line survives
	waitFor(t, func() bool { return c.n() == 1 })
	if l.Status().DroppedBy["oversize"] < 1 {
		t.Fatalf("oversize not counted: %+v", l.Status().DroppedBy)
	}
	// octet-counted oversize closes the connection
	tc2, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer tc2.Close()
	_, _ = tc2.Write([]byte("99999 x"))
	_ = tc2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := tc2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected close")
	}
}

func TestSyslogAllowlistRefusal(t *testing.T) {
	l, c := startSys(t, "udp:127.0.0.1:0,tcp:127.0.0.1:0", "10.99.0.0/16", nil)
	uc, _ := net.Dial("udp", addrOf(l, "udp"))
	defer uc.Close()
	_, _ = uc.Write([]byte(sshLine))
	tc, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer tc.Close()
	_, _ = tc.Write([]byte(sshLine + "\n"))
	waitFor(t, func() bool { return l.Status().DroppedBy["not_allowed"] >= 2 })
	if c.n() != 0 || l.Status().Received != 0 {
		t.Fatal("disallowed source was processed")
	}
}

func TestSyslogRateLimit(t *testing.T) {
	l, c := startSys(t, "udp:127.0.0.1:0", "127.0.0.1", func(cfg *SyslogConfig) { cfg.Rate, cfg.Burst = 1, 3 })
	uc, _ := net.Dial("udp", addrOf(l, "udp"))
	defer uc.Close()
	for i := 0; i < 30; i++ {
		_, _ = uc.Write([]byte(sshLine))
	}
	waitFor(t, func() bool { return l.Status().Received == 30 })
	st := l.Status()
	if st.RateLimited < 20 || st.DroppedBy["rate_limited"] != st.RateLimited {
		t.Fatalf("rate limit not applied: %+v", st)
	}
	waitFor(t, func() bool { return c.n() >= 1 })
	if _, ok := st.LastBySource["127.0.0.1"]; !ok {
		t.Fatal("last message per source missing")
	}
}

func TestSyslogMaxConnsAndQueue(t *testing.T) {
	l, _ := startSys(t, "tcp:127.0.0.1:0", "127.0.0.1", func(cfg *SyslogConfig) { cfg.MaxConns = 1 })
	a, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer a.Close()
	waitFor(t, func() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.conns == 1 })
	b, _ := net.Dial("tcp", addrOf(l, "tcp"))
	defer b.Close()
	waitFor(t, func() bool { return l.Status().DroppedBy["max_conns"] == 1 })

	// bounded queue: with no consumer, overflow is dropped and counted.
	cfg, _ := ParseSyslogConfig("udp:127.0.0.1:0", "127.0.0.1")
	q := NewSyslogListener(cfg, nil)
	for i := 0; i < syslogQueueCap+5; i++ {
		q.admit(fmt.Sprintf("10.0.%d.%d", 0, i%20), "x")
	}
	if q.Status().DroppedBy["queue_full"] != 5 {
		t.Fatalf("queue_full = %d", q.Status().DroppedBy["queue_full"])
	}
}

func TestSyslogShutdownNoLeak(t *testing.T) {
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	cfg, _ := ParseSyslogConfig("udp:127.0.0.1:0,tcp:127.0.0.1:0", "127.0.0.1")
	l := NewSyslogListener(cfg, nil)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	tc, _ := net.Dial("tcp", addrOf(l, "tcp"))
	_, _ = tc.Write([]byte(sshLine + "\n"))
	waitFor(t, func() bool { return l.Status().Received == 1 })
	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	tc.Close()
	if _, err := net.Dial("tcp", strings.TrimPrefix(l.Addrs()[1], "tcp:")); err == nil {
		t.Fatal("still listening")
	}
	var after int
	for i := 0; i < 50; i++ {
		after = runtime.NumGoroutine()
		if after <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d", before, after)
}

func TestSyslogImpersonationProtection(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterTelemetryRoutes(mux, "tok", st, nil)
	sink := storeSink(st)
	// A device claims to be the enrolled agent host "agent1" (and tries ':' tricks).
	for _, host := range []string{"agent1", "syslog:agent1", "agent1:evil"} {
		line := fmt.Sprintf("<38>Nov 13 10:00:01 %s sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2", host)
		m, ok := ParseSyslog(line, time.Now())
		if !ok {
			t.Fatal("parse")
		}
		for _, e := range NormaliseSyslog(m, "192.0.2.50", time.Now()) {
			if !strings.HasPrefix(e.Tel.Host, "syslog:") || strings.Count(e.Tel.Host, ":") != 1 {
				t.Fatalf("host %q", e.Tel.Host)
			}
			sink(e)
		}
	}
	if got := RecentTelemetry("auth", "agent1", 10); len(got) != 0 {
		t.Fatalf("syslog event landed on enrolled host: %v", got)
	}
	if got := RecentTelemetry("auth", "syslog:agent1", 10); len(got) < 1 {
		t.Fatalf("namespaced events missing")
	}
}

func TestSyslogEndToEndNetworkIngest(t *testing.T) {
	st, _ := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	mux := http.NewServeMux()
	RegisterTelemetryRoutes(mux, "tok", st, nil)
	m, _ := ParseSyslog("<134>date=2024-11-13 time=10:00:00 devname=fw1 type=traffic srcip=10.0.0.5 dstip=203.0.113.9 dstport=443 action=deny", time.Now())
	for _, e := range NormaliseSyslog(m, "192.0.2.1", time.Now()) {
		storeSink(st)(e)
	}
	ns := st.networkSnapshot()
	if len(ns) != 1 || ns[0].Destination != "203.0.113.9:443" || ns[0].Verdict != "deny" || ns[0].Source != "syslog:192.0.2.1" || ns[0].Host != "syslog:192.0.2.1" {
		t.Fatalf("%+v", ns)
	}
}

func TestSyslogParserGolden(t *testing.T) {
	now := time.Date(2024, 11, 13, 12, 0, 0, 0, time.UTC)
	type want struct {
		format, shape, typ, user, outcome, method, dst, verdict, host, query string
	}
	cases := []struct {
		name, line string
		w          want
	}{
		{"3164 ssh accepted", "<38>Nov 13 10:00:01 gw1 sshd[812]: Accepted publickey for alice from 198.51.100.7 port 51234 ssh2",
			want{format: "rfc3164", shape: "ssh-accepted-publickey", typ: "auth", user: "alice", outcome: "success", method: "ssh", host: "gw1"}},
		{"3164 ssh failed invalid", "<38>Nov 13 10:00:01 gw1 sshd[812]: Failed password for invalid user zed from 198.51.100.7 port 51234 ssh2",
			want{format: "rfc3164", shape: "ssh-failed-password", typ: "auth", user: "zed", outcome: "failure", method: "ssh", host: "gw1"}},
		{"3164 no host", "<86>Nov  3 09:00:00 sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
			want{format: "rfc3164", shape: "sudo-command", typ: "auth", user: "bob", outcome: "success", method: "sudo"}},
		{"sudo fail", "<85>Nov 13 10:00:01 h1 sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
			want{format: "rfc3164", shape: "sudo-failure", typ: "auth", user: "bob", outcome: "failure", method: "sudo", host: "h1"}},
		{"pam", "<85>Nov 13 10:00:01 h1 sshd[9]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=root",
			want{format: "rfc3164", shape: "pam-auth-failure", typ: "auth", user: "root", outcome: "failure", method: "ssh", host: "h1"}},
		{"5424 ssh", `<165>1 2024-11-13T10:00:01.003Z gw2 sshd 812 ID47 [exampleSDID@32473 iut="3" e="a\]b"] Accepted password for carol from 203.0.113.4 port 22 ssh2`,
			want{format: "rfc5424", shape: "ssh-accepted-password", typ: "auth", user: "carol", outcome: "success", method: "ssh", host: "gw2"}},
		{"5424 nil fields", `<34>1 - - - - - - Failed password for dave from 203.0.113.4 port 22 ssh2`,
			want{format: "rfc5424", shape: "ssh-failed-password", typ: "auth", user: "dave", outcome: "failure", method: "ssh"}},
		{"asa 106100", "<166>Nov 13 10:00:01 asa1 %ASA-6-106100: access-list outside_in denied tcp outside/198.51.100.7(4444) -> inside/10.1.1.5(22) hit-cnt 1 first hit",
			want{format: "rfc3164", shape: "cisco-asa-106100", typ: "network", dst: "10.1.1.5:22", verdict: "deny", host: "asa1"}},
		{"asa 106023", `<166>Nov 13 10:00:01 asa1 %ASA-4-106023: Deny tcp src outside:198.51.100.7/4444 dst inside:10.1.1.5/22 by access-group "outside_in"`,
			want{format: "rfc3164", shape: "cisco-asa-106023", typ: "network", dst: "10.1.1.5:22", verdict: "deny", host: "asa1"}},
		{"asa built", "<166>Nov 13 10:00:01 asa1 %ASA-6-302013: Built inbound TCP connection 1 for outside:198.51.100.7/4444 (198.51.100.7/4444) to inside:10.1.1.5/80 (10.1.1.5/80)",
			want{format: "rfc3164", shape: "cisco-asa-built", typ: "network", dst: "10.1.1.5:80", verdict: "allow", host: "asa1"}},
		{"fortinet", `<189>date=2024-11-13 time=10:00:00 devname="fw1" type="traffic" subtype="forward" srcip=10.0.0.5 dstip=203.0.113.9 dstport=443 action="accept"`,
			want{format: "rfc3164", shape: "fortinet-traffic", typ: "network", dst: "203.0.113.9:443", verdict: "allow"}},
		{"fortinet dns", `<189>date=2024-11-13 type="utm" subtype="dns" srcip=10.0.0.5 qname="evil.example.com" qtype="A"`,
			want{format: "rfc3164", shape: "fortinet-dns", typ: "dns", query: "evil.example.com"}},
		{"dnsmasq", "<30>Nov 13 10:00:01 dns1 dnsmasq[1]: query[A] example.org from 10.0.0.9",
			want{format: "rfc3164", shape: "dnsmasq-query", typ: "dns", query: "example.org", host: "dns1"}},
		{"pan traffic", "<14>Nov 13 10:00:01 pa1 1,2024/11/13 10:00:00,0011C103117,TRAFFIC,end,2562,2024/11/13 10:00:00,10.0.0.5,203.0.113.9,0.0.0.0,0.0.0.0,rule1,,,web-browsing,vsys1,trust,untrust,eth1,eth2,fwd,2024/11/13 10:00:00,1,1,51000,443,0,0,0x0,tcp,deny,100,100,0,1,2024/11/13 10:00:00",
			want{format: "rfc3164", shape: "paloalto-traffic", typ: "network", dst: "203.0.113.9:443", verdict: "deny", host: "pa1"}},
		{"cef flow", `CEF:0|Acme|FW|1.0|100|Connection blocked|5|src=10.0.0.5 dst=203.0.113.9 dpt=443 act=blocked msg=a\=b`,
			want{format: "cef", shape: "cef-flow", typ: "network", dst: "203.0.113.9:443", verdict: "deny"}},
		{"cef via syslog login", `<134>Nov 13 10:00:01 dev1 CEF:0|Acme|IDP|2|7|User login failed|3|suser=eve src=198.51.100.7 outcome=failure`,
			want{format: "cef", shape: "cef-auth", typ: "auth", user: "eve", outcome: "failure", method: "console", host: "dev1"}},
		{"leef2", "LEEF:2.0|Acme|FW|1.0|deny|^|src=10.0.0.5^dst=203.0.113.9^dstPort=8080^act=deny",
			want{format: "leef", shape: "leef-flow", typ: "network", dst: "203.0.113.9:8080", verdict: "deny"}},
		{"leef1 tab", "LEEF:1.0|Acme|FW|1.0|allow|src=10.0.0.5\tdst=203.0.113.9\tact=allow",
			want{format: "leef", shape: "leef-flow", typ: "network", dst: "203.0.113.9", verdict: "allow"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := ParseSyslog(tc.line, now)
			if !ok || m.Format != tc.w.format {
				t.Fatalf("ok=%v format=%q", ok, m.Format)
			}
			evs := NormaliseSyslog(m, "192.0.2.9", now)
			if len(evs) == 0 {
				t.Fatalf("no events: %+v", m)
			}
			e := evs[0]
			if e.Shape != tc.w.shape || e.Type != tc.w.typ {
				t.Fatalf("shape/type %s/%s", e.Shape, e.Type)
			}
			wantHost := "syslog:192.0.2.9"
			if tc.w.host != "" {
				wantHost = "syslog:" + tc.w.host
			}
			if e.Tel != nil {
				if e.Tel.Host != wantHost {
					t.Fatalf("host %q want %q", e.Tel.Host, wantHost)
				}
				if tc.w.typ == "auth" && (e.Tel.User != tc.w.user || e.Tel.Outcome != tc.w.outcome || e.Tel.Method != tc.w.method) {
					t.Fatalf("%+v", e.Tel)
				}
				if tc.w.typ == "dns" && e.Tel.Query != tc.w.query {
					t.Fatalf("%+v", e.Tel)
				}
				if err := e.Tel.Validate(e.Type); err != nil {
					t.Fatalf("validate: %v", err)
				}
			}
			if e.Net != nil {
				if e.Net.Destination != tc.w.dst || e.Net.Verdict != tc.w.verdict || e.Net.Host != wantHost || e.Net.Source != "syslog:192.0.2.9" {
					t.Fatalf("%+v", e.Net)
				}
			}
		})
	}
	// Envelope details.
	m, _ := ParseSyslog(`<165>1 2024-11-13T10:00:01.003Z gw2 sshd 812 ID47 [x@1 a="b\"c"][y@2] hi`, now)
	if m.Facility != 20 || m.Severity != 5 || m.SD["x@1"]["a"] != `b"c` || m.Body != "hi" || m.MsgID != "ID47" {
		t.Fatalf("%+v", m)
	}
	// Known shapes with no telemetry type: parsed, no event.
	m, ok := ParseSyslog(`<190>Nov 13 10:00:01 web1 nginx: 198.51.100.7 - bob [13/Nov/2024:10:00:00 +0000] "GET /x HTTP/1.1" 200 12 "-" "curl/8"`, now)
	if !ok || len(NormaliseSyslog(m, "192.0.2.9", now)) != 0 {
		t.Fatal("access line")
	}
	if _, ok := ParseSyslog(`198.51.100.7 - - [13/Nov/2024:10:00:00 +0000] "GET / HTTP/1.1" 404 0`, now); !ok {
		t.Fatal("bare access line should be recognised")
	}
	if _, ok := ParseSyslog("complete nonsense", now); ok {
		t.Fatal("nonsense should be unparsed")
	}
}

func TestSyslogRedaction(t *testing.T) {
	got := RedactSyslog(`login password=hunter2 token: abc123 Authorization: Bearer xyz.y api_key="k k" ok`)
	for _, leak := range []string{"hunter2", "abc123", "xyz.y", `k k`} {
		if strings.Contains(got, leak) {
			t.Fatalf("leaked %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "ok") {
		t.Fatal(got)
	}
}

func TestSyslogHTTPEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	registerSyslogRoutes(mux, "tok")
	do := func(method, path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, p := range []string{"/v1/syslog/status", "/v1/syslog/samples"} {
		if do("GET", p, "", "").Code != 401 {
			t.Fatalf("%s unauthenticated", p)
		}
	}
	if w := do("GET", "/v1/syslog/status", "", "tok"); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if do("POST", "/v1/syslog/parse", `{"line":"x"}`, "").Code != 401 {
		t.Fatal("parse unauthenticated")
	}
	b, _ := json.Marshal(map[string]string{"line": sshLine})
	w := do("POST", "/v1/syslog/parse", string(b), "tok")
	var out struct {
		Parsed   bool
		Ingested bool
		Events   []SyslogEvent
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || !out.Parsed || out.Ingested || len(out.Events) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if do("POST", "/v1/syslog/parse", `{"line":"`+strings.Repeat("a", syslogMaxMsg+1)+`"}`, "tok").Code != 400 {
		t.Fatal("oversize parse must 400")
	}
}

func FuzzSyslogParse(f *testing.F) {
	for _, s := range []string{sshLine, `<165>1 2024-11-13T10:00:01Z h a p m [x@1 a="b"] hi`, "CEF:0|a|b|c|d|e|5|k=v x=y", "LEEF:2.0|a|b|c|d|^|k=v", "<", "<999>", bytes.NewBufferString("\x00\xff").String()} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > syslogMaxMsg {
			s = s[:syslogMaxMsg]
		}
		m, ok := ParseSyslog(s, time.Unix(1700000000, 0))
		if ok {
			for _, e := range NormaliseSyslog(m, "192.0.2.1", time.Unix(1700000000, 0)) {
				if e.Tel != nil && !strings.HasPrefix(e.Tel.Host, "syslog:") {
					t.Fatal("host namespace")
				}
			}
		}
		_ = RedactSyslog(s)
	})
}
