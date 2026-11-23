// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func netFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "network", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func netRulesOf(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Rule]++
	}
	return m
}

func TestNetFixtures(t *testing.T) {
	bad, _ := netParseBadNets(string(netFixture(t, "badips.txt")))
	fps := netParseFPs(string(netFixture(t, "fingerprints.txt")))
	cases := []struct {
		file, format string
		want         []string
		notWant      []string
		minParsed    int
	}{
		{"zeek_conn.log", "auto", []string{"net-an-beaconing", "net-an-port-scan-vertical", "net-an-port-scan-horizontal", "net-an-long-connection", "net-an-smb-fanout", "net-an-login-bruteforce"}, nil, 150},
		{"zeek_ssl.log", "auto", []string{"net-an-tls-selfsigned", "net-an-tls-fingerprint-match"}, []string{"net-an-tls-expired"}, 3},
		{"zeek_x509.log", "auto", []string{"net-an-tls-expired"}, nil, 2},
		{"zeek_ssh.log", "auto", []string{"net-an-login-bruteforce", "net-an-ssh-guesser-success"}, nil, 13},
		{"zeek_json.log", "auto", []string{"net-an-zeek-notice", "net-an-smb-admin-share"}, nil, 4},
		{"eve.json", "auto", []string{"net-eve-c2", "net-eve-exploit", "net-an-alert-storm", "net-eve-dos", "net-eve-credential", "net-eve-policy", "net-eve-recon", "net-an-tls-selfsigned", "net-an-tls-expired", "net-an-tls-fingerprint-match"}, nil, 200},
		{"dns_queries.json", "auto", []string{"net-an-dns-dga", "net-an-dns-tunnel", "net-an-dns-nxdomain-storm", "net-an-dns-fast-flux"}, nil, 200},
		{"vpc_flow.log", "auto", []string{"net-an-exfil-volume", "net-an-port-scan-horizontal"}, nil, 40},
		{"netflow.csv", "auto", []string{"net-an-exfil-volume", "net-an-badlist-contact"}, nil, 16},
		{"panos.log", "auto", []string{"net-an-fw-config-change", "net-an-fw-allow-after-deny"}, nil, 25},
		{"fortigate.log", "auto", []string{"net-an-fw-admin-login-failed", "net-an-fw-config-change", "net-an-fw-threat-allowed"}, nil, 10},
		{"asa.log", "auto", []string{"net-an-fw-config-change"}, nil, 5},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			rep, fs, err := NetRun(netFixture(t, c.file), c.format, NetOptions{BadNets: bad, FPs: fps})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Parsed < c.minParsed {
				t.Errorf("parsed %d, want >= %d (errors %v)", rep.Parsed, c.minParsed, rep.Errors)
			}
			got := netRulesOf(fs)
			for _, w := range c.want {
				if got[w] == 0 {
					t.Errorf("rule %s missing; got %v", w, got)
				}
			}
			for _, w := range c.notWant {
				if got[w] != 0 {
					t.Errorf("rule %s fired unexpectedly", w)
				}
			}
			for _, f := range fs {
				if strings.Contains(f.Description+f.Evidence.Command, "hunter2") || strings.Contains(f.Description+f.Evidence.Command, "Sup3rSecret") || strings.Contains(f.Description, "ABCDEF1234567890") {
					t.Errorf("secret leaked into finding: %s", f.Description)
				}
				if _, ok := ResolveGuidance(f.Rule); !ok {
					t.Errorf("no guidance for %s", f.Rule)
				}
				if f.Severity == "" || f.Host == "" || f.Time.IsZero() {
					t.Errorf("incomplete finding %+v", f)
				}
			}
		})
	}
}

func TestNetFormatsSniffed(t *testing.T) {
	for file, want := range map[string]string{"zeek_conn.log": "zeek", "eve.json": "eve", "dns_queries.json": "dns", "vpc_flow.log": "vpc", "nsg_flow.json": "nsg", "netflow.csv": "flowcsv", "panos.log": "panos", "fortigate.log": "fortigate", "asa.log": "asa", "zeek_json.log": "zeek-json"} {
		p, err := netParseLog(netFixture(t, file), "auto")
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if p.Format != want {
			t.Errorf("%s: format %s, want %s", file, p.Format, want)
		}
	}
	p, _ := netParseLog(netFixture(t, "nsg_flow.json"), "nsg")
	if len(p.Events) != 8 || p.Events[0].Kind != "flow" {
		t.Errorf("nsg events: %d", len(p.Events))
	}
}

func TestNetScanNoiseFree(t *testing.T) {
	// the benign background traffic alone must produce no findings
	var b strings.Builder
	b.WriteString("#separator \\x09\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\torig_bytes\tresp_bytes\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "%d.%03d\t10.0.0.%d\t%d\t203.0.113.%d\t443\ttcp\tSF\t%d\t%d\n", 1790000000+i*37+(i*i)%29, i%1000, 10+i%20, 40000+i, 1+i%9, 500+i*13%900, 20000+i*997%80000)
	}
	rep, fs, err := NetRun([]byte(b.String()), "auto", NetOptions{})
	if err != nil || rep.Parsed != 200 {
		t.Fatalf("%v parsed=%d", err, rep.Parsed)
	}
	if len(fs) != 0 {
		t.Errorf("benign traffic produced findings: %v", netRulesOf(fs))
	}
}

func TestNetBeaconStats(t *testing.T) {
	mk := func(n int, step float64, jitter func(i int) float64) []float64 {
		ts := make([]float64, n)
		for i := range ts {
			ts[i] = 1e9 + float64(i)*step + jitter(i)
		}
		return ts
	}
	cases := []struct {
		name string
		ts   []float64
		want bool
	}{
		{"regular", mk(20, 60, func(i int) float64 { return float64(i%3) - 1 }), true},
		{"too few", mk(8, 60, func(int) float64 { return 0 }), false},
		{"human bursts", mk(30, 60, func(i int) float64 { return float64((i * i * 37) % 55) }), false},
		{"too fast", mk(30, 1, func(int) float64 { return 0 }), false},
		{"too slow", mk(20, 8*3600, func(int) float64 { return 0 }), false},
		{"wide jitter", mk(40, 60, func(i int) float64 { return float64((i*i*29)%40) - 20 }), false},
	}
	for _, c := range cases {
		if ok, _, _, _ := netBeacon(c.ts); ok != c.want {
			t.Errorf("%s: got %v want %v", c.name, ok, c.want)
		}
	}
}

func TestNetDGAScore(t *testing.T) {
	for _, l := range []string{"microsoftonline", "googleusercontent", "wikipedia", "stackoverflow", "cloudflarenetwork", "amazonaws"} {
		if s, ok := dnsDGAScore(l); ok && s >= dnsDGAMinScore {
			t.Errorf("%s scored %d as DGA-like", l, s)
		}
	}
	for _, l := range []string{"x7k2q9zt4b1w8r", "qzkx3v9b2n7mjd5", "k3j9x0q7z2bv4"} {
		if s, ok := dnsDGAScore(l); !ok || s < dnsDGAMinScore {
			t.Errorf("%s scored %d, want DGA-like", l, s)
		}
	}
	if _, ok := dnsDGAScore("short"); ok {
		t.Error("short label judged")
	}
}

func TestNetRegDomain(t *testing.T) {
	for in, want := range map[string]string{"a.b.example.com": "example.com", "x.example.co.uk": "example.co.uk", "example.com": "example.com", "com": ""} {
		if got, _ := netRegDomain(in); got != want {
			t.Errorf("%s: %q want %q", in, got, want)
		}
	}
}

func TestNetExfilNeedsPopulation(t *testing.T) {
	emitted := 0
	emit := func(string, int64, string, string, string, string) { emitted++ }
	v := map[[2]string]int64{}
	for i := 0; i < 5; i++ {
		v[[2]string{"10.0.0.1", fmt.Sprint(i)}] = 1 << 20
	}
	v[[2]string{"10.0.0.2", "x"}] = 900 << 20
	netExfil(v, emit)
	if emitted != 0 {
		t.Error("exfil fired on a population of 6 pairs")
	}
	for i := 0; i < 10; i++ {
		v[[2]string{"10.0.0.3", fmt.Sprint(i)}] = int64(1+i%3) << 20
	}
	netExfil(v, emit)
	if emitted != 1 {
		t.Errorf("emitted %d, want 1", emitted)
	}
}

func TestNetRedact(t *testing.T) {
	for in, banned := range map[string]string{
		"login password=hunter2 ok":            "hunter2",
		"api_key: ABCDEF123456":                "ABCDEF123456",
		"url https://user:s3cret@host/x":       "s3cret",
		"Authorization: Bearer abcdefghij1234": "abcdefghij1234",
		"token=\"quoted secret value\"":        "quoted secret",
	} {
		if out := netRedact(in); strings.Contains(out, banned) {
			t.Errorf("%q -> %q still contains %q", in, out, banned)
		}
	}
	if got := netRedact("a\x00b\r\nc"); strings.ContainsAny(got, "\x00\r\n") {
		t.Errorf("control characters kept: %q", got)
	}
}

func TestNetHostileInputs(t *testing.T) {
	long := strings.Repeat("A", 200000)
	deep := strings.Repeat("{\"a\":", 5000) + "1" + strings.Repeat("}", 5000)
	nul := "#fields\tts\tid.orig_h\tid.resp_h\n1790000000.0\t10.0.0.1\x00\t203.0.113.1\r\n"
	redos := strings.Repeat("password=", 50000)
	cases := []struct{ name, body, format string }{
		{"huge line zeek", "#fields\tts\tid.orig_h\n1790000000\t" + long + "\n", "zeek"},
		{"deep json eve", deep + "\n", "eve"},
		{"deep json dns", "[" + deep + "]", "dns"},
		{"nul and crlf zeek", nul, "zeek"},
		{"redos notice", "{\"ts\":1790000000,\"note\":\"X\",\"msg\":\"" + redos + "\"}\n", "zeek-json"},
		{"garbage", "\x00\x01\x02\xff\xfe", "auto"},
		{"binary csv", "a,b,c,d\n\x00,\x01,\x02,\x03\n", "flowcsv"},
		{"asa overlong", "%ASA-6-106100: " + long, "asa"},
		{"fortigate pairs bomb", strings.Repeat("k=v ", 100000), "fortigate"},
		{"pan quotes", "x,\"" + long + ",TRAFFIC,", "panos"},
		{"nsg broken", "{\"records\":[{\"properties\":{\"flows\":[{\"flows\":[{\"flowTuples\":[1,2,\"x\"]}]}]}}]}", "nsg"},
		{"vpc ragged", "version\n2 a b\n2 1 2 3 4 5 6 7 8 9 10 11 ACCEPT OK extra extra\n", "vpc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic: %v", r)
					}
				}()
				rep, fs, err := NetRun([]byte(c.body), c.format, NetOptions{})
				if err == nil {
					for _, f := range fs {
						if strings.ContainsAny(f.Description, "\x00\r\n") {
							t.Errorf("control character in finding")
						}
					}
					_ = rep
				}
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("did not finish in 10s")
			}
		})
	}
}

func TestNetTooManyRecords(t *testing.T) {
	var b strings.Builder
	b.WriteString("#fields\tts\tid.orig_h\tid.resp_h\n")
	for i := 0; i < netLinesMax+5; i++ {
		b.WriteString("1790000000\t10.0.0.1\t10.0.0.2\n")
	}
	if _, _, err := NetRun([]byte(b.String()), "zeek", NetOptions{}); err != errNetTooMany {
		t.Errorf("err = %v", err)
	}
}

func TestNetCardinalityBomb(t *testing.T) {
	// 90,000 distinct destinations and 90,000 distinct DNS names must stay bounded and finish quickly
	var b strings.Builder
	b.WriteString("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n")
	for i := 0; i < 90000; i++ {
		fmt.Fprintf(&b, "%d\t10.0.0.1\t%d\t%d.%d.%d.%d\t%d\ttcp\tS0\n", 1790000000+i/50, 1024+i%60000, 20+i/65536, (i/256)%256, i%256, 1+i%250, 1+i%65000)
	}
	start := time.Now()
	rep, fs, err := NetRun([]byte(b.String()), "zeek", NetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	for r, n := range rep.ByRule {
		if n > netFindCapPerRule {
			t.Errorf("rule %s emitted %d > cap", r, n)
		}
	}
	_ = fs
	var d strings.Builder
	for i := 0; i < 90000; i++ {
		fmt.Fprintf(&d, "{\"ts\":%d,\"client\":\"10.0.%d.%d\",\"qname\":\"n%d.sub%d.example.org\",\"qtype\":\"A\"}\n", 1790000000+i/100, i%200, i%250, i, i)
	}
	if _, _, err := NetRun([]byte(d.String()), "dns", NetOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestNetBadListAndFingerprints(t *testing.T) {
	nets, badN := netParseBadNets("# c\n192.0.2.0/24\n203.0.113.66 # inline\nbogus\n2001:db8::/32\n\n")
	if len(nets) != 3 || badN != 1 {
		t.Fatalf("nets=%v bad=%d", nets, badN)
	}
	fp := netParseFPs("ABCDEF label with password=x\n# c\n\nt13d1517h2_8daaf6152771_cb7bf5808d99\n")
	if len(fp) != 2 || strings.Contains(fp["abcdef"], "=x") {
		t.Fatalf("fps=%v", fp)
	}
	big := strings.Repeat("10.0.0.0/8\n", netListMax*2)
	if n, _ := netParseBadNets(big); len(n) != netListMax {
		t.Errorf("list not capped: %d", len(n))
	}
}

func TestNetEveMapping(t *testing.T) {
	for _, c := range []struct{ cat, sig, want string }{
		{"A Network Trojan was detected", "x", "net-eve-c2"},
		{"Web Application Attack", "x", "net-eve-exploit"},
		{"Attempted Denial of Service", "x", "net-eve-dos"},
		{"Attempted Information Leak", "x", "net-eve-recon"},
		{"Misc Activity", "x", "net-eve-policy"},
		{"", "ET-like CnC beacon", "net-eve-c2"},
	} {
		if got := netEveRule(c.cat, c.sig); got != c.want {
			t.Errorf("%q: %s want %s", c.cat, got, c.want)
		}
	}
}

func TestNetFirewallParsers(t *testing.T) {
	p, _ := netParseLog(netFixture(t, "asa.log"), "asa")
	if p.Rejected != 2 || len(p.Events) != 5 {
		t.Errorf("asa parsed %d rejected %d", len(p.Events), p.Rejected)
	}
	for _, e := range p.Events {
		if strings.Contains(e.Msg, "hunter2") {
			t.Error("asa command text kept")
		}
	}
	p, _ = netParseLog(netFixture(t, "panos.log"), "panos")
	if len(p.Events) != 25 || p.Events[0].Action != "deny" || p.Events[22].Action != "allow" || p.Events[22].DPort != 443 {
		t.Errorf("panos: %+v", p.Events)
	}
	p, _ = netParseLog(netFixture(t, "fortigate.log"), "fortigate")
	cats := map[string]int{}
	for _, e := range p.Events {
		cats[e.Category]++
		if strings.Contains(e.Msg, "ENC") {
			t.Error("cfgattr value kept")
		}
	}
	if cats["admin-login-failed"] < 7 || cats["config-change"] != 1 || cats["threat"] != 1 {
		t.Errorf("forti categories %v", cats)
	}
}

func TestNetTimeline(t *testing.T) {
	now := time.Now().UTC()
	fs := []Finding{
		{ID: "1", Time: now, Host: "net:logs", Rule: "net-an-beaconing", Severity: "medium", Destination: "10.0.0.5", Description: "10.0.0.5 beacon"},
		{ID: "2", Time: now.Add(2 * time.Minute), Host: "auth:x", Rule: "auth-an-success-after-failures", Severity: "high", Destination: "10.0.0.5", Description: "login"},
		{ID: "3", Time: now.Add(3 * time.Minute), Host: "web:y", Rule: "web-sqli", Severity: "low", Destination: "10.9.9.9", Description: "mentions 10.0.0.5 in referer"},
		{ID: "4", Time: now.Add(3 * time.Hour), Host: "ws1", Rule: "ransomware-burst", Severity: "high", Destination: "10.7.7.7", Description: "unrelated"},
		{ID: "5", Time: now.Add(time.Minute), Host: "ws1", Rule: "persistence-attempt", Severity: "medium", Description: "agent host"},
		{ID: "6", Time: now.Add(time.Minute), Host: "ws1", Rule: "net-an-dns-dga", Severity: "medium", Destination: "10.0.0.5"},
	}
	tl := BuildNetTimeline(fs, "10.0.0.5", "", 30*time.Minute)
	if tl.Anchors != 4 || len(tl.Items) < 4 {
		t.Fatalf("anchors=%d items=%d", tl.Anchors, len(tl.Items))
	}
	if tl.Items[0].Rule != "auth-an-success-after-failures" {
		t.Errorf("top item %s", tl.Items[0].Rule)
	}
	has := map[string]string{}
	for _, it := range tl.Items {
		has[it.Rule] = it.Relation
	}
	if has["persistence-attempt"] != "same host, within window" {
		t.Errorf("host-near finding missing: %v", has)
	}
	if _, ok := has["ransomware-burst"]; ok {
		t.Error("finding hours away was joined")
	}
	if len(tl.Families) < 3 {
		t.Errorf("families %v", tl.Families)
	}
	ents := BuildNetTimeline(fs, "", "", time.Hour)
	if len(ents.Entities) != 1 || ents.Entities[0].Entity != "10.0.0.5" {
		t.Errorf("entities %+v", ents.Entities)
	}
}

func netDo(t *testing.T, h http.Handler, method, path, body, tok string) (int, []byte) {
	w := telDo(h, method, path, body, tok)
	return w.Code, w.Body.Bytes()
}

func TestNetHTTP(t *testing.T) {
	h := telHandler(t)
	ec, _ := netDo(t, h, "POST", "/v1/net/logs", "x", "")
	if ec != http.StatusUnauthorized {
		t.Errorf("unauthenticated %d", ec)
	}
	zeek := string(netFixture(t, "zeek_conn.log"))
	code, body := netDo(t, h, "POST", "/v1/net/logs?host=Edge-1", zeek, "tok")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var rep NetReport
	if err := json.Unmarshal(body, &rep); err != nil || rep.Format != "zeek" || rep.ByRule["net-an-beaconing"] == 0 || rep.Findings == 0 {
		t.Fatalf("report %+v err %v", rep, err)
	}
	env, _ := json.Marshal(map[string]any{"log": string(netFixture(t, "netflow.csv")), "format": "flowcsv", "bad_nets": []string{"192.0.2.0/24", "junk"}, "fingerprints": "abc123 label"})
	code, body = netDo(t, h, "POST", "/v1/net/analyze", string(env), "tok")
	if code != 200 || !strings.Contains(string(body), "net-an-badlist-contact") || !strings.Contains(string(body), "bad_nets entries") {
		t.Fatalf("analyze %d %s", code, body)
	}
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/v1/net/logs", "", 400},
		{"/v1/net/logs", "nothing parseable here", 400},
		{"/v1/net/logs?format=bogus", "x", 400},
		{"/v1/net/logs", strings.Repeat("a", webBodyMax+1), 413},
		{"/v1/net/analyze", "[]", 400},
		{"/v1/net/analyze", `{"log":""}`, 400},
	} {
		if code, _ := netDo(t, h, "POST", c.path, c.body, "tok"); code != c.want {
			t.Errorf("%s %q: %d want %d", c.path, webTruncate(c.body, 20), code, c.want)
		}
	}
	code, body = netDo(t, h, "GET", "/v1/net/timeline?ip=10.0.0.5&window_minutes=60", "", "tok")
	if code != 200 || !strings.Contains(string(body), "net-an-beaconing") {
		t.Errorf("timeline %d %s", code, webTruncate(string(body), 300))
	}
	for _, p := range []string{"/v1/net/timeline?ip=zzz", "/v1/net/timeline?window_minutes=0", "/v1/net/timeline?window_minutes=99999"} {
		if code, _ := netDo(t, h, "GET", p, "", "tok"); code != 400 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, _ := netDo(t, h, "GET", "/v1/net/sources", "", ""); code != 401 {
		t.Errorf("sources unauth %d", code)
	}
	code, body = netDo(t, h, "GET", "/v1/net/sources", "", "tok")
	if code != 200 || !strings.Contains(string(body), "net-an-dns-tunnel") {
		t.Errorf("sources %d", code)
	}
}

func TestNetRulesHaveMITREAndGuidance(t *testing.T) {
	for _, r := range netRules {
		m, ok := mitreFor(r.ID)
		if !ok || m.ID != r.TechID {
			t.Errorf("%s not mapped to %s", r.ID, r.TechID)
		}
		if _, ok := ResolveGuidance(r.ID); !ok {
			t.Errorf("%s has no guidance", r.ID)
		}
	}
}
