// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ncNow = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func ncFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "netcfg", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ncRun(t *testing.T, raw []byte, format string) (*NetcfgReport, []Finding) {
	t.Helper()
	rep, fs, err := NetcfgRun(raw, format, NetcfgOptions{Now: ncNow})
	if err != nil {
		t.Fatal(err)
	}
	return rep, fs
}

func TestNetcfgFixtures(t *testing.T) {
	cases := []struct {
		file, format string
		rules        int
		want         []string
		notWant      []string
	}{
		{"pan.xml", "auto", 4, []string{"netcfg-rule-shadowed", "netcfg-mgmt-exposed-untrusted", "netcfg-mgmt-weak-protocol", "netcfg-permit-risky-service", "netcfg-rule-no-logging", "netcfg-rule-temporary", "netcfg-rule-disabled", "netcfg-object-unused", "netcfg-object-duplicate", "netcfg-permit-no-inspection", "netcfg-permit-any-any"}, nil},
		{"forti.conf", "auto", 3, []string{"netcfg-permit-any-any", "netcfg-rule-shadowed", "netcfg-mgmt-exposed-untrusted", "netcfg-mgmt-weak-protocol", "netcfg-admin-unrestricted", "netcfg-weak-crypto", "netcfg-weak-snmp", "netcfg-default-credentials", "netcfg-permit-risky-service", "netcfg-rule-no-logging", "netcfg-rule-temporary", "netcfg-object-unused", "netcfg-object-duplicate", "netcfg-logging-disabled"}, nil},
		{"asa.conf", "auto", 5, []string{"netcfg-permit-any-any", "netcfg-permit-risky-service", "netcfg-rule-shadowed", "netcfg-mgmt-exposed-untrusted", "netcfg-mgmt-weak-protocol", "netcfg-weak-crypto", "netcfg-weak-snmp", "netcfg-default-credentials", "netcfg-object-unused", "netcfg-object-duplicate", "netcfg-rule-no-logging"}, nil},
		{"iptables.txt", "auto", 7, []string{"netcfg-default-policy-accept", "netcfg-permit-risky-service", "netcfg-rule-shadowed"}, nil},
		{"nft.txt", "auto", 6, []string{"netcfg-default-policy-accept", "netcfg-permit-risky-service", "netcfg-rule-shadowed"}, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			rep, fs := ncRun(t, ncFixture(t, c.file), c.format)
			if rep.Rules != c.rules {
				t.Errorf("rules = %d, want %d", rep.Rules, c.rules)
			}
			for _, w := range c.want {
				if rep.ByRule[w] == 0 {
					t.Errorf("rule %s did not fire; fired %v", w, rep.ByRule)
				}
			}
			for _, w := range c.notWant {
				if rep.ByRule[w] != 0 {
					t.Errorf("rule %s fired", w)
				}
			}
			if rep.Score >= 100 || rep.Grade == "" {
				t.Errorf("score %d grade %q", rep.Score, rep.Grade)
			}
			for _, f := range fs {
				if _, ok := ResolveGuidance(f.Rule); !ok {
					t.Errorf("no guidance for %s", f.Rule)
				}
				if !strings.Contains(f.Description, "heuristic") || f.Evidence.Command == "" {
					t.Errorf("finding lacks wording or evidence: %+v", f)
				}
			}
			for _, it := range rep.Items {
				if it.Location == "" || it.Why == "" || it.Benign == "" || it.Reference == "" || it.Technique == "" {
					t.Errorf("incomplete item %+v", it)
				}
			}
		})
	}
}

func TestNetcfgNoSecretsLeak(t *testing.T) {
	canaries := []string{"Canary-Plain-Pass-9", "CanaryHashValue", "CanaryPskHash", "Canary-ASA-Pass-7", "Canary-Enable-Pass-3"}
	for _, f := range []string{"forti.conf", "asa.conf"} {
		rep, fs := ncRun(t, ncFixture(t, f), "auto")
		b, _ := json.Marshal(rep)
		fb, _ := json.Marshal(fs)
		all := string(b) + string(fb)
		for _, c := range canaries {
			if strings.Contains(all, c) {
				t.Errorf("%s: secret %q appears in output", f, c)
			}
		}
		if strings.Contains(all, `"public"`) || strings.Contains(strings.ToLower(all), "community public") {
			t.Errorf("%s: SNMP community value appears", f)
		}
	}
	// secrets inside free text (comments, names) are scrubbed
	cfg := "config firewall policy\nedit 1\nset name \"p password=Hunter2Canary\"\nset srcintf \"wan1\"\nset dstintf \"lan\"\nset srcaddr \"all\"\nset dstaddr \"all\"\nset action accept\nset service \"ALL\"\nset logtraffic disable\nset comments \"api_key=AKIAABCDEFGHIJKLMNOP temp\"\nnext\nend\n"
	rep, fs := ncRun(t, []byte(cfg), "fortigate")
	b, _ := json.Marshal(rep)
	fb, _ := json.Marshal(fs)
	if strings.Contains(string(b)+string(fb), "Hunter2Canary") || strings.Contains(string(b)+string(fb), "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("free-text secret leaked: %s", b)
	}
}

func TestNetcfgPANParsing(t *testing.T) {
	m, err := ncParsePAN(ncFixture(t, "pan.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 4 {
		t.Fatalf("rules %d", len(m.Rules))
	}
	r := m.Rules[2]
	if r.Name != "inbound-rdp" || !r.Allow || r.Log != "off" || !r.SrcZ.M["untrust"] || len(r.Apps) != 1 || !r.Src.Any {
		t.Errorf("rule parsed wrong: %+v", r)
	}
	if !m.Rules[3].Disabled || m.Rules[3].Allow {
		t.Errorf("disabled deny parsed wrong")
	}
	if !strings.Contains(r.Loc, "line ") {
		t.Errorf("location %q", r.Loc)
	}
	// the safe profile has permitted-ip, so only the open one is exposed
	n := 0
	for _, is := range m.Issues {
		if is.Rule == "netcfg-mgmt-exposed-untrusted" {
			n++
			if !strings.Contains(is.Detail, "ethernet1/1") {
				t.Errorf("wrong interface: %s", is.Detail)
			}
		}
	}
	if n != 1 {
		t.Errorf("exposed issues = %d", n)
	}
}

func TestNetcfgPANHostile(t *testing.T) {
	bomb := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><config><devices>&lol2;</devices></config>`
	if _, _, err := NetcfgRun([]byte(bomb), "pan-xml", NetcfgOptions{}); err == nil || !strings.Contains(err.Error(), "DOCTYPE") {
		t.Errorf("entity bomb must be refused, got %v", err)
	}
	xxe := `<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]><config>&x;</config>`
	if _, _, err := NetcfgRun([]byte(xxe), "pan-xml", NetcfgOptions{}); err == nil {
		t.Errorf("external entity must be refused")
	}
	deep := strings.Repeat("<a>", 5000) + strings.Repeat("</a>", 5000)
	if _, _, err := NetcfgRun([]byte("<config>"+deep+"</config>"), "pan-xml", NetcfgOptions{}); err == nil {
		t.Errorf("deep nesting must be refused")
	}
	if _, _, err := NetcfgRun([]byte("<config><devices>"), "pan-xml", NetcfgOptions{}); err == nil {
		t.Errorf("unterminated xml must be refused")
	}
	if _, _, err := NetcfgRun([]byte(`<?xml version="1.0" encoding="UTF-16"?><config/>`), "pan-xml", NetcfgOptions{}); err == nil {
		t.Errorf("foreign charset must be refused")
	}
	// element-count bomb
	var b strings.Builder
	b.WriteString("<config>")
	for i := 0; i < ncXMLNodes+10; i++ {
		b.WriteString("<a/>")
	}
	b.WriteString("</config>")
	if _, _, err := NetcfgRun([]byte(b.String()), "pan-xml", NetcfgOptions{}); err == nil {
		t.Errorf("element bomb must be refused")
	}
	// a malformed rule entry with NUL and unknown children must not panic
	odd := "<config><devices><entry name=\"x\"><vsys><entry name=\"v\"><rulebase><security><rules><entry name=\"a\x00b\"><from/><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"
	if _, _, err := NetcfgRun([]byte(odd), "pan-xml", NetcfgOptions{}); err != nil {
		t.Logf("odd input rejected: %v", err)
	}
}

func TestNetcfgForti(t *testing.T) {
	m, err := ncParseForti(string(ncFixture(t, "forti.conf")))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 3 {
		t.Fatalf("rules %d", len(m.Rules))
	}
	r := m.Rules[0]
	if !r.Allow || r.Log != "off" || !r.Src.Any || !r.Dst.Any || !r.Svc.Any || r.Name != "allow-everything" {
		t.Errorf("policy 1 parsed wrong: %+v", r)
	}
	r3 := m.Rules[2]
	if r3.Svc.Any || len(r3.Svc.R) == 0 || len(r3.Dst.Pfx) != 1 || r3.Dst.Pfx[0].String() != "10.1.0.10/32" {
		t.Errorf("policy 3 parsed wrong: %+v", r3)
	}
	// vdom and nested config blocks
	cfg := "config vdom\nedit root\nconfig firewall policy\nedit 7\nset srcintf \"a\"\nset dstintf \"b\"\nset srcaddr \"all\"\nset dstaddr \"all\"\nset action accept\nset service \"ALL\"\nnext\nend\nnext\nend\n"
	m2, err := ncParseForti(cfg)
	if err != nil || len(m2.Rules) != 1 || m2.Rules[0].Scope != "policy:root" {
		t.Fatalf("vdom parse: %v %+v", err, m2)
	}
	if _, err := ncParseForti("hello world\nnothing here"); err == nil {
		t.Error("non-forti text must be refused")
	}
}

func TestNetcfgASA(t *testing.T) {
	m, err := ncParseASA(string(ncFixture(t, "asa.conf")))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 5 {
		t.Fatalf("rules %d", len(m.Rules))
	}
	r1 := m.Rules[0]
	if !r1.Allow || !r1.SrcZ.M["outside"] || !r1.UntrustedSrc || len(r1.Dst.Pfx) != 1 || len(r1.Svc.R) != 1 || r1.Svc.R[0].Lo != 80 {
		t.Errorf("ace 1 parsed wrong: %+v", r1)
	}
	r2 := m.Rules[1]
	if len(r2.Svc.R) != 2 {
		t.Errorf("service group not expanded: %+v", r2.Svc)
	}
	if r2.Desc != "inbound publishing" {
		t.Errorf("remark not attached: %q", r2.Desc)
	}
	if m.Rules[3].Log != "off" || m.Rules[3].Allow {
		t.Errorf("deny with log disable parsed wrong")
	}
	if m.Rules[4].SrcZ.M["inside"] == false || m.Rules[4].UntrustedSrc {
		t.Errorf("inside ACL bound wrong")
	}
	if _, err := ncParseASA("hello\nworld\n"); err == nil {
		t.Error("non-asa text must be refused")
	}
	// negation and unknown tokens do not panic or fabricate rules
	if _, err := ncParseASA("access-list A extended permit tcp any\naccess-list B extended permit\naccess-list C extended permit tcp any any eq\nssh\ntelnet 1 2\n"); err != nil {
		t.Logf("%v", err)
	}
}

func TestNetcfgIptablesNft(t *testing.T) {
	m, err := ncParseIptables(string(ncFixture(t, "iptables.txt")))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 7 {
		t.Fatalf("iptables rules %d", len(m.Rules))
	}
	if !m.Rules[2].Svc.R[0].Overlaps(22) || len(m.Rules[2].Svc.R) != 2 {
		t.Errorf("multiport parsed wrong: %+v", m.Rules[2].Svc)
	}
	if m.Rules[3].Src.Pfx[0].String() != "192.0.2.0/24" {
		t.Errorf("-s parsed wrong")
	}
	if !m.Rules[0].Egress {
		t.Errorf("loopback accept should be exempt from breadth checks")
	}
	if _, err := ncParseIptables("*nat\nCOMMIT\n"); err == nil {
		t.Error("no filter table must be refused")
	}
	// negation marks complex
	m2, _ := ncParseIptables("*filter\n:INPUT DROP [0:0]\n-A INPUT ! -s 10.0.0.0/8 -j DROP\nCOMMIT\n")
	if len(m2.Rules) != 1 || !m2.Rules[0].Complex {
		t.Errorf("negated rule must be complex")
	}
	n, err := ncParseNft(string(ncFixture(t, "nft.txt")))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Rules) != 6 {
		t.Fatalf("nft rules %d", len(n.Rules))
	}
	if len(n.Rules[2].Svc.R) != 2 || n.Rules[3].Src.Pfx[0].String() != "192.0.2.0/24" {
		t.Errorf("nft sets or addresses parsed wrong: %+v", n.Rules[2])
	}
	if _, err := ncParseNft("nothing"); err == nil {
		t.Error("non-nft text must be refused")
	}
}

func (r ncRange) Overlaps(p int) bool { return r.Lo <= p && p <= r.Hi }

func TestNetcfgContainment(t *testing.T) {
	var a, b ncSet
	a.addPrefix(mustPfx("10.0.0.0/8"))
	b.addPrefix(mustPfx("10.1.2.0/24"))
	if !a.covers(&b) || b.covers(&a) {
		t.Error("prefix containment wrong")
	}
	var v6 ncSet
	v6.addPrefix(mustPfx("2001:db8::/32"))
	if a.covers(&v6) {
		t.Error("v4 must not cover v6")
	}
	var s1, s2 ncSvc
	s1.addRange(ncRange{"tcp", 1, 1024})
	s2.addRange(ncRange{"tcp", 22, 22})
	if !s1.covers(&s2) || s2.covers(&s1) {
		t.Error("service containment wrong")
	}
	s3 := ncSvc{}
	s3.addRange(ncRange{"udp", 22, 22})
	if s1.covers(&s3) {
		t.Error("tcp must not cover udp")
	}
	if p, ok := ncMaskPrefix("10.0.0.0", "255.0.255.0"); ok {
		t.Errorf("non-contiguous mask accepted: %v", p)
	}
}

func TestNetcfgHostileText(t *testing.T) {
	// NUL and CRLF
	cfg := strings.ReplaceAll(string(ncFixture(t, "forti.conf")), "\n", "\r\n")
	cfg = strings.Replace(cfg, "edge-fw", "edge\x00fw", 1)
	rep, _ := ncRun(t, []byte(cfg), "fortigate")
	if rep.Rules != 3 {
		t.Errorf("CRLF/NUL changed the parse: %d rules", rep.Rules)
	}
	// regex-DoS style and overlong lines
	long := "config firewall policy\nedit 1\nset comments \"" + strings.Repeat("a", 5<<20) + "\"\nset action accept\nset srcintf \"a\"\nset dstintf \"b\"\nset srcaddr \"all\"\nset dstaddr \"all\"\nset service \"ALL\"\nnext\nend\n"
	start := time.Now()
	if _, _, err := NetcfgRun([]byte(long), "fortigate", NetcfgOptions{Now: ncNow}); err != nil {
		t.Fatal(err)
	}
	evil := "config firewall policy\nedit 1\nset comments \"" + strings.Repeat("(a+)+$ password ", 20000) + "\"\nset action accept\nset srcintf \"a\"\nset dstintf \"b\"\nset srcaddr \"all\"\nset dstaddr \"all\"\nset service \"ALL\"\nnext\nend\n"
	if _, _, err := NetcfgRun([]byte(evil), "fortigate", NetcfgOptions{Now: ncNow}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("hostile text took %v", time.Since(start))
	}
	// too many lines are cut, not crashed on
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n")
	for i := 0; i < ncMaxLines+500; i++ {
		fmt.Fprintf(&b, "-A INPUT -s 10.%d.%d.%d -j ACCEPT\n", i>>16&255, i>>8&255, i&255)
	}
	b.WriteString("COMMIT\n")
	start = time.Now()
	rep, _, err := NetcfgRun([]byte(b.String()), "iptables", NetcfgOptions{Now: ncNow})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Truncated || rep.Rules > ncMaxRules {
		t.Errorf("truncated=%v rules=%d", rep.Truncated, rep.Rules)
	}
	// A quadratic regression takes minutes; the bound is loose because -race on a loaded CI host measured 24s for 2s of real work.
	if time.Since(start) > 90*time.Second {
		t.Errorf("cardinality bomb took %v", time.Since(start))
	}
}

func TestNetcfgShadowIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "-A INPUT -s 10.%d.%d.0/24 -p tcp --dport %d -j ACCEPT\n", i/250, i%250, 1000+i%60000)
	}
	b.WriteString("COMMIT\n")
	start := time.Now()
	rep, _ := ncRun(t, []byte(b.String()), "iptables")
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("shadow analysis took %v", d)
	}
	found := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "only the first") || strings.Contains(n, "budget") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a note that the analysis was capped; notes %v", rep.Notes)
	}
}

func TestNetcfgAddressExpansionCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("config firewall addrgrp\nedit \"big\"\nset member")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, " \"h%d\"", i)
	}
	b.WriteString("\nnext\nend\nconfig firewall policy\nedit 1\nset srcintf \"a\"\nset dstintf \"b\"\nset srcaddr \"big\"\nset dstaddr \"all\"\nset action accept\nset service \"HTTPS\"\nnext\nedit 2\nset srcintf \"a\"\nset dstintf \"b\"\nset srcaddr \"big\"\nset dstaddr \"all\"\nset action accept\nset service \"HTTPS\"\nnext\nend\n")
	rep, _ := ncRun(t, []byte(b.String()), "fortigate")
	if rep.Skipped != 2 || rep.ByRule["netcfg-rule-redundant"] != 0 {
		t.Errorf("oversized groups must be skipped by shadow analysis, skipped=%d", rep.Skipped)
	}
}

func TestNetcfgDiff(t *testing.T) {
	old, nw := ncFixture(t, "forti_old.conf"), ncFixture(t, "forti.conf")
	d, err := NetcfgDiff(old, nw, "auto", NetcfgOptions{Now: ncNow})
	if err != nil {
		t.Fatal(err)
	}
	var added, removed, state bool
	for _, it := range d.Items {
		if it.Change == "permit-added" && it.Rule == "allow-everything" && it.Severity == "high" {
			added = true
		}
		if it.Change == "permit-removed" && it.Rule == "web-in" {
			removed = true
		}
		_ = state
	}
	if !added || !removed {
		t.Errorf("diff items wrong: %+v", d.Items)
	}
	if d.ScoreDelta >= 0 || d.New.Rules != 3 || d.Old.Rules != 2 {
		t.Errorf("score delta %d, sides %+v %+v", d.ScoreDelta, d.Old, d.New)
	}
	if len(d.NewFindings) == 0 {
		t.Errorf("new findings missing")
	}
	// reversed: the permit disappears; a removed deny is reported
	cfgDeny := ncFixture(t, "forti_old.conf")
	noDeny := strings.Replace(string(cfgDeny), "set action deny", "set action accept", 1)
	d2, err := NetcfgDiff(cfgDeny, []byte(noDeny), "fortigate", NetcfgOptions{Now: ncNow})
	if err != nil {
		t.Fatal(err)
	}
	var denyGone bool
	for _, it := range d2.Items {
		if it.Change == "deny-removed" && it.Rule == "block-telnet" {
			denyGone = true
		}
	}
	if !denyGone {
		t.Errorf("removed deny not reported: %+v", d2.Items)
	}
	// identical files give an empty diff
	d3, _ := NetcfgDiff(nw, nw, "auto", NetcfgOptions{Now: ncNow})
	if len(d3.Items) != 0 || d3.ScoreDelta != 0 {
		t.Errorf("identical files differ: %+v", d3.Items)
	}
	// disabling a rule is a state change
	dis := strings.Replace(string(old), "set logtraffic all", "set logtraffic all\n        set status disable", 1)
	d4, _ := NetcfgDiff(old, []byte(dis), "fortigate", NetcfgOptions{Now: ncNow})
	ok := false
	for _, it := range d4.Items {
		if it.Change == "rule-disabled" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("disable not reported: %+v", d4.Items)
	}
	if _, err := NetcfgDiff([]byte("x"), nw, "auto", NetcfgOptions{}); err == nil {
		t.Error("unreadable old export must error")
	}
}

func TestNetcfgAutoDetect(t *testing.T) {
	for f, want := range map[string]string{"pan.xml": "pan-xml", "forti.conf": "fortigate", "asa.conf": "asa", "iptables.txt": "iptables", "nft.txt": "nft"} {
		if got := ncDetect(ncFixture(t, f)); got != want {
			t.Errorf("%s detected as %q, want %q", f, got, want)
		}
	}
	if _, _, err := NetcfgRun([]byte("random text"), "auto", NetcfgOptions{}); err == nil {
		t.Error("unknown text must be refused")
	}
	if _, _, err := NetcfgRun([]byte("x"), "bogus", NetcfgOptions{}); err == nil {
		t.Error("unknown format must be refused")
	}
	if _, _, err := NetcfgRun(nil, "auto", NetcfgOptions{}); err == nil {
		t.Error("empty input must be refused")
	}
}

func TestNetcfgRulesHaveMITREAndGuidance(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range netcfgRules {
		if seen[r.ID] {
			t.Errorf("duplicate %s", r.ID)
		}
		seen[r.ID] = true
		m, ok := mitreFor(r.ID)
		if !ok || m.ID != r.TechID {
			t.Errorf("%s not mapped to %s", r.ID, r.TechID)
		}
		e, ok := ResolveGuidance(r.ID)
		if !ok || e.Kind != "rule" || len(e.HowToInvestigate) == 0 || len(e.HowToRemediate) == 0 {
			t.Errorf("%s has no rule guidance", r.ID)
		}
		if _, ok := guidanceByID(r.TechID); !ok {
			t.Errorf("technique %s has no guidance entry", r.TechID)
		}
		if r.Reference == "" || r.Why == "" || r.Benign == "" {
			t.Errorf("%s lacks reference, why or benign text", r.ID)
		}
	}
}

func TestNetcfgHTTP(t *testing.T) {
	h := telHandler(t)
	if c, _ := netDo(t, h, "POST", "/v1/netcfg/analyze", "x", ""); c != 401 {
		t.Errorf("unauthenticated %d", c)
	}
	if c, _ := netDo(t, h, "GET", "/v1/netcfg/sources", "", ""); c != 401 {
		t.Errorf("sources unauth %d", c)
	}
	code, body := netDo(t, h, "POST", "/v1/netcfg/analyze?host=Edge-1", string(ncFixture(t, "forti.conf")), "tok")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var rep NetcfgReport
	if err := json.Unmarshal(body, &rep); err != nil || rep.Format != "fortigate" || rep.ByRule["netcfg-permit-any-any"] == 0 || rep.Findings == 0 {
		t.Fatalf("report %+v err %v", rep, err)
	}
	if strings.Contains(string(body), "Canary-Plain-Pass-9") {
		t.Error("secret in response")
	}
	// stored findings are visible and carry the host label
	if c, b := netDo(t, h, "GET", "/v1/findings", "", "tok"); c != 200 || !strings.Contains(string(b), "netcfg:edge-1") || strings.Contains(string(b), "Canary-Plain-Pass-9") {
		t.Errorf("stored findings %d", c)
	}
	env, _ := json.Marshal(map[string]string{"config": string(ncFixture(t, "asa.conf")), "format": "asa", "now": "2026-11-23T00:00:00Z"})
	if c, b := netDo(t, h, "POST", "/v1/netcfg/analyze", string(env), "tok"); c != 200 || !strings.Contains(string(b), "netcfg-mgmt-exposed-untrusted") {
		t.Errorf("envelope %d %s", c, b)
	}
	denv, _ := json.Marshal(map[string]string{"old": string(ncFixture(t, "forti_old.conf")), "new": string(ncFixture(t, "forti.conf"))})
	if c, b := netDo(t, h, "POST", "/v1/netcfg/diff", string(denv), "tok"); c != 200 || !strings.Contains(string(b), "permit-added") {
		t.Errorf("diff %d %s", c, b)
	}
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/v1/netcfg/analyze", "", 400},
		{"/v1/netcfg/analyze", "just some words", 400},
		{"/v1/netcfg/analyze?format=bogus", string(ncFixture(t, "forti.conf")), 400},
		{"/v1/netcfg/analyze", `{"config":"x","now":"yesterday"}`, 400},
		{"/v1/netcfg/diff", "{}", 400},
		{"/v1/netcfg/diff", `{"old":"a","new":"b"}`, 400},
	} {
		if code, _ := netDo(t, h, "POST", c.path, c.body, "tok"); code != c.want {
			t.Errorf("%s %q: %d, want %d", c.path, c.body, code, c.want)
		}
	}
	code, body = netDo(t, h, "GET", "/v1/netcfg/sources", "", "tok")
	if code != 200 || !strings.Contains(string(body), "netcfg-weak-snmp") {
		t.Errorf("sources %d", code)
	}
}

func mustPfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
