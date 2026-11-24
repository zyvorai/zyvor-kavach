// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"strings"
	"testing"
)

func TestSaseRulesHaveMITREAndGuidance(t *testing.T) {
	seen := map[string]bool{}
	n := 0
	for _, rs := range [][]SvRule{cfRules, umbRules, cfPolRules} {
		for _, r := range rs {
			n++
			if seen[r.ID] {
				t.Errorf("duplicate %s", r.ID)
			}
			seen[r.ID] = true
			if m, ok := mitreFor(r.ID); !ok || m.ID != r.TechID {
				t.Errorf("%s not mapped to %s", r.ID, r.TechID)
			}
			if e, ok := ResolveGuidance(r.ID); !ok || e.Kind != "rule" || len(e.HowToInvestigate) == 0 || len(e.HowToRemediate) == 0 {
				t.Errorf("%s has no rule guidance", r.ID)
			}
			if _, ok := guidanceByID(r.TechID); !ok {
				t.Errorf("technique %s has no guidance entry", r.TechID)
			}
		}
	}
	if n != 24 {
		t.Errorf("rule count %d, docs say 24", n)
	}
}

func TestSaseSelfTestCoversEveryRule(t *testing.T) {
	st, err := SelfTest(HarnessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, r := range st.Rules {
		if strings.HasPrefix(r.ID, "cf-an-") || strings.HasPrefix(r.ID, "umb-an-") || strings.HasPrefix(r.ID, "cfpol-") {
			got++
			if r.Positive == 0 || r.Negative == 0 || r.Status != "ok" {
				t.Errorf("%s: positive %d negative %d status %s", r.ID, r.Positive, r.Negative, r.Status)
			}
		}
	}
	if got != 24 {
		t.Errorf("selftest covers %d rules, want 24", got)
	}
}

func TestUmbrellaHeaderlessAndHeaderedAgree(t *testing.T) {
	headerless := "2026-11-20 10:00:00,alice@example.test,alice@example.test,10.1.1.10,203.0.113.50,Allowed,1 (A),NOERROR,evil.example.test.,Malware,Roaming Computers,Roaming Computers,\n"
	headered := "timestamp,identity,internalIp,externalIp,action,queryType,responseCode,domain,categories\n2026-11-20 10:00:00,alice@example.test,10.1.1.10,203.0.113.50,Allowed,1 (A),NOERROR,evil.example.test.,Malware\n"
	for name, in := range map[string]string{"headerless": headerless, "headered": headered} {
		rep, fs, err := UmbrellaRun([]byte(in), "", SvOptions{})
		if err != nil || rep.Parsed != 1 || rep.ByKind["umb-dns"] != 1 {
			t.Fatalf("%s: err=%v rep=%+v", name, err, rep)
		}
		if len(fs) != 1 || fs[0].Rule != "umb-an-threat-category-allowed" {
			t.Errorf("%s: findings %+v", name, fs)
		}
	}
	px := "2026-11-20 10:00:00,bob@example.test,10.1.1.11,203.0.113.7,203.0.113.50,text/html,Blocked,http://x.example.test/p?token=Canary-Secret-9,,Mozilla/5.0,200\n"
	rep, _, err := UmbrellaRun([]byte(px), "", SvOptions{})
	if err != nil || rep.ByKind["umb-proxy"] != 1 {
		t.Fatalf("proxy: %v %+v", err, rep)
	}
}

func TestSaseBadInputAndSecrets(t *testing.T) {
	for _, in := range []string{"", "   ", "just words", "a,b\n1,2\n"} {
		if rep, _, err := CloudflareRun([]byte(in), "", SvOptions{}); err == nil && rep.Parsed != 0 {
			t.Errorf("cloudflare accepted %q", in)
		}
		if rep, _, err := UmbrellaRun([]byte(in), "", SvOptions{}); err == nil && rep.Parsed != 0 {
			t.Errorf("umbrella accepted %q", in)
		}
	}
	if _, _, err := CloudflareRun([]byte(`{"ClientIP":"1.1.1.1","EdgeResponseStatus":200}`), "bogus", SvOptions{}); err == nil {
		t.Error("bogus format accepted")
	}
	l := `{"Datetime":"2026-11-20T10:00:00Z","ClientIP":"203.0.113.9","ClientRequestHost":"a.example.test","ClientRequestPath":"/x?token=Canary-Secret-7","ClientRequestMethod":"GET","EdgeResponseStatus":200,"WAFAttackScore":3}`
	_, fs, err := CloudflareRun([]byte(l), "", SvOptions{})
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %+v", err, fs)
	}
	if strings.Contains(fs[0].Description+fs[0].Evidence.Command, "Canary-Secret-7") {
		t.Error("query string leaked into a finding")
	}
	for _, in := range []string{"", "[]", "{}", `{"result":[]}`, "words"} {
		if _, _, err := CfPolicyRun([]byte(in), CfPolOptions{}); err == nil {
			t.Errorf("policy accepted %q", in)
		}
	}
}

func TestSaseHTTP(t *testing.T) {
	h := telHandler(t)
	for _, p := range []string{"/v1/cloudflare/logs", "/v1/cloudflare/policy", "/v1/umbrella/logs"} {
		if c, _ := netDo(t, h, "POST", p, "x", ""); c != 401 {
			t.Errorf("%s unauthenticated %d", p, c)
		}
	}
	for _, p := range []string{"/v1/cloudflare/sources", "/v1/umbrella/sources"} {
		if c, _ := netDo(t, h, "GET", p, "", ""); c != 401 {
			t.Errorf("%s unauth %d", p, c)
		}
		if c, b := netDo(t, h, "GET", p, "", "tok"); c != 200 || !strings.Contains(string(b), "observe-only") {
			t.Errorf("%s %d", p, c)
		}
	}
	cf := `{"Datetime":"2026-11-20T10:00:00Z","ClientIP":"203.0.113.9","ClientRequestHost":"a.example.test","ClientRequestPath":"/x","ClientRequestMethod":"GET","EdgeResponseStatus":200,"WAFAttackScore":3}`
	if c, b := netDo(t, h, "POST", "/v1/cloudflare/logs?host=Zone-A", cf, "tok"); c != 200 || !strings.Contains(string(b), "cf-an-attack-score-allowed") {
		t.Fatalf("cf logs %d %s", c, b)
	}
	if c, b := netDo(t, h, "GET", "/v1/findings", "", "tok"); c != 200 || !strings.Contains(string(b), "cloudflare:zone-a") {
		t.Errorf("stored findings %d", c)
	}
	um := "2026-11-20 10:00:00,alice@example.test,alice@example.test,10.1.1.10,203.0.113.50,Allowed,1 (A),NOERROR,evil.example.test.,Malware,x,x,\n"
	if c, b := netDo(t, h, "POST", "/v1/umbrella/logs", um, "tok"); c != 200 || !strings.Contains(string(b), "umb-an-threat-category-allowed") {
		t.Errorf("umbrella %d %s", c, b)
	}
	if c, b := netDo(t, h, "POST", "/v1/cloudflare/policy", `{"result":[{"phase":"http_request_firewall_custom","rules":[{"action":"skip","expression":"true","enabled":true,"description":"x"}]}]}`, "tok"); c != 200 || !strings.Contains(string(b), "cfpol-skip-broad") {
		t.Errorf("policy %d %s", c, b)
	}
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/v1/cloudflare/logs", "", 400}, {"/v1/cloudflare/logs", "just words", 400}, {"/v1/umbrella/logs?format=bogus", um, 400},
		{"/v1/cloudflare/policy", "", 400}, {"/v1/cloudflare/policy", `{"x":1}`, 400}, {"/v1/cloudflare/policy", `{"policy":{"phase":"p","rules":[]},"now":"yesterday"}`, 400},
	} {
		if code, _ := netDo(t, h, "POST", c.path, c.body, "tok"); code != c.want {
			t.Errorf("%s %q: %d, want %d", c.path, c.body, code, c.want)
		}
	}
}
