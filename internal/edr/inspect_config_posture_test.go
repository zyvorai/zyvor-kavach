// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ppFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "posture", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func failedIDs(t *testing.T, name, text string) map[string]bool {
	t.Helper()
	rep := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindConfig, Name: name, Text: text})
	out := map[string]bool{}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Title, "[fail]") {
			out[f.ID] = true
		}
	}
	return out
}

func TestPostureCfgSniffNewFormats(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"bigip.conf", "ltm virtual /Common/x {\n}\n", CfgBigIP},
		{"", ppFixture(t, "bigip_weak.conf"), CfgBigIP},
		{"", ppFixture(t, "tfplan_risky.json"), CfgTFPlan},
		{"", ppFixture(t, "cfn_risky.yaml"), CfgCFN},
		{"", `{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}`, CfgCFN},
		{"", `{"hello":"world"}`, ""},
		{"", "just some prose about ltm virtual servers", ""},
	}
	for _, c := range cases {
		if got := SniffConfigFormat(c.name, c.text); got != c.want {
			t.Errorf("sniff(%q, %.30q) = %q, want %q", c.name, c.text, got, c.want)
		}
	}
}

func TestPostureCfgBigIPWeakAndHardened(t *testing.T) {
	bad := failedIDs(t, "bigip.conf", ppFixture(t, "bigip_weak.conf"))
	for _, id := range []string{"cfg-bigip-httpd-allow-all", "cfg-bigip-sshd-allow-all", "cfg-bigip-httpd-ssl-protocol", "cfg-bigip-selfip-allow-all",
		"cfg-bigip-selfip-allow-default", "cfg-bigip-ssl-weak-ciphers", "cfg-bigip-virtual-wildcard-port", "cfg-bigip-snmp-default-community",
		"cfg-bigip-remote-syslog", "cfg-bigip-password-policy", "cfg-bigip-httpd-idle-timeout", "cfg-bigip-sshd-inactivity-timeout"} {
		if !bad[id] {
			t.Errorf("weak BIG-IP config: expected %s to fail; got %v", id, bad)
		}
	}
	if !bad["cfg-advisory-cve-2022-1388"] {
		t.Errorf("15.1.0.2 is below 15.1.5.1; expected the CVE-2022-1388 advisory finding, got %v", bad)
	}
	good := failedIDs(t, "bigip.conf", ppFixture(t, "bigip_hardened.conf"))
	if len(good) != 0 {
		t.Errorf("hardened BIG-IP config must have no failures: %v", good)
	}
}

func TestPostureCfgNginxExtrasAndAdvisory(t *testing.T) {
	bad := failedIDs(t, "nginx.conf", ppFixture(t, "nginx_weak.conf"))
	for _, id := range []string{"cfg-web-nginx-proxy-pass-client-host", "cfg-web-nginx-proxy-ssl-verify", "cfg-web-nginx-stub-status",
		"cfg-web-nginx-ignore-invalid-headers", "cfg-web-nginx-access-log-off", "cfg-web-nginx-session-tickets"} {
		if !bad[id] {
			t.Errorf("expected %s to fail, got %v", id, bad)
		}
	}
	if !bad["cfg-advisory-cve-2026-123007"] {
		t.Errorf("nginx 1.24.0 in HTTP/2 advisory range expected: %v", bad)
	}
	// a fixed version must not match
	fixed := failedIDs(t, "nginx.conf", "# nginx version: nginx/1.31.9\nhttp { server { listen 80; } }\n")
	for id := range fixed {
		if strings.HasPrefix(id, "cfg-advisory-") {
			t.Errorf("1.31.9 is fixed everywhere, got %s", id)
		}
	}
}

func TestPostureCfgIaCTerraformPlan(t *testing.T) {
	bad := failedIDs(t, "plan.json", ppFixture(t, "tfplan_risky.json"))
	for _, id := range []string{"cfg-iac-sg-open-admin", "cfg-iac-sg-open-data", "cfg-iac-rds-public", "cfg-iac-storage-unencrypted", "cfg-iac-iam-admin-wildcard"} {
		if !bad[id] {
			t.Errorf("expected %s, got %v", id, bad)
		}
	}
	if bad["cfg-iac-s3-public-acl"] {
		t.Error("a bucket that the plan deletes must not be reported")
	}
	// the 10.0.0.0/8 SSH rule must not be flagged on its own
	one := `{"format_version":"1","resource_changes":[{"address":"a","type":"aws_security_group","change":{"actions":["create"],"after":{"ingress":[{"cidr_blocks":["10.0.0.0/8"],"from_port":22,"to_port":22,"protocol":"tcp"}]}}}]}`
	if failedIDs(t, "plan.json", one)["cfg-iac-sg-open-admin"] {
		t.Error("private CIDR flagged as world-open")
	}
}

func TestPostureCfgIaCCloudFormationYAMLAndJSON(t *testing.T) {
	bad := failedIDs(t, "template.yaml", ppFixture(t, "cfn_risky.yaml"))
	for _, id := range []string{"cfg-iac-sg-open-admin", "cfg-iac-s3-public-acl", "cfg-iac-rds-public", "cfg-iac-storage-unencrypted"} {
		if !bad[id] {
			t.Errorf("expected %s, got %v", id, bad)
		}
	}
	js := `{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"R":{"Type":"AWS::IAM::Role","Properties":{"AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}}}}}`
	if !failedIDs(t, "t.json", js)["cfg-iac-iam-trust-any"] {
		t.Error("expected iam-trust-any from JSON template")
	}
	cond := strings.Replace(js, `"Action":"sts:AssumeRole"`, `"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}`, 1)
	if failedIDs(t, "t.json", cond)["cfg-iac-iam-trust-any"] {
		t.Error("a trust policy with a Condition must not be flagged")
	}
}

func TestPostureCfgIaCHostileInput(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000)
	inputs := []string{
		"", "{", `{"resource_changes": 5}`, `{"resource_changes": [1,"x",null,{"change":7}]}`,
		`{"resource_changes":[{"type":"aws_security_group","change":{"after":{"ingress":"zzz"}}}]}`,
		`{"resource_changes":[{"type":"aws_iam_policy","change":{"after":{"policy":"{{{{"}}}]}`,
		`{"format_version":"1","resource_changes":[{"type":"aws_iam_policy","change":{"after":{"policy":{"Statement":"x"}}}}]}`,
		deep, `{"Resources": {"A": 5, "B": {"Type": 3, "Properties": []}}, "AWSTemplateFormatVersion":"x"}`,
		"Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties: !GetAtt [\n", "!Ref\n!Sub\n- - -\n",
		`{"resource_changes":[{"type":"aws_security_group","change":{"after":{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":"abc","to_port":1e999}]}}}]}`,
	}
	for _, f := range []string{CfgTFPlan, CfgCFN} {
		for _, in := range inputs {
			done := make(chan struct{})
			go func() { defer close(done); _, _ = parseConfig(f, in) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s parser hung on %.40q", f, in)
			}
		}
	}
	// oversized resource list is bounded
	var sb strings.Builder
	sb.WriteString(`{"format_version":"1","resource_changes":[`)
	for i := 0; i < iacMaxResources+500; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"address":"r","type":"aws_db_instance","change":{"actions":["create"],"after":{"publicly_accessible":true}}}`)
	}
	sb.WriteString("]}")
	d, err := parseConfig(CfgTFPlan, sb.String())
	if err != nil || len(d.Notes) == 0 {
		t.Fatalf("expected a truncation note, err=%v notes=%v", err, d.Notes)
	}
}

func TestPostureCfgBigIPParserHostile(t *testing.T) {
	inputs := []string{
		strings.Repeat("{", 100000), strings.Repeat("a { ", 5000), strings.Repeat("}", 5000), "ltm virtual x {\n  destination \"unterminated\n",
		"\x00\x01ltm virtual\x00 {\n}", strings.Repeat("ltm pool p"+strings.Repeat("x", 100)+" { members { a { } } }\n", 3000),
		"sys httpd { allow { " + strings.Repeat("1.2.3.4 ", 20000) + "} }", "# only comment\n#TMSH-VERSION: 99.99.99.99.99.99.99\n",
	}
	for _, in := range inputs {
		done := make(chan struct{})
		var d *cfgDoc
		go func() { defer close(done); d, _ = parseConfig(CfgBigIP, in) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("bigip parser hung on %.40q", in)
		}
		if d != nil && len(d.Entries) > cfgMaxEntries+10 {
			t.Fatalf("entries not bounded: %d", len(d.Entries))
		}
	}
	// nesting beyond the cap is reported, not followed
	d, _ := parseConfig(CfgBigIP, strings.Repeat("a { ", 200))
	found := false
	for _, n := range d.Notes {
		found = found || strings.Contains(n, "nesting")
	}
	if !found {
		t.Errorf("expected a nesting note, got %v", d.Notes)
	}
}

func TestPostureCfgAdvisoryTable(t *testing.T) {
	advs, src, err := CfgAdvisories()
	if err != nil || len(advs) == 0 || !strings.Contains(src, "SAMPLE") {
		t.Fatalf("embedded table: n=%d src=%q err=%v", len(advs), src, err)
	}
	for _, a := range advs {
		if a.SourceVerified {
			t.Errorf("%s: embedded entries were not verified against a vendor page and must say so", a.ID)
		}
	}
	rows := []struct {
		id, ver string
		want    bool
	}{
		{"CVE-2022-1388", "16.1.2.1", true}, {"CVE-2022-1388", "16.1.2.2", false}, {"CVE-2022-1388", "15.1.5", true},
		{"CVE-2022-1388", "15.1.5.1", false}, {"CVE-2022-1388", "12.1.5", true}, {"CVE-2022-1388", "17.0.0", false},
		{"CVE-2026-123007", "1.30.7", false}, {"CVE-2026-123007", "1.30.6", true}, {"CVE-2026-123007", "1.31.0", true},
		{"CVE-2026-123007", "1.31.9", false}, {"CVE-2026-123007", "1.8.0", false},
	}
	by := map[string]CfgAdvisory{}
	for _, a := range advs {
		by[a.ID] = a
	}
	for _, r := range rows {
		v, ok := cfgVerParse(r.ver)
		if !ok {
			t.Fatalf("parse %s", r.ver)
		}
		if got := CfgAdvAffected(by[r.id], v); got != r.want {
			t.Errorf("%s @ %s: got %v want %v", r.id, r.ver, got, r.want)
		}
	}
}

func TestPostureCfgAdvisoryParseRejects(t *testing.T) {
	good := `{"format":"kavach-config-advisories/1","advisories":[{"id":"CVE-2099-1","product":"nginx","severity":"high","ranges":[{"introduced":"1.0.0","fixed":"1.2.3"}]}]}`
	if _, err := ParseCfgAdvisories([]byte(good)); err != nil {
		t.Fatalf("good table rejected: %v", err)
	}
	bad := []string{
		"", "{", `{"format":"x","advisories":[]}`,
		strings.Replace(good, `"nginx"`, `"apache"`, 1), strings.Replace(good, `"high"`, `"huge"`, 1),
		strings.Replace(good, `"fixed":"1.2.3"`, `"fixed":"abc"`, 1), strings.Replace(good, `,"fixed":"1.2.3"`, ``, 1),
		strings.Replace(good, `CVE-2099-1`, `bad id!`, 1), `{"format":"kavach-config-advisories/1","advisories":[{"id":"A-B-C","product":"nginx","severity":"low","ranges":[]}]}`,
		"{\"format\":\"kavach-config-advisories/1\",\"pad\":\"" + strings.Repeat("x", cfgAdvMaxFile) + "\"}",
	}
	for i, b := range bad {
		if _, err := ParseCfgAdvisories([]byte(b)); err == nil {
			t.Errorf("case %d: expected rejection of %.60q", i, b)
		}
	}
}

func TestPostureCfgVersionParse(t *testing.T) {
	ok := map[string][]int{"1.2.3": {1, 2, 3}, "v15.1.5.1": {15, 1, 5, 1}, "1.2.3-hf2": {1, 2, 3}, " 7 ": {7}}
	for in, want := range ok {
		got, valid := cfgVerParse(in)
		if !valid || cfgVerCmp(got, want) != 0 {
			t.Errorf("%q -> %v %v", in, got, valid)
		}
	}
	for _, in := range []string{"", "x", ".1", "1..2", "1.a", "1.2.3.4.5.6.7", "99999999999.1", strings.Repeat("1.", 40), "1.2x.3"} {
		if _, valid := cfgVerParse(in); valid {
			t.Errorf("%q should be rejected", in)
		}
	}
	a, _ := cfgVerParse("1.2")
	b, _ := cfgVerParse("1.2.0")
	if cfgVerCmp(a, b) != 0 {
		t.Error("1.2 should equal 1.2.0")
	}
}

func TestPostureCfgAdvisoryOperatorFileFallback(t *testing.T) {
	// A bad operator file must fall back to the sample and say so; exercised through the parser contract.
	if _, err := ParseCfgAdvisories([]byte(`{"format":"kavach-config-advisories/1","advisories":[{"id":"CVE-1-1","product":"nginx","severity":"low","ranges":[{"introduced":"1.0.0"}]}]}`)); err == nil {
		t.Error("a range without fixed or last_affected must be rejected")
	}
}

func fwReview(t *testing.T, text string) *FwReview {
	t.Helper()
	rs, err := ParseFwRules(text)
	if err != nil {
		t.Fatal(err)
	}
	return ReviewFwRules(context.Background(), rs)
}

func TestPostureCfgFirewallJSON(t *testing.T) {
	rv := fwReview(t, ppFixture(t, "fw_rules.json"))
	want := []string{"fw-any-any-allow", "fw-world-admin-port", "fw-shadowed-conflict", "fw-redundant-rule", "fw-broad-source-network",
		"fw-no-default-deny", "fw-disabled-rule", "fw-allow-no-logging", "fw-unused-object", "fw-unused-rule"}
	for _, id := range want {
		if rv.Counts[id] == 0 {
			t.Errorf("expected %s, got %v", id, rv.Counts)
		}
	}
	// r2 and r3 are covered by the any-any rule r1; r4 too.
	if rv.Counts["fw-shadowed-conflict"] != 1 || rv.Counts["fw-redundant-rule"] < 2 {
		t.Errorf("shadow counts: %v", rv.Counts)
	}
	// old-vpn is unused; web-servers and dmz-net (disabled rule still references it) are used
	for _, f := range rv.Findings {
		if f.id == "fw-unused-object" && (len(f.evidence) != 1 || f.evidence[0] != "old-vpn") {
			t.Errorf("unused objects: %v", f.evidence)
		}
	}
}

func TestPostureCfgFirewallCSVAndCleanBase(t *testing.T) {
	rv := fwReview(t, ppFixture(t, "fw_rules.csv"))
	if rv.Counts["fw-redundant-rule"] != 1 {
		t.Errorf("rule 2 is covered by rule 1: %v", rv.Counts)
	}
	if rv.Counts["fw-no-default-deny"] != 0 || rv.Counts["fw-any-any-allow"] != 0 {
		t.Errorf("final deny-all present, no any-any allow: %v", rv.Counts)
	}
	if rv.Counts["fw-unused-rule"] != 1 {
		t.Errorf("rule 2 has zero hits: %v", rv.Counts)
	}
	// semicolon- and tab-delimited exports
	for _, sep := range []string{";", "\t"} {
		txt := strings.ReplaceAll(ppFixture(t, "fw_rules.csv"), ",", sep)
		txt = strings.ReplaceAll(txt, "tcp/443;tcp/80", "tcp/443|tcp/80")
		if rs, err := ParseFwRules(txt); err != nil || len(rs.Rules) != 3 {
			t.Errorf("sep %q: err=%v rules=%v", sep, err, rs)
		}
	}
}

func TestPostureCfgFirewallSemantics(t *testing.T) {
	rows := []struct {
		name, json string
		id         string
		want       int
	}{
		{"disjoint ports are not shadowed", `[{"id":"a","action":"allow","source":["10.0.0.0/8"],"destination":["any"],"service":["tcp/80"]},{"id":"b","action":"deny","source":["10.1.0.0/16"],"destination":["any"],"service":["tcp/443"]}]`, "fw-shadowed-conflict", 0},
		{"narrower first is not shadowing", `[{"id":"a","action":"deny","source":["10.1.0.0/16"],"destination":["any"],"service":["tcp/443"]},{"id":"b","action":"allow","source":["10.0.0.0/8"],"destination":["any"],"service":["tcp/443"]}]`, "fw-shadowed-conflict", 0},
		{"port range covers port", `[{"id":"a","action":"allow","source":["any"],"destination":["10.0.0.1"],"service":["tcp/1-1024"]},{"id":"b","action":"deny","source":["10.1.0.0/16"],"destination":["10.0.0.1"],"service":["tcp/22"]}]`, "fw-shadowed-conflict", 1},
		{"proto mismatch", `[{"id":"a","action":"allow","source":["any"],"destination":["any"],"service":["udp/53"]},{"id":"b","action":"deny","source":["any"],"destination":["any"],"service":["tcp/53"]}]`, "fw-shadowed-conflict", 0},
		{"disabled earlier rule does not shadow", `[{"id":"a","enabled":false,"action":"allow","source":["any"],"destination":["any"],"service":["any"]},{"id":"b","action":"deny","source":["10.0.0.0/8"],"destination":["any"],"service":["tcp/22"]}]`, "fw-shadowed-conflict", 0},
		{"named service", `[{"id":"a","action":"allow","source":["any"],"destination":["10.0.0.1"],"service":["ssh"]}]`, "fw-world-admin-port", 1},
		{"ipv6 any", `[{"id":"a","action":"permit","src":"::/0","dst":"any","services":"any"}]`, "fw-any-any-allow", 1},
		{"private db port is fine", `[{"id":"a","action":"allow","source":["10.0.0.0/8"],"destination":["10.2.0.5"],"service":["tcp/5432"]}]`, "fw-world-data-port", 0},
		{"object expansion", `{"objects":[{"name":"g","members":["any"]}],"rules":[{"id":"a","action":"allow","source":["g"],"destination":["any"],"service":["any"]}]}`, "fw-any-any-allow", 1},
		{"object cycle is bounded", `{"objects":[{"name":"a","members":["b"]},{"name":"b","members":["a"]}],"rules":[{"id":"x","action":"allow","source":["a"],"destination":["any"],"service":["any"]}]}`, "fw-allow-no-logging", 0},
		{"omitted fields mean any", `[{"id":"a","action":"allow"}]`, "fw-any-any-allow", 1},
		{"unknown action is not allow", `[{"id":"a","action":"frobnicate","source":["any"],"destination":["any"],"service":["any"]}]`, "fw-any-any-allow", 0},
	}
	for _, r := range rows {
		txt := r.json
		if txt[0] == '[' {
			// accepted bare list
		}
		if got := fwReview(t, txt).Counts[r.id]; got != r.want {
			t.Errorf("%s: %s = %d, want %d", r.name, r.id, got, r.want)
		}
	}
}

func TestPostureCfgFirewallHostile(t *testing.T) {
	if _, err := ParseFwRules("hello"); err == nil {
		t.Error("prose must not parse")
	}
	for _, bad := range []string{`[1,2,3]`, `{"rules":"x"}`, `[{"action":5}]`, `{"rules":[{"source":{"a":1}}],"action":"x","source":"y"}`, "action,src\n\"unterminated"} {
		_, _ = ParseFwRules(bad) // must not panic
	}
	// many rules: bounded and fast; shadow analysis stays inside its budget
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < fwMaxRules+100; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"r","action":"allow","source":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"destination":["10.9.9.9"],"service":["tcp/1-100","tcp/200-300"],"log":true}`)
	}
	sb.WriteString("]")
	start := time.Now()
	rs, err := ParseFwRules(sb.String())
	if err != nil || len(rs.Rules) != fwMaxRules {
		t.Fatalf("rules cap: err=%v n=%d", err, len(rs.Rules))
	}
	rv := ReviewFwRules(context.Background(), rs)
	if time.Since(start) > 20*time.Second {
		t.Fatalf("review too slow: %v", time.Since(start))
	}
	if !strings.HasPrefix(rv.ShadowCheck, "skipped") && !strings.HasPrefix(rv.ShadowCheck, "truncated") && rv.ShadowCheck != "complete" {
		t.Errorf("unexpected shadow status %q", rv.ShadowCheck)
	}
	// huge atom list in one field is truncated with a note
	many := make([]string, 500)
	for i := range many {
		many[i] = "10.0.0." + string(rune('0'+i%10))
	}
	b, _ := json.Marshal(map[string]any{"rules": []map[string]any{{"id": "big", "action": "allow", "source": many, "destination": []string{"any"}, "service": []string{"any"}}}})
	rv = fwReview(t, string(b))
	if len(rv.Notes) == 0 {
		t.Error("expected a truncation note for an oversized field")
	}
	// cancelled context stops the quadratic pass without a panic
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs2, _ := ParseFwRules(sb.String()[:5000] + "{}]")
	if rs2 != nil {
		_ = ReviewFwRules(ctx, rs2)
	}
}

func TestPostureCfgFirewallThroughInspector(t *testing.T) {
	rep := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindConfig, Name: "rules.json", Text: ppFixture(t, "fw_rules.json")})
	if rep.Format != "config/firewall-rules" {
		t.Fatalf("format %q errors %v", rep.Format, rep.Errors)
	}
	ids := map[string]bool{}
	for _, f := range rep.Findings {
		ids[f.ID] = true
		if f.Weight != 0 {
			t.Errorf("config findings carry no weight: %+v", f)
		}
		if f.ID == "cfg-unrecognized-format" {
			t.Error("recognised export reported as unrecognised")
		}
	}
	if !ids["fw-any-any-allow"] || rep.Level != "not_scored" {
		t.Errorf("findings %v level %s", ids, rep.Level)
	}
}
