// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigPolicyLoaderValidation(t *testing.T) {
	pols, err := ConfigPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) < 100 {
		t.Fatalf("expected a substantial policy set, got %d", len(pols))
	}
	ids := map[string]bool{}
	for i := range pols {
		p := &pols[i]
		if ids[p.ID] {
			t.Fatalf("duplicate id %s", p.ID)
		}
		ids[p.ID] = true
		if strings.TrimSpace(p.Remediation) == "" || strings.TrimSpace(p.AbsenceNote) == "" {
			t.Errorf("%s: missing remediation or absence note", p.ID)
		}
		checkRegexLens(t, p.ID, p.Check)
		if p.AppliesWhen != nil {
			checkRegexLens(t, p.ID, p.AppliesWhen)
		}
		if err := cfgSelfTest(p); err != nil {
			t.Errorf("%s self-test: %v", p.ID, err)
		}
	}
}

func checkRegexLens(t *testing.T, id string, c *CfgCond) {
	if len(c.Value) > cfgMaxRegex && (c.Op == "regex" || c.Op == "not_regex") || len(c.KeyRegex) > cfgMaxRegex {
		t.Errorf("%s: regex over %d chars", id, cfgMaxRegex)
	}
	for _, s := range c.All {
		checkRegexLens(t, id, s)
	}
	for _, s := range c.Any {
		checkRegexLens(t, id, s)
	}
	if c.Not != nil {
		checkRegexLens(t, id, c.Not)
	}
}

func TestConfigPolicyValidateRejects(t *testing.T) {
	mk := func() CfgPolicy {
		var p CfgPolicy
		p.ID, p.Title, p.Description, p.Rationale = "x-test", "t", "d", "r"
		p.Severity, p.OnAbsent, p.AbsenceNote, p.Remediation = "low", "pass", "n", "fix"
		p.AppliesTo.Formats = []string{CfgSSHD}
		p.Check = &CfgCond{Key: "a", Op: "equals", Value: "b"}
		p.Positive, p.Negative = "a x", "a b"
		return p
	}
	ok := mk()
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	bad := mk()
	bad.Severity = "bogus"
	if bad.validate() == nil {
		t.Error("bad severity accepted")
	}
	bad = mk()
	bad.Remediation = " "
	if bad.validate() == nil {
		t.Error("missing remediation accepted")
	}
	bad = mk()
	bad.Check = &CfgCond{Key: "a", Op: "regex", Value: strings.Repeat("a", 300)}
	if bad.validate() == nil {
		t.Error("long regex accepted")
	}
	bad = mk()
	bad.Check = &CfgCond{Key: "a", Op: "nope"}
	if bad.validate() == nil {
		t.Error("bad op accepted")
	}
}

func TestConfigAbsenceSemantics(t *testing.T) {
	d, _ := parseConfig(CfgSSHD, "Port 22\n")
	get := func(id string) CfgResult {
		pols, _ := ConfigPolicies()
		for i := range pols {
			if pols[i].ID == id {
				return pols[i].Evaluate(d)
			}
		}
		t.Fatalf("no policy %s", id)
		return CfgResult{}
	}
	if r := get("ssh-password-auth"); r.Status != CfgFail {
		t.Errorf("absent PasswordAuthentication defaults to yes: want fail, got %s", r.Status)
	}
	if r := get("ssh-empty-passwords"); r.Status != CfgPass {
		t.Errorf("absent PermitEmptyPasswords defaults to no: want pass, got %s", r.Status)
	}
	ds, _ := parseConfig(CfgSysctl, "vm.swappiness = 10\n")
	pols, _ := ConfigPolicies()
	for i := range pols {
		if pols[i].ID == "sys-aslr" {
			if r := pols[i].Evaluate(ds); r.Status != CfgUnknown {
				t.Errorf("absent sysctl must be unknown, got %s", r.Status)
			}
		}
	}
	dn, _ := parseConfig(CfgNginx, "server { listen 80; }\n")
	for i := range pols {
		if pols[i].ID == "web-hsts" {
			if r := pols[i].Evaluate(dn); r.Status != CfgNotApplicable {
				t.Errorf("HSTS on a non-TLS server must be not_applicable, got %s", r.Status)
			}
		}
	}
}

func TestConfigSniffer(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"", "PermitRootLogin no\nPasswordAuthentication no\n", CfgSSHD},
		{"sshd_config", "# nothing\n", CfgSSHD},
		{"", "net.ipv4.ip_forward = 0\nkernel.randomize_va_space = 2\n", CfgSysctl},
		{"", "PASS_MAX_DAYS 90\nUMASK 027\n", CfgLoginDefs},
		{"", "Defaults use_pty\nroot ALL=(ALL:ALL) ALL\n", CfgSudoers},
		{"", "-w /etc/passwd -p wa -k id\n-e 2\n", CfgAuditd},
		{"", "auth required pam_unix.so\naccount required pam_unix.so\n", CfgPAM},
		{"", "server {\n listen 443 ssl;\n}\n", CfgNginx},
		{"", "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n", CfgApache},
		{"", "apiVersion: v1\nkind: Pod\nspec:\n  containers: []\n", CfgK8s},
		{"", "version: '3'\nservices:\n  a:\n    image: x:1\n", CfgCompose},
		{"", "FROM alpine:3.20\nRUN true\n", CfgDockerfile},
		{"", "resource \"aws_s3_bucket\" \"b\" {\n}\n", CfgTerraform},
		{"", "this is just prose from a human, nothing like a config\n", ""},
		{"Dockerfile.prod", "x", CfgDockerfile},
	}
	for _, c := range cases {
		if got := SniffConfigFormat(c.name, c.text); got != c.want {
			t.Errorf("sniff(%q,%.30q) = %q want %q", c.name, c.text, got, c.want)
		}
	}
}

func assess(t *testing.T, name, text string) *ConfigAssessment {
	t.Helper()
	a, err := AssessConfig(context.Background(), name, text)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func failIDs(a *ConfigAssessment) []string {
	var out []string
	for _, r := range a.Results {
		if r.Status == CfgFail {
			out = append(out, r.PolicyID)
		}
	}
	return out
}

func TestConfigAnalyzerThroughInspector(t *testing.T) {
	rep := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindConfig, Name: "sshd_config",
		Text: "PermitRootLogin yes\nPermitEmptyPasswords yes\n"})
	if rep.Format != "config/sshd" {
		t.Fatalf("format %q errors %v", rep.Format, rep.Errors)
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID == "cfg-ssh-root-login" {
			found = true
			if !strings.HasPrefix(f.Title, "[fail]") || f.Severity != "high" || f.Weight != 0 {
				t.Errorf("unexpected finding %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("expected cfg-ssh-root-login")
	}
	sum, ok := rep.Meta["config-assess.summary"].(*ConfigAssessment)
	if !ok || sum.CompliancePct == nil || sum.Counts[CfgFail] < 2 || !strings.Contains(sum.Note, "only the submitted file") {
		t.Fatalf("bad summary: %+v", rep.Meta)
	}
	rep = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindConfig, Text: "hello, this is not a config"})
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "cfg-unrecognized-format" {
		t.Fatalf("unrecognised input: %+v", rep.Findings)
	}
	// other kinds must not run the config analyzer
	rep = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindScript, Text: "PermitRootLogin yes"})
	for _, a := range rep.Analyzers {
		if a == "config-assess" {
			t.Fatal("config analyzer ran for a script")
		}
	}
}

func TestConfigEvidenceRedactsSecrets(t *testing.T) {
	a := assess(t, "Dockerfile", "FROM alpine:3.20\nENV DB_PASSWORD=supersecretvalue\nUSER app\n")
	for _, r := range a.Results {
		if r.PolicyID == "dockerfile-env-secret" {
			if r.Status != CfgFail {
				t.Fatalf("want fail got %s", r.Status)
			}
			if strings.Contains(strings.Join(r.Evidence, " "), "supersecretvalue") {
				t.Fatal("secret leaked into evidence")
			}
			return
		}
	}
	t.Fatal("policy not evaluated")
}

func TestConfigK8sEnvEvidenceRedacted(t *testing.T) {
	k := assess(t, "", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: a\n    image: a:1\n    env:\n    - name: API_TOKEN\n      value: tok-123456\n")
	hit := false
	for _, r := range k.Results {
		if r.PolicyID == "k8s-env-secret" && r.Status == CfgFail {
			hit = true
		}
		if strings.Contains(strings.Join(r.Evidence, " "), "tok-123456") {
			t.Fatal("secret leaked from k8s env")
		}
	}
	if !hit {
		t.Fatal("k8s-env-secret should fail")
	}
}

func TestConfigNewKindHTTP(t *testing.T) {
	mux := http.NewServeMux()
	RegisterInspect(mux, "tok")
	body, _ := json.Marshal(map[string]string{"text": "PermitRootLogin yes\n", "name": "sshd_config"})
	req := httptest.NewRequest("POST", "/v1/inspect/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("config inspect: %d %s", w.Code, w.Body.String())
	}
	var rep InspectReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "config" || rep.Format != "config/sshd" || rep.Mode != "observe-only" {
		t.Fatalf("unexpected report %+v", rep)
	}
	req = httptest.NewRequest("POST", "/v1/inspect/config", strings.NewReader("x"))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated config inspect must be 401, got %d", w.Code)
	}
	big := bytes.Repeat([]byte("a"), InspectMaxTextBytes+4096)
	req = httptest.NewRequest("POST", "/v1/inspect/config", bytes.NewReader(big))
	req.Header.Set("Authorization", "Bearer tok")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized config must be 413, got %d", w.Code)
	}
	found := false
	for _, k := range InspectAnalyzerNames()["config"] {
		found = found || k == "config-assess"
	}
	if !found {
		t.Fatal("config analyzer not listed for kind config")
	}
}

func TestConfigSecretFileReferencesAreNotSecrets(t *testing.T) {
	a := assess(t, "Dockerfile", "FROM alpine:3.20\nENV DB_PASSWORD_FILE=/run/secrets/db\nUSER app\n")
	for _, id := range failIDs(a) {
		if id == "dockerfile-env-secret" {
			t.Fatal("a *_FILE path was reported as a literal secret")
		}
	}
}

func TestConfigParsersAreTotal(t *testing.T) {
	// hostile / malformed input must never panic or hang
	inputs := []string{"", "{", "}}}}", "\x00\x01\x02", strings.Repeat("a=", 5000), strings.Repeat("{", 3000),
		"resource \"a\" \"b\" {\n" + strings.Repeat("x {\n", 500), "- - - -\n: :\n", "FROM\nENV\nARG =\n\\\n", "<a\n</b>\n<>\n",
		"Defaults\nroot = \n= =\n", "apiVersion: v1\nkind: Pod\nspec: [\n"}
	for _, f := range cfgFormats {
		for _, in := range inputs {
			if _, err := parseConfig(f, in); err != nil {
				continue
			}
		}
	}
}
