// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const harnessTestHdr = `{"schema":"kavach-content-tests/1","name":"t"}` + "\n"

func harnessRunText(t *testing.T, body string, dir string) *HarnessReport {
	t.Helper()
	rep, err := RunHarnessData("t.jsonl", []byte(body), dir, HarnessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestEveryRuleHasPassingExamples is the CI gate: no registered rule may ship without a positive
// and a negative example that behave. Add examples to content_examples/*.jsonl (analytic rules) or
// to the rule's own tests (content packs).
func TestEveryRuleHasPassingExamples(t *testing.T) {
	st, err := SelfTest(HarnessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range st.Failing() {
		t.Errorf("rule %s (%s): %s, positive %d/%d passing, negative %d/%d passing", r.ID, r.Family, r.Status, r.PositivePass, r.Positive, r.NegativePass, r.Negative)
	}
	for _, c := range st.Results {
		if !c.Pass {
			t.Errorf("example case %q failed: %v", c.Case, c.Diff)
		}
	}
	fam := map[string]int{}
	for _, r := range st.Rules {
		fam[r.Family]++
	}
	want := map[string]int{"web-analytic": len(webAnalyticRules), "auth-analytic": len(authAnalyticRules), "idp-analytic": len(idpRules), "ransom-analytic": len(rwRules), "tripwire": len(twRules)}
	for f, n := range want {
		if fam[f] != n {
			t.Errorf("family %s has %d rules in the inventory, want %d", f, fam[f], n)
		}
	}
	if fam["web-content"] < 49 {
		t.Errorf("web-content rules = %d, want at least 49", fam["web-content"])
	}
	// every rule id that registers itself for ATT&CK mapping under a built-in analytic prefix must be in the inventory
	inv := map[string]bool{}
	for _, r := range st.Rules {
		inv[r.ID] = true
	}
	for id := range ruleMITRE {
		for _, p := range []string{"web-an-", "auth-an-", "idp-an-", "rwlog-an-", "tripwire-", "netcfg-"} {
			if strings.HasPrefix(id, p) && !inv[id] {
				t.Errorf("rule %s is registered but missing from the harness inventory (add it to harnessAnalytics)", id)
			}
		}
	}
	if !st.OK() {
		t.Errorf("selftest not ok: %d failing rules, %d failed cases", st.RulesFailing, st.Failed)
	}
}

func TestCoverageByTestedRule(t *testing.T) {
	st, err := SelfTest(HarnessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cov := CoverageByTestedRule(st)
	if cov.TechniquesTested == 0 || cov.TechniquesTested > cov.TechniquesTotal || cov.RulesTested != st.RulesOK {
		t.Fatalf("bad coverage totals: %+v", cov)
	}
	found := false
	for _, tq := range cov.Techniques {
		if tq.ID == "T1110.004" {
			found = len(tq.Tested) >= 2
		}
	}
	if !found {
		t.Error("T1110.004 should be covered by the credential-stuffing rules")
	}
	// a rule without a passing example must not count
	st.Rules[0].Status = "positive-not-firing"
	st.RulesOK--
	c2 := CoverageByTestedRule(st)
	if c2.RulesTested != cov.RulesTested-1 {
		t.Error("failing rule still counted as tested")
	}
}

func TestHarnessFormat(t *testing.T) {
	bad := map[string]string{
		"no header":     `{"case":"a","kind":"web","lines":["x"],"expect":["web-an-ua-rotation"]}` + "\n",
		"wrong schema":  `{"schema":"kavach-content-tests/2"}` + "\n",
		"header fields": `{"schema":"kavach-content-tests/1","bogus":1}` + "\n",
		"empty":         "",
		"binary":        "\x00\x01\x02\xff\n",
	}
	for name, body := range bad {
		if _, err := RunHarnessData("t", []byte(body), "", HarnessOptions{}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	cases := map[string]string{
		"unknown field":   `{"case":"a","kind":"web","lines":["x"],"expect":["web-an-ua-rotation"],"expct":[]}`,
		"unknown rule":    `{"case":"a","kind":"web","lines":["x"],"expect":["web-an-no-such-rule"]}`,
		"bad kind":        `{"case":"a","kind":"nope","lines":["x"],"expect":["web-an-ua-rotation"]}`,
		"asserts nothing": `{"case":"a","kind":"web","lines":["x"]}`,
		"no input":        `{"case":"a","kind":"web","expect":["web-an-ua-rotation"]}`,
		"no name":         `{"kind":"web","lines":["x"],"expect":["web-an-ua-rotation"]}`,
		"malformed":       `{"case":"a","kind":`,
		"two values":      `{"case":"a","kind":"web","lines":["x"],"expect":["web-an-ua-rotation"]} {"x":1}`,
		"rule alone":      `{"case":"a","kind":"web","lines":["x"],"rule":"web-an-ua-rotation"}`,
		"format on auth":  `{"case":"a","kind":"auth","format":"json","records":[{"a":1}],"expect":["auth-an-high-velocity"]}`,
		"input exclusive": `{"case":"a","kind":"web","lines":["x"],"input":"f.log","expect":["web-an-ua-rotation"]}`,
		"huge gen":        `{"case":"a","kind":"web","gen":[{"count":99999999,"template":"x"}],"expect":["web-an-ua-rotation"]}`,
		"gen template":    `{"case":"a","kind":"web","gen":[{"count":2,"template":5}],"expect":["web-an-ua-rotation"]}`,
		"bad dormant":     `{"case":"a","kind":"idp","records":[{"a":1}],"dormant_days":3,"expect":["idp-an-mfa-removed"]}`,
	}
	for name, c := range cases {
		rep := harnessRunText(t, harnessTestHdr+c+"\n", "")
		if rep.Cases != 1 || rep.Failed != 1 || rep.Results[0].Error == "" {
			t.Errorf("%s: want one failing case with an error, got %+v", name, rep.Results)
		}
	}
	// a typo on one line does not hide the others; comments and blank lines are ignored
	body := "# comment\n// another\n\n" + harnessTestHdr + `{"case":"broken"` + "\n" +
		`{"case":"ok","kind":"auth","records":[{"time":"2026-01-15T10:00:00Z","user":"a","ip":"203.0.113.1","outcome":"success"}],"forbid":["auth-an-high-velocity"]}` + "\n"
	rep := harnessRunText(t, body, "")
	if rep.Cases != 2 || rep.Passed != 1 || rep.Failed != 1 || rep.Results[0].Line != 5 {
		t.Fatalf("got %+v", rep)
	}
}

func TestHarnessLimits(t *testing.T) {
	big := harnessTestHdr + strings.Repeat(`{"case":"c","kind":"auth","records":[{"time":"2026-01-15T10:00:00Z","user":"a","ip":"1.2.3.4","outcome":"success"}],"forbid":["auth-an-high-velocity"]}`+"\n", harnessMaxCases+5)
	rep := harnessRunText(t, big, "")
	if rep.Cases != harnessMaxCases+1 || rep.Failed != 1 { // the cap line becomes one failing "(file)" case
		t.Errorf("case cap: cases=%d failed=%d", rep.Cases, rep.Failed)
	}
	if _, err := RunHarnessData("t", make([]byte, harnessMaxFileBytes+1), "", HarnessOptions{}); err == nil {
		t.Error("oversize file accepted")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.jsonl")
	if err := os.WriteFile(p, []byte(harnessTestHdr+strings.Repeat("#", harnessMaxFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunHarnessFile(p, HarnessOptions{}); err == nil {
		t.Error("oversize file on disk accepted")
	}
	// record cap per case
	rep = harnessRunText(t, harnessTestHdr+`{"case":"g","kind":"auth","gen":[{"count":50000,"template":{"time":"{t}","user":"a","ip":"1.2.3.4","outcome":"success"}},{"count":5,"template":{"time":"{t}"}}],"forbid":["auth-an-high-velocity"]}`+"\n", "")
	if rep.Failed != 1 || !strings.Contains(rep.Results[0].Error, "over") {
		t.Errorf("record cap: %+v", rep.Results)
	}
	// a long single line and invalid UTF-8 are tolerated
	long := strings.Repeat("A", 200000)
	rep = harnessRunText(t, harnessTestHdr+fmt.Sprintf(`{"case":"long","kind":"web","lines":[%q,"\u0000� bad"],"forbid":["web-an-ua-rotation"]}`, long)+"\n", "")
	if rep.Failed != 1 || rep.Results[0].Error == "" { // nothing parseable is an error, never a panic
		t.Errorf("long line: %+v", rep.Results)
	}
}

func TestHarnessInputPathsAreConfined(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tests")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret.log")
	line := `203.0.113.7 - - [15/Jan/2026:10:00:00 +0000] "GET /a?id=1 union select 1,2 HTTP/1.1" 200 5 "-" "x"` + "\n"
	_ = os.WriteFile(secret, []byte(line), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ok.log"), []byte(strings.ReplaceAll(line, " union select 1,2", "%20union%20select%201,2")), 0o600)
	if err := os.Symlink(secret, filepath.Join(dir, "link.log")); err != nil {
		t.Skip("symlinks unavailable")
	}
	for _, in := range []string{"../secret.log", secret, "link.log", "missing.log", "."} {
		rep := harnessRunText(t, harnessTestHdr+fmt.Sprintf(`{"case":"x","kind":"web","input":%q,"expect":["web-sqli-union-select"]}`, in)+"\n", dir)
		if rep.Failed != 1 || rep.Results[0].Error == "" {
			t.Errorf("input %q accepted: %+v", in, rep.Results)
		}
		if strings.Contains(rep.Results[0].Error, root) {
			t.Errorf("error leaks a path: %s", rep.Results[0].Error)
		}
	}
	rep := harnessRunText(t, harnessTestHdr+`{"case":"x","kind":"web","input":"ok.log","expect":["web-sqli-union-select"]}`+"\n", dir)
	if rep.Passed != 1 {
		t.Errorf("confined input rejected: %+v", rep.Results)
	}
	rep = harnessRunText(t, harnessTestHdr+`{"case":"x","kind":"web","input":"ok.log","expect":["web-sqli-union-select"]}`+"\n", "")
	if rep.Failed != 1 {
		t.Error("input without a base directory must fail")
	}
}

func TestHarnessLineNumberedDiff(t *testing.T) {
	body := harnessTestHdr + `{"case":"web diff","kind":"web","format":"combined","lines":[` +
		`"203.0.113.7 - - [15/Jan/2026:10:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 5 \"-\" \"x\"",` +
		`"203.0.113.7 - - [15/Jan/2026:10:00:01 +0000] \"GET /a?id=1%20union%20select%201,2 HTTP/1.1\" 200 5 \"-\" \"x\""],` +
		`"expect":["web-xss-script-tag"],"forbid":["web-sqli-union-select"]}` + "\n"
	rep := harnessRunText(t, body, "")
	r := rep.Results[0]
	if r.Pass || len(r.Diff) != 2 {
		t.Fatalf("want 2 diff lines, got %+v", r)
	}
	if !strings.Contains(r.Diff[0], "t.jsonl:2 expected rule web-xss-script-tag did not fire") {
		t.Errorf("diff[0] = %q", r.Diff[0])
	}
	if !strings.Contains(r.Diff[1], "forbidden rule web-sqli-union-select fired 1x (input line 2)") {
		t.Errorf("diff[1] = %q", r.Diff[1])
	}
	// exact mode flags anything extra
	body = harnessTestHdr + `{"case":"exact","kind":"web","format":"combined","lines":["203.0.113.7 - - [15/Jan/2026:10:00:01 +0000] \"GET /a?id=1%20union%20select%201,2 HTTP/1.1\" 200 5 \"-\" \"x\""],"expect":["web-an-ua-rotation"],"exact":true}` + "\n"
	r = harnessRunText(t, body, "").Results[0]
	if r.Pass || len(r.Diff) < 2 {
		t.Errorf("exact: %+v", r)
	}
}

func TestHarnessEventKindAndGen(t *testing.T) {
	// event kind: use a registered content rule's own positive sample through the file format
	reg := loadTestRegistry(t)
	var ev LabEvent
	var id string
	for _, r := range reg.rules {
		if r.Batch != webBatchTag && r.Tests != nil && len(r.Tests.Positive) > 0 && r.EventType == "process" {
			ev, id = r.Tests.Positive[0], r.ID
			break
		}
	}
	ev.Kind = "process"
	j, _ := json.Marshal(ev)
	rep := harnessRunText(t, harnessTestHdr+fmt.Sprintf(`{"case":"ev","kind":"event","events":[%s],"expect":[%q]}`, j, id)+"\n", "")
	if rep.Passed != 1 {
		t.Fatalf("event case: %+v", rep.Results)
	}
	if got := harnessGenSub("ip-{i%3}-{i/2}-{i}", 7, time.Unix(0, 0)); got != "ip-1-3-7" {
		t.Errorf("harnessGenSub = %q", got)
	}
	if got := harnessGenSub("[{clf}] {t}", 0, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != "[02/Jan/2026:03:04:05 +0000] 2026-01-02T03:04:05Z" {
		t.Errorf("harnessGenSub time = %q", got)
	}
}

func TestHarnessTripwireStateRestored(t *testing.T) {
	twReg.mu.Lock()
	before, beforePath := len(twReg.defs), twReg.path
	twReg.mu.Unlock()
	st, err := SelfTest(HarnessOptions{})
	if err != nil || !st.OK() {
		t.Fatalf("selftest: %v", err)
	}
	twReg.mu.Lock()
	after, p := len(twReg.defs), twReg.path
	twReg.mu.Unlock()
	if before != after || p != beforePath {
		t.Errorf("tripwire registry changed: %d -> %d path %q -> %q", before, after, beforePath, p)
	}
}

func TestReplayBenignBuiltinCorpus(t *testing.T) {
	rep, err := ReplayBenign(nil, FPOptions{Builtin: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Files) != 4 || rep.Records["web"] < 3000 {
		t.Fatalf("builtin corpus not replayed: %+v", rep.Files)
	}
	for _, r := range rep.Rules {
		t.Logf("builtin benign hit: %s hits=%d rate=%.2f noisy=%v", r.Rule, r.Hits, r.RatePer1000, r.Noisy)
	}
	if len(rep.Noisy) > 0 {
		t.Errorf("the synthetic benign corpus makes rules noisy: %v", rep.Noisy)
	}
}

func TestReplayBenignFilesRedactionAndLimits(t *testing.T) {
	dir := t.TempDir()
	attack := `203.0.113.7 - - [15/Jan/2026:10:00:00 +0000] "GET /a?id=1%20union%20select%201,2&token=SECRETVALUE123 HTTP/1.1" 200 5 "-" "x"` + "\n"
	ok := `203.0.113.8 - - [15/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "x"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "web_access.log"), []byte(attack+strings.Repeat(ok, 9)), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "ignored.bin"), []byte("x"), 0o600)
	// a file larger than the per-file cap is truncated, not loaded whole
	big := strings.Repeat(strings.Repeat("a", 1000)+"\n", (fpMaxFileBytes/1001)+100)
	_ = os.WriteFile(filepath.Join(dir, "huge.log"), []byte(big), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "events.json"), []byte(`[{"kind":"process","executable":"/bin/ls","command":"ls -la"}]`), 0o600)
	rep, err := ReplayBenign([]string{dir}, FPOptions{Threshold: 50})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Truncated {
		t.Error("oversize file should set truncated")
	}
	var hit *FPRule
	for i := range rep.Rules {
		if rep.Rules[i].Rule == "web-sqli-union-select" {
			hit = &rep.Rules[i]
		}
	}
	if hit == nil || hit.Hits != 1 || !hit.Noisy {
		t.Fatalf("expected one noisy web-sqli-union-select hit, rules=%+v", rep.Rules)
	}
	if hit.RatePer1000 < 90 || hit.RatePer1000 > 110 {
		t.Errorf("rate = %v, want about 100 per 1000", hit.RatePer1000)
	}
	for _, s := range hit.Samples {
		if strings.Contains(s, "SECRETVALUE123") {
			t.Errorf("sample not redacted: %s", s)
		}
	}
	if len(hit.Samples) == 0 {
		t.Error("no sample kept")
	}
	if _, err := ReplayBenign(nil, FPOptions{}); err == nil {
		t.Error("empty input must be rejected")
	}
	if _, err := ReplayBenign([]string{filepath.Join(dir, "nope")}, FPOptions{}); err == nil {
		t.Error("missing path must be rejected")
	}
	if _, err := ReplayBenign([]string{dir}, FPOptions{Kind: "bogus"}); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestReplayBenignRepoEventCorpus(t *testing.T) {
	rep, err := ReplayBenign([]string{"testdata/benign_corpus.json"}, FPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files[0].Kind != "event" || rep.Files[0].Parsed < 500 {
		t.Fatalf("event corpus not detected: %+v", rep.Files[0])
	}
	for _, r := range rep.Rules {
		if r.Noisy && r.Severity != "low" {
			t.Errorf("medium+ rule %s is noisy on the repo benign corpus: %.2f per 1000", r.Rule, r.RatePer1000)
		}
	}
}

func TestSniffKind(t *testing.T) {
	cases := map[string]string{
		`{"eventType":"user.session.start"}`:      "idp",
		`{"time":"x","user":"a","ip":"1.1.1.1"}`:  "auth",
		`{"time":"x","op":"rename","path":"/a"}`:  "ransom",
		`{"method":"GET","uri":"/","status":200}`: "web",
		`[{"kind":"process","command":"ls"}]`:     "event",
		`203.0.113.1 - - [x] "GET / HTTP/1.1"`:    "web",
		``:                                        "web",
		`[`:                                       "web",
	}
	for in, want := range cases {
		if got := fpSniffKind("data.json", []byte(in)); got != want {
			t.Errorf("sniff(%q) = %s, want %s", in, got, want)
		}
	}
	if fpSniffKind("okta_export.json", []byte(`{}`)) != "idp" {
		t.Error("name hint ignored")
	}
}
