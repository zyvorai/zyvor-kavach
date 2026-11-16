package edr

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type sigmaReportT struct {
	DryRun  bool                      `json:"dry_run"`
	Summary map[string]int            `json:"summary"`
	Gaps    map[string]map[string]int `json:"gap_summary"`
	Results []sigmaItem               `json:"results"`
}

func sigmaCall(t *testing.T, mux *http.ServeMux, path, body string) (int, sigmaReportT) {
	t.Helper()
	w := customDo(mux, "POST", path, body)
	var rep sigmaReportT
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body)
	}
	return w.Code, rep
}

func sigmaByID(rep sigmaReportT) map[string]sigmaItem {
	m := map[string]sigmaItem{}
	for _, it := range rep.Results {
		m[it.ID] = it
	}
	return m
}

func sigmaFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/sigma/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSigmaImportRouteDryRunDefaultAndAuth(t *testing.T) {
	mux, _ := ruleSetup(t, t.TempDir())
	r := httptest.NewRequest("POST", "/v1/content/import/sigma", strings.NewReader("x"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	code, rep := sigmaCall(t, mux, "/v1/content/import/sigma", sigmaFixture(t, "examples_ok.yml"))
	if code != 200 || !rep.DryRun {
		t.Fatalf("default must be dry run: %d %+v", code, rep.DryRun)
	}
	if rep.Summary["imported"] != 0 {
		t.Fatalf("dry run imported rules: %+v", rep.Summary)
	}
	if w := customDo(mux, "GET", "/v1/content/custom", ""); strings.Contains(w.Body.String(), "ex-sigma-") {
		t.Fatalf("dry run stored rules: %s", w.Body)
	}
	if code, _ := sigmaCall(t, mux, "/v1/content/import/sigma?dry_run=maybe", "x"); code != 400 {
		t.Fatalf("bad dry_run: %d", code)
	}
	// Envelope form with dry_run in the body; the query string wins.
	env, _ := json.Marshal(map[string]any{"sigma": sigmaFixture(t, "examples_ok.yml"), "dry_run": false})
	if code, rep := sigmaCall(t, mux, "/v1/content/import/sigma?dry_run=true", string(env)); code != 200 || !rep.DryRun {
		t.Fatalf("query must win over envelope: %d %v", code, rep.DryRun)
	}
}

func TestSigmaFixturesDryRunAndApply(t *testing.T) {
	mux, _ := ruleSetup(t, t.TempDir())
	ok, skipped := sigmaFixture(t, "examples_ok.yml"), sigmaFixture(t, "examples_skipped.yml")

	_, rep := sigmaCall(t, mux, "/v1/content/import/sigma", ok)
	by := sigmaByID(rep)
	for _, id := range []string{"ex-sigma-encoded-pwsh", "ex-sigma-certutil-fetch", "ex-sigma-pipe-to-shell", "ex-sigma-b64-marker",
		"ex-sigma-onion-dest", "ex-sigma-cron-drop", "ex-sigma-runkey-temp", "ex-sigma-dyndns", "ex-sigma-unverifiable"} {
		it, found := by[id]
		if !found || it.Status != "converted" {
			t.Errorf("%s: want converted, got %+v", id, it)
		}
	}
	if by["ex-sigma-unverifiable"].Samples != "none" || by["ex-sigma-unverifiable"].Lifecycle != "testing" {
		t.Errorf("unverifiable must start in testing: %+v", by["ex-sigma-unverifiable"])
	}
	for id, it := range by {
		if id != "ex-sigma-unverifiable" && it.Samples != "derived" {
			t.Errorf("%s: samples %q, want derived", id, it.Samples)
		}
	}

	_, rep = sigmaCall(t, mux, "/v1/content/import/sigma", skipped)
	by = sigmaByID(rep)
	if it := by["ex-sigma-noisy-git"]; it.Status != "noisy" || len(it.Errors) == 0 {
		t.Errorf("noisy git: %+v", it)
	}
	if it := by["ex-sigma-unsupported"]; it.Status != "skipped" {
		t.Errorf("unsupported: %+v", it)
	}
	var names []string
	for _, g := range by["ex-sigma-unsupported"].Gaps {
		names = append(names, g.Kind+":"+g.Name)
	}
	sort.Strings(names)
	if want := []string{"field:Hashes", "modifier:cidr", "modifier:fieldref"}; !reflect.DeepEqual(names, want) {
		t.Errorf("gaps %v, want %v (all unsupported fields/modifiers reported, not just the first)", names, want)
	}
	if it := by["ex-sigma-unsupported-cat"]; it.Status != "skipped" || len(it.Gaps) == 0 || it.Gaps[0].Kind != "category" {
		t.Errorf("category: %+v", it)
	}
	if it := by["ex-sigma-redos"]; it.Status != "skipped" || it.Gaps[0].Kind != "regex" || !strings.Contains(it.Gaps[0].Detail, "ReDoS") {
		t.Errorf("redos: %+v", it)
	}
	if rep.Gaps["field"]["Hashes"] != 1 || rep.Summary["noisy"] != 1 || rep.Summary["skipped"] != 3 {
		t.Errorf("summary %+v gaps %+v", rep.Summary, rep.Gaps)
	}

	// Apply (admin token): clean rules imported, noisy never, unverifiable in testing.
	_, rep = sigmaCall(t, mux, "/v1/content/import/sigma?dry_run=false", ok+"\n---\n"+skipped)
	if rep.DryRun || rep.Summary["imported"] != 9 || rep.Summary["noisy"] != 1 || rep.Summary["skipped"] != 3 {
		t.Fatalf("apply: %+v", rep.Summary)
	}
	list := customDo(mux, "GET", "/v1/content/custom", "").Body.String()
	if strings.Contains(list, "ex-sigma-noisy-git") || !strings.Contains(list, "ex-sigma-encoded-pwsh") {
		t.Fatalf("custom list wrong: %s", list)
	}
	lc := customDo(mux, "GET", "/v1/rules/lifecycle/ex-sigma-unverifiable", "").Body.String()
	if !strings.Contains(lc, `"state":"testing"`) || !strings.Contains(lc, `"explicit":true`) {
		t.Fatalf("lifecycle: %s", lc)
	}
	if lc := customDo(mux, "GET", "/v1/rules/lifecycle/ex-sigma-onion-dest", "").Body.String(); !strings.Contains(lc, `"explicit":false`) {
		t.Fatalf("verified rule must not be forced into testing: %s", lc)
	}
	// The unverified rule is persisted with unverified=true.
	if got := customDo(mux, "GET", "/v1/content/custom?tests=1", "").Body.String(); !strings.Contains(got, `"unverified":true`) {
		t.Fatalf("unverified flag missing: %s", got)
	}
}

func TestSigmaConverterFeatures(t *testing.T) {
	conv := func(detection string, extra string) sigmaResult {
		src := "title: T One\nlevel: low\ntags: [attack.execution, attack.t1059]\nlogsource:\n  category: process_creation\n" + extra + "detection:\n" + detection
		res, err := sigmaConvertDocument([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return res[0]
	}
	// quantifiers
	r := conv("  a1:\n    Image|endswith: '/a'\n  a2:\n    Image|endswith: '/b'\n  b1:\n    CommandLine|contains: x\n  condition: all of a* and 1 of them\n", "")
	if r.Rule == nil || len(r.Rule.Match.All) != 2 {
		t.Fatalf("all of a* and 1 of them: %+v %v %v", r.Rule, r.Errors, r.Unsupported)
	}
	r = conv("  s1:\n    Image: a\n  s2:\n    Image: b\n  s3:\n    Image: c\n  condition: 2 of s*\n", "")
	if r.Rule == nil || len(r.Rule.Match.Any) != 3 {
		t.Fatalf("2 of s*: %+v %v %v", r.Rule, r.Errors, r.Unsupported)
	}
	if r := conv("  s1:\n    Image: a\n  condition: 1 of zz*\n", ""); r.Rule != nil || len(r.Errors) == 0 {
		t.Fatalf("empty glob must error: %+v", r)
	}
	// wildcards
	for val, wantOp := range map[string]string{"'*x*'": "contains", "'x*'": "prefix", "'*x'": "suffix", "'a*b'": "regex", "'a?b'": "regex", "'a\\*b'": "equals"} {
		r := conv("  s:\n    CommandLine: "+val+"\n  condition: s\n", "")
		if r.Rule == nil || r.Rule.Match.Op != wantOp {
			t.Errorf("%s: want op %s, got %+v %v %v", val, wantOp, r.Rule, r.Errors, r.Unsupported)
		}
	}
	if r := conv("  s:\n    CommandLine: 'a\\*b'\n  condition: s\n", ""); r.Rule == nil || r.Rule.Match.Pattern != "a*b" {
		t.Errorf("escaped wildcard: %+v", r.Rule)
	}
	// windash
	r = conv("  s:\n    CommandLine|contains|windash: ' -enc '\n  condition: s\n", "")
	if r.Rule == nil || len(r.Rule.Match.Patterns) != 5 {
		t.Fatalf("windash: %+v %v", r.Rule, r.Unsupported)
	}
	// base64offset: all three alignments must match their encodings
	vals := sigmaBase64Offset("hello world")
	if len(vals) != 3 {
		t.Fatalf("offsets: %v", vals)
	}
	for _, pre := range []string{"", "a", "ab"} {
		enc := base64Std(pre + "hello world!")
		hit := false
		for _, v := range vals {
			hit = hit || strings.Contains(enc, v)
		}
		if !hit {
			t.Errorf("no base64offset variant found in %q (prefix %q)", enc, pre)
		}
	}
	// modifier combos reported
	r = conv("  s:\n    CommandLine|re|windash: a\n    Image|zzz: b\n  condition: s\n", "")
	if r.Rule != nil || len(r.Gaps) < 2 {
		t.Fatalf("combos: %+v", r.Gaps)
	}
	// auth category
	src := "title: Auth Rule\nlevel: high\ntags: [attack.credential_access, attack.t1110]\nlogsource:\n  category: authentication\ndetection:\n  s:\n    TargetUserName: root\n    IpAddress|startswith: '203.0.113.'\n  condition: s\n"
	res, _ := sigmaConvertDocument([]byte(src))
	if res[0].Rule == nil || res[0].Rule.EventType != "auth" || res[0].Samples != "derived" {
		t.Fatalf("auth: %+v %v %v", res[0].Rule, res[0].Errors, res[0].Unsupported)
	}
}

func TestSigmaRegexSafetyAndLimits(t *testing.T) {
	for _, p := range []string{"(a+)+$", "(a*)*", "(.*a){3,}x(b+)*", "(x+x+)+y", strings.Repeat("a", sigmaMaxRegexLen+1), "a{1000}", "(?=x)y", `(a)\1`} {
		if err := sigmaCheckRegex(p); err == nil {
			t.Errorf("regex %q must be rejected", p)
		}
	}
	for _, p := range []string{`\\temp\\[a-z]+\.exe`, `(foo|bar)+`, `^a(b|c){1,5}d$`, `[(]+x`, `\(+a`} {
		if err := sigmaCheckRegex(p); err != nil {
			t.Errorf("regex %q must be accepted: %v", p, err)
		}
	}
	if _, err := sigmaConvertDocument([]byte(strings.Repeat("a", sigmaMaxBytes+1))); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("size limit: %v", err)
	}
	var b strings.Builder
	for i := 0; i <= sigmaMaxRules; i++ {
		b.WriteString("title: R\n---\n")
	}
	if _, err := sigmaConvertDocument([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("rule count limit: %v", err)
	}
	mux, _ := ruleSetup(t, t.TempDir())
	if w := customDo(mux, "POST", "/v1/content/import/sigma", strings.Repeat("a", sigmaMaxBytes+10)); w.Code != 413 {
		t.Fatalf("oversized body: %d", w.Code)
	}
}

func TestSigmaOldRouteStillWorksAndUsesGuards(t *testing.T) {
	mux, _ := customSetup(t, t.TempDir())
	w := customDo(mux, "POST", "/v1/content/import?format=sigma&validate_only=true", sigmaFixture(t, "examples_skipped.yml"))
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"unsupported":3`) || !strings.Contains(w.Body.String(), `"rejected":1`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// canon normalises a match tree for comparison: single-element Patterns collapse to Pattern and
// all/any children are sorted, because Sigma selection maps carry no ordering.
func canon(n ContentMatch) string {
	if len(n.Patterns) == 1 {
		n.Pattern, n.Patterns = n.Patterns[0], nil
	}
	enc := func(l []ContentMatch) []string {
		out := make([]string, len(l))
		for i := range l {
			out[i] = canon(l[i])
		}
		sort.Strings(out)
		return out
	}
	m := map[string]any{"f": n.Field, "o": n.Op, "p": n.Pattern, "ps": n.Patterns, "cs": n.CaseSensitive}
	if len(n.All) > 0 {
		m["all"] = enc(n.All)
	}
	if len(n.Any) > 0 {
		m["any"] = enc(n.Any)
	}
	if n.Not != nil {
		m["not"] = canon(*n.Not)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestSigmaExportRoundTrip(t *testing.T) {
	rules := []*ContentRule{
		{ID: "rt-proc", Name: "Round trip process", Description: "d", Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell", Severity: "high", OS: "linux", EventType: "process",
			Tags: []string{"lab", "x-y"}, Batch: "acme",
			Match: ContentMatch{All: []ContentMatch{
				{Field: "executable", Op: "suffix", Patterns: []string{"/curl", "/wget"}},
				{Field: "command", Op: "contains", Pattern: "http://", CaseSensitive: true},
				{Field: "command", Op: "regex", Pattern: `\|\s*(ba)?sh`},
				{Not: &ContentMatch{Field: "parent_exe", Op: "prefix", Pattern: "/usr/bin/apt"}},
				{Any: []ContentMatch{{Field: "command", Op: "contains", Pattern: "-o-"}, {Field: "command", Op: "equals", Pattern: "it's"}}},
			}},
			Tests: &ContentTests{
				Positive: []LabEvent{{Executable: "/usr/bin/curl", Command: "curl http://x.test | sh -o-"}},
				Negative: []LabEvent{{Executable: "/usr/bin/curl", Command: "curl https://x.test"}, {Executable: "/bin/ls", Command: "ls", Attrs: map[string]string{"k": "v"}}},
			}},
		{ID: "rt-reg", Name: "Round trip registry", Description: "d2", Tactic: "Persistence", Technique: "T1547.001", Severity: "low", OS: "windows", EventType: "registry",
			Match: ContentMatch{Field: "key", Op: "contains", Pattern: `\Run\`},
			Tests: &ContentTests{Positive: []LabEvent{{Attrs: map[string]string{"key": `HKCU\X\Run\y`}}}, Negative: []LabEvent{{Attrs: map[string]string{"key": `HKCU\X`}}}}},
	}
	for _, r := range rules {
		cp := *r
		if err := validateCustomRule(&cp); err != nil {
			t.Fatalf("fixture %s invalid: %v", r.ID, err)
		}
	}
	yaml, exported, skipped := sigmaExportAll(rules)
	if len(exported) != 2 || len(skipped) != 0 {
		t.Fatalf("exported %v skipped %v\n%s", exported, skipped, yaml)
	}
	res, err := sigmaConvertDocument([]byte(yaml))
	if err != nil {
		t.Fatalf("re-import: %v\n%s", err, yaml)
	}
	for i, r := range rules {
		got := res[i]
		if got.Rule == nil {
			t.Fatalf("%s: round trip failed: %v %v\n%s", r.ID, got.Errors, got.Unsupported, yaml)
		}
		g := got.Rule
		if g.ID != r.ID || g.Name != r.Name || g.Description != r.Description || g.Tactic != r.Tactic || g.Technique != r.Technique ||
			g.TechniqueName != r.TechniqueName || g.Severity != r.Severity || g.OS != r.OS || g.EventType != r.EventType ||
			!reflect.DeepEqual(g.Tags, r.Tags) {
			t.Errorf("%s: metadata differs:\n got %+v\nwant %+v", r.ID, g, r)
		}
		wantBatch := r.Batch
		if wantBatch == "" {
			wantBatch = "sigma"
		}
		if g.Batch != wantBatch {
			t.Errorf("%s: batch %q want %q", r.ID, g.Batch, wantBatch)
		}
		if canon(g.Match) != canon(r.Match) {
			t.Errorf("%s: match tree differs:\n got %s\nwant %s", r.ID, canon(g.Match), canon(r.Match))
		}
		if !reflect.DeepEqual(g.Tests, r.Tests) {
			t.Errorf("%s: tests differ:\n got %+v\nwant %+v", r.ID, g.Tests, r.Tests)
		}
		if got.Samples != "provided" {
			t.Errorf("%s: samples %q", r.ID, got.Samples)
		}
		// And the re-imported rule still passes the full harness.
		if err := validateCustomRule(g); err != nil {
			t.Errorf("%s: re-imported rule fails the harness: %v", r.ID, err)
		}
	}
	// A second export of the re-imported rules is byte-identical (stable form).
	y2, _, _ := sigmaExportAll([]*ContentRule{res[0].Rule, res[1].Rule})
	if y2 != yaml {
		t.Errorf("export not stable across a round trip:\n%s\n---\n%s", yaml, y2)
	}
}

func TestSigmaExportSkipsLossy(t *testing.T) {
	base := ContentRule{ID: "lossy", Name: "n", Description: "d", Tactic: "Execution", Technique: "T1059", Severity: "low", OS: "any", EventType: "process"}
	cases := map[string]ContentRule{}
	mk := func(name string, f func(r *ContentRule)) {
		r := base
		r.Match = ContentMatch{Field: "command", Op: "contains", Pattern: "x"}
		f(&r)
		cases[name] = r
	}
	mk("wildcard char", func(r *ContentRule) { r.Match.Pattern = "a*b" })
	mk("in op", func(r *ContentRule) { r.Match = ContentMatch{Field: "command", Op: "in", Patterns: []string{"a"}} })
	mk("unmapped field", func(r *ContentRule) { r.Match.Field = "host" })
	mk("module type", func(r *ContentRule) { r.EventType = "module" })
	mk("newline", func(r *ContentRule) { r.Match.Pattern = "a\nb" })
	mk("upper tag", func(r *ContentRule) { r.Tags = []string{"Lab"} })
	for name, r := range cases {
		r := r
		if _, err := sigmaExportRule(&r); err == nil {
			t.Errorf("%s: must not export", name)
		}
	}
}

func TestSigmaExportRoute(t *testing.T) {
	mux, _ := ruleSetup(t, t.TempDir())
	if w := customDo(mux, "POST", "/v1/content/custom", customGood); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w := customDo(mux, "POST", "/v1/content/export/sigma", "")
	var out struct {
		YAML     string      `json:"yaml"`
		Exported []string    `json:"exported"`
		Skipped  []sigmaSkip `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Exported) != 1 || out.Exported[0] != "acme-evil-tool" || !strings.Contains(out.YAML, "CommandLine|contains") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := customDo(mux, "POST", "/v1/content/export/sigma", `{"nope":1}`); w.Code != 400 {
		t.Fatalf("bad filter: %d", w.Code)
	}
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
