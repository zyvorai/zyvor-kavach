// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// benignBaseline is a small set of everyday events no content rule may match. Add to it freely;
// every rule in every pack is checked against all of it (events are tried under every kind).
var benignBaseline = []LabEvent{
	{Executable: "/bin/ls", Command: "ls -la /home/dev"},
	{Executable: "/bin/cat", Command: "cat /etc/hostname"},
	{Executable: "/bin/bash", ParentExe: "/usr/sbin/sshd", Command: "bash -c echo hi"},
	{Executable: "/usr/lib/systemd/systemd", ParentExe: "", Command: "/sbin/init splash"},
	{Executable: "/usr/bin/curl", Command: "curl https://example.com"},
	{Executable: "/usr/bin/ssh-agent", Command: "ssh-agent -s"},
	{Executable: "/usr/local/go/bin/go", Command: "go build ./..."},
	{Executable: "/usr/bin/python3", Command: "python3 script.py"},
	{Executable: "/usr/bin/apt", Command: "apt update"},
	{Executable: "/usr/bin/git", Command: "git status"},
	{Executable: "/usr/bin/tar", Command: "tar czf backup.tgz /var/www"},
	{Executable: "/usr/bin/vim", Command: "vim notes.txt"},
	{Executable: "C:\\Windows\\explorer.exe", Command: "explorer.exe C:\\Users\\ann\\Documents"},
	{Executable: "C:\\Windows\\System32\\cmd.exe", Command: "cmd.exe /c dir"},
	{Executable: "/usr/bin/open", Command: "open -a Safari https://example.com"},
	{Path: "/home/dev/project/main.go", Operation: "modify"},
	{Path: "/var/log/syslog", Operation: "modify"},
	{Path: "/tmp/build.log", Operation: "create"},
	{Path: "/Users/ann/Documents/report.docx", Operation: "create"},
	{Path: "C:\\Users\\ann\\Documents\\report.docx", Operation: "modify"},
	{Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"},
	{Destination: "example.com:443"},
	{Destination: "93.184.216.34:443"},
	{Destination: "github.com:22"},
	{Destination: "registry.npmjs.org:443"},
}

func loadTestRegistry(t *testing.T) *ContentRegistry {
	t.Helper()
	packs, err := embeddedContentPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) == 0 {
		t.Fatal("no embedded content packs")
	}
	reg, err := buildContentRegistry(packs)
	if err != nil {
		t.Fatalf("content packs failed validation:\n%v", err)
	}
	return reg
}

// TestContentHarness gates every embedded rule: schema, regex compilation, samples, benign baseline.
func TestContentHarness(t *testing.T) {
	reg := loadTestRegistry(t)
	if len(reg.rules) < 10 {
		t.Fatalf("expected at least the 10 seed rules, got %d", len(reg.rules))
	}
	seen := map[string]bool{}
	for _, r := range reg.rules {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			if seen[r.ID] {
				t.Fatalf("rule %s: duplicate id", r.ID)
			}
			seen[r.ID] = true
			if !contentIDRe.MatchString(r.ID) {
				t.Errorf("rule %s: id is not kebab-case", r.ID)
			}
			if !labTechRe.MatchString(r.Technique) {
				t.Errorf("rule %s: bad ATT&CK id %q", r.ID, r.Technique)
			}
			tacticOK := false
			for _, tac := range attackTactics {
				tacticOK = tacticOK || tac == r.Tactic
			}
			if !tacticOK {
				t.Errorf("rule %s: tactic %q not in enum", r.ID, r.Tactic)
			}
			if !contentSeverities[r.Severity] {
				t.Errorf("rule %s: severity %q not in enum", r.ID, r.Severity)
			}
			if !contentOSes[r.OS] || !contentAllTypes[r.EventType] {
				t.Errorf("rule %s: bad os %q or event_type %q", r.ID, r.OS, r.EventType)
			}
			if r.PendingTelemetry != !contentLiveTypes[r.EventType] {
				t.Errorf("rule %s: pending_telemetry flag inconsistent with event_type %s", r.ID, r.EventType)
			}
			if r.node == nil {
				t.Fatalf("rule %s: matcher (regex) did not compile", r.ID)
			}
			if r.Tests == nil || len(r.Tests.Positive) == 0 || len(r.Tests.Negative) == 0 {
				t.Fatalf("rule %s: needs at least one positive and one negative sample", r.ID)
			}
			for i, ev := range r.Tests.Positive {
				ev.Kind = r.EventType
				if !r.Matches(ev) {
					t.Errorf("rule %s: positive sample #%d does not match: %+v", r.ID, i, ev)
				}
			}
			for i, ev := range r.Tests.Negative {
				ev.Kind = r.EventType
				if r.Matches(ev) {
					t.Errorf("rule %s: negative sample #%d matched but must not: %+v", r.ID, i, ev)
				}
			}
			for i, ev := range benignBaseline {
				for _, kind := range []string{r.EventType, "process", "file", "network"} {
					ev.Kind = kind
					if r.Matches(ev) {
						t.Errorf("rule %s: matches benign baseline #%d (%+v) as %s", r.ID, i, ev, kind)
					}
				}
			}
		})
	}
}

func TestContentValidationRejects(t *testing.T) {
	good := func() ContentRule {
		return ContentRule{ID: "unit-test-rule", Name: "n", Description: "d", Tactic: "Execution", Technique: "T1059",
			Severity: "high", OS: "linux", EventType: "process",
			Match: ContentMatch{Field: "command", Op: "contains", Pattern: "zzz"},
			Tests: &ContentTests{Positive: []LabEvent{{Command: "zzz"}}, Negative: []LabEvent{{Command: "a"}}}}
	}
	g := good()
	if err := g.validateAndCompile(); err != nil {
		t.Fatalf("good rule rejected: %v", err)
	}
	cases := map[string]func(*ContentRule){
		"bad id":        func(r *ContentRule) { r.ID = "Bad_ID" },
		"builtin clash": func(r *ContentRule) { r.ID = "download-execute" },
		"bad tactic":    func(r *ContentRule) { r.Tactic = "Evil" },
		"bad technique": func(r *ContentRule) { r.Technique = "1059" },
		"bad severity":  func(r *ContentRule) { r.Severity = "urgent" },
		"bad os":        func(r *ContentRule) { r.OS = "beos" },
		"bad type":      func(r *ContentRule) { r.EventType = "magic" },
		"bad regex":     func(r *ContentRule) { r.Match = ContentMatch{Field: "command", Op: "regex", Pattern: "(unclosed"} },
		"bad op":        func(r *ContentRule) { r.Match = ContentMatch{Field: "command", Op: "like", Pattern: "x"} },
		"bad field":     func(r *ContentRule) { r.Match = ContentMatch{Field: "nope", Op: "equals", Pattern: "x"} },
		"no negatives":  func(r *ContentRule) { r.Tests.Negative = nil },
		"no tests":      func(r *ContentRule) { r.Tests = nil },
		"mixed node":    func(r *ContentRule) { r.Match.All = []ContentMatch{{Field: "command", Op: "equals", Pattern: "x"}} },
	}
	for name, mut := range cases {
		r := good()
		mut(&r)
		err := r.validateAndCompile()
		if err == nil {
			t.Errorf("%s: expected rejection", name)
		} else if name != "builtin clash" && name != "bad id" && !strings.Contains(err.Error(), r.ID) {
			t.Errorf("%s: error does not name the rule id: %v", name, err)
		}
	}
	// duplicate ids across packs
	a := `{"rules":[{"id":"dup-rule","name":"n","description":"d","tactic":"Execution","technique":"T1059","severity":"low","os":"any","event_type":"process","match":{"field":"command","op":"contains","pattern":"x"},"tests":{"positive":[{"command":"x"}],"negative":[{"command":"y"}]}}]}`
	if _, err := buildContentRegistry(map[string][]byte{"a.json": []byte(a), "b.json": []byte(a)}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids across packs not rejected: %v", err)
	}
	if _, err := buildContentRegistry(map[string][]byte{"c.json": []byte(`{"rules":[{"id":"x","bogus":1}]}`)}); err == nil {
		t.Errorf("unknown pack field not rejected")
	}
}

func TestContentEvaluationCreatesFindings(t *testing.T) {
	// No packs loaded => no-op.
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	contentReg.Store(nil)
	now := time.Now().UTC()
	e := Event{Time: now, Host: "h1", PID: 7, UID: 1000, Executable: "/usr/bin/env", Command: "env LD_PRELOAD=/tmp/x.so id"}
	for _, f := range Detect(e) {
		if strings.HasPrefix(f.Rule, "linux-") {
			t.Fatalf("content rule fired with no packs loaded: %s", f.Rule)
		}
	}
	if err := LoadContentPacks(); err != nil {
		t.Fatal(err)
	}
	var got *Finding
	for _, f := range Detect(e) {
		if f.Rule == "linux-ld-preload-from-writable-dir" {
			f := f
			got = &f
		}
	}
	if got == nil {
		t.Fatal("process content rule did not produce a finding via Detect")
	}
	if got.Severity != "high" || got.Host != "h1" || got.PID != 7 || got.Evidence.Command != e.Command {
		t.Fatalf("finding fields wrong: %+v", got)
	}
	d := MapDetection(*got)
	if d.TechniqueID != "T1574.006" || d.Tactic != "Persistence" {
		t.Fatalf("MapDetection fallback wrong: %+v", d)
	}
	if nf := contentNetworkFindings(NetworkEvent{Time: now, Host: "h1", PID: 7, Destination: "abc.onion:80"}); len(nf) != 1 || nf[0].Rule != "any-tor-onion-service-contact" || nf[0].Destination != "abc.onion:80" {
		t.Fatalf("network content rule: %+v", nf)
	}
	if ff := contentFileFindings(FileEvent{Time: now, Host: "h1", Path: "/root/.ssh/authorized_keys", Operation: "modify"}); len(ff) != 1 || ff[0].Rule != "linux-authorized-keys-modified" {
		t.Fatalf("file content rule: %+v", ff)
	}
	// registry/dns/auth/module rules are live now (no pending_telemetry)
	if x := contentEvaluate("registry", LabEvent{Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}, Finding{}); len(x) != 1 {
		t.Fatalf("registry rule not evaluated: %+v", x)
	}
	// ATT&CK matrix includes every live content rule, telemetry types included.
	m := BuildATTACKMatrix(nil)
	blob, _ := json.Marshal(m)
	if !strings.Contains(string(blob), "linux-ld-preload-from-writable-dir") || !strings.Contains(string(blob), "windows-run-key-value-added") {
		t.Fatalf("attack matrix content coverage wrong")
	}
	// End to end through the store.
	st, err := NewStore(t.TempDir()+"/f.jsonl", 100)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := st.IngestNetwork(NetworkEvent{ID: "n1", Time: now, Host: "h1", PID: 1, Destination: "zzz.onion:443"})
	if err != nil || len(fs) != 1 || len(st.List()) != 1 {
		t.Fatalf("ingest network content finding: %v %v", fs, err)
	}
	fs, err = st.IngestFile(FileEvent{ID: "f1", Time: now, Host: "h1", Path: "/home/a/.ssh/authorized_keys", Operation: "create"}, &FileDetections{})
	if err != nil || len(fs) != 1 {
		t.Fatalf("ingest file content finding: %v %v", fs, err)
	}
}

func TestContentEndpoints(t *testing.T) {
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	mux := http.NewServeMux()
	RegisterContentFramework(mux, "tok")
	get := func(path string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := get("/v1/content/rules", false); w.Code != 401 {
		t.Fatalf("unauthenticated list: %d", w.Code)
	}
	var list struct {
		Count int           `json:"count"`
		Rules []ContentRule `json:"rules"`
	}
	w := get("/v1/content/rules", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || list.Count < 10 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if list.Rules[0].Tests != nil {
		t.Fatalf("list should omit test samples")
	}
	count := func(q string) int {
		var l struct{ Count int }
		w := get("/v1/content/rules?"+q, true)
		_ = json.Unmarshal(w.Body.Bytes(), &l)
		return l.Count
	}
	if n := count("tactic=persistence&batch=seed-v1"); n != 4 {
		t.Errorf("tactic filter: %d", n)
	}
	if n := count("os=macos&batch=seed-v1"); n != 2+2 { // 2 macos rules plus the 2 os=any rules
		t.Errorf("os filter (macos + any): %d", n)
	}
	if n := count("os=windows&batch=seed-v1"); n < 3 {
		t.Errorf("os+batch filter: %d", n)
	}
	if n := count("technique=T1574&batch=seed-v1"); n != 1 {
		t.Errorf("technique parent prefix filter: %d", n)
	}
	if n := count("technique=T1574.006&batch=seed-v1"); n != 1 {
		t.Errorf("technique exact filter: %d", n)
	}
	if n := count("q=onion&batch=seed-v1"); n != 1 {
		t.Errorf("q filter: %d", n)
	}
	if n := count("q=zzzznomatch"); n != 0 {
		t.Errorf("q no-match: %d", n)
	}
	if w := get("/v1/content/rules/linux-authorized-keys-modified", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"positive"`) {
		t.Errorf("detail: %d %s", w.Code, w.Body.String())
	}
	if w := get("/v1/content/rules/nope", true); w.Code != 404 {
		t.Errorf("detail 404: %d", w.Code)
	}
	var cov map[string]any
	w = get("/v1/content/coverage", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cov) != nil {
		t.Fatalf("coverage: %d", w.Code)
	}
	pend := cov["pending_telemetry"].(map[string]any)
	if pend["count"].(float64) != 0 || cov["total_rules"].(float64) != float64(list.Count) {
		t.Errorf("coverage numbers: %v", cov)
	}
	for _, k := range []string{"by_tactic", "by_technique", "by_os", "by_batch", "techniques_covered"} {
		if cov[k] == nil {
			t.Errorf("coverage missing %s", k)
		}
	}
}

// TestContentEvaluationScales checks that a large rule set stays cheap per event (regexes are precompiled).
func TestContentEvaluationScales(t *testing.T) {
	rules := make([]*ContentRule, 0, 300)
	for i := 0; i < 300; i++ {
		r := &ContentRule{ID: "bulk-" + strings.Repeat("a", i%5+1), EventType: "process", Severity: "low", Tactic: "Execution", Technique: "T1059",
			Match: ContentMatch{Field: "command", Op: "regex", Pattern: `(foo|bar)\d+baz`}}
		n, err := r.Match.toLab("match")
		if err != nil {
			t.Fatal(err)
		}
		nodes := 0
		if err := n.validate("match", 0, &nodes); err != nil {
			t.Fatal(err)
		}
		r.node = &n
		rules = append(rules, r)
	}
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	contentReg.Store(&ContentRegistry{byType: map[string][]*ContentRule{"process": rules}, byID: map[string]*ContentRule{}})
	if out := contentEvaluate("process", LabEvent{Command: "foo12baz"}, Finding{}); len(out) != contentMaxPerEvent {
		t.Fatalf("per-event finding cap not applied: %d", len(out))
	}
	ev := LabEvent{Command: strings.Repeat("x", 3000) + " foo12qux"} // matches nothing: all 300 rules run
	start := time.Now()
	for i := 0; i < 5; i++ {
		if out := contentEvaluate("process", ev, Finding{}); len(out) != 0 {
			t.Fatal("unexpected match")
		}
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("content evaluation too slow: %v", d)
	}
}

func TestContentFilterSeverityAndEventType(t *testing.T) {
	if contentReg.Load() == nil {
		if err := LoadContentPacks(); err != nil {
			t.Fatal(err)
		}
	}
	reg := contentReg.Load()
	hi := contentFilter(reg, map[string][]string{"severity": {"HIGH"}, "event_type": {"process"}})
	if len(hi) == 0 {
		t.Fatal("expected high process rules")
	}
	for _, r := range hi {
		if r.Severity != "high" || r.EventType != "process" {
			t.Fatalf("leaked %s %s/%s", r.ID, r.Severity, r.EventType)
		}
	}
	if len(hi) >= len(reg.rules) {
		t.Fatal("filter did not narrow")
	}
}
