// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withContentPacks(t *testing.T) {
	t.Helper()
	prev := contentReg.Load()
	t.Cleanup(func() { contentReg.Store(prev) })
	if err := LoadContentPacks(); err != nil {
		t.Fatal(err)
	}
}

func telStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.jsonl")
	st, err := NewStore(path, 200)
	if err != nil {
		t.Fatal(err)
	}
	return st, path
}

func TestTelemetryRulesFireOnPost(t *testing.T) {
	withContentPacks(t)
	st, _ := telStore(t)
	h := API("tok", st)
	now := time.Now().UTC().Format(time.RFC3339)
	post := func(typ, body string) map[string]int {
		w := telDo(h, "POST", "/v1/events/"+typ, body, "tok")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", typ, w.Code, w.Body)
		}
		var out map[string]int
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	rulesSeen := func() map[string]bool {
		m := map[string]bool{}
		for _, f := range st.List() {
			m[f.Rule] = true
		}
		return m
	}

	// registry: the shipped seed rule plus a T-telemetry rule
	post("registry", `{"host":"h1","time":"`+now+`","key":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","value_name":"Updater","value_data":"powershell.exe -w hidden -enc AAAA","operation":"set"}`)
	// dns: tunnelling-style long TXT query (array form)
	long := strings.Repeat("a1b2c3d4e5", 12) + ".t.evil.example"
	post("dns", `[{"host":"h1","time":"`+now+`","query":"`+long+`","qtype":"TXT"},{"host":"h1","time":"`+now+`","query":"www.example.com","qtype":"A"}]`)
	// auth
	post("auth", `{"host":"h2","time":"`+now+`","user":"root","source_ip":"203.0.113.50","method":"ssh","outcome":"success"}`)
	// module: unsigned dll from temp
	post("module", `{"host":"h2","time":"`+now+`","module_path":"C:\\Users\\a\\AppData\\Local\\Temp\\x.dll","kind":"dll","signed":false}`)

	got := rulesSeen()
	for _, want := range []string{"windows-run-key-value-added", "reg-run-value-script-interpreter", "dns-tunnel-long-txt-query",
		"auth-root-ssh-success-public-ip", "module-unsigned-dll-from-temp"} {
		if !got[want] {
			t.Errorf("expected finding for %s, got %v", want, got)
		}
	}
	for _, f := range st.List() {
		if f.Rule == "dns-tunnel-long-txt-query" && (f.Host != "h1" || f.Destination != long || !strings.Contains(f.Evidence.Command, "TXT")) {
			t.Errorf("dns finding fields wrong: %+v", f)
		}
		if f.Rule == "auth-root-ssh-success-public-ip" && (f.Severity != "high" || !containsTag(f.Tags, "T1078") || !containsTag(f.Tags, "batch:T-telemetry")) {
			t.Errorf("auth finding fields wrong: %+v", f)
		}
	}

	// negatives: benign events create no finding
	before := len(st.List())
	out := post("auth", `{"host":"h2","time":"`+now+`","user":"alice","source_ip":"10.0.0.2","method":"ssh","outcome":"success"}`)
	post("dns", `{"host":"h1","time":"`+now+`","query":"www.example.com","qtype":"A"}`)
	post("registry", `{"host":"h1","time":"`+now+`","key":"HKLM\\Software\\Vendor\\App","value_name":"x","value_data":"1","operation":"set"}`)
	post("module", `{"host":"h1","time":"`+now+`","module_path":"/usr/lib/libc.so.6","kind":"so","signed":true}`)
	if len(st.List()) != before || out["findings"] != 0 {
		t.Errorf("benign telemetry produced findings: %d -> %d", before, len(st.List()))
	}

	// the API reports counts and the finding is visible through the normal detections surface
	w := telDo(h, "POST", "/v1/events/auth", `{"host":"h3","time":"`+now+`","user":"root","source_ip":"198.51.100.1","method":"ssh","outcome":"success"}`, "tok")
	if !strings.Contains(w.Body.String(), `"findings":1`) {
		t.Errorf("response should report findings: %s", w.Body)
	}
}

func containsTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

func TestTelemetryContentNoOpWithoutRules(t *testing.T) {
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	contentReg.Store(nil)
	e := TelemetryEvent{Time: time.Now(), Host: "h", User: "root", SourceIP: "203.0.113.5", Method: "ssh", Outcome: "success"}
	if fs := contentTelemetryFindings("auth", e); fs != nil {
		t.Fatalf("expected no-op with nothing loaded: %+v", fs)
	}
	st, _ := telStore(t)
	if n, skipped, err := st.IngestTelemetry("auth", []TelemetryEvent{e}, time.Second); n != 0 || skipped != 0 || err != nil {
		t.Fatalf("IngestTelemetry no-op: %d %d %v", n, skipped, err)
	}
	var nilStore *Store
	if n, _, err := nilStore.IngestTelemetry("auth", []TelemetryEvent{e}, time.Second); n != 0 || err != nil {
		t.Fatalf("nil store must be a no-op: %d %v", n, err)
	}
	// registry present but no rules for the type
	contentReg.Store(&ContentRegistry{byType: map[string][]*ContentRule{"process": nil}, byID: map[string]*ContentRule{}})
	if fs := contentTelemetryFindings("auth", e); fs != nil {
		t.Fatal("no rules for type must be a no-op")
	}
}

func TestTelemetryPerEventCapAndMatrix(t *testing.T) {
	prev := contentReg.Load()
	defer contentReg.Store(prev)
	rules := make([]*ContentRule, 0, 25)
	byID := map[string]*ContentRule{}
	for i := 0; i < 25; i++ {
		r := compileTestRule(t, "cap-"+strings.Repeat("a", i+1), "dns", ContentMatch{Field: "query", Op: "contains", Pattern: "evil"})
		r.Tactic, r.Technique = "Command and Control", "T1071.004"
		rules = append(rules, r)
		byID[r.ID] = r
	}
	contentReg.Store(&ContentRegistry{rules: rules, byID: byID, byType: map[string][]*ContentRule{"dns": rules}})
	fs := contentTelemetryFindings("dns", TelemetryEvent{Time: time.Now(), Host: "h", Query: "x.evil.test", QType: "A"})
	if len(fs) != contentMaxPerEvent {
		t.Fatalf("per-event cap not applied to telemetry: %d", len(fs))
	}
	ids := map[string]bool{}
	for _, f := range fs {
		if ids[f.ID] {
			t.Fatalf("duplicate finding id %s", f.ID)
		}
		ids[f.ID] = true
	}
}

func TestTelemetryRulesInMatrixAndCoverage(t *testing.T) {
	withContentPacks(t)
	blob, _ := json.Marshal(BuildATTACKMatrix(nil))
	for _, id := range []string{"reg-ifeo-debugger-set", "dns-onion-gateway-lookup", "auth-krbtgt-kerberos-logon", "module-known-vulnerable-driver-load"} {
		if !strings.Contains(string(blob), id) {
			t.Errorf("ATT&CK matrix missing telemetry rule %s", id)
		}
	}
	cov := ContentCoverage()
	if p := cov["pending_telemetry"].(map[string]any); p["count"].(int) != 0 {
		t.Errorf("no rule should be pending any more: %v", p)
	}
	if cov["active_rules"] != cov["total_rules"] {
		t.Errorf("all rules should be active: %v / %v", cov["active_rules"], cov["total_rules"])
	}
	n := 0
	for _, r := range ContentRules() {
		if r.Batch == "T-telemetry" {
			n++
			if r.PendingTelemetry {
				t.Errorf("%s flagged pending", r.ID)
			}
		}
	}
	if n < 40 {
		t.Errorf("expected about 40+ T-telemetry rules, got %d", n)
	}
}

func TestTelemetryEvaluationBudget(t *testing.T) {
	withContentPacks(t)
	now := time.Now().UTC()
	evs := make([]TelemetryEvent, 50)
	for i := range evs {
		evs[i] = TelemetryEvent{Time: now, Host: "h", User: "root", SourceIP: "203.0.113.5", Method: "ssh", Outcome: "success"}
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	before := telemetryEvalSkipped.Load()
	fs, skipped := contentTelemetryBatch("auth", evs, -time.Nanosecond) // budget already spent after the first event
	if skipped != 49 || len(fs) != 1 {
		t.Fatalf("budget: skipped=%d findings=%d", skipped, len(fs))
	}
	if telemetryEvalSkipped.Load()-before != 49 || !strings.Contains(logs.String(), "49 of 50 events stored but not evaluated") {
		t.Fatalf("budget overrun must be counted and logged: %q", logs.String())
	}
	if !strings.Contains(TelemetryMetrics(), "kavach_telemetry_eval_skipped_total") {
		t.Fatal("skipped metric missing")
	}
	fs, skipped = contentTelemetryBatch("auth", evs, time.Minute)
	if skipped != 0 || len(fs) != 50 {
		t.Fatalf("generous budget: skipped=%d findings=%d", skipped, len(fs))
	}
}

func TestTelemetryCorruptLedgerIsLoggedNotSilent(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	st, path := telStore(t)
	bad := path + ".events.telemetry"
	if err := os.WriteFile(bad, []byte("{\"type\":\"dns\",\"time\":\"2026-01-01T00:00:00Z\",\"host\":\"h\",\"query\":\"a.example\"}\nnot json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := API("tok", st)
	if !strings.Contains(logs.String(), "telemetry: persisted ledger unreadable") || !strings.Contains(logs.String(), "line 2") {
		t.Fatalf("corrupt telemetry ledger must be logged with the line number, got %q", logs.String())
	}
	matches, _ := filepath.Glob(bad + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("corrupt ledger should be moved aside, found %v", matches)
	}
	// service keeps working and persistence restarts on a fresh file
	w := telDo(h, "POST", "/v1/events/dns", `{"host":"h","time":"2026-01-01T00:00:00Z","query":"b.example"}`, "tok")
	if w.Code != 200 {
		t.Fatalf("post after corrupt ledger: %d", w.Code)
	}
	if b, err := os.ReadFile(bad); err != nil || !strings.Contains(string(b), "b.example") {
		t.Fatalf("persistence not restarted: %v %q", err, b)
	}
}
