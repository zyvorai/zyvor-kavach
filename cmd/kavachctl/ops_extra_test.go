// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jsonDecode(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }

func TestIntelFeeds(t *testing.T) {
	mux := http.NewServeMux()
	var added map[string]any
	var deleted, refreshed string
	mux.HandleFunc("GET /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"feeds": []any{map[string]any{"id": "fd-1", "name": "Abuse", "url": "https://feeds.example.com/secret/path?key=abc",
			"format": "csv", "interval": 60, "ttl_days": 7, "tlp": "green", "enabled": true}}})
	})
	mux.HandleFunc("GET /v1/intel/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"status": []any{map[string]any{"id": "fd-1", "name": "Abuse", "status": "ok", "added": 3, "active": 9}}})
	})
	mux.HandleFunc("POST /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = jsonDecode(r.Body, &m)
		if m["name"] == "dup" {
			http.Error(w, "feed name already exists", 409)
			return
		}
		added = m
		w.WriteHeader(201)
		jsonResp(w, map[string]any{"id": "fd-2", "name": m["name"], "url": m["url"]})
	})
	mux.HandleFunc("DELETE /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		deleted = r.URL.Query().Get("id")
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v1/intel/feeds/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshed = r.URL.Query().Get("id")
		jsonResp(w, map[string]any{"name": "Abuse", "status": "ok", "added": 2})
	})
	setupMock(t, mux)

	var buf strings.Builder
	if err := intelFeedsCmd(&buf, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "Abuse") || !strings.Contains(s, "https://feeds.example.com/***?***") || strings.Contains(s, "secret") || strings.Contains(s, "abc") {
		t.Fatalf("list not masked:\n%s", s)
	}
	buf.Reset()
	if err := intelFeedsCmd(&buf, []string{"status"}); err != nil || !strings.Contains(buf.String(), "ok") {
		t.Fatalf("status: %v\n%s", err, buf.String())
	}
	buf.Reset()
	err := intelFeedsCmd(&buf, []string{"add", "--name", "n1", "--url", "https://x.example.com/p?t=1", "--format", "csv", "--interval", "30", "--ttl-days", "5", "--tlp", "amber"})
	if err != nil || added["interval"] != float64(30) || added["ttl_days"] != float64(5) || added["tlp"] != "amber" || strings.Contains(buf.String(), "p?t") {
		t.Fatalf("add: %v %v\n%s", err, added, buf.String())
	}
	if err := intelFeedsCmd(io.Discard, []string{"add", "--name", "dup", "--url", "https://x", "--format", "csv"}); err == nil || !strings.Contains(err.Error(), "feed name already exists") {
		t.Fatalf("expected server message, got %v", err)
	}
	if err := intelFeedsCmd(io.Discard, []string{"add", "--name", "x"}); err == nil {
		t.Fatal("expected missing flag error")
	}
	if err := intelFeedsCmd(io.Discard, []string{"rm", "Abuse"}); err != nil || deleted != "fd-1" {
		t.Fatalf("rm by name: %v %q", err, deleted)
	}
	if err := intelFeedsCmd(io.Discard, []string{"refresh", "fd-9"}); err != nil || refreshed != "fd-9" {
		t.Fatalf("refresh: %v %q", err, refreshed)
	}
	if err := intelFeedsCmd(io.Discard, []string{"rm", "ghost"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestLabCommands(t *testing.T) {
	mux := http.NewServeMux()
	var lastBody map[string]any
	capture := func(r *http.Request) { lastBody = nil; _ = jsonDecode(r.Body, &lastBody) }
	mux.HandleFunc("POST /v1/lab/rules/validate", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "bad") {
			w.WriteHeader(400)
			jsonResp(w, map[string]any{"valid": false, "error": "rule: unknown field \"bad\""})
			return
		}
		jsonResp(w, map[string]any{"valid": true, "mode": "sandbox"})
	})
	mux.HandleFunc("POST /v1/lab/rules/test", func(w http.ResponseWriter, r *http.Request) {
		capture(r)
		jsonResp(w, map[string]any{"events": 2, "condition_matched": 1,
			"results": []any{map[string]any{"index": 0, "matched": true}, map[string]any{"index": 1, "matched": false}},
			"hits":    []any{map[string]any{"event": map[string]any{"time": "2026-01-02T03:04:05Z", "host": "h1"}, "why": "matched"}}})
	})
	mux.HandleFunc("POST /v1/lab/rules/backtest", func(w http.ResponseWriter, r *http.Request) {
		capture(r)
		jsonResp(w, map[string]any{"events_scanned": 100, "hosts_observed": 4, "span_days": 3.0, "hit_count": 6, "noise_per_host_per_day": 0.5,
			"hits_per_day": []any{map[string]any{"day": "2026-01-01", "hits": 1}, map[string]any{"day": "2026-01-02", "hits": 5}},
			"top_hosts":    []any{map[string]any{"host": "h1", "hits": 6}},
			"hit_sample":   []any{map[string]any{"event": map[string]any{"time": "2026-01-02T03:04:05Z", "host": "h1"}, "why": "sample why"}}})
	})
	mux.HandleFunc("GET /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"mode": "sandbox", "rules": []any{map[string]any{"id": "lab-1", "name": "R1", "enabled": true, "mode": "sandbox"}}})
	})
	mux.HandleFunc("POST /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		capture(r)
		if lastBody["name"] == "full" {
			w.WriteHeader(409)
			jsonResp(w, map[string]any{"error": "rule cap of 50 reached"})
			return
		}
		jsonResp(w, map[string]any{"rule": map[string]any{"id": "lab-9", "name": lastBody["name"]}})
	})
	mux.HandleFunc("DELETE /v1/lab/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "lab-1" {
			w.WriteHeader(404)
			jsonResp(w, map[string]any{"error": "lab rule not found"})
			return
		}
		jsonResp(w, map[string]any{"deleted": "lab-1"})
	})
	setupMock(t, mux)

	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "rule.json")
	badFile := filepath.Join(dir, "bad.json")
	evFile := filepath.Join(dir, "events.json")
	_ = os.WriteFile(ruleFile, []byte(`{"name":"R1","condition":{"field":"command","op":"contains","value":"x"}}`), 0o600)
	_ = os.WriteFile(badFile, []byte(`{"bad":1}`), 0o600)
	_ = os.WriteFile(evFile, []byte(`[{"host":"h1"},{"host":"h2"}]`), 0o600)

	var buf strings.Builder
	if err := labCmd(&buf, []string{"validate", ruleFile}); err != nil || !strings.Contains(buf.String(), "SANDBOX") || !strings.Contains(buf.String(), "valid") {
		t.Fatalf("validate: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := labCmd(&buf, []string{"validate", badFile}); err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(buf.String(), "SANDBOX") {
		t.Fatalf("validate bad: %v", err)
	}
	// stdin rule input
	opsStdin = strings.NewReader(`{"name":"FromStdin","condition":{}}`)
	t.Cleanup(func() { opsStdin = os.Stdin })
	buf.Reset()
	if err := labCmd(&buf, []string{"rules", "add", "-"}); err != nil || !strings.Contains(buf.String(), "lab-9") || lastBody["name"] != "FromStdin" {
		t.Fatalf("add stdin: %v %v\n%s", err, lastBody, buf.String())
	}
	opsStdin = strings.NewReader(`{"name":"full"}`)
	if err := labCmd(io.Discard, []string{"rules", "add", "-"}); err == nil || !strings.Contains(err.Error(), "rule cap of 50 reached") {
		t.Fatalf("cap: %v", err)
	}
	buf.Reset()
	if err := labCmd(&buf, []string{"rules", "list"}); err != nil || !strings.Contains(buf.String(), "lab-1") || !strings.Contains(buf.String(), "SANDBOX") {
		t.Fatalf("list: %v\n%s", err, buf.String())
	}
	if err := labCmd(io.Discard, []string{"rules", "rm", "lab-1"}); err != nil {
		t.Fatal(err)
	}
	if err := labCmd(io.Discard, []string{"rules", "rm", "zzz"}); err == nil || !strings.Contains(err.Error(), "lab rule not found") {
		t.Fatalf("rm missing: %v", err)
	}
	buf.Reset()
	if err := labCmd(&buf, []string{"test", ruleFile, "--events", evFile}); err != nil {
		t.Fatal(err)
	}
	if evs, _ := lastBody["events"].([]any); len(evs) != 2 || lastBody["rule"] == nil {
		t.Fatalf("test body=%v", lastBody)
	}
	if !strings.Contains(buf.String(), "SANDBOX") || !strings.Contains(buf.String(), "condition matched: 1") || !strings.Contains(buf.String(), "Sample hits") {
		t.Fatalf("test out:\n%s", buf.String())
	}
	buf.Reset()
	if err := labCmd(&buf, []string{"backtest", "--rule", ruleFile}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{"SANDBOX", "hits: 6", "0.50 hits/host/day", "hits/day: ", "2026-01-01 .. 2026-01-02", "Top hosts", "sample why"} {
		if !strings.Contains(s, want) {
			t.Fatalf("backtest missing %q:\n%s", want, s)
		}
	}
	if err := labCmd(io.Discard, []string{"backtest", "--id", "lab-1"}); err != nil || lastBody["rule_id"] != "lab-1" {
		t.Fatalf("backtest id: %v %v", err, lastBody)
	}
	if err := labCmd(io.Discard, []string{"backtest"}); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestSOCCommands(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/soc/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("days") == "999" {
			http.Error(w, "days out of range", 400)
			return
		}
		jsonResp(w, map[string]any{"days": 7, "tickets": 10, "mtta_minutes": 12.0, "mttr_minutes": 240.0, "open_backlog": 3,
			"backlog_by_severity": map[string]any{"high": map[string]any{"lt_1h": 1, "gt_7d": 2}},
			"top_noisy_rules":     []any{map[string]any{"rule": "noisy-rule", "total": 5, "false_positive_rate": 20.0}}})
	})
	mux.HandleFunc("GET /v1/soc/shift-report", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"hours": 8, "generated_at": "2026-01-02T03:04:05Z", "counts": map[string]any{"new": 2, "open": 3, "closed": 1},
			"highest_risk_hosts":    []any{map[string]any{"host": "h1", "risk": 80, "band": "high", "findings": 3}},
			"recommended_questions": []any{"Who owns it?"}})
	})
	mux.HandleFunc("GET /v1/storyline/host", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("host") != "box1" || r.URL.Query().Get("hours") != "6" {
			t.Errorf("query=%v", r.URL.Query())
		}
		jsonResp(w, map[string]any{"host": "box1", "since": "2026-01-01T00:00:00Z", "tactics": []any{"execution", "exfiltration"}, "bursts": []any{1},
			"steps": []any{map[string]any{"time": "2026-01-01T01:00:00Z", "burst": 1, "tactic": "execution", "kind": "process", "summary": "ran sh"}}})
	})
	setupMock(t, mux)

	var buf strings.Builder
	if err := socCmd(&buf, []string{"metrics", "--days", "7"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MTTA 12m", "MTTR 4.0h", "noisy-rule", "20.0%"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, buf.String())
		}
	}
	if err := socCmd(io.Discard, []string{"metrics", "--days", "999"}); err == nil || !strings.Contains(err.Error(), "days out of range") {
		t.Fatalf("expected server msg, got %v", err)
	}
	buf.Reset()
	if err := socCmd(&buf, []string{"metrics", "--json"}); err != nil || !strings.Contains(buf.String(), "\"tickets\": 10") {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := socCmd(&buf, []string{"storyline", "box1", "--hours", "6"}); err != nil || !strings.Contains(buf.String(), "execution > exfiltration") || !strings.Contains(buf.String(), "ran sh") {
		t.Fatalf("storyline: %v\n%s", err, buf.String())
	}

	// shift-report file output: no overwrite, then --force
	out := filepath.Join(t.TempDir(), "shift.txt")
	buf.Reset()
	if err := socCmd(&buf, []string{"shift-report", "--hours", "8", "--out", out}); err != nil || !strings.Contains(buf.String(), "wrote") {
		t.Fatalf("shift: %v\n%s", err, buf.String())
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "Shift report") || !strings.Contains(string(data), "Who owns it?") {
		t.Fatalf("file=%s", data)
	}
	_ = os.WriteFile(out, []byte("KEEP"), 0o600)
	if err := socCmd(io.Discard, []string{"shift-report", "--out", out}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refuse, got %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "KEEP" {
		t.Fatal("file was overwritten")
	}
	if err := socCmd(io.Discard, []string{"shift-report", "--out", out, "--force"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "Shift report") {
		t.Fatal("force did not overwrite")
	}
}

func TestPostureCommands(t *testing.T) {
	mux := http.NewServeMux()
	var posted map[string]any
	var delHost, baseHost string
	mux.HandleFunc("GET /v1/posture/summary", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"observed_hosts": 4,
			"assets":          map[string]any{"registered": 2, "by_criticality": map[string]any{"1": 0, "2": 0, "3": 1, "4": 0, "5": 1}},
			"vulnerabilities": map[string]any{"total": 3, "score_70_plus": 1, "top": []any{map[string]any{"rank": 1, "score": 88.5, "cve": "CVE-1", "host": "h1"}}},
			"drift":           map[string]any{"baselined_hosts": 1, "hosts_with_drift": []any{map[string]any{"host": "h1", "total": 2, "highest_severity": "high"}}}})
	})
	mux.HandleFunc("GET /v1/posture/vuln-priority", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "5" {
			t.Errorf("limit=%q", r.URL.Query().Get("limit"))
		}
		jsonResp(w, map[string]any{"model": "cvss*4 + ...", "items": []any{map[string]any{"rank": 1, "score": 88.5, "cve": "CVE-1", "host": "h1", "severity": "high",
			"breakdown": []any{map[string]any{"factor": "cvss", "points": 36.0, "max": 40.0, "detail": "CVSS 9.0"}}}}})
	})
	mux.HandleFunc("GET /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, []any{map[string]any{"host": "h1", "criticality": 5, "owner": "ops", "tags": []any{"pci", "db"}}})
	})
	mux.HandleFunc("POST /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		posted = nil
		_ = jsonDecode(r.Body, &posted)
		w.WriteHeader(201)
		jsonResp(w, posted)
	})
	mux.HandleFunc("DELETE /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		delHost = r.URL.Query().Get("host")
		if delHost == "ghost" {
			http.Error(w, "not found", 404)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/posture/drift", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("host") == "nobase" {
			jsonResp(w, map[string]any{"host": "nobase", "has_baseline": false})
			return
		}
		jsonResp(w, map[string]any{"host": "h1", "has_baseline": true, "baseline_at": "2026-01-01T00:00:00Z", "total": 1, "highest_severity": "high",
			"added": []any{map[string]any{"domain": "service", "key": "evil.service", "severity_hint": "high", "reason": "new unit"}}})
	})
	mux.HandleFunc("POST /v1/posture/baseline", func(w http.ResponseWriter, r *http.Request) {
		baseHost = r.URL.Query().Get("host")
		jsonResp(w, map[string]any{"baselined": 1})
	})
	setupMock(t, mux)

	var buf strings.Builder
	if err := postureCmd(&buf, []string{"summary"}); err != nil || !strings.Contains(buf.String(), "score >= 70: 1") || !strings.Contains(buf.String(), "CVE-1") {
		t.Fatalf("summary: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := postureCmd(&buf, []string{"vulns", "--limit", "5"}); err != nil || strings.Contains(buf.String(), "CVSS 9.0") {
		t.Fatalf("vulns: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := postureCmd(&buf, []string{"vulns", "--limit", "5", "--explain"}); err != nil || !strings.Contains(buf.String(), "cvss") || !strings.Contains(buf.String(), "36.0/40") {
		t.Fatalf("explain: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := postureCmd(&buf, []string{"assets", "list"}); err != nil || !strings.Contains(buf.String(), "pci,db") {
		t.Fatalf("assets: %v\n%s", err, buf.String())
	}
	if err := postureCmd(io.Discard, []string{"assets", "add", "--host", "h2", "--criticality", "4", "--owner", "me", "--tags", "a,b"}); err != nil ||
		posted["host"] != "h2" || posted["criticality"] != float64(4) {
		t.Fatalf("add: %v %v", err, posted)
	}
	if err := postureCmd(io.Discard, []string{"assets", "add", "--host", "h2", "--criticality", "9"}); err == nil {
		t.Fatal("expected criticality error")
	}
	if err := postureCmd(io.Discard, []string{"assets", "rm", "h2"}); err != nil || delHost != "h2" {
		t.Fatalf("rm: %v", err)
	}
	if err := postureCmd(io.Discard, []string{"assets", "rm", "ghost"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("rm ghost: %v", err)
	}
	buf.Reset()
	if err := postureCmd(&buf, []string{"drift", "h1"}); err != nil || !strings.Contains(buf.String(), "evil.service") {
		t.Fatalf("drift: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := postureCmd(&buf, []string{"drift", "nobase"}); err != nil || !strings.Contains(buf.String(), "no baseline") {
		t.Fatalf("nobase: %v\n%s", err, buf.String())
	}
	if err := postureCmd(io.Discard, []string{"baseline", "h1"}); err != nil || baseHost != "h1" {
		t.Fatalf("baseline: %v", err)
	}
	if err := postureCmd(io.Discard, []string{"baseline"}); err != nil || baseHost != "" {
		t.Fatalf("baseline all: %v %q", err, baseHost)
	}
}

func TestComplianceExtraAndRegression(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/compliance/controls", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("framework") == "nope" {
			http.Error(w, "unknown framework", 400)
			return
		}
		jsonResp(w, map[string]any{"framework": "cis", "controls": []any{map[string]any{"id": "CIS-1", "status": "pass", "title": "Inventory"}}})
	})
	mux.HandleFunc("GET /v1/compliance/evidence", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>evidence</html>"))
			return
		}
		jsonResp(w, map[string]any{"controls": []any{}})
	})
	mux.HandleFunc("GET /v1/compliance/cert-in-clock", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"window_hours": 6, "incidents": []any{
			map[string]any{"finding_id": "f1", "severity": "high", "host": "h1", "rule": "r", "status": "open", "deadline": "2026-01-02T03:04:05Z", "remaining_seconds": 5400},
			map[string]any{"finding_id": "f2", "severity": "critical", "host": "h2", "rule": "r", "status": "open", "overdue": true, "remaining_seconds": -3600}}})
	})
	mux.HandleFunc("/v1/compliance", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"legacy": true})
	})
	mux.HandleFunc("/v1/compliance/score", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"overall": 77, "grade": "C", "mode": "observe-only", "frameworks": []any{map[string]any{"framework": "CIS", "score": 70, "grade": "C", "failing": 2}}})
	})
	setupMock(t, mux)

	var buf strings.Builder
	if err := complianceExtraCmd(&buf, []string{"controls", "--framework", "cis"}); err != nil || !strings.Contains(buf.String(), "CIS-1") {
		t.Fatalf("controls: %v\n%s", err, buf.String())
	}
	if err := complianceExtraCmd(io.Discard, []string{"controls"}); err == nil || !strings.Contains(err.Error(), "--framework") {
		t.Fatalf("missing fw: %v", err)
	}
	if err := complianceExtraCmd(io.Discard, []string{"controls", "--framework", "nope"}); err == nil || !strings.Contains(err.Error(), "unknown framework") {
		t.Fatalf("server msg: %v", err)
	}
	buf.Reset()
	if err := complianceExtraCmd(&buf, []string{"cert-in-clock"}); err != nil || !strings.Contains(buf.String(), "1h30m") || !strings.Contains(buf.String(), "OVERDUE 1h00m") {
		t.Fatalf("clock: %v\n%s", err, buf.String())
	}

	out := filepath.Join(t.TempDir(), "ev.html")
	buf.Reset()
	if err := complianceExtraCmd(&buf, []string{"evidence", "--framework", "cis", "--format", "html", "--out", out}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "<html>evidence</html>" {
		t.Fatalf("file=%q", b)
	}
	if err := complianceExtraCmd(io.Discard, []string{"evidence", "--framework", "cis", "--format", "html", "--out", out}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refuse, got %v", err)
	}
	if err := complianceExtraCmd(io.Discard, []string{"evidence", "--framework", "cis", "--format", "json", "--out", out, "--force"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "controls") {
		t.Fatalf("force file=%q", b)
	}
	if err := complianceExtraCmd(io.Discard, []string{"evidence", "--framework", "cis", "--format", "pdf"}); err == nil {
		t.Fatal("expected bad format")
	}

	// Regression: existing compliance commands still route and work.
	buf.Reset()
	if err := run([]string{"compliance", "score"}); err != nil {
		t.Fatalf("compliance score via run: %v", err)
	}
	if err := complianceScoreCmd(&buf, nil); err != nil || !strings.Contains(buf.String(), "Overall posture: 77") {
		t.Fatalf("score: %v\n%s", err, buf.String())
	}
	if err := run([]string{"compliance"}); err != nil {
		t.Fatalf("bare compliance: %v", err)
	}
	if err := run([]string{"compliance", "controls", "--framework", "cis"}); err != nil {
		t.Fatalf("compliance controls via run: %v", err)
	}
}

func TestOpsRoutingAndCompletion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/storyline", func(w http.ResponseWriter, r *http.Request) { jsonResp(w, map[string]any{"legacy": true}) })
	mux.HandleFunc("GET /v1/intel/feeds", func(w http.ResponseWriter, r *http.Request) { jsonResp(w, map[string]any{"feeds": []any{}}) })
	mux.HandleFunc("/v1/intel/actors", func(w http.ResponseWriter, r *http.Request) { jsonResp(w, []any{}) })
	setupMock(t, mux)
	for _, args := range [][]string{{"storyline", "--host", "h"}, {"intel", "feeds", "list"}, {"intel", "actors"}} {
		if err := run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var buf strings.Builder
		if err := completionCmd(&buf, []string{sh}); err != nil || !strings.Contains(buf.String(), "framework") || !strings.Contains(buf.String(), "posture") {
			t.Fatalf("%s completion: %v", sh, err)
		}
	}
}
