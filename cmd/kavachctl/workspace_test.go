// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func jsonResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestRiskAndTrends(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/risk/hosts", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"hosts": []any{map[string]any{"host": "h1", "rank": 1, "risk": 80, "band": "critical",
			"findings": 4, "last_seen": "2026-01-02T03:04:05Z", "top_rules": []any{map[string]any{"rule": "r1", "count": 3}}}}})
	})
	mux.HandleFunc("/v1/risk/summary", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"fleet_risk_index": 61, "band": "high", "hosts": 1, "bands": map[string]int{"critical": 1}})
	})
	mux.HandleFunc("/v1/trends", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("days") == "99" {
			http.Error(w, "days must be 7, 14 or 30", 400)
			return
		}
		if r.URL.Query().Get("days") != "14" || r.URL.Query().Get("bucket") != "hour" {
			t.Errorf("query=%v", r.URL.Query())
		}
		jsonResp(w, map[string]any{"days": 14, "bucket": "hour", "total": 6, "previous_total": 3, "delta": 3, "delta_pct": 100.0,
			"buckets": []any{
				map[string]any{"start": "2026-01-01T00:00:00Z", "total": 0, "severity": map[string]int{}},
				map[string]any{"start": "2026-01-01T01:00:00Z", "total": 2, "severity": map[string]int{"high": 2}},
				map[string]any{"start": "2026-01-02T00:00:00Z", "total": 4, "severity": map[string]int{"low": 4}}},
			"top_rules": []any{map[string]any{"rule": "r1", "count": 6}}})
	})
	setupMock(t, mux)
	var buf strings.Builder
	if err := riskCmd(&buf, []string{"hosts"}); err != nil || !strings.Contains(buf.String(), "critical") || !strings.Contains(buf.String(), "r1(3)") {
		t.Fatalf("hosts: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := riskCmd(&buf, []string{"summary"}); err != nil || !strings.Contains(buf.String(), "index: 61") {
		t.Fatalf("summary: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := riskCmd(&buf, []string{"summary", "--json"}); err != nil || !strings.Contains(buf.String(), "\"fleet_risk_index\": 61") {
		t.Fatalf("summary json: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := trendsCmd(&buf, []string{"--days", "14", "--bucket", "hour"}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "▁") || !strings.Contains(s, "█") || !strings.Contains(s, "2026-01-01") || !strings.Contains(s, "top rules: r1(6)") {
		t.Fatalf("trends:\n%s", s)
	}
	if got := sparkline([]int{0, 1, 8}); got != "▁▂█" {
		t.Fatalf("sparkline=%q", got)
	}
	err := trendsCmd(io.Discard, []string{"--days", "99"})
	if err == nil || !strings.Contains(err.Error(), "days must be 7, 14 or 30") {
		t.Fatalf("expected server message, got %v", err)
	}
}

func TestExportFindingsAndNoOverwrite(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/export/findings", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("severity") != "high" || q.Get("host") != "h1" || q.Get("rule") != "r1" || q.Get("since") != "2026-01-01T00:00:00Z" {
			t.Errorf("filters not forwarded: %v", q)
		}
		_, _ = w.Write([]byte("{\"id\":\"f1\"}\n"))
	})
	mux.HandleFunc("/v1/export/report", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>report " + r.URL.Query().Get("format") + "</html>"))
	})
	setupMock(t, mux)
	args := []string{"findings", "--format", "ndjson", "--severity", "high", "--host", "h1", "--rule", "r1", "--since", "2026-01-01T00:00:00Z"}
	var buf strings.Builder
	if err := exportCmd(&buf, args); err != nil || buf.String() != "{\"id\":\"f1\"}\n" {
		t.Fatalf("stdout: %v %q", err, buf.String())
	}
	file := t.TempDir() + "/out.ndjson"
	buf.Reset()
	if err := exportCmd(&buf, append(append([]string{}, args...), "--out", file)); err != nil || !strings.Contains(buf.String(), "wrote 12 bytes") {
		t.Fatalf("file: %v %q", err, buf.String())
	}
	if err := exportCmd(io.Discard, append(append([]string{}, args...), "--out", file)); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected no-overwrite refusal, got %v", err)
	}
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exportCmd(io.Discard, append(append([]string{}, args...), "--out", file)); err == nil {
		t.Fatal("expected refusal")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Fatalf("file clobbered: %q", b)
	}
	if err := exportCmd(io.Discard, append(append([]string{}, args...), "--out", file, "--force")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "{\"id\":\"f1\"}\n" {
		t.Fatalf("force did not overwrite: %q", b)
	}
	if err := exportCmd(io.Discard, []string{"findings", "--format", "xml"}); err == nil || !strings.Contains(err.Error(), "invalid --format") {
		t.Fatalf("expected format error, got %v", err)
	}
	buf.Reset()
	if err := exportCmd(&buf, []string{"report", "--format", "html"}); err != nil || !strings.Contains(buf.String(), "report html") {
		t.Fatalf("report: %v %q", err, buf.String())
	}
}

func TestExportServerErrorCreatesNoFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/export/findings", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "since must be RFC3339", 400)
	})
	setupMock(t, mux)
	file := t.TempDir() + "/x.json"
	err := exportCmd(io.Discard, []string{"findings", "--since", "yesterday", "--out", file})
	if err == nil || !strings.Contains(err.Error(), "since must be RFC3339") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(file); serr == nil {
		t.Fatal("file should not exist after server error")
	}
}

func TestNotesAndSavedSearches(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/notes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if r.URL.Query().Get("finding_id") != "f1" {
				t.Errorf("finding_id=%q", r.URL.Query().Get("finding_id"))
			}
			jsonResp(w, map[string]any{"notes": []any{map[string]any{"id": "note-1", "author": "me", "text": "looks bad", "created": "2026-01-01T00:00:00Z"}}})
		case "POST":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["finding_id"] != "f1" || in["text"] != "hello world" {
				t.Errorf("body=%v", in)
			}
			w.WriteHeader(201)
			jsonResp(w, map[string]any{"id": "note-2"})
		case "DELETE":
			if r.URL.Query().Get("id") == "nope" {
				http.Error(w, "not found", 404)
				return
			}
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("/v1/saved-searches", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			jsonResp(w, map[string]any{"saved_searches": []any{map[string]any{"id": "ss-1", "name": "hot", "scope": "findings", "query": "sev:high", "author": "me"}}})
		case "POST":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["scope"] == "bogus" {
				http.Error(w, "scope must be detections, findings or hosts", 400)
				return
			}
			if in["name"] != "hot" || in["scope"] != "findings" || in["query"] != "sev:high" {
				t.Errorf("body=%v", in)
			}
			w.WriteHeader(201)
			jsonResp(w, map[string]any{"id": "ss-2"})
		case "DELETE":
			w.WriteHeader(204)
		}
	})
	setupMock(t, mux)
	var buf strings.Builder
	if err := notesCmd(&buf, []string{"list", "--finding", "f1"}); err != nil || !strings.Contains(buf.String(), "looks bad") {
		t.Fatalf("notes list: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := notesCmd(&buf, []string{"add", "--finding", "f1", "hello", "world"}); err != nil || !strings.Contains(buf.String(), "note-2") {
		t.Fatalf("notes add: %v %s", err, buf.String())
	}
	buf.Reset()
	if err := notesCmd(&buf, []string{"rm", "note-1"}); err != nil || !strings.Contains(buf.String(), "removed note note-1") {
		t.Fatalf("notes rm: %v %s", err, buf.String())
	}
	if err := notesCmd(io.Discard, []string{"rm", "nope"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
	if err := notesCmd(io.Discard, []string{"list"}); err == nil {
		t.Fatal("expected --finding required")
	}
	buf.Reset()
	if err := savedSearchesCmd(&buf, []string{"list"}); err != nil || !strings.Contains(buf.String(), "sev:high") {
		t.Fatalf("ss list: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := savedSearchesCmd(&buf, []string{"add", "--name", "hot", "--query", "sev:high"}); err != nil || !strings.Contains(buf.String(), "ss-2") {
		t.Fatalf("ss add: %v %s", err, buf.String())
	}
	err := savedSearchesCmd(io.Discard, []string{"add", "--name", "x", "--scope", "bogus"})
	if err == nil || !strings.Contains(err.Error(), "scope must be detections") {
		t.Fatalf("expected server message, got %v", err)
	}
	if err := savedSearchesCmd(io.Discard, []string{"rm", "ss-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestAlertsAndJournal(t *testing.T) {
	var journaled []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			jsonResp(w, map[string]any{"rules": []any{map[string]any{"id": "alr-1", "min_severity": "high", "type": "slack",
				"url": "https://hooks.slack.com/services/T0/B0/SECRETSECRET?token=abc", "created": "2026-01-01T00:00:00Z"}}})
		case "POST":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["type"] == "ftp" {
				http.Error(w, "type must be webhook or slack", 400)
				return
			}
			if in["min_severity"] != "critical" || in["rule_contains"] != "ssh" || in["host_contains"] != "prod" {
				t.Errorf("body=%v", in)
			}
			w.WriteHeader(201)
			jsonResp(w, map[string]any{"id": "alr-2", "type": "webhook", "url": in["url"]})
		case "DELETE":
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("/v1/alerts/deliveries", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"deliveries": []any{map[string]any{"time": "2026-01-01T00:00:00Z", "rule_id": "alr-1",
			"finding_id": "f1", "type": "slack", "destination_host": "hooks.slack.com", "status": "failed", "attempts": 4, "http_status": 500, "error": "boom"}}})
	})
	mux.HandleFunc("/v1/journal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			journaled = append(journaled, in["action"]+" "+in["target"])
			w.WriteHeader(201)
			jsonResp(w, map[string]any{})
			return
		}
		jsonResp(w, map[string]any{"entries": []any{map[string]any{"seq": 1, "time": "2026-01-01T00:00:00Z", "actor": "me", "action": "note.create", "target": "note-1"}}})
	})
	valid := true
	mux.HandleFunc("/v1/journal/verify", func(w http.ResponseWriter, r *http.Request) {
		if valid {
			jsonResp(w, map[string]any{"valid": true, "entries": 1})
			return
		}
		jsonResp(w, map[string]any{"valid": false, "entries": 3, "first_broken_seq": 2, "reason": "hash mismatch"})
	})
	setupMock(t, mux)
	var buf strings.Builder
	if err := alertsCmd(&buf, []string{"rules", "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "https://hooks.slack.com/***?***") || strings.Contains(buf.String(), "SECRET") || strings.Contains(buf.String(), "abc") {
		t.Fatalf("url not masked:\n%s", buf.String())
	}
	buf.Reset()
	add := []string{"rules", "add", "--url", "https://example.com/hook/secret", "--min-severity", "critical", "--rule-contains", "ssh", "--host-contains", "prod"}
	if err := alertsCmd(&buf, add); err != nil || !strings.Contains(buf.String(), "alr-2") || strings.Contains(buf.String(), "secret") {
		t.Fatalf("add: %v\n%s", err, buf.String())
	}
	if err := alertsCmd(io.Discard, []string{"rules", "rm", "alr-1"}); err != nil {
		t.Fatal(err)
	}
	if len(journaled) != 2 || journaled[0] != "alert_rule.create alr-2" || journaled[1] != "alert_rule.delete alr-1" {
		t.Fatalf("journaled=%v", journaled)
	}
	err := alertsCmd(io.Discard, []string{"rules", "add", "--url", "https://x.example", "--type", "ftp"})
	if err == nil || !strings.Contains(err.Error(), "type must be webhook or slack") {
		t.Fatalf("expected server message, got %v", err)
	}
	if maskURL("https://h.example") != "https://h.example" || maskURL("::bad") != "***" {
		t.Fatal("maskURL edge cases")
	}
	buf.Reset()
	if err := alertsCmd(&buf, []string{"deliveries"}); err != nil || !strings.Contains(buf.String(), "hooks.slack.com") || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("deliveries: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := journalCmd(&buf, nil); err != nil || !strings.Contains(buf.String(), "note.create") {
		t.Fatalf("journal: %v\n%s", err, buf.String())
	}
	buf.Reset()
	if err := journalCmd(&buf, []string{"verify"}); err != nil || !strings.Contains(buf.String(), "valid (1 entries)") {
		t.Fatalf("verify: %v\n%s", err, buf.String())
	}
	valid = false
	buf.Reset()
	if err := journalCmd(&buf, []string{"verify"}); err == nil || !strings.Contains(buf.String(), "BROKEN at seq 2: hash mismatch") {
		t.Fatalf("expected broken: %v\n%s", err, buf.String())
	}
}

func TestWorkspaceRoutingAndCompletion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/risk/summary", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]any{"fleet_risk_index": 1, "band": "low", "hosts": 0, "bands": map[string]int{}})
	})
	setupMock(t, mux)
	if err := run([]string{"risk", "summary"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"risk"}); err == nil {
		t.Fatal("expected usage error")
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var buf strings.Builder
		if err := completionCmd(&buf, []string{sh}); err != nil || !strings.Contains(buf.String(), "bucket") {
			t.Fatalf("%s: %v", sh, err)
		}
		if sh != "fish" && !strings.Contains(buf.String(), "saved-searches") {
			t.Fatalf("%s lacks saved-searches", sh)
		}
	}
}
