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

func imRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	if h, err := inspectDispatch(args, &buf); h {
		return buf.String(), err
	}
	h, err := mlDispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

const imReport = `{"id":"insp-1","kind":"file","name":"a.bin","sha256":"abc","size":4,"format":"pe","score":80,"level":"malicious-likely",
"factors":["packed"],"findings":[{"id":"f1","title":"Packed","severity":"high","weight":40,"technique":"T1027","evidence":"upx","analyzer":"pe"}],
"iocs":[{"type":"url","value":"http://x.test"}],"layers":[{"depth":1,"method":"base64","bytes":10,"preview":"hi"}],"limits_hit":["layers"],"analyzers":["pe"],"note":"static only"}`

func TestInspectFileAndText(t *testing.T) {
	mux := http.NewServeMux()
	var path, ctype, name string
	var body []byte
	mux.HandleFunc("POST /v1/inspect/", func(w http.ResponseWriter, r *http.Request) {
		path, ctype, name = r.URL.Path, r.Header.Get("Content-Type"), r.URL.Query().Get("name")
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(imReport))
	})
	setupMock(t, mux)
	dir := t.TempDir()
	fp := filepath.Join(dir, "a.bin")
	_ = os.WriteFile(fp, []byte("MZ\x00\x01"), 0o600)

	out, err := imRun(t, "inspect", "file", fp)
	if err != nil || path != "/v1/inspect/file" || name != "a.bin" || ctype != "application/octet-stream" || string(body) != "MZ\x00\x01" {
		t.Fatalf("file: %v path=%s name=%s ct=%s body=%q", err, path, name, ctype, body)
	}
	for _, want := range []string{"malicious-likely", "80/100", "packed", "T1027", "http://x.test", "base64", "Limits hit: layers"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if out, err = imRun(t, "inspect", "file", fp, "--json"); err != nil || strings.TrimSpace(out) != strings.ReplaceAll(imReport, "\n", "") && !strings.Contains(out, `"insp-1"`) {
		t.Fatalf("json passthrough: %v %s", err, out)
	}

	omStdin = strings.NewReader("echo hi | base64\n")
	if _, err = imRun(t, "inspect", "script", "-"); err != nil || path != "/v1/inspect/script" {
		t.Fatalf("script stdin: %v %s", err, path)
	}
	var m map[string]string
	_ = json.Unmarshal(body, &m)
	if m["text"] != "echo hi | base64\n" {
		t.Fatalf("stdin body: %s", body)
	}
	omStdin = strings.NewReader("whoami /all")
	if _, err = imRun(t, "inspect", "cmdline", "-"); err != nil || path != "/v1/inspect/cmdline" {
		t.Fatalf("cmdline: %v", err)
	}
	if _, err = imRun(t, "inspect", "cmdline", "powershell", "-enc", "AAA"); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(body, &m)
	if m["text"] != "powershell -enc AAA" {
		t.Fatalf("cmdline join: %s", body)
	}
	if _, err = imRun(t, "inspect", "domain", "evil.test"); err != nil || path != "/v1/inspect/domain" {
		t.Fatalf("domain: %v", err)
	}
	omStdin = strings.NewReader("  \n")
	if _, err = imRun(t, "inspect", "script", "-"); err == nil {
		t.Fatal("empty stdin must fail")
	}
}

func TestInspectSizeRefusal(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/inspect/file", func(w http.ResponseWriter, r *http.Request) { calls++ })
	setupMock(t, mux)
	fp := filepath.Join(t.TempDir(), "big.bin")
	fh, _ := os.Create(fp)
	_ = fh.Truncate(inspectMaxFile + 1)
	fh.Close()
	_, err := imRun(t, "inspect", "file", fp)
	if err == nil || !strings.Contains(err.Error(), "32 MiB") || calls != 0 {
		t.Fatalf("want local refusal, err=%v calls=%d", err, calls)
	}
	if _, err = imRun(t, "inspect", "file", t.TempDir()); err == nil {
		t.Fatal("directory must be refused")
	}
}

func TestInspectReportsAnalyzers(t *testing.T) {
	mux := http.NewServeMux()
	var q string
	mux.HandleFunc("GET /v1/inspect/reports", func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		omJSON(w, map[string]any{"count": 1, "reports": []map[string]any{{"id": "insp-9", "kind": "domain", "name": "x", "level": "clean", "score": 0, "sha256": "0123456789abcdef0123"}}})
	})
	mux.HandleFunc("GET /v1/inspect/analyzers", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{"analyzers": map[string][]string{"file": {"pe", "zip"}}, "max_bytes": 33554432})
	})
	setupMock(t, mux)
	out, err := imRun(t, "inspect", "reports", "--limit", "3")
	if err != nil || q != "limit=3" || !strings.Contains(out, "insp-9") || !strings.Contains(out, "1 reports") {
		t.Fatalf("reports: %v %q %s", err, q, out)
	}
	if out, err = imRun(t, "inspect", "analyzers"); err != nil || !strings.Contains(out, "pe, zip") {
		t.Fatalf("analyzers: %v %s", err, out)
	}
	if _, err = imRun(t, "inspect", "bogus"); err == nil {
		t.Fatal("bogus must fail")
	}
}

func TestMLReadCommands(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	h := func(resp any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.Method+" "+r.URL.RequestURI())
			omJSON(w, resp)
		}
	}
	mux.HandleFunc("GET /v1/ml/status", h(map[string]any{"method": "ml-v1", "models": map[string]any{"lineage": map[string]any{"status": "not_enough_data"}}}))
	mux.HandleFunc("GET /v1/ml/lineage", h(map[string]any{"method": "ml-v1", "status": "not_enough_data"}))
	mux.HandleFunc("GET /v1/ml/similar", h(map[string]any{"method": "ml-v1", "status": "ok"}))
	mux.HandleFunc("GET /v1/ml/baseline", h(map[string]any{"method": "ml-v1", "status": "ok"}))
	mux.HandleFunc("GET /v1/ml/beacons", h(map[string]any{"model": "statistical-beacon-v1", "min_events": 8, "series_scored": 1, "not_enough_data": 3,
		"suspects": []map[string]any{{"host": "h1", "destination": "1.2.3.4:443", "level": "high", "score": 91.5, "events": 20, "status": "scored"}}}))
	mux.HandleFunc("GET /v1/ml/priority", h(map[string]any{"model": "priority-fusion-v1", "total": 1,
		"priorities": []map[string]any{{"finding_id": "f1", "host": "h1", "rule": "r", "severity": "high", "score": 70.0, "level": "high"}}}))
	setupMock(t, mux)

	out, err := imRun(t, "ml", "status")
	if err != nil || !strings.Contains(out, "method: ml-v1") || !strings.Contains(out, "not_enough_data: models.lineage") {
		t.Fatalf("status: %v %s", err, out)
	}
	if out, err = imRun(t, "ml", "lineage", "--host", "h1", "--limit", "5"); err != nil || !strings.Contains(out, "status: not_enough_data") {
		t.Fatalf("lineage: %v %s", err, out)
	}
	if _, err = imRun(t, "ml", "similar", "curl", "http://x", "--host", "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err = imRun(t, "ml", "baseline"); err == nil {
		t.Fatal("baseline needs --host")
	}
	if _, err = imRun(t, "ml", "baseline", "--host", "h1"); err != nil {
		t.Fatal(err)
	}
	if out, err = imRun(t, "ml", "beacons", "--min-events", "8", "--exclude-private"); err != nil ||
		!strings.Contains(out, "not_enough_data: 3") || !strings.Contains(out, "statistical-beacon-v1") || !strings.Contains(out, "1.2.3.4:443") {
		t.Fatalf("beacons: %v %s", err, out)
	}
	if out, err = imRun(t, "ml", "priority", "--host", "h1"); err != nil || !strings.Contains(out, "priority-fusion-v1") || !strings.Contains(out, "f1") {
		t.Fatalf("priority: %v %s", err, out)
	}
	if _, err = imRun(t, "ml", "priority"); err == nil {
		t.Fatal("priority needs a selector")
	}
	if out, err = imRun(t, "ml", "status", "--json"); err != nil || strings.Contains(out, "method:") || !strings.Contains(out, `"method":"ml-v1"`) {
		t.Fatalf("json: %v %s", err, out)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{"GET /v1/ml/lineage?host=h1&limit=5", "GET /v1/ml/similar?host=h1&q=curl+http%3A%2F%2Fx",
		"GET /v1/ml/baseline?host=h1", "GET /v1/ml/beacons?exclude_private=1&min_events=8", "GET /v1/ml/priority?host=h1"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing request %q in\n%s", want, all)
		}
	}
}

func TestMLSynthesize(t *testing.T) {
	mux := http.NewServeMux()
	var body map[string]string
	status := 200
	mux.HandleFunc("POST /v1/ml/synthesize", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "synthesis-conjunction-v1", "saved": false,
			"rule": map[string]any{"id": "syn-1"}, "validation": map[string]any{"valid": status == 200, "error": "bad sample"},
			"source_event_matches": true, "recommended_initial_lifecycle": "testing", "next_steps": []string{"review"}})
	})
	setupMock(t, mux)
	outFile := filepath.Join(t.TempDir(), "rule.json")
	out, err := imRun(t, "ml", "synthesize", "--command", "whoami /all", "--out", outFile)
	if err != nil || body["command"] != "whoami /all" || !strings.Contains(out, "Nothing was saved") || !strings.Contains(out, "VALID") || !strings.Contains(out, "synthesis-conjunction-v1") {
		t.Fatalf("synth: %v %v %s", err, body, out)
	}
	if b, _ := os.ReadFile(outFile); !strings.Contains(string(b), `"syn-1"`) {
		t.Fatalf("out file: %s", b)
	}
	if _, err = imRun(t, "ml", "synthesize", "--finding", "f9"); err != nil || body["finding_id"] != "f9" {
		t.Fatalf("finding: %v %v", err, body)
	}
	status = 422
	out, err = imRun(t, "ml", "synthesize", "--finding", "f9")
	if err == nil || !strings.Contains(out, "INVALID: bad sample") {
		t.Fatalf("422: %v %s", err, out)
	}
	if _, err = imRun(t, "ml", "synthesize"); err == nil {
		t.Fatal("selector required")
	}
	if _, err = imRun(t, "ml", "synthesize", "--finding", "a", "--command", "b"); err == nil {
		t.Fatal("exactly one selector")
	}
}

func TestMLMutatingRequiresConfirmation(t *testing.T) {
	mux := http.NewServeMux()
	var calls []string
	mux.HandleFunc("POST /v1/ml/reset", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		omJSON(w, map[string]any{"method": "ml-v1", "status": "reset"})
	})
	mux.HandleFunc("POST /v1/ml/learn/replay", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		omJSON(w, map[string]any{"method": "ml-v1", "status": "replayed", "events_replayed": 12})
	})
	setupMock(t, mux)
	old := mlInteractive
	mlInteractive = func() bool { return false }
	defer func() { mlInteractive = old }()
	for _, c := range []string{"reset", "replay"} {
		if _, err := imRun(t, "ml", c); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("%s without --yes: %v", c, err)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("no request may be sent without confirmation: %v", calls)
	}
	if out, err := imRun(t, "ml", "reset", "--yes"); err != nil || !strings.Contains(out, "reset") {
		t.Fatalf("reset: %v %s", err, out)
	}
	if out, err := imRun(t, "ml", "replay", "--yes"); err != nil || !strings.Contains(out, "events_replayed") {
		t.Fatalf("replay: %v %s", err, out)
	}
	if len(calls) != 2 {
		t.Fatalf("calls: %v", calls)
	}
}
