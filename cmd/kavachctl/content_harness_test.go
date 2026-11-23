// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	handled, err := chDispatch(append([]string{"content"}, args...), &buf)
	if !handled {
		t.Fatalf("content %v not handled", args)
	}
	return buf.String(), err
}

func TestChDispatchFallsThrough(t *testing.T) {
	var buf bytes.Buffer
	for _, a := range [][]string{{"status"}, {"content"}, {"content", "list"}, {"content", "custom", "list"}, {"content", "manifest"}} {
		if h, _ := chDispatch(a, &buf); h {
			t.Errorf("%v must fall through", a)
		}
	}
}

func TestChUsageErrors(t *testing.T) {
	for _, a := range [][]string{{"test"}, {"fp-report"}, {"test", "--bogus"}, {"fp-report", "--benign"}, {"fp-report", "--threshold", "x", "--builtin"}, {"selftest", "--pack"}} {
		if _, err := chRun(t, a...); err == nil {
			t.Errorf("%v: want error", a)
		}
	}
	if _, err := chRun(t, "test", filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Error("missing file accepted")
	}
}

const chHdr = `{"schema":"kavach-content-tests/1"}` + "\n"
const chAuth = `{"time":"2026-01-15T10:00:00Z","user":"a","ip":"203.0.113.1","outcome":"success"}`

func TestChTestPassFailJSON(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	bad := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(good, []byte(chHdr+`{"case":"quiet","kind":"auth","records":[`+chAuth+`],"forbid":["auth-an-high-velocity"]}`+"\n"), 0o600)
	_ = os.WriteFile(bad, []byte(chHdr+`{"case":"missing","kind":"auth","records":[`+chAuth+`],"expect":["auth-an-high-velocity"]}`+"\n"), 0o600)
	out, err := chRun(t, "test", good)
	if err != nil || !strings.Contains(out, "PASS") || !strings.Contains(out, "1 passed, 0 failed") {
		t.Fatalf("good: %v\n%s", err, out)
	}
	out, err = chRun(t, "test", good, bad)
	if err == nil || !strings.Contains(out, "FAIL  bad.jsonl:2") || !strings.Contains(out, "expected rule auth-an-high-velocity did not fire") {
		t.Fatalf("bad: %v\n%s", err, out)
	}
	out, err = chRun(t, "test", bad, "--json")
	if err == nil {
		t.Fatal("json mode must still exit non-zero on failure")
	}
	var rep map[string]any
	if json.Unmarshal([]byte(out), &rep) != nil || rep["schema"] != "kavach-content-tests/1" || rep["failed"].(float64) != 1 {
		t.Fatalf("json: %s", out)
	}
}

func TestChSelftestAndCoverage(t *testing.T) {
	out, err := chRun(t, "selftest")
	if err != nil || !strings.Contains(out, "rules fire on their own positive example") {
		t.Fatalf("selftest: %v\n%s", err, out)
	}
	out, err = chRun(t, "selftest", "--json")
	var m map[string]any
	if err != nil || json.Unmarshal([]byte(out), &m) != nil || m["rules_failing"].(float64) != 0 {
		t.Fatalf("selftest json: %v", err)
	}
	out, err = chRun(t, "tested-coverage")
	if err != nil || !strings.Contains(out, "ATT&CK techniques with at least one passing positive example") {
		t.Fatalf("coverage: %v\n%s", err, out)
	}
	// a custom pack with a rule that has no matching positive sample is rejected, not run
	pack := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(pack, []byte(`{"rules":[{"id":"x-bad","name":"n"}]}`), 0o600)
	if _, err := chRun(t, "selftest", "--pack", pack); err == nil {
		t.Error("invalid pack accepted")
	}
}

func TestChFPReport(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "web.log"), []byte(`203.0.113.8 - - [15/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "x"`+"\n"), 0o600)
	out, err := chRun(t, "fp-report", "--benign", dir, "--builtin")
	if err != nil || !strings.Contains(out, "measures only the corpus you supplied") {
		t.Fatalf("fp: %v\n%s", err, out)
	}
	bad := filepath.Join(dir, "attack.log")
	_ = os.WriteFile(bad, []byte(`203.0.113.8 - - [15/Jan/2026:10:00:01 +0000] "GET /a?x=1%20union%20select%201 HTTP/1.1" 200 5 "-" "x"`+"\n"), 0o600)
	out, err = chRun(t, "fp-report", "--benign", bad, "--fail-on-noisy", "--json")
	if err == nil || !strings.Contains(out, `"noisy_rules"`) {
		t.Fatalf("fail-on-noisy: %v\n%s", err, out)
	}
}
