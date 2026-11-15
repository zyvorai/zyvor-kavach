package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestPostureReportsCtl(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	mux.HandleFunc("GET /v1/posture/trend", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		omJSON(w, map[string]any{"count": 1, "history_cap": 400, "interval_hours": 6, "snapshots": []any{map[string]any{"time": "2026-11-01T00:00:00Z", "compliance_score": 42, "attack_tactics_covered": 12, "attack_tactics_total": 14}}})
	})
	mux.HandleFunc("GET /v1/posture/trend/diff", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		omJSON(w, map[string]any{"from": map[string]any{"time": "a"}, "to": map[string]any{"time": "b"}, "delta": map[string]any{"compliance_score": 3}})
	})
	mux.HandleFunc("GET /v1/reports/digest", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		_, _ = w.Write([]byte("# Kavach weekly security digest\n"))
	})
	mux.HandleFunc("GET /v1/compliance/auditor-bundle", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		omJSON(w, map[string]any{"files": []any{}})
	})
	setupMock(t, mux)
	run := func(args ...string) string {
		t.Helper()
		var buf strings.Builder
		ok, err := prDispatch(args, &buf)
		if !ok || err != nil {
			t.Fatalf("%v: handled=%v err=%v", args, ok, err)
		}
		return buf.String()
	}
	if out := run("posture-trend", "--days", "7"); !strings.Contains(out, "42") {
		t.Fatal(out)
	}
	if out := run("posture-trend", "diff", "--from", "2026-11-01"); !strings.Contains(out, "+3") {
		t.Fatal(out)
	}
	if out := run("digest", "--days", "7"); !strings.Contains(out, "digest") {
		t.Fatal(out)
	}
	run("auditor-bundle", "--manifest")
	if ok, _ := prDispatch([]string{"other"}, &strings.Builder{}); ok {
		t.Fatal("must not handle other commands")
	}
	want := []string{"/v1/posture/trend?days=7", "/v1/posture/trend/diff?from=2026-11-01", "/v1/reports/digest?days=7&format=md", "/v1/compliance/auditor-bundle?manifest=1"}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Fatalf("calls %v want %v", got, want)
		}
	}
}
