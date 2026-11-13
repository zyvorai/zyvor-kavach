package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRulesHealthCtl(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	h := func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		omJSON(w, map[string]any{"count": 1, "rules": []any{map[string]any{"rule": "r1", "state": "testing", "source": "custom", "hits_7d": 3, "silent": true}}})
	}
	for _, p := range []string{"GET /v1/rules/health", "GET /v1/rules/health/{id}", "GET /v1/rules/lifecycle/{id}",
		"PUT /v1/rules/lifecycle/{id}", "GET /v1/rules/history/{id}"} {
		mux.HandleFunc(p, h)
	}
	setupMock(t, mux)
	run := func(args ...string) string {
		t.Helper()
		var buf strings.Builder
		ok, err := rhDispatch(append([]string{"rules"}, args...), &buf)
		if !ok || err != nil {
			t.Fatalf("%v: handled=%v err=%v", args, ok, err)
		}
		return buf.String()
	}
	if out := run("health", "--silent", "--state", "testing"); !strings.Contains(out, "r1") || !strings.Contains(out, "silent") {
		t.Fatalf("table: %s", out)
	}
	run("health", "r1")
	run("lifecycle", "r1")
	run("lifecycle", "r1", "--set", "retired", "--note", "obsolete")
	run("history", "r1")
	want := []string{"GET /v1/rules/health?silent=1&state=testing ", "GET /v1/rules/health/r1 ", "GET /v1/rules/lifecycle/r1 ",
		`PUT /v1/rules/lifecycle/r1 {"note":"obsolete","state":"retired"}`, "GET /v1/rules/history/r1 "}
	for i, w := range want {
		if i >= len(got) || !strings.Contains(got[i], w) {
			t.Fatalf("req %d: want %q got %v", i, w, got)
		}
	}
	if ok, _ := rhDispatch([]string{"status"}, io.Discard); ok {
		t.Fatal("must not claim other commands")
	}
}
