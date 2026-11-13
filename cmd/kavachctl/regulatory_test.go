package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRegulatoryCtl(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	rec := func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
	}
	mux.HandleFunc("GET /v1/regulatory/regimes", func(w http.ResponseWriter, r *http.Request) {
		rec(r)
		omJSON(w, map[string]any{"regimes": []any{
			map[string]any{"id": "uk-gdpr", "jurisdiction": "United Kingdom", "name": "UK GDPR", "verified": true, "stages": []any{map[string]any{"name": "Report to ICO"}}},
			map[string]any{"id": "br-lgpd", "jurisdiction": "Brazil", "name": "LGPD", "verified": false, "stages": []any{}},
		}})
	})
	mux.HandleFunc("GET /v1/regulatory/clocks", func(w http.ResponseWriter, r *http.Request) {
		rec(r)
		omJSON(w, map[string]any{"regimes": []any{map[string]any{"regime": "uk-gdpr", "name": "UK GDPR", "verified": true, "start_event": "awareness",
			"stages": []any{
				map[string]any{"name": "Report to ICO", "hours": 72, "computable": true, "incidents": []any{
					map[string]any{"finding_id": "f1", "severity": "high", "host": "h1", "remaining_seconds": -3600, "overdue": true}}},
				map[string]any{"name": "Final", "computable": false, "description": "one month"},
			}}}})
	})
	mux.HandleFunc("GET /v1/regulatory/profile", func(w http.ResponseWriter, r *http.Request) {
		rec(r)
		omJSON(w, map[string]any{"profile": map[string]any{"regimes": []string{}}})
	})
	mux.HandleFunc("PUT /v1/regulatory/profile", func(w http.ResponseWriter, r *http.Request) {
		rec(r)
		omJSON(w, map[string]any{"status": "saved"})
	})
	setupMock(t, mux)
	run := func(args ...string) string {
		t.Helper()
		var buf strings.Builder
		ok, err := regDispatch(append([]string{"regulatory"}, args...), &buf)
		if !ok || err != nil {
			t.Fatalf("%v: handled=%v err=%v", args, ok, err)
		}
		return buf.String()
	}
	if out := run("regimes", "--jurisdiction", "Brazil"); !strings.Contains(out, "UNVERIFIED") || !strings.Contains(out, "not legal advice") || !strings.Contains(out, "uk-gdpr") {
		t.Fatalf("regimes: %s", out)
	}
	if out := run("clocks", "--regime", "uk-gdpr"); !strings.Contains(out, "OVERDUE 1h00m") || !strings.Contains(out, "not computed") || !strings.Contains(out, "does not file") {
		t.Fatalf("clocks: %s", out)
	}
	run("profile")
	run("profile", "set", "uk-gdpr,br-lgpd")
	want := []string{"GET /v1/regulatory/regimes?jurisdiction=Brazil ", "GET /v1/regulatory/clocks?regime=uk-gdpr ", "GET /v1/regulatory/profile ",
		`PUT /v1/regulatory/profile {"regimes":["uk-gdpr","br-lgpd"]}`}
	for i, w := range want {
		if i >= len(got) || !strings.Contains(got[i], w) {
			t.Fatalf("req %d: want %q got %v", i, w, got)
		}
	}
	if ok, _ := regDispatch([]string{"status"}, io.Discard); ok {
		t.Fatal("must not claim other commands")
	}
	if _, err := regDispatch([]string{"regulatory"}, io.Discard); err == nil {
		t.Fatal("usage expected")
	}
}
