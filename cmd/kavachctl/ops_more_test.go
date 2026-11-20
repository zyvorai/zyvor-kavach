// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func omJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func omRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	h, err := omDispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

func TestOpsMoreReads(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	for _, p := range []string{"/v1/fleet/health", "/v1/fleet/coverage-gaps", "/v1/fleet/stale", "/v1/fleet/health/{host}",
		"/v1/prevalence/executables", "/v1/prevalence/rare", "/v1/prevalence/first-seen", "/v1/graph/blast-radius",
		"/v1/deception/canaries", "/v1/deception/trips", "/v1/governance/inventory", "/v1/governance/retention",
		"/v1/governance/redaction", "/v1/governance/subject", "/v1/tuning/suggestions", "/v1/tuning/history",
		"/v1/digests", "/v1/digests/deliveries"} {
		mux.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.URL.RequestURI())
			omJSON(w, map[string]any{"ok": true})
		})
	}
	setupMock(t, mux)
	for _, a := range [][]string{
		{"fleet", "health"}, {"fleet", "gaps"}, {"fleet", "stale", "--minutes", "30"}, {"fleet", "host", "web 1"},
		{"prevalence", "executables", "--min-hosts", "2", "--limit", "5"}, {"prevalence", "rare", "--hours", "6", "--fraction", "0.1"},
		{"prevalence", "first-seen", "--host", "h1"}, {"blast-radius", "--host", "h1", "--depth", "3"},
		{"canary", "list"}, {"canary", "trips"}, {"governance", "inventory"}, {"governance", "retention"},
		{"governance", "redaction"}, {"governance", "subject", "alice@example.com"},
		{"tuning", "suggestions", "--days", "7"}, {"tuning", "history"}, {"digest", "list"}, {"digest", "deliveries", "--json"},
	} {
		out, err := omRun(t, a...)
		if err != nil || !strings.Contains(out, "true") {
			t.Fatalf("%v: %v %q", a, err, out)
		}
	}
	want := []string{"/v1/fleet/stale?minutes=30", "/v1/fleet/health/web%201", "/v1/prevalence/executables?limit=5&min_hosts=2",
		"/v1/prevalence/rare?fraction=0.1&hours=6", "/v1/graph/blast-radius?depth=3&host=h1", "/v1/governance/subject?q=alice%40example.com"}
	all := strings.Join(got, " ")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Errorf("missing request %s in %v", w, got)
		}
	}
	if _, err := omRun(t, "prevalence", "first-seen"); err == nil {
		t.Fatal("expected host error")
	}
}

func TestOpsMoreWrites(t *testing.T) {
	mux := http.NewServeMux()
	bodies := map[string]map[string]any{}
	rec := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			m := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&m)
			m["_q"] = r.URL.RawQuery
			bodies[name] = m
			omJSON(w, map[string]any{"ok": true})
		}
	}
	mux.HandleFunc("POST /v1/deception/canaries", rec("canary"))
	mux.HandleFunc("DELETE /v1/deception/canaries/{id}", func(w http.ResponseWriter, r *http.Request) {
		bodies["canary-del"] = map[string]any{"id": r.PathValue("id")}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v1/governance/retention", rec("ret"))
	mux.HandleFunc("POST /v1/governance/retention/preview", rec("prev"))
	mux.HandleFunc("POST /v1/governance/redaction", rec("red"))
	mux.HandleFunc("POST /v1/governance/redact/preview", rec("rp"))
	mux.HandleFunc("POST /v1/tuning/apply", rec("tapply"))
	mux.HandleFunc("POST /v1/tuning/revert", rec("trev"))
	mux.HandleFunc("POST /v1/digests", rec("dg"))
	mux.HandleFunc("DELETE /v1/digests", rec("dgdel"))
	mux.HandleFunc("POST /v1/digests/send-now", rec("send"))
	setupMock(t, mux)

	run := func(a ...string) {
		t.Helper()
		if _, err := omRun(t, a...); err != nil {
			t.Fatalf("%v: %v", a, err)
		}
	}
	run("canary", "create", "--kind", "dns-name", "--name", "n1", "--owner", "soc")
	if bodies["canary"]["kind"] != "dns-name" || bodies["canary"]["owner"] != "soc" {
		t.Fatalf("canary body %v", bodies["canary"])
	}
	out, err := omRun(t, "canary", "delete", "c-1")
	if err != nil || !strings.Contains(out, "ok") || bodies["canary-del"]["id"] != "c-1" {
		t.Fatalf("delete: %v %q", err, out)
	}
	run("governance", "retention", "set", "findings=30", "audit=unlimited")
	days := bodies["ret"]["days"].(map[string]any)
	if days["findings"] != float64(30) || days["audit"] != nil {
		t.Fatalf("days %v", days)
	}
	run("governance", "retention", "preview")
	run("governance", "redaction", "set", "on")
	if bodies["red"]["enabled"] != true {
		t.Fatalf("redaction %v", bodies["red"])
	}
	run("governance", "redact-preview", "mail", "bob@example.com")
	if bodies["rp"]["text"] != "mail bob@example.com" {
		t.Fatalf("rp %v", bodies["rp"])
	}
	run("tuning", "apply", "--rule", "r1", "--pattern", "r1 host1", "--reason", "noisy")
	if bodies["tapply"]["rule"] != "r1" || bodies["tapply"]["reason"] != "noisy" {
		t.Fatalf("tapply %v", bodies["tapply"])
	}
	run("tuning", "revert", "tn-1")
	if bodies["trev"]["_q"] != "id=tn-1" {
		t.Fatalf("revert %v", bodies["trev"])
	}
	run("digest", "set", "--name", "d", "--schedule", "daily", "--hour", "7", "--content", "top-risks", "--type", "slack", "--url", "https://x.example/h")
	if bodies["dg"]["hour_utc"] != float64(7) || bodies["dg"]["type"] != "slack" {
		t.Fatalf("dg %v", bodies["dg"])
	}
	run("digest", "delete", "dg-1")
	run("digest", "send-now", "dg-1")
	if bodies["dgdel"]["_q"] != "id=dg-1" || bodies["send"]["_q"] != "id=dg-1" {
		t.Fatalf("digest ids %v %v", bodies["dgdel"], bodies["send"])
	}
}

func TestGovernanceApplyRequiresYes(t *testing.T) {
	mux := http.NewServeMux()
	calls := 0
	var body map[string]any
	mux.HandleFunc("POST /v1/governance/retention/apply", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewDecoder(r.Body).Decode(&body)
		omJSON(w, map[string]any{"dry_run": false})
	})
	setupMock(t, mux)
	if _, err := omRun(t, "governance", "retention", "apply"); err == nil || calls != 0 {
		t.Fatalf("apply without --yes must fail locally: %v calls=%d", err, calls)
	}
	if _, err := omRun(t, "governance", "retention", "apply", "--yes"); err != nil || calls != 1 || body["confirm"] != "purge" {
		t.Fatalf("apply --yes: %v calls=%d body=%v", err, calls, body)
	}
}

func TestOpsMoreDispatchFallthrough(t *testing.T) {
	if h, _ := omDispatch([]string{"fleet"}, &strings.Builder{}); h {
		t.Fatal("bare fleet must fall through to legacy")
	}
	if h, _ := omDispatch([]string{"hosts"}, &strings.Builder{}); h {
		t.Fatal("hosts not ours")
	}
}
