// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"strings"
	"testing"
)

func surfMock(t *testing.T) *[]string {
	t.Helper()
	mux := http.NewServeMux()
	got := &[]string{}
	rec := func(w http.ResponseWriter, r *http.Request, body string) {
		*got = append(*got, r.Method+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
		if strings.Contains(r.URL.Path, "render") {
			w.Header().Set("Content-Type", "text/markdown")
		}
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("/v1/events/auth", func(w http.ResponseWriter, r *http.Request) {
		rec(w, r, `{"type":"auth","events":[{"host":"h1","user":"root","ok":false}]}`)
	})
	mux.HandleFunc("/v1/guidance/", func(w http.ResponseWriter, r *http.Request) { rec(w, r, `{"id":"g1","title":"T"}`) })
	mux.HandleFunc("/v1/reports/templates/", func(w http.ResponseWriter, r *http.Request) { rec(w, r, "# Report\n") })
	mux.HandleFunc("/v1/regression/gate", func(w http.ResponseWriter, r *http.Request) {
		*got = append(*got, r.Method+" "+r.URL.RequestURI())
		w.WriteHeader(412)
		_, _ = w.Write([]byte(`{"pass":false,"reason":"x"}`))
	})
	setupMock(t, mux)
	return got
}

func TestSurfaceCommands(t *testing.T) {
	got := surfMock(t)

	var b strings.Builder
	ok, err := surfDispatch([]string{"events", "auth", "--host", "h1", "--limit", "5"}, &b)
	if !ok || err != nil {
		t.Fatalf("handled=%v err=%v", ok, err)
	}
	if !strings.Contains(b.String(), "HOST") || !strings.Contains(b.String(), "root") {
		t.Fatalf("expected table output, got %q", b.String())
	}
	if (*got)[0] != "GET /v1/events/auth?host=h1&limit=5 auth=Bearer test-token" {
		t.Fatalf("request: %v", *got)
	}
	if strings.Contains(b.String(), "test-token") {
		t.Fatal("token must never be printed")
	}

	b.Reset()
	if _, err := surfDispatch([]string{"events", "auth", "--json"}, &b); err != nil || !strings.HasPrefix(b.String(), `{"type":"auth"`) {
		t.Fatalf("json mode: %v %q", err, b.String())
	}

	b.Reset()
	if _, err := surfDispatch([]string{"guidance", "a/b"}, &b); err != nil || !strings.Contains(b.String(), "title: T") {
		t.Fatalf("guidance by id: %v %q", err, b.String())
	}
	if !strings.Contains((*got)[len(*got)-1], "/v1/guidance/a%2Fb") {
		t.Fatalf("id must be escaped: %v", *got)
	}

	b.Reset()
	if _, err := surfDispatch([]string{"reports", "templates", "t1"}, &b); err != nil || b.String() != "# Report\n" {
		t.Fatalf("render: %v %q", err, b.String())
	}

	b.Reset()
	_, err = surfDispatch([]string{"regression", "gate", "--min-detected", "90"}, &b)
	if err == nil || !strings.Contains(b.String(), "pass: false") {
		t.Fatalf("gate 412 must print body and fail: err=%v out=%q", err, b.String())
	}
	if !strings.Contains((*got)[len(*got)-1], "min_detected=90") {
		t.Fatalf("flag mapping: %v", *got)
	}

	if ok, _ := surfDispatch([]string{"findings"}, &b); ok {
		t.Fatal("must not claim unrelated commands")
	}
}
