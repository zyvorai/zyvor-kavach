// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestAdvisoriesCommands(t *testing.T) {
	mux := http.NewServeMux()
	var got string
	enabled := true
	mux.HandleFunc("GET /v1/advisories", func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		omJSON(w, map[string]any{"count": 1, "total": 3, "enabled_feeds": []string{"cisa"}, "advisories": []map[string]any{
			{"source": "cisa", "id": "icsa-26-1", "title": "Siemens thing", "published": "2026-11-11T12:00:00Z", "cves": []string{"CVE-2099-1"}, "matched": true, "matched_hosts": []string{"h1"}}}})
	})
	mux.HandleFunc("GET /v1/advisories/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		omJSON(w, map[string]any{"enabled": []string{"cisa"}, "counts": map[string]int{"cisa": 7}, "note": "n"})
	})
	mux.HandleFunc("POST /v1/advisories/feeds/refresh", func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			w.WriteHeader(409)
			return
		}
		omJSON(w, map[string]any{"enabled": []string{"cisa"}, "counts": map[string]int{"cisa": 8}})
	})
	setupMock(t, mux)
	var buf strings.Builder
	h, err := cfDispatch([]string{"advisories", "list", "--source", "cisa,jvn", "--cve", "CVE-2099-1", "--matched", "--limit", "5"}, &buf)
	if !h || err != nil || !strings.Contains(buf.String(), "icsa-26-1") || !strings.Contains(buf.String(), "YES h1") || !strings.Contains(buf.String(), "1 of 3") {
		t.Fatalf("%v %v %q", h, err, buf.String())
	}
	for _, want := range []string{"source=cisa%2Cjvn", "cve=CVE-2099-1", "matched=true", "limit=5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("query %q missing %s", got, want)
		}
	}
	buf.Reset()
	if _, err = cfDispatch([]string{"advisories", "status"}, &buf); err != nil || !strings.Contains(buf.String(), "cisa") || !strings.Contains(buf.String(), "7 advisories") {
		t.Fatalf("status %v %q", err, buf.String())
	}
	buf.Reset()
	if _, err = cfDispatch([]string{"advisories", "refresh"}, &buf); err != nil || !strings.Contains(buf.String(), "8 advisories") {
		t.Fatalf("refresh %v %q", err, buf.String())
	}
	enabled = false
	if _, err = cfDispatch([]string{"advisories", "refresh"}, &buf); err == nil || !strings.Contains(err.Error(), "KAVACH_CERT_FEEDS") {
		t.Fatalf("409 err %v", err)
	}
	if _, err = cfDispatch([]string{"advisories"}, &buf); err == nil {
		t.Fatal("usage expected")
	}
	if h, _ := cfDispatch([]string{"status"}, &buf); h {
		t.Fatal("must not claim other commands")
	}
}
