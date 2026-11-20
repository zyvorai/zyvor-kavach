// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestSearchCommand(t *testing.T) {
	mux := http.NewServeMux()
	var got string
	mux.HandleFunc("GET /v1/search", func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		omJSON(w, map[string]any{"count": 1, "results": []map[string]any{{"type": "technique", "id": "T1059", "title": "Command and Scripting", "score": 100, "route": "#/content"}}})
	})
	setupMock(t, mux)
	var buf strings.Builder
	h, err := gsDispatch([]string{"search", "T1059", "--type", "technique,cve", "--limit", "5"}, &buf)
	if !h || err != nil || !strings.Contains(buf.String(), "T1059") || !strings.Contains(buf.String(), "1 results") {
		t.Fatalf("%v %v %q", h, err, buf.String())
	}
	for _, want := range []string{"q=T1059", "types=technique%2Ccve", "limit=5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("query %q missing %s", got, want)
		}
	}
	buf.Reset()
	if _, err = gsDispatch([]string{"search", "x"}, &buf); err == nil {
		t.Fatal("short query must show usage")
	}
	if h, _ := gsDispatch([]string{"status"}, &buf); h {
		t.Fatal("must not claim other commands")
	}
}
