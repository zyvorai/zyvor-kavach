// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExportSIEMCmd(t *testing.T) {
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		w.Write([]byte("ok\n"))
	}))
	defer ts.Close()
	t.Setenv("KAVACH_URL", ts.URL)
	t.Setenv("KAVACH_TOKEN", "tok")
	t.Setenv("HOME", t.TempDir())
	run := func(args ...string) error {
		var buf bytes.Buffer
		return exportCmdSIEM(&buf, args)
	}
	for _, a := range [][]string{
		{"findings", "--format", "ocsf", "--since", "2026-01-01T00:00:00Z", "--limit", "5", "--cursor", "abc"},
		{"findings", "--format", "cef", "--kind", "events"},
		{"iocs"}, {"layer"},
		{"findings", "--format", "csv"}, // legacy delegation
	} {
		if err := run(a...); err != nil {
			t.Fatalf("%v: %v", a, err)
		}
	}
	want := []string{
		"/v1/export/findings?cursor=abc&format=ocsf&limit=5&since=2026-01-01T00%3A00%3A00Z",
		"/v1/export/findings?format=cef&kind=events",
		"/v1/export/iocs?format=stix", "/v1/export/attack-layer", "/v1/export/findings?format=csv",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %v", got)
	}
	if run("iocs", "--format", "csv") == nil || run() == nil {
		t.Fatal("expected usage errors")
	}
}
