// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"strings"
	"testing"
	"time"
)

func seedExport(t *testing.T, s *Store) {
	t.Helper()
	now := time.Now().UTC()
	for _, f := range []Finding{
		{ID: "1", Time: now, Host: "h1", PID: 1, Rule: "r1", Severity: "high", Description: "=cmd|' /C calc'!A0"},
		{ID: "2", Time: now.Add(-48 * time.Hour), Host: "<script>x</script>", PID: 2, Rule: "r2", Severity: "low", Description: "+1 @a -b"},
	} {
		if err := s.Append(f); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExportAuthAndCSV(t *testing.T) {
	srv, s, tok := obsServer(t)
	seedExport(t, s)
	if r, _ := get(t, srv.URL+"/v1/export/findings", ""); r.StatusCode != 401 {
		t.Fatalf("want 401 got %d", r.StatusCode)
	}
	if r, _ := get(t, srv.URL+"/v1/export/report", ""); r.StatusCode != 401 {
		t.Fatalf("want 401 got %d", r.StatusCode)
	}
	r, body := get(t, srv.URL+"/v1/export/findings?format=csv", tok)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("bad response %d %v", r.StatusCode, r.Header)
	}
	for _, want := range []string{"'=cmd", "'+1 @a -b"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}
	if strings.Contains(body, ",=cmd") || strings.Contains(body, ",\"=cmd") {
		t.Fatalf("unneutralised formula: %s", body)
	}
}

func TestExportFilters(t *testing.T) {
	srv, s, tok := obsServer(t)
	seedExport(t, s)
	_, b := get(t, srv.URL+"/v1/export/findings?format=ndjson&severity=HIGH", tok)
	if strings.Count(strings.TrimSpace(b), "\n") != 0 || !strings.Contains(b, `"id":"1"`) {
		t.Fatalf("severity: %s", b)
	}
	_, b = get(t, srv.URL+"/v1/export/findings?format=ndjson&rule=r2", tok)
	if !strings.Contains(b, `"id":"2"`) || strings.Contains(b, `"id":"1"`) {
		t.Fatalf("rule: %s", b)
	}
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	_, b = get(t, srv.URL+"/v1/export/findings?format=json&since="+since, tok)
	if !strings.Contains(b, `"id":"1"`) || strings.Contains(b, `"id":"2"`) {
		t.Fatalf("since: %s", b)
	}
	if r, _ := get(t, srv.URL+"/v1/export/findings?since=bogus", tok); r.StatusCode != 400 {
		t.Fatalf("want 400 got %d", r.StatusCode)
	}
	if r, _ := get(t, srv.URL+"/v1/export/findings?format=xml", tok); r.StatusCode != 400 {
		t.Fatalf("want 400 got %d", r.StatusCode)
	}
}

func TestExportReportHTMLEscaping(t *testing.T) {
	srv, s, tok := obsServer(t)
	seedExport(t, s)
	r, b := get(t, srv.URL+"/v1/export/report?format=html", tok)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("bad %d", r.StatusCode)
	}
	if strings.Contains(b, "<script>x") || !strings.Contains(b, "&lt;script&gt;x") {
		t.Fatalf("not escaped: %s", b)
	}
	if strings.Contains(b, "http://") || strings.Contains(b, "https://") || !strings.Contains(b, "@media print") {
		t.Fatal("external assets or missing print styles")
	}
	_, j := get(t, srv.URL+"/v1/export/report?format=json", tok)
	if !strings.Contains(j, `"compliance"`) || !strings.Contains(j, `"attack"`) {
		t.Fatalf("json: %s", j)
	}
}
