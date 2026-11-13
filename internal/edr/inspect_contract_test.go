// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withAnalyzers swaps the registry for the duration of a test.
func withAnalyzers(t *testing.T, as ...inspectAnalyzer) {
	t.Helper()
	inspectMu.Lock()
	saved := inspectAnalyzers
	inspectAnalyzers = as
	inspectMu.Unlock()
	t.Cleanup(func() {
		inspectMu.Lock()
		inspectAnalyzers = saved
		inspectMu.Unlock()
	})
}

func an(name string, kinds []string, fn AnalyzerFunc) inspectAnalyzer {
	m := map[string]bool{}
	for _, k := range kinds {
		m[k] = true
	}
	return inspectAnalyzer{name: name, kinds: m, fn: fn}
}

func TestInspectPanicAndErrorAreIsolated(t *testing.T) {
	withAnalyzers(t,
		an("boom", []string{InspectKindScript}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
			panic("kaboom")
		}),
		an("fails", []string{InspectKindScript}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
			return context.DeadlineExceeded
		}),
		an("ok", []string{InspectKindScript}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
			b.Finding(InspectFinding{ID: "x", Title: "found it", Severity: "high", Weight: 50})
			return nil
		}),
	)
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindScript, Text: "hello"})
	if len(r.Errors) != 2 {
		t.Fatalf("want 2 analyzer errors, got %v", r.Errors)
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "panic: kaboom") {
		t.Fatalf("panic not reported: %v", r.Errors)
	}
	if len(r.Findings) != 1 || r.Findings[0].Analyzer != "ok" {
		t.Fatalf("good analyzer result lost: %+v", r.Findings)
	}
}

func TestInspectAnalyzerTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the analyzer budget")
	}
	withAnalyzers(t, an("slow", []string{InspectKindCmdline}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
		<-ctx.Done()
		return ctx.Err()
	}))
	start := time.Now()
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindCmdline, Text: "x"})
	if time.Since(start) > InspectAnalyzerTime+2*time.Second {
		t.Fatalf("analyzer was not bounded: %v", time.Since(start))
	}
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "timed out") {
		t.Fatalf("want timeout error, got %v", r.Errors)
	}
}

func TestInspectCapsAndDedupe(t *testing.T) {
	withAnalyzers(t, an("flood", []string{InspectKindFile}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
		for i := 0; i < InspectMaxFindings+50; i++ {
			b.Finding(InspectFinding{ID: "f", Title: strings.Repeat("t", 2000), Severity: "bogus", Weight: 500})
		}
		for i := 0; i < InspectMaxIOCs+50; i++ {
			b.IOC("domain", "d"+string(rune('a'+i%26))+strings.Repeat("x", i)+".example")
		}
		b.IOC("domain", "dup.example")
		b.IOC("domain", "dup.example")
		for i := 0; i < InspectMaxLayers+5; i++ {
			b.Layer(InspectLayer{Depth: i, Method: "m", Preview: strings.Repeat("p", 5000)})
		}
		return nil
	}))
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Data: []byte("x")})
	if len(r.Findings) != InspectMaxFindings || len(r.IOCs) > InspectMaxIOCs || len(r.Layers) != InspectMaxLayers {
		t.Fatalf("caps not enforced: findings=%d iocs=%d layers=%d", len(r.Findings), len(r.IOCs), len(r.Layers))
	}
	for _, name := range []string{"findings", "iocs", "layers"} {
		found := false
		for _, l := range r.LimitsHit {
			if l == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("limit %q not reported in %v", name, r.LimitsHit)
		}
	}
	f := r.Findings[0]
	if len(f.Title) > InspectMaxStringLen+3 || f.Weight != 100 || f.Severity != "info" {
		t.Fatalf("finding not normalised: weight=%d sev=%q titlelen=%d", f.Weight, f.Severity, len(f.Title))
	}
	if r.Score != 100 || r.Level != "malicious-likely" {
		t.Fatalf("score/level wrong: %d %s", r.Score, r.Level)
	}
}

func TestInspectScoreIsTransparentAndBounded(t *testing.T) {
	r := &InspectReport{}
	for i := 0; i < 30; i++ {
		r.Findings = append(r.Findings, InspectFinding{Title: "weak", Weight: 2})
	}
	scoreInspectReport(r)
	if r.Score != 20 || r.Level != "low" {
		t.Fatalf("only the top 10 findings should count: score=%d level=%s", r.Score, r.Level)
	}
	if len(r.Factors) != 10 {
		t.Fatalf("every contributing finding must be listed: %d", len(r.Factors))
	}
	clean := &InspectReport{}
	scoreInspectReport(clean)
	if clean.Score != 0 || clean.Level != "clean" {
		t.Fatalf("empty report should be clean: %+v", clean)
	}
}

func TestInspectHashAndKnownIOC(t *testing.T) {
	withAnalyzers(t, an("noop", []string{InspectKindDomain}, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
		b.IOC("domain", in.Text)
		return nil
	}))
	// defaultIOCs include a known-bad domain; use whatever the store ships.
	ioc := ""
	for _, i := range defaultIOCs() {
		if i.Type == "domain" && i.Enabled {
			ioc = i.Value
			break
		}
	}
	if ioc == "" {
		t.Skip("no default domain IOC to test with")
	}
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindDomain, Text: ioc})
	if len(r.SHA256) != 64 {
		t.Fatalf("sha256 missing: %q", r.SHA256)
	}
	if len(r.KnownIOCs) == 0 || r.Score < 40 {
		t.Fatalf("known IOC not cross-checked: known=%v score=%d", r.KnownIOCs, r.Score)
	}
}

func inspectMux(token string) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterInspect(mux, token)
	return mux
}

func TestInspectHTTP(t *testing.T) {
	withAnalyzers(t, an("echo", inspectKinds, func(ctx context.Context, in InspectInput, b *InspectBuilder) error {
		b.Format("test")
		b.Finding(InspectFinding{ID: "e", Title: "saw " + in.Kind, Severity: "low", Weight: 5})
		return nil
	}))
	mux := inspectMux("tok")
	do := func(method, path, ct string, body []byte, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := do("POST", "/v1/inspect/script", "text/plain", []byte("x"), false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must be 401, got %d", w.Code)
	}
	if w := do("POST", "/v1/inspect/script", "text/plain", nil, true); w.Code != http.StatusBadRequest {
		t.Fatalf("empty input must be 400, got %d", w.Code)
	}
	if w := do("POST", "/v1/inspect/script", "application/json", []byte("{bad"), true); w.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON must be 400, got %d", w.Code)
	}
	big := bytes.Repeat([]byte("a"), InspectMaxTextBytes+4096)
	if w := do("POST", "/v1/inspect/cmdline", "text/plain", big, true); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized text must be 413, got %d", w.Code)
	}
	w := do("POST", "/v1/inspect/script", "application/json", []byte(`{"text":"echo hi","name":"a.sh"}`), true)
	if w.Code != 200 {
		t.Fatalf("script inspect: %d %s", w.Code, w.Body.String())
	}
	var rep InspectReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "script" || rep.Name != "a.sh" || rep.Format != "test" || rep.Mode != "observe-only" || len(rep.Findings) != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	secret := []byte("SECRET-FILE-CONTENT-MARKER")
	w = do("POST", "/v1/inspect/file?name=x.bin", "application/octet-stream", secret, true)
	if w.Code != 200 {
		t.Fatalf("file inspect: %d %s", w.Code, w.Body.String())
	}
	w = do("GET", "/v1/inspect/reports", "", nil, true)
	if w.Code != 200 {
		t.Fatalf("reports: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "SECRET-FILE-CONTENT-MARKER") {
		t.Fatal("submitted bytes must never be stored in the report ring")
	}
	if w := do("GET", "/v1/inspect/analyzers", "", nil, true); w.Code != 200 || !strings.Contains(w.Body.String(), "echo") {
		t.Fatalf("analyzers listing: %d %s", w.Code, w.Body.String())
	}
}

func TestInspectRingIsCapped(t *testing.T) {
	inspectRingMu.Lock()
	inspectRing = nil
	inspectRingMu.Unlock()
	for i := 0; i < InspectRingCapacity+25; i++ {
		storeInspectReport(&InspectReport{ID: "r"})
	}
	if n := len(RecentInspectReports(0)); n != InspectRingCapacity {
		t.Fatalf("ring must cap at %d, got %d", InspectRingCapacity, n)
	}
}
