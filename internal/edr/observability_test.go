// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func obsServer(t *testing.T) (*httptest.Server, *Store, string) {
	t.Helper()
	s, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	tok := "0123456789abcdef"
	srv := httptest.NewServer(API(tok, s))
	t.Cleanup(srv.Close)
	return srv, s, tok
}

func get(t *testing.T, url, tok string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, string(b)
}

func TestHealthMetricsAndHeaders(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, p := range []string{"/livez", "/readyz"} {
		if r, _ := get(t, srv.URL+p, ""); r.StatusCode != 200 {
			t.Fatalf("%s: %d", p, r.StatusCode)
		}
	}
	if r, _ := get(t, srv.URL+"/metrics", ""); r.StatusCode != 401 {
		t.Fatalf("metrics must require auth: %d", r.StatusCode)
	}
	r, body := get(t, srv.URL+"/metrics", tok)
	if r.StatusCode != 200 || !strings.Contains(body, "kavach_findings_total 0") || !strings.Contains(body, "kavach_http_requests_total") {
		t.Fatalf("metrics: %d %s", r.StatusCode, body)
	}
	if r.Header.Get("X-Frame-Options") != "DENY" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", r.Header)
	}
}

func TestRateLimiterBlocksLoginBurst(t *testing.T) {
	srv, _, _ := obsServer(t)
	got429 := false
	for i := 0; i < 30; i++ {
		r, err := http.Post(srv.URL+"/v1/session", "application/json", strings.NewReader(`{"username":"x","password":"y"}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected 429 after login burst")
	}
}

func TestTokenBucketRefills(t *testing.T) {
	l := newRateLimiter(1, 2)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) {
		t.Fatal("burst of 2 expected")
	}
	if !l.allow("a", now.Add(1100*time.Millisecond)) {
		t.Fatal("expected refill")
	}
}

func TestATTACKMatrixAndCompliance(t *testing.T) {
	srv, s, tok := obsServer(t)
	_ = s.Append(Finding{ID: "f1", Time: time.Now(), Host: "h", Rule: "ransomware-burst", Severity: "high"})
	_, body := get(t, srv.URL+"/v1/attack/matrix", tok)
	var m struct {
		Covered, Total, ObservedHits int
		Tactics                      []ATTACKTactic
	}
	if err := json.Unmarshal([]byte(strings.NewReplacer("observed_hits", "ObservedHits").Replace(body)), &m); err != nil {
		t.Fatal(err)
	}
	if m.Total != 14 || m.Covered < 5 || m.ObservedHits != 1 {
		t.Fatalf("matrix: %+v", m)
	}
	var impact *ATTACKTactic
	for i := range m.Tactics {
		if m.Tactics[i].Tactic == "Impact" {
			impact = &m.Tactics[i]
		}
	}
	if impact == nil || impact.Hits != 1 {
		t.Fatalf("impact tactic: %+v", impact)
	}
	_, body = get(t, srv.URL+"/v1/compliance/score", tok)
	if !strings.Contains(body, `"overall"`) || !strings.Contains(body, `"grade"`) {
		t.Fatalf("score: %s", body)
	}
	if r, _ := get(t, srv.URL+"/v1/attack/matrix", ""); r.StatusCode != 401 {
		t.Fatal("matrix must require auth")
	}
}

func TestStreamEmitsNewFinding(t *testing.T) {
	srv, s, tok := obsServer(t)
	req, _ := http.NewRequest("GET", srv.URL+"/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = s.Append(Finding{ID: "live1", Time: time.Now(), Host: "h", Rule: "download-execute", Severity: "high"})
	}()
	done := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				done <- sc.Text()
				return
			}
		}
	}()
	select {
	case line := <-done:
		if !strings.Contains(line, "live1") {
			t.Fatalf("unexpected: %s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SSE event")
	}
}
