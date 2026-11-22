// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSIEMURLValidation(t *testing.T) {
	bad := []string{
		"ftp://example.com/x",
		"file:///etc/passwd",
		"http://127.0.0.1/x",
		"http://[::1]/x",
		"http://localhost/x",
		"http://169.254.169.254/latest",
		"http://[fe80::1]/x",
		"http://0.0.0.0/x",
		"http://10.1.2.3/x",
		"http://192.168.1.1/x",
		"http://172.16.0.1/x",
		"http://[fd00::1]/x",
		"http:///nohost",
	}
	for _, u := range bad {
		if _, err := validateSIEMURL(u, false, false); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	// opt-in allows private only, never loopback/metadata/unspecified.
	for _, u := range []string{"http://10.1.2.3/x", "http://192.168.1.1/x", "http://[fd00::1]/x"} {
		if _, err := validateSIEMURL(u, true, false); err != nil {
			t.Errorf("%s with opt-in: %v", u, err)
		}
	}
	for _, u := range []string{"http://127.0.0.1/x", "http://169.254.169.254/x", "http://0.0.0.0/x"} {
		if _, err := validateSIEMURL(u, true, false); err == nil {
			t.Errorf("%s accepted despite private opt-in", u)
		}
	}
	if _, err := validateSIEMURL("https://203.0.113.10/hook", false, false); err != nil {
		t.Errorf("public ip rejected: %v", err)
	}
}

func TestSIEMExporterDropsUnsafeWebhook(t *testing.T) {
	s := newSIEMExporter(SIEMConfig{WebhookURL: "http://169.254.169.254/x", Enabled: true})
	if s.cfg.WebhookURL != "" || s.cfg.Enabled || s.Status()["last_error"] == "" {
		t.Fatalf("unsafe webhook kept: %+v", s.Status())
	}
}

func TestSIEMPrivateOptInEnv(t *testing.T) {
	t.Setenv("KAVACH_SIEM_ALLOW_PRIVATE", "1")
	s := newSIEMExporter(SIEMConfig{WebhookURL: "http://10.9.9.9/x", Enabled: true})
	if s.cfg.WebhookURL == "" {
		t.Fatal("private webhook dropped despite opt-in")
	}
}

func TestSIEMDialGuardBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached loopback server")
	}))
	defer srv.Close()
	c := newSIEMHTTPClient(false, false)
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("dial guard let loopback through")
	}
}

func TestSIEMRedirectToBlockedRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()
	c := newSIEMHTTPClient(false, true) // loopback allowed for the test server only
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("redirect to metadata address followed")
	}
}

func testSIEM(url string) *SIEMExporter {
	s := newSIEMExporter(SIEMConfig{WebhookURL: url, Enabled: true, allowLoopback: true})
	s.backoff = time.Millisecond
	return s
}

func TestSIEMWebhookRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	s := testSIEM(srv.URL)
	s.postWebhook([]byte(`{}`))
	if n.Load() != 3 || s.okCount.Load() != 1 || s.errCount.Load() != 0 {
		t.Fatalf("attempts=%d ok=%d err=%d", n.Load(), s.okCount.Load(), s.errCount.Load())
	}
}

func TestSIEMWebhookRetryBoundedAndNo4xxRetry(t *testing.T) {
	var n atomic.Int32
	var code atomic.Int32
	code.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(int(code.Load()))
	}))
	defer srv.Close()
	s := testSIEM(srv.URL)
	s.postWebhook([]byte(`{}`))
	if n.Load() != 3 || s.errCount.Load() != 1 {
		t.Fatalf("5xx attempts=%d err=%d", n.Load(), s.errCount.Load())
	}
	n.Store(0)
	code.Store(400)
	s.postWebhook([]byte(`{}`))
	if n.Load() != 1 {
		t.Fatalf("4xx retried: %d", n.Load())
	}
}

func TestSIEMWebhookRetryStopsOnShutdown(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := testSIEM(srv.URL)
	s.backoff = time.Hour
	done := make(chan struct{})
	go func() { s.postWebhook([]byte(`{}`)); close(done) }()
	time.Sleep(100 * time.Millisecond)
	s.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not stop on Close")
	}
	if n.Load() != 1 {
		t.Fatalf("attempts after shutdown: %d", n.Load())
	}
}
