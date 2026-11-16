package edr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHardenHeadersAndNoStore(t *testing.T) {
	h := Harden(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	for _, p := range []string{"/v1/findings", "/metrics", "/"} {
		req := httptest.NewRequest("GET", p, nil)
		req.RemoteAddr = "192.0.2.1:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		hd := rec.Header()
		if hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s missing security headers: %v", p, hd)
		}
		if p != "/" && hd.Get("Cache-Control") != "no-store" {
			t.Errorf("%s Cache-Control=%q, want no-store", p, hd.Get("Cache-Control"))
		}
	}
}

func TestLoginThrottleSurvivesRateLimitOff(t *testing.T) {
	t.Setenv("KAVACH_RATE_LIMIT", "0")
	h := Harden(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unauthorized", 401) }))
	limited := false
	for i := 0; i < 40; i++ {
		req := httptest.NewRequest("POST", "/v1/session", strings.NewReader("{}"))
		req.RemoteAddr = "192.0.2.9:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("login was never throttled with KAVACH_RATE_LIMIT=0")
	}
}

func TestRepeatedBadBearerIsThrottledPerIP(t *testing.T) {
	h := secTestHandler(t, "a-long-enough-admin-token")
	got429 := false
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest("GET", "/v1/findings", nil)
		req.RemoteAddr = "192.0.2.77:5"
		req.Header.Set("Authorization", "Bearer guess")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("token guessing against a Bearer route was never throttled")
	}
	// A different client is unaffected, and a correct token from the throttled IP is still refused only by the throttle window.
	req := httptest.NewRequest("GET", "/v1/findings", nil)
	req.RemoteAddr = "192.0.2.78:5"
	req.Header.Set("Authorization", "Bearer a-long-enough-admin-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("other client got %d", rec.Code)
	}
}

// A library embedder passing an empty token must get a closed API, not an open one
// (empty bearer == empty token, and an empty HMAC key is forgeable).
func TestEmptyTokenFailsClosed(t *testing.T) {
	h := secTestHandler(t, "")
	for _, p := range []string{"/v1/findings", "/v1/sensor", "/v1/fleet", "/v1/summary", "/v1/recent-events"} {
		req := httptest.NewRequest("GET", p, nil)
		req.RemoteAddr = nextAddr()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s with empty token and no credentials -> %d", p, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/v1/session", strings.NewReader(`{"token":""}`))
	req.RemoteAddr = nextAddr()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("empty-token login -> %d", rec.Code)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	h := secTestHandler(t, "a-long-enough-admin-token")
	req := httptest.NewRequest("POST", "/v1/session", strings.NewReader(`{"token":"a-long-enough-admin-token"}`))
	req.RemoteAddr = "192.0.2.5:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login %d", rec.Code)
	}
	c := rec.Result().Cookies()
	if len(c) != 1 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode || c[0].MaxAge != 3600 || c[0].Path != "/" {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	// Secure must be set when served over TLS.
	req = httptest.NewRequest("POST", "https://example.test/v1/session", strings.NewReader(`{"token":"a-long-enough-admin-token"}`))
	req.RemoteAddr = "192.0.2.6:1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Secure != (req.TLS != nil) {
		t.Fatalf("secure flag mismatch %+v", c)
	}
}
