// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a per-key token bucket.
type rateLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[string]*bucket
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, m: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil {
		if len(l.m) > 10000 { // bound memory
			l.m = map[string]*bucket{}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Harden adds security headers and rate limits login and write requests.
// KAVACH_RATE_LIMIT=0 disables limiting; otherwise it is the write requests/sec per client IP (default 100).
func Harden(next http.Handler) http.Handler {
	writeRate := 100.0
	if v := os.Getenv("KAVACH_RATE_LIMIT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			writeRate = f
		}
	}
	writes := newRateLimiter(writeRate, writeRate*2)
	logins := newRateLimiter(0.5, 10)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if writeRate > 0 {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			now := time.Now()
			limited := false
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
				limited = !logins.allow(ip, now)
			case r.Method == http.MethodPost || r.Method == http.MethodDelete:
				limited = !writes.allow(ip, now)
			}
			if limited {
				h.Set("Retry-After", "2")
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
