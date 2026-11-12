// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics is a tiny dependency-free Prometheus text exposition registry.
type Metrics struct {
	mu       sync.Mutex
	requests map[string]uint64 // "METHOD|route|class"
	buckets  []float64
	hist     []uint64
	histSum  float64
	histN    uint64
	started  time.Time
	inflight atomic.Int64
}

func NewMetrics() *Metrics {
	b := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	return &Metrics{requests: map[string]uint64{}, buckets: b, hist: make([]uint64, len(b)), started: time.Now()}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

// Flush keeps SSE working through the middleware.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// routeLabel bounds label cardinality: only the first two path segments.
func routeLabel(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return "/" + strings.Join(parts, "/")
}

// Middleware records request counts and latency.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.inflight.Add(1)
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		m.inflight.Add(-1)
		d := time.Since(start).Seconds()
		key := fmt.Sprintf("%s|%s|%dxx", r.Method, routeLabel(r.URL.Path), rec.code/100)
		m.mu.Lock()
		m.requests[key]++
		m.histN++
		m.histSum += d
		for i, b := range m.buckets {
			if d <= b {
				m.hist[i]++
			}
		}
		m.mu.Unlock()
	})
}

// Write renders Prometheus text format, including store/fleet gauges.
func (m *Metrics) Write(w http.ResponseWriter, store *Store, registry *CredentialRegistry) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	b.WriteString("# HELP kavach_uptime_seconds Seconds since server start.\n# TYPE kavach_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "kavach_uptime_seconds %.0f\n", time.Since(m.started).Seconds())
	b.WriteString("# HELP kavach_http_inflight In-flight HTTP requests.\n# TYPE kavach_http_inflight gauge\n")
	fmt.Fprintf(&b, "kavach_http_inflight %d\n", m.inflight.Load())

	sev := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	total := 0
	if store != nil {
		for _, f := range store.List() {
			sev[strings.ToLower(f.Severity)]++
			total++
		}
	}
	b.WriteString("# HELP kavach_findings Findings held by the store, by severity.\n# TYPE kavach_findings gauge\n")
	keys := make([]string, 0, len(sev))
	for k := range sev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "kavach_findings{severity=%q} %d\n", k, sev[k])
	}
	fmt.Fprintf(&b, "# HELP kavach_findings_total Total findings.\n# TYPE kavach_findings_total gauge\nkavach_findings_total %d\n", total)

	b.WriteString(riskGauges(store, time.Now()))

	online, all := 0, 0
	if registry != nil {
		for _, st := range registry.Status(time.Now(), 90*time.Second) {
			all++
			if st.State == "online" {
				online++
			}
		}
	}
	fmt.Fprintf(&b, "# HELP kavach_agents Enrolled agents.\n# TYPE kavach_agents gauge\nkavach_agents{state=\"online\"} %d\nkavach_agents{state=\"offline\"} %d\n", online, all-online)

	m.mu.Lock()
	rk := make([]string, 0, len(m.requests))
	for k := range m.requests {
		rk = append(rk, k)
	}
	sort.Strings(rk)
	b.WriteString("# HELP kavach_http_requests_total HTTP requests.\n# TYPE kavach_http_requests_total counter\n")
	for _, k := range rk {
		p := strings.SplitN(k, "|", 3)
		fmt.Fprintf(&b, "kavach_http_requests_total{method=%q,route=%q,class=%q} %d\n", p[0], p[1], p[2], m.requests[k])
	}
	b.WriteString("# HELP kavach_http_request_duration_seconds Request latency.\n# TYPE kavach_http_request_duration_seconds histogram\n")
	for i, le := range m.buckets {
		fmt.Fprintf(&b, "kavach_http_request_duration_seconds_bucket{le=\"%g\"} %d\n", le, m.hist[i])
	}
	fmt.Fprintf(&b, "kavach_http_request_duration_seconds_bucket{le=\"+Inf\"} %d\nkavach_http_request_duration_seconds_sum %f\nkavach_http_request_duration_seconds_count %d\n", m.histN, m.histSum, m.histN)
	m.mu.Unlock()
	_, _ = w.Write([]byte(b.String()))
}
