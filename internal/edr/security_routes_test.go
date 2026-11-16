package edr

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// publicRoutes are intentionally reachable without credentials.
var publicRoutes = map[string]string{
	"GET /healthz":            "liveness probe, static body",
	"GET /":                   "static dashboard shell; no data, data calls need auth",
	"GET /zyvor-mark.svg":     "embedded static brand asset",
	"GET /zyvor-logomark.svg": "embedded static brand asset",
	"POST /v1/session":        "login: exchanges the token for a cookie (rate limited)",
	"POST /v1/logout":         "clears the cookie, no state",
	"GET /livez":              "liveness probe, static body",
	"GET /readyz":             "readiness probe, status only",
	"GET /c/{}":               "deception canary beacon: must be reachable by an intruder; rate limited, never reflects input",
	"POST /c/{}":              "deception canary beacon (see GET)",
}

// ingestRoutes authenticate per-host agent credentials (or the admin token)
// AFTER decoding the body, so a body-less probe sees 400. They are covered by
// TestIngestRoutesRejectUnauthenticated with a well-formed payload instead.
var ingestRoutes = map[string]string{
	"POST /v1/events":           "agent process events; host credential or admin",
	"POST /v1/file-events":      "agent file metadata; host credential or admin",
	"POST /v1/events/registry":  "agent telemetry; host credential or admin",
	"POST /v1/events/dns":       "agent telemetry; host credential or admin",
	"POST /v1/events/auth":      "agent telemetry; host credential or admin",
	"POST /v1/events/module":    "agent telemetry; host credential or admin",
	"POST /v1/agents/heartbeat": "agent liveness; host credential only",
}

var swapAddr uint32 // test-only, single goroutine

// nextAddr gives each probe its own client IP so the rate limiter does not mask auth results.
func nextAddr() string {
	swapAddr++
	return "10." + strconv.Itoa(int(swapAddr>>16&255)) + "." + strconv.Itoa(int(swapAddr>>8&255)) + "." + strconv.Itoa(int(swapAddr&255)) + ":1"
}

func secTestHandler(t *testing.T, token string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "state.json"), 100)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := OpenCredentialRegistry(filepath.Join(dir, "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	return APIWithCredentials(token, store, reg)
}

func TestEveryRouteRequiresAuth(t *testing.T) {
	const token = "route-walk-secret-token"
	h := secTestHandler(t, token)
	routes := registeredRoutes(t)
	var bad []string
	for r := range routes {
		if _, ok := publicRoutes[r]; ok {
			continue
		}
		if _, ok := ingestRoutes[r]; ok {
			continue
		}
		parts := strings.SplitN(r, " ", 2)
		path := strings.ReplaceAll(parts[1], "{}", "x")
		codes := [2]int{}
		for i, auth := range []string{"", "Bearer wrong"} {
			req := httptest.NewRequest(parts[0], path, strings.NewReader("{}"))
			req.RemoteAddr = nextAddr()
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}
		ok := func(c int) bool { return c == 401 || c == 403 }
		if !ok(codes[0]) || !ok(codes[1]) {
			bad = append(bad, r+" -> "+strconv.Itoa(codes[0])+"/"+strconv.Itoa(codes[1])+" ("+routes[r]+")")
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d routes reachable without credentials (gate them or add to publicRoutes with a reason):\n%s", len(bad), strings.Join(bad, "\n"))
	}
	for r, why := range publicRoutes {
		if why == "" {
			t.Errorf("publicRoutes %q needs a reason", r)
		}
		if _, ok := routes[r]; !ok {
			t.Errorf("publicRoutes %q is stale", r)
		}
	}
}

func TestIngestRoutesRejectUnauthenticated(t *testing.T) {
	const token = "route-walk-secret-token"
	h := secTestHandler(t, token)
	now := time.Now().UTC().Format(time.RFC3339)
	bodies := map[string]string{
		"POST /v1/events":           `{"host":"h1","pid":5,"time":"` + now + `","command":"ls"}`,
		"POST /v1/file-events":      `{"host":"h1","time":"` + now + `","path":"/tmp/a","operation":"write"}`,
		"POST /v1/events/registry":  `{"host":"h1","time":"` + now + `","key":"HKLM\\x","operation":"set"}`,
		"POST /v1/events/dns":       `{"host":"h1","time":"` + now + `","query":"a.example"}`,
		"POST /v1/events/auth":      `{"host":"h1","time":"` + now + `","method":"ssh","outcome":"failure","user":"u"}`,
		"POST /v1/events/module":    `{"host":"h1","time":"` + now + `","module_path":"/lib/x.so","kind":"so"}`,
		"POST /v1/agents/heartbeat": `{"host":"h1","sensor":"s","queued":0}`,
	}
	for r := range ingestRoutes {
		body, ok := bodies[r]
		if !ok {
			t.Fatalf("no probe body for %s", r)
		}
		parts := strings.SplitN(r, " ", 2)
		for _, auth := range []string{"", "Bearer wrong", "Bearer zedr_" + strings.Repeat("a", 64)} {
			req := httptest.NewRequest(parts[0], parts[1], strings.NewReader(body))
			req.RemoteAddr = nextAddr()
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Errorf("%s with auth %q -> %d, want 401", r, auth, rec.Code)
			}
		}
	}
}

// A per-host credential and a forged/expired session cookie must never open
// admin routes: only the shared admin token (or a valid session minted from it) may.
func TestAgentCredentialAndForgedSessionsRejectedEverywhere(t *testing.T) {
	const token = "route-walk-secret-token"
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "state.json"), 100)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := OpenCredentialRegistry(filepath.Join(dir, "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	agentTok, err := reg.Issue("h1")
	if err != nil {
		t.Fatal(err)
	}
	h := APIWithCredentials(token, store, reg)
	old := strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)
	cur := strconv.FormatInt(time.Now().Unix(), 10)
	cookies := []*http.Cookie{
		{Name: "zyvor_session", Value: cur + ".AAAA"},
		{Name: "zyvor_session", Value: old + "." + sessionSignature(token, old)},
		{Name: "zyvor_session", Value: cur + "." + sessionSignature("other-secret", cur)},
		{Name: "zyvor_session", Value: "garbage"},
	}
	var bad []string
	for r, f := range registeredRoutes(t) {
		if _, ok := publicRoutes[r]; ok {
			continue
		}
		if _, ok := ingestRoutes[r]; ok {
			continue
		}
		parts := strings.SplitN(r, " ", 2)
		path := strings.ReplaceAll(parts[1], "{}", "x")
		try := func(label string, mod func(*http.Request)) {
			req := httptest.NewRequest(parts[0], path, strings.NewReader("{}"))
			req.RemoteAddr = nextAddr()
			mod(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 401 && rec.Code != 403 {
				bad = append(bad, r+" ["+label+"] -> "+strconv.Itoa(rec.Code)+" ("+f+")")
			}
		}
		try("agent-token", func(q *http.Request) { q.Header.Set("Authorization", "Bearer "+agentTok) })
		for i, c := range cookies {
			c := c
			try("forged-cookie-"+strconv.Itoa(i), func(q *http.Request) { q.AddCookie(c) })
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d route/credential combos not rejected:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}
