package edr

import (
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// Malformed-but-authenticated JSON must never panic a handler (net/http would
// recover and log a stack trace, but a panic is still an unhandled-input bug).
func TestRoutesDoNotPanicOnMalformedBodies(t *testing.T) {
	const token = "route-walk-secret-token"
	h := secTestHandler(t, token)
	bodies := []string{"", "null", "[]", "{}", `"x"`, "123", "true", `{"a":null}`, `[null]`, `{"host":null,"id":null,"events":null,"rules":null,"query":null}`, "{", "\x00\xff"}
	var bad []string
	for r, f := range registeredRoutes(t) {
		parts := strings.SplitN(r, " ", 2)
		if strings.Contains(parts[1], "stream") {
			continue // long-lived SSE; blocks by design
		}
		path := strings.ReplaceAll(parts[1], "{}", "x")
		for _, b := range bodies {
			func() {
				defer func() {
					if p := recover(); p != nil {
						bad = append(bad, fmt.Sprintf("%s body=%q panic=%v (%s)", r, b, p, f))
					}
				}()
				req := httptest.NewRequest(parts[0], path, strings.NewReader(b))
				req.RemoteAddr = nextAddr()
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				h.ServeHTTP(httptest.NewRecorder(), req)
			}()
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d handler panics:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}
