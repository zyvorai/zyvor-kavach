package edr

import (
	"io"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// zeroJSONBody streams `{"a":"xxxx...` without ever allocating the payload and counts bytes consumed.
type zeroJSONBody struct {
	n, limit int64
}

const zeroJSONPrefix = `{"a":"`

func (c *zeroJSONBody) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, io.EOF
	}
	for i := range p {
		if c.n < int64(len(zeroJSONPrefix)) {
			p[i] = zeroJSONPrefix[c.n]
		} else {
			p[i] = 'x'
		}
		c.n++
		if c.n >= c.limit {
			return i + 1, nil
		}
	}
	return len(p), nil
}

// Every write route must cap how much of an authenticated body it will read.
func TestWriteRoutesCapRequestBody(t *testing.T) {
	const token = "route-walk-secret-token"
	const limit = int64(96 << 20)
	const maxAllowed = int64(40 << 20) // largest legitimate cap is inspect/evidence at ~32 MiB
	h := secTestHandler(t, token)
	var bad []string
	for r, f := range registeredRoutes(t) {
		parts := strings.SplitN(r, " ", 2)
		if parts[0] == "GET" || parts[0] == "HEAD" {
			continue
		}
		if _, ok := publicRoutes[r]; ok {
			continue
		}
		path := strings.ReplaceAll(parts[1], "{}", "x")
		body := &zeroJSONBody{limit: limit}
		req := httptest.NewRequest(parts[0], path, body)
		req.RemoteAddr = nextAddr()
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if body.n > maxAllowed {
			bad = append(bad, r+" read "+strconv.FormatInt(body.n>>20, 10)+" MiB ("+f+")")
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d routes read an unbounded request body:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}
