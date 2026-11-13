package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func TestCertFeedToolsReadOnlyAndLive(t *testing.T) {
	store, err := edr.NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(edr.APIWithCredentials("test-token-12345678", store, nil))
	defer ts.Close()
	c := &client{base: ts.URL, token: "test-token-12345678", http: ts.Client(), actor: "test"}
	ro := listToolsJSON(t, c, false)
	for _, tl := range certFeedTools() {
		if tl.method != "GET" || ro[tl.name] == nil {
			t.Fatalf("tool %s missing or not GET in read-only mode", tl.name)
		}
	}
	// Feeds are disabled by default: empty list, no network.
	out, status, err := c.do(context.Background(), "GET", "/v1/advisories?matched=true", nil, nil)
	if err != nil || status != 200 || !strings.Contains(string(out), `"advisories":[]`) {
		t.Fatalf("advisories: %v %d %s", err, status, out)
	}
	out, status, err = c.do(context.Background(), "GET", "/v1/advisories/feeds/status", nil, nil)
	if err != nil || status != 200 || !strings.Contains(string(out), `"enabled":[]`) {
		t.Fatalf("status: %v %d %s", err, status, out)
	}
}
