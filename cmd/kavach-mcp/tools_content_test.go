package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func TestContentToolsReadOnlyAndLive(t *testing.T) {
	store, err := edr.NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(edr.APIWithCredentials("test-token-12345678", store, nil))
	defer ts.Close()
	c := &client{base: ts.URL, token: "test-token-12345678", http: ts.Client(), actor: "test"}
	ro := listToolsJSON(t, c, false)
	for _, tl := range contentReadTools() {
		if tl.method != "GET" || ro[tl.name] == nil {
			t.Fatalf("content tool %s missing or not GET in read-only mode", tl.name)
		}
	}
	out, status, err := c.do(context.Background(), "GET", "/v1/content/coverage", nil, nil)
	if err != nil || status != 200 {
		t.Fatalf("coverage: %v %d", err, status)
	}
	var cov map[string]any
	if json.Unmarshal(out, &cov) != nil || cov["mode"] != "observe-only" {
		t.Fatalf("unexpected coverage %s", out)
	}
	out, status, _ = c.do(context.Background(), "GET", "/v1/content/rules?severity=high&event_type=process", nil, nil)
	var rules struct {
		Count int `json:"count"`
		Rules []struct {
			Severity  string `json:"severity"`
			EventType string `json:"event_type"`
		} `json:"rules"`
	}
	if status != 200 || json.Unmarshal(out, &rules) != nil || rules.Count == 0 {
		t.Fatalf("rules filter: status %d count %d", status, rules.Count)
	}
	for _, r := range rules.Rules {
		if r.Severity != "high" || r.EventType != "process" {
			t.Fatalf("filter leaked %+v", r)
		}
	}
}
