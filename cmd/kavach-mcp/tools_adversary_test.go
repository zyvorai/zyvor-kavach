// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func TestAdversaryToolsReadOnlyAndLive(t *testing.T) {
	store, err := edr.NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(edr.APIWithCredentials("test-token-12345678", store, nil))
	defer ts.Close()
	c := &client{base: ts.URL, token: "test-token-12345678", http: ts.Client(), actor: "test"}
	ro := listToolsJSON(t, c, false)
	if len(adversaryReadTools()) != 3 {
		t.Fatal("expected 3 adversary tools")
	}
	for _, tl := range adversaryReadTools() {
		if tl.method != "GET" || ro[tl.name] == nil {
			t.Fatalf("adversary tool %s missing or not GET in read-only mode", tl.name)
		}
	}
	out, status, err := c.do(context.Background(), "GET", "/v1/adversaries/apt28", nil, nil)
	if err != nil || status != 200 {
		t.Fatalf("profile: %v %d", err, status)
	}
	var r struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	if json.Unmarshal(out, &r) != nil || r.Profile.ID != "apt28" {
		t.Fatalf("unexpected %s", out)
	}
}
