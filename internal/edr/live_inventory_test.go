// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveInventoryDeriveAndIngest(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Ingest(Event{
		Time: time.Now().UTC(), Host: "lab", PID: 7, Executable: "/usr/bin/curl",
		Command: "curl https://slack.com/api",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.IngestNetwork(NetworkEvent{
		Time: time.Now().UTC(), Host: "lab", PID: 7, Destination: "slack.com:443", Verdict: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	casb := deriveCASB(store)
	if len(casb) == 0 {
		t.Fatal("expected derived CASB from slack destination")
	}
	geo := deriveGeo("127.0.0.1")
	if geo["country"] != "LO" {
		t.Fatalf("loopback geo: %+v", geo)
	}
	zt := deriveZeroTrust(store, nil)
	if zt["source"] != "derived" {
		t.Fatalf("zt: %+v", zt)
	}

	srv := httptest.NewServer(API("0123456789abcdef", store))
	defer srv.Close()
	body, _ := json.Marshal(map[string]any{
		"domain": "persistence", "host": "lab", "replace": true,
		"items": []map[string]any{{"type": "systemd", "name": "demo.service", "risk": "low"}},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/inventory", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("inventory status %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/v1/persistence", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []map[string]any
	if json.NewDecoder(resp.Body).Decode(&rows) != nil || len(rows) == 0 {
		t.Fatalf("persistence empty after ingest")
	}
}
