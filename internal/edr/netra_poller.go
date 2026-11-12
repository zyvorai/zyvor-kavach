// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetraPoller pulls normalized-ish events from a live Netra controller and
// posts them into Kavach /v1/network-events. Kavach never touches Netra BPF maps.

type NetraPoller struct {
	NetraURL   string
	APIKey     string
	KavachURL  string
	KavachTok  string
	Insecure   bool
	Interval   time.Duration
	client     *http.Client
	kClient    *http.Client
	lastCursor string
}

// PollerStatus is updated by the background poller for Integrations UI.
var (
	pollerMu     sync.Mutex
	pollerLastOK time.Time
	pollerLastEr string
	pollerURL    string
)

func NetraPollerStatus() map[string]any {
	pollerMu.Lock()
	defer pollerMu.Unlock()
	out := map[string]any{
		"configured": pollerURL != "",
		"url":        pollerURL,
		"last_error": pollerLastEr,
	}
	if !pollerLastOK.IsZero() {
		out["last_ok"] = pollerLastOK.Format(time.RFC3339)
	}
	return out
}

func NewNetraPollerFromEnv() *NetraPoller {
	u := firstEnv("KAVACH_NETRA_URL", "KAVACH_NETRA_POLLER_URL")
	if u == "" {
		return nil
	}
	insecure, _ := strconv.ParseBool(firstEnv("KAVACH_NETRA_TLS_INSECURE", "KAVACH_NETRA_POLLER_INSECURE_SKIP_VERIFY"))
	interval := 15 * time.Second
	if v := firstEnv("KAVACH_NETRA_POLL_INTERVAL", "KAVACH_NETRA_POLLER_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}} //nolint:gosec // lab opt-in
	pollerMu.Lock()
	pollerURL = strings.TrimRight(u, "/")
	pollerMu.Unlock()
	return &NetraPoller{
		NetraURL:  strings.TrimRight(u, "/"),
		APIKey:    firstEnv("KAVACH_NETRA_API_KEY", "KAVACH_NETRA_POLLER_API_KEY", "NETRA_API_KEY"),
		KavachURL: strings.TrimRight(firstEnv("KAVACH_URL", "http://127.0.0.1:8099"), "/"),
		KavachTok: firstEnv("KAVACH_TOKEN", "ZYVOR_EDR_TOKEN"),
		Insecure:  insecure,
		Interval:  interval,
		client:    &http.Client{Timeout: 10 * time.Second, Transport: tr},
		kClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func (p *NetraPoller) Run(ctx context.Context) {
	if p == nil {
		return
	}
	log.Printf("netra poller → %s every %s", p.NetraURL, p.Interval)
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	if err := p.tick(ctx); err != nil {
		pollerMu.Lock()
		pollerLastEr = err.Error()
		pollerMu.Unlock()
		log.Printf("netra poller: %v", err)
	} else {
		pollerMu.Lock()
		pollerLastOK = time.Now().UTC()
		pollerLastEr = ""
		pollerMu.Unlock()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.tick(ctx); err != nil {
				pollerMu.Lock()
				pollerLastEr = err.Error()
				pollerMu.Unlock()
				log.Printf("netra poller: %v", err)
			} else {
				pollerMu.Lock()
				pollerLastOK = time.Now().UTC()
				pollerLastEr = ""
				pollerMu.Unlock()
			}
		}
	}
}

func (p *NetraPoller) tick(ctx context.Context) error {
	// Prefer a lightweight findings/drops style endpoint; fall back to health-gated stub.
	paths := []string{"/api/v1/drops", "/v1/drops", "/api/v1/findings"}
	var body []byte
	var lastErr error
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.NetraURL+path, nil)
		if err != nil {
			return err
		}
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
			req.Header.Set("X-API-Key", p.APIKey)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body = b
			break
		}
		lastErr = fmt.Errorf("%s → HTTP %d", path, resp.StatusCode)
	}
	if body == nil {
		// Still verify Netra is up for demo wiring.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.NetraURL+"/healthz", nil)
		resp, err := p.client.Do(req)
		if err != nil {
			return fmt.Errorf("netra unreachable: %w (last %v)", err, lastErr)
		}
		resp.Body.Close()
		return lastErr
	}
	events, err := normalizeNetraPayload(body)
	if err != nil {
		return err
	}
	for _, n := range events {
		if err := p.post(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

func normalizeNetraPayload(body []byte) ([]NetworkEvent, error) {
	// Accept either a JSON array or {items:[...]} / {drops:[...]}.
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var items []map[string]any
	switch v := raw.(type) {
	case []any:
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	case map[string]any:
		for _, key := range []string{"items", "drops", "findings", "data"} {
			if arr, ok := v[key].([]any); ok {
				for _, x := range arr {
					if m, ok := x.(map[string]any); ok {
						items = append(items, m)
					}
				}
				break
			}
		}
	}
	out := []NetworkEvent{}
	now := time.Now().UTC()
	for i, m := range items {
		n := NetworkEvent{Source: "netra", Verdict: "deny", Time: now}
		if h, ok := m["host"].(string); ok {
			n.Host = h
		}
		if h, ok := m["node"].(string); ok && n.Host == "" {
			n.Host = h
		}
		if d, ok := m["destination"].(string); ok {
			n.Destination = d
		}
		if d, ok := m["dst"].(string); ok && n.Destination == "" {
			n.Destination = d
		}
		if pid, ok := asInt(m["pid"]); ok {
			n.PID = pid
		}
		if n.Host == "" {
			n.Host = "netra-unknown"
		}
		if n.PID <= 0 {
			n.PID = 1
		}
		if n.Destination == "" {
			n.Destination = "unknown:0"
		}
		if id, ok := m["id"].(string); ok {
			n.ID = id
		} else {
			n.ID = fmt.Sprintf("netra-poll-%d-%d", now.Unix(), i)
		}
		out = append(out, n)
	}
	return out, nil
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case json.Number:
		i, err := t.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(t)
		return i, err == nil
	default:
		return 0, false
	}
}

func (p *NetraPoller) post(ctx context.Context, n NetworkEvent) error {
	b, _ := json.Marshal(n)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.KavachURL+"/v1/network-events", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.KavachTok)
	resp, err := p.kClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("kavach ingest HTTP %d", resp.StatusCode)
	}
	return nil
}
