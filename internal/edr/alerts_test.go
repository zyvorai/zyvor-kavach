// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func alertSetup(t *testing.T) (*httptest.Server, *Store, *Dispatcher, string) {
	t.Helper()
	s, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	tok := "0123456789abcdef"
	mux := http.NewServeMux()
	d := NewDispatcher(s)
	d.Interval, d.Backoff = 20*time.Millisecond, 10*time.Millisecond
	d.secret = func() string { return "s3cret" }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.Start(ctx)
	registerAlertRoutes(mux, tok, d)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s, d, tok
}

func send(t *testing.T, method, url, tok, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, string(b)
}

func waitDeliveries(d *Dispatcher) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(d.Deliveries()) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond) // surface any (incorrect) duplicates
}

func TestAlertRuleValidationAndAuth(t *testing.T) {
	srv, _, _, tok := alertSetup(t)
	u := srv.URL + "/v1/alerts/rules"
	if r, _ := send(t, "GET", u, "", ""); r.StatusCode != 401 {
		t.Fatalf("want 401 got %d", r.StatusCode)
	}
	if r, _ := send(t, "POST", u, "", `{}`); r.StatusCode != 401 {
		t.Fatalf("want 401 got %d", r.StatusCode)
	}
	for _, bad := range []string{
		`{"url":"http://example.com/x"}`,
		`{"url":"https://127.0.0.1/x"}`,
		`{"url":"https://169.254.169.254/x"}`,
		`{"url":"https://10.0.0.5/x"}`,
		`{"url":"https://localhost/x"}`,
		`{"url":"ftp://example.com/x"}`,
		`{"url":"https://example.com/x","min_severity":"bogus"}`,
		`{"url":"https://example.com/x","type":"email"}`,
	} {
		if r, _ := send(t, "POST", u, tok, bad); r.StatusCode != 400 {
			t.Fatalf("%s: want 400 got %d", bad, r.StatusCode)
		}
	}
	r, body := send(t, "POST", u, tok, `{"url":"https://example.com/x","type":"slack"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create: %d %s", r.StatusCode, body)
	}
	var rule AlertRule
	_ = json.Unmarshal([]byte(body), &rule)
	if rule.MinSeverity != "high" {
		t.Fatalf("default severity: %+v", rule)
	}
	if _, b := send(t, "GET", u, tok, ""); !strings.Contains(b, rule.ID) {
		t.Fatalf("list: %s", b)
	}
	if r, _ := send(t, "DELETE", u+"?id="+rule.ID, tok, ""); r.StatusCode != 204 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if r, _ := send(t, "DELETE", u+"?id="+rule.ID, tok, ""); r.StatusCode != 404 {
		t.Fatalf("delete again: %d", r.StatusCode)
	}
}

func TestAlertDeliverySignedRetriedDeduped(t *testing.T) {
	srv, store, d, tok := alertSetup(t)
	var mu sync.Mutex
	var bodies []string
	var sigOK bool
	var calls int32
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "boom", 500) // force a retry
			return
		}
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write(b)
		mu.Lock()
		sigOK = r.Header.Get("X-Kavach-Signature") == "sha256="+hex.EncodeToString(m.Sum(nil))
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer rcv.Close()

	rb, _ := json.Marshal(map[string]string{"url": rcv.URL, "min_severity": "high", "host_contains": "web"})
	if r, b := send(t, "POST", srv.URL+"/v1/alerts/rules", tok, string(rb)); r.StatusCode != 201 {
		t.Fatalf("create: %d %s", r.StatusCode, b)
	}
	now := time.Now()
	_ = store.Append(Finding{ID: "f1", Time: now, Host: "web-1", Rule: "r", Severity: "critical", Description: "d"})
	_ = store.Append(Finding{ID: "f2", Time: now, Host: "db-1", Rule: "r", Severity: "critical"}) // host filter
	_ = store.Append(Finding{ID: "f3", Time: now, Host: "web-2", Rule: "r", Severity: "low"})     // severity
	waitDeliveries(d)
	dl := d.Deliveries()
	if len(dl) != 1 || dl[0].Status != "delivered" || dl[0].Attempts != 2 || dl[0].FindingID != "f1" {
		t.Fatalf("deliveries: %+v", dl)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sigOK || len(bodies) != 1 {
		t.Fatalf("sig=%v bodies=%v", sigOK, bodies)
	}
	if strings.Contains(bodies[0], tok) {
		t.Fatal("token leaked in payload")
	}
	if _, b := send(t, "GET", srv.URL+"/v1/alerts/deliveries", tok, ""); !strings.Contains(b, `"f1"`) {
		t.Fatalf("deliveries api: %s", b)
	}
}

func TestSlackPayloadAndFailure(t *testing.T) {
	f := Finding{ID: "x", Host: "h", Rule: "rr", Severity: "high", Description: "dd"}
	var m map[string]string
	if err := json.Unmarshal(alertPayload(AlertRule{Type: "slack"}, f), &m); err != nil || !strings.Contains(m["text"], "rr") {
		t.Fatalf("slack: %v %v", m, err)
	}
	srv, store, d, tok := alertSetup(t)
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer rcv.Close()
	rb, _ := json.Marshal(map[string]string{"url": rcv.URL, "type": "slack"})
	send(t, "POST", srv.URL+"/v1/alerts/rules", tok, string(rb))
	_ = store.Append(Finding{ID: "g1", Time: time.Now(), Host: "h", Rule: "r", Severity: "high"})
	waitDeliveries(d)
	dl := d.Deliveries()
	if len(dl) != 1 || dl[0].Status != "failed" || dl[0].Attempts != deliveryTries {
		t.Fatalf("deliveries: %+v", dl)
	}
}
