// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedReq struct {
	method, uri, ctype string
	body               []byte
}

// recorder starts a server that records every request and answers {"ok":true}.
func recorder(t *testing.T) (*client, func() []recordedReq) {
	t.Helper()
	var mu sync.Mutex
	var reqs []recordedReq
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, recordedReq{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), b})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)
	c := &client{base: ts.URL, token: "test-token-12345678", http: ts.Client(), actor: "test"}
	return c, func() []recordedReq {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedReq(nil), reqs...)
	}
}

func callTool(t *testing.T, c *client, mut bool, name, args string) string {
	t.Helper()
	srv, err := buildServer(c, mut)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Serve(ctx, in, &out)
	return out.String()
}

func TestInspectToolsReadOnlyModeAndSchemas(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	for _, n := range []string{"inspect_script", "inspect_cmdline", "inspect_domain", "inspect_file_b64", "inspect_reports", "inspect_analyzers",
		"ml_status", "ml_lineage", "ml_similar", "ml_baseline", "ml_beacons", "ml_synthesize", "ml_priority"} {
		if ro[n] == nil {
			t.Fatalf("%s missing in read-only mode", n)
		}
	}
	for _, n := range []string{"ml_reset", "ml_replay", "ml_learn_replay"} {
		if ro[n] != nil {
			t.Fatalf("%s must not be exposed", n)
		}
	}
	for _, n := range []string{"inspect_script", "inspect_cmdline", "inspect_domain", "inspect_file_b64", "inspect_reports", "inspect_analyzers"} {
		desc, _ := ro[n]["description"].(string)
		if n != "inspect_reports" && n != "inspect_analyzers" && (!strings.Contains(desc, "never executed") || !strings.Contains(desc, "without --allow-mutations")) {
			t.Fatalf("%s description lacks safety statements: %s", n, desc)
		}
		props, _ := ro[n]["inputSchema"].(map[string]any)["properties"].(map[string]any)
		for k := range props {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "path") || strings.Contains(lk, "file") && lk != "content_b64" || lk == "uri" || lk == "url" {
				t.Fatalf("%s exposes suspicious parameter %q", n, k)
			}
		}
	}
	if d := ro["ml_synthesize"]["description"].(string); !strings.Contains(d, "analyst reviews it and saves it separately") {
		t.Fatalf("ml_synthesize description: %s", d)
	}
}

func TestInspectTextToolsRequests(t *testing.T) {
	c, got := recorder(t)
	for kind, text := range map[string]string{"script": "echo hi", "cmdline": "curl x | sh", "domain": "evil.example"} {
		o := callTool(t, c, false, "inspect_"+kind, `{"text":"`+text+`","name":"n1"}`)
		if !strings.Contains(o, "ok") {
			t.Fatalf("%s: %s", kind, o)
		}
	}
	callTool(t, c, false, "inspect_reports", `{"limit":"5"}`)
	callTool(t, c, false, "inspect_analyzers", `{}`)
	reqs := got()
	if len(reqs) != 5 {
		t.Fatalf("want 5 requests, got %d: %+v", len(reqs), reqs)
	}
	want := map[string]string{"script": "echo hi", "cmdline": "curl x | sh", "domain": "evil.example"}
	for _, r := range reqs[:3] {
		kind := strings.TrimPrefix(r.uri, "/v1/inspect/")
		var b map[string]string
		if r.method != "POST" || json.Unmarshal(r.body, &b) != nil || b["text"] != want[kind] || b["name"] != "n1" || !strings.HasPrefix(r.ctype, "application/json") {
			t.Fatalf("bad request %+v", r)
		}
	}
	if reqs[3].method != "GET" || reqs[3].uri != "/v1/inspect/reports?limit=5" {
		t.Fatalf("reports: %+v", reqs[3])
	}
	if reqs[4].method != "GET" || reqs[4].uri != "/v1/inspect/analyzers" {
		t.Fatalf("analyzers: %+v", reqs[4])
	}
}

func TestInspectFileB64(t *testing.T) {
	c, got := recorder(t)
	payload := []byte("MZ\x90\x00binary\xff\x00data")
	enc := base64.StdEncoding.EncodeToString(payload)
	if o := callTool(t, c, false, "inspect_file_b64", `{"content_b64":"`+enc+`","name":"a b.exe"}`); !strings.Contains(o, "ok") {
		t.Fatalf("call: %s", o)
	}
	reqs := got()
	if len(reqs) != 1 || reqs[0].method != "POST" || reqs[0].uri != "/v1/inspect/file?name=a+b.exe" ||
		reqs[0].ctype != "application/octet-stream" || !bytes.Equal(reqs[0].body, payload) {
		t.Fatalf("bad file request: %+v", reqs)
	}

	// Exactly at the cap is accepted.
	atCap := base64.StdEncoding.EncodeToString(make([]byte, inspectFileMaxBytes))
	if o := callTool(t, c, false, "inspect_file_b64", `{"content_b64":"`+atCap+`"}`); !strings.Contains(o, "ok") {
		t.Fatalf("at-cap rejected: %.200s", o)
	}
	if n := len(got()); n != 2 {
		t.Fatalf("want 2 requests, got %d", n)
	}
	// One byte over is rejected without contacting the server.
	over := base64.StdEncoding.EncodeToString(make([]byte, inspectFileMaxBytes+1))
	if o := callTool(t, c, false, "inspect_file_b64", `{"content_b64":"`+over+`"}`); !strings.Contains(o, "too large") && !strings.Contains(o, "must be 1..") {
		t.Fatalf("over-cap not rejected: %.200s", o)
	}
	// Far over the cap.
	huge := strings.Repeat("A", 8<<20)
	if o := callTool(t, c, false, "inspect_file_b64", `{"content_b64":"`+huge+`"}`); !strings.Contains(o, "too large") {
		t.Fatalf("huge not rejected: %.200s", o)
	}
	// Invalid base64 and missing content.
	if o := callTool(t, c, false, "inspect_file_b64", `{"content_b64":"not base64!!"}`); !strings.Contains(o, "not valid standard base64") {
		t.Fatalf("invalid b64: %s", o)
	}
	if o := callTool(t, c, false, "inspect_file_b64", `{}`); !strings.Contains(o, "required") {
		t.Fatalf("missing: %s", o)
	}
	// A path-like argument is ignored: it is never read from disk.
	if o := callTool(t, c, false, "inspect_file_b64", `{"path":"/etc/passwd"}`); !strings.Contains(o, "required") {
		t.Fatalf("path arg: %s", o)
	}
	if n := len(got()); n != 2 {
		t.Fatalf("rejected calls must not reach the server, got %d requests", n)
	}
}

func TestMLToolsRequests(t *testing.T) {
	c, got := recorder(t)
	calls := []struct{ name, args string }{
		{"ml_status", `{}`},
		{"ml_lineage", `{"host":"h1","limit":"5"}`},
		{"ml_similar", `{"q":"curl x","host":"h1"}`},
		{"ml_baseline", `{"host":"h1"}`},
		{"ml_beacons", `{"min_events":"8","exclude_private":"1"}`},
		{"ml_synthesize", `{"command":"curl x | sh"}`},
		{"ml_priority", `{"finding_id":"f1"}`},
	}
	for _, cl := range calls {
		if o := callTool(t, c, false, cl.name, cl.args); !strings.Contains(o, "ok") {
			t.Fatalf("%s: %s", cl.name, o)
		}
	}
	reqs := got()
	wantReq := []struct{ method, uri string }{
		{"GET", "/v1/ml/status"},
		{"GET", "/v1/ml/lineage?host=h1&limit=5"},
		{"GET", "/v1/ml/similar?host=h1&q=curl+x"},
		{"GET", "/v1/ml/baseline?host=h1"},
		{"GET", "/v1/ml/beacons?exclude_private=1&min_events=8"},
		{"POST", "/v1/ml/synthesize"},
		{"GET", "/v1/ml/priority?finding_id=f1"},
	}
	if len(reqs) != len(wantReq) {
		t.Fatalf("got %d requests", len(reqs))
	}
	for i, w := range wantReq {
		if reqs[i].method != w.method || reqs[i].uri != w.uri {
			t.Fatalf("req %d: got %s %s want %s %s", i, reqs[i].method, reqs[i].uri, w.method, w.uri)
		}
	}
	if string(reqs[5].body) != `{"command":"curl x | sh"}` {
		t.Fatalf("synth body: %s", reqs[5].body)
	}
}
