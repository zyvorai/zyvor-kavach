package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func TestKavachMCPToolsListAndCall(t *testing.T) {
	dir := t.TempDir()
	store, err := edr.NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	_ = store.Append(edr.Finding{
		ID: "f1", Time: time.Now().UTC(), Host: "h1", Rule: "download-execute",
		Severity: "high", Description: "test", Evidence: edr.Event{Host: "h1", Executable: "/bin/curl", PID: 1},
	})
	api := edr.APIWithCredentials(token, store, nil)
	ts := httptest.NewServer(api)
	defer ts.Close()

	c := &client{base: ts.URL, token: token, http: ts.Client(), actor: "test"}
	srv, err := buildServer(c, true)
	if err != nil {
		t.Fatal(err)
	}

	// tools/list
	var buf bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Serve(ctx, in, &buf); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "kavach_findings") || !strings.Contains(out, "kavach_ai_capabilities") {
		t.Fatalf("missing tools in list: %s", out)
	}
	if !strings.Contains(out, "kavach_ai_chat") {
		t.Fatalf("mutations should be registered: %s", out)
	}
	for _, tool := range []string{
		"kavach_sectors_public_vehicles", "kavach_sectors_city_buses", "kavach_sectors_taxis_cabs",
		"kavach_sectors_ferries", "kavach_sectors_gov_vehicles", "kavach_sectors_isro_centers",
		"kavach_finance_insurance", "kavach_finance_insurance_lines", "kavach_finance_irdai",
		"kavach_finance_motor_insurance", "kavach_finance_insurance_tpa", "kavach_finance_reinsurance",
	} {
		if !strings.Contains(out, tool) {
			t.Fatalf("missing tool %s in list: %s", tool, out)
		}
	}

	// tools/call findings
	var callOut bytes.Buffer
	callIn := bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kavach_findings","arguments":{}}}` + "\n")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_ = srv.Serve(ctx2, callIn, &callOut)
	if !strings.Contains(callOut.String(), "download-execute") {
		t.Fatalf("findings call: %s", callOut.String())
	}

	// read-only server should omit mutate tools
	srvRO, err := buildServer(c, false)
	if err != nil {
		t.Fatal(err)
	}
	var roBuf bytes.Buffer
	roIn := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	_ = srvRO.Serve(ctx3, roIn, &roBuf)
	if strings.Contains(roBuf.String(), `"name":"kavach_ai_chat"`) {
		t.Fatalf("mutate tool leaked into read-only: %s", roBuf.String())
	}
}

func listToolsJSON(t *testing.T, c *client, mut bool) map[string]map[string]any {
	t.Helper()
	srv, err := buildServer(c, mut)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Serve(ctx, in, &buf)
	var resp struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("bad tools/list: %v: %s", err, buf.String())
	}
	m := map[string]map[string]any{}
	for _, tl := range resp.Result.Tools {
		name, _ := tl["name"].(string)
		if _, dup := m[name]; dup {
			t.Fatalf("duplicate tool %s", name)
		}
		m[name] = tl
	}
	return m
}

func TestAnalystToolsClassificationAndSchemas(t *testing.T) {
	dir := t.TempDir()
	store, err := edr.NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	token := "test-token-12345678"
	for i := 0; i < 3; i++ {
		_ = store.Append(edr.Finding{ID: fmt.Sprintf("f%d", i), Time: time.Now().UTC(), Host: "h1", Rule: "r", Severity: "high"})
	}
	ts := httptest.NewServer(edr.APIWithCredentials(token, store, nil))
	defer ts.Close()
	c := &client{base: ts.URL, token: token, http: ts.Client(), actor: "test"}

	reads := []string{"kavach_risk_hosts", "kavach_risk_summary", "kavach_trends", "kavach_export_findings", "kavach_notes",
		"kavach_saved_searches", "kavach_alert_rules", "kavach_alert_deliveries", "kavach_journal", "kavach_journal_verify"}
	mutates := []string{"kavach_note_add", "kavach_saved_search_add"}
	forbidden := []string{"kavach_alert_rule_create", "kavach_alert_rule_delete", "kavach_alert_rules_create", "kavach_webhook_create"}

	ro := listToolsJSON(t, c, false)
	rw := listToolsJSON(t, c, true)
	for _, n := range reads {
		if ro[n] == nil || rw[n] == nil {
			t.Fatalf("read tool %s missing", n)
		}
	}
	for _, n := range mutates {
		if ro[n] != nil {
			t.Fatalf("mutating tool %s leaked into read-only mode", n)
		}
		if rw[n] == nil {
			t.Fatalf("mutating tool %s missing with mutations on", n)
		}
	}
	for _, n := range forbidden {
		if rw[n] != nil {
			t.Fatalf("tool %s must not exist", n)
		}
	}
	if len(rw) <= len(ro) {
		t.Fatalf("tool count: rw=%d ro=%d", len(rw), len(ro))
	}
	for _, set := range []map[string]map[string]any{ro, rw} {
		for name, tl := range set {
			if d, _ := tl["description"].(string); d == "" {
				t.Errorf("%s: empty description", name)
			}
			s, _ := tl["inputSchema"].(map[string]any)
			if s["type"] != "object" {
				t.Errorf("%s: schema type != object", name)
			}
			props, _ := s["properties"].(map[string]any)
			if props == nil {
				t.Errorf("%s: schema missing properties", name)
			}
			if req, ok := s["required"].([]any); ok {
				for _, r := range req {
					if _, ok := props[r.(string)]; !ok {
						t.Errorf("%s: required %v not in properties", name, r)
					}
				}
			}
		}
	}
	props := ro["kavach_export_findings"]["inputSchema"].(map[string]any)["properties"].(map[string]any)
	if fmt.Sprint(props["format"].(map[string]any)["enum"]) != "[json ndjson]" {
		t.Fatalf("export format enum: %v", props["format"])
	}

	call := func(name, args string) string {
		srv, _ := buildServer(c, false)
		var out bytes.Buffer
		in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}` + "\n")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Serve(ctx, in, &out)
		return out.String()
	}
	if o := call("kavach_export_findings", `{"limit":2,"format":"ndjson"}`); !strings.Contains(o, `\"returned\": 2`) || !strings.Contains(o, `\"truncated\": true`) {
		t.Fatalf("export cap not applied: %s", o)
	}
	if o := call("kavach_export_findings", `{"format":"csv"}`); !strings.Contains(o, "format must be") {
		t.Fatalf("csv should be rejected: %s", o)
	}
	if o := call("kavach_risk_summary", `{}`); !strings.Contains(o, "fleet_risk_index") {
		t.Fatalf("risk summary: %s", o)
	}
}

func TestOpsToolsClassificationAndSchemas(t *testing.T) {
	dir := t.TempDir()
	store, err := edr.NewStore(filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(edr.APIWithCredentials("test-token-12345678", store, nil))
	defer ts.Close()
	c := &client{base: ts.URL, token: "test-token-12345678", http: ts.Client(), actor: "test"}
	ro := listToolsJSON(t, c, false)
	rw := listToolsJSON(t, c, true)

	reads := []string{"kavach_intel_feeds", "kavach_intel_feed_status", "kavach_lab_rules", "kavach_soc_metrics",
		"kavach_host_storyline", "kavach_shift_report", "kavach_posture_summary", "kavach_vuln_priority",
		"kavach_posture_assets", "kavach_posture_drift", "kavach_compliance_controls", "kavach_compliance_evidence", "kavach_cert_in_clock"}
	mutates := []string{"kavach_lab_validate", "kavach_lab_test", "kavach_lab_backtest", "kavach_posture_asset_set"}
	for _, n := range reads {
		if ro[n] == nil || rw[n] == nil {
			t.Fatalf("read tool %s missing", n)
		}
	}
	for _, n := range mutates {
		if ro[n] != nil {
			t.Fatalf("%s leaked into read-only mode", n)
		}
		if rw[n] == nil {
			t.Fatalf("%s missing with mutations on", n)
		}
	}
	// Create/delete/refresh/baseline for feeds, lab rules and assets must not exist.
	for _, set := range []map[string]map[string]any{ro, rw} {
		for name := range set {
			if !strings.HasPrefix(name, "kavach_intel_feed") && !strings.HasPrefix(name, "kavach_lab_") && !strings.HasPrefix(name, "kavach_posture_") {
				continue
			}
			for _, bad := range []string{"create", "delete", "add", "remove", "refresh", "baseline"} {
				if strings.Contains(name, bad) {
					t.Fatalf("forbidden tool %s", name)
				}
			}
		}
	}
	if len(ro) < 40 || len(rw) < len(ro)+len(mutates) {
		t.Fatalf("tool counts: ro=%d rw=%d", len(ro), len(rw))
	}
	enum := func(tool, prop string) string {
		p := ro[tool]["inputSchema"].(map[string]any)["properties"].(map[string]any)[prop].(map[string]any)
		return fmt.Sprint(p["enum"])
	}
	if got := enum("kavach_compliance_controls", "framework"); got != "[cis-v8 nist-csf-2 soc2 iso27001 rbi cert-in dpdp]" {
		t.Fatalf("framework enum: %s", got)
	}
	if got := enum("kavach_compliance_evidence", "format"); got != "[json]" {
		t.Fatalf("evidence format enum must be json only: %s", got)
	}
	for _, n := range []string{"kavach_host_storyline", "kavach_posture_drift"} {
		req, _ := ro[n]["inputSchema"].(map[string]any)["required"].([]any)
		if len(req) != 1 || req[0] != "host" {
			t.Fatalf("%s must require host: %v", n, req)
		}
	}
	srv, _ := buildServer(c, false)
	var out bytes.Buffer
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}` + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Serve(ctx, in, &out)
	for _, p := range []string{"kavach_shift_handoff", "kavach_compliance_gap_review"} {
		if !strings.Contains(out.String(), p) {
			t.Fatalf("prompt %s missing: %s", p, out.String())
		}
	}
}
