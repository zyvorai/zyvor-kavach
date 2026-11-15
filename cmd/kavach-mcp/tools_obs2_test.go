// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var obs2ReadNames = []string{
	"validate_scenarios", "validate_scenario", "validate_run", "validate_coverage",
	"vulns_priority", "vulns_priority_cve", "vulns_priority_status",
	"hunt_seq", "hunt_seq_fields", "hunt_seq_explain", "hunt_seq_examples",
	"feedback_list", "feedback_rules", "feedback_summary", "feedback_verify", "competitive",
	"chains_list", "chains_get", "case_templates_list", "case_template_get", "case_workflow_get",
	"content_versions", "content_changes", "content_changelog", "coverage_blindspots", "coverage_telemetry",
	"detections_scheduled_list", "detections_scheduled_get", "detections_scheduled_history", "detections_scheduled_dryrun",
	"hunts_limits_get", "exceptions_list", "exceptions_suppressed", "exceptions_history",
	"reports_scheduled_list", "reports_scheduled_runs", "fleet_slo", "fleet_slo_history", "fleet_slo_definitions",
	"syslog_status", "syslog_samples", "syslog_parse", "inspect_config_b64",
}

var obs2MutatingNames = []string{
	"feedback_record", "chain_create_case", "case_assign", "case_apply_template", "case_checklist_set",
	"detections_scheduled_create", "detections_scheduled_update", "detections_scheduled_delete", "detections_scheduled_run",
	"exceptions_create", "exceptions_update", "exceptions_expire", "exceptions_delete",
	"reports_scheduled_create", "reports_scheduled_update", "reports_scheduled_delete", "reports_scheduled_run",
	"fleet_slo_set",
}

func TestObs2ReadOnlyVsMutatingRegistration(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	rw := listToolsJSON(t, c, true)
	if len(obs2ReadNames) != 43 || len(obs2MutatingNames) != 18 {
		t.Fatalf("counts: %d read, %d mutating", len(obs2ReadNames), len(obs2MutatingNames))
	}
	for _, n := range obs2ReadNames {
		if ro[n] == nil || rw[n] == nil {
			t.Fatalf("read tool %s missing (ro=%v rw=%v)", n, ro[n] != nil, rw[n] != nil)
		}
	}
	for _, n := range obs2MutatingNames {
		if ro[n] != nil {
			t.Fatalf("mutating tool %s leaked into read-only mode", n)
		}
		if rw[n] == nil {
			t.Fatalf("mutating tool %s missing with --allow-mutations", n)
		}
		d, _ := rw[n]["description"].(string)
		if !strings.Contains(d, "--allow-mutations") || !strings.Contains(d, "observation-only") {
			t.Fatalf("%s description lacks mutation/observation-only statement: %s", n, d)
		}
	}
	// Destructive-bulk / reset / replace-limits tools must not exist anywhere.
	for _, n := range []string{"hunts_limits_set", "vulns_priority_refresh", "feedback_export", "case_template_create", "case_template_delete", "exceptions_reset", "detections_scheduled_reset"} {
		if rw[n] != nil {
			t.Fatalf("%s must not be exposed", n)
		}
	}
}

func TestObs2Honesty(t *testing.T) {
	c, _ := recorder(t)
	ro := listToolsJSON(t, c, false)
	rw := listToolsJSON(t, c, true)
	need := map[string][]string{
		"validate_run":                {"SYNTHETIC", "records nothing"},
		"validate_coverage":           {"SYNTHETIC"},
		"vulns_priority":              {"UNKNOWN", "opt-in"},
		"vulns_priority_cve":          {"UNKNOWN"},
		"hunt_seq":                    {"nothing is recorded"},
		"chains_get":                  {"NOT attribution"},
		"detections_scheduled_dryrun": {"records nothing"},
		"exceptions_list":             {"suppress REPORTING"},
		"syslog_status":               {"OFF by default", "opt-in"},
		"syslog_parse":                {"DRY RUN", "ingested is always false"},
		"inspect_config_b64":          {"never a local file path", "not an audit of the host"},
		"feedback_rules":              {"not fleet-wide precision"},
	}
	for n, subs := range need {
		d, _ := ro[n]["description"].(string)
		for _, s := range subs {
			if !strings.Contains(d, s) {
				t.Fatalf("%s description lacks %q: %s", n, s, d)
			}
		}
	}
	if d := rw["exceptions_create"]["description"].(string); !strings.Contains(d, "suppress REPORTING") {
		t.Fatalf("exceptions_create: %s", d)
	}
}

func TestObs2NoPathLikeParamsInInspectTools(t *testing.T) {
	c, _ := recorder(t)
	rw := listToolsJSON(t, c, true)
	for n, tl := range rw {
		if !strings.HasPrefix(n, "inspect_") {
			continue
		}
		props, _ := tl["inputSchema"].(map[string]any)["properties"].(map[string]any)
		for k := range props {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "path") || (strings.Contains(lk, "file") && lk != "content_b64") || lk == "uri" || lk == "url" {
				t.Fatalf("%s exposes path-like parameter %q", n, k)
			}
		}
	}
}

func TestObs2ReadRequests(t *testing.T) {
	c, got := recorder(t)
	calls := []struct{ name, args, method, uri, body string }{
		{"validate_scenarios", `{"kind":"attack","platform":"linux","technique":"T1059"}`, "GET", "/v1/validate/scenarios?kind=attack&platform=linux&technique=T1059", ""},
		{"validate_scenario", `{"id":"a/b c"}`, "GET", "/v1/validate/scenarios/a%2Fb%20c", ""},
		{"validate_run", `{"ids":["s1","s2"],"include_custom":true}`, "POST", "/v1/validate/run", `{"ids":["s1","s2"],"include_custom":true}`},
		{"validate_coverage", `{"include_custom":"true"}`, "GET", "/v1/validate/coverage?include_custom=true", ""},
		{"vulns_priority", `{"host":"h1","limit":"10"}`, "GET", "/v1/vulns/priority?host=h1&limit=10", ""},
		{"vulns_priority_cve", `{"cve":"CVE-2024-3094"}`, "GET", "/v1/vulns/priority/CVE-2024-3094", ""},
		{"vulns_priority_status", `{}`, "GET", "/v1/vulns/priority/status", ""},
		{"hunt_seq", `{"query":"sequence by host [process where name == \"x\"]","since":"7d","limit":5}`, "POST", "/v1/hunt/seq", `{"limit":5,"query":"sequence by host [process where name == \"x\"]","since":"7d"}`},
		{"hunt_seq_fields", `{}`, "GET", "/v1/hunt/seq/fields", ""},
		{"hunt_seq_explain", `{"query":"q"}`, "POST", "/v1/hunt/seq/explain", `{"query":"q"}`},
		{"hunt_seq_examples", `{}`, "GET", "/v1/hunt/seq/examples", ""},
		{"feedback_list", `{"finding_id":"f1","limit":"5"}`, "GET", "/v1/feedback?finding_id=f1&limit=5", ""},
		{"feedback_rules", `{"min_verdicts":"3","review_below":"0.5"}`, "GET", "/v1/feedback/rules?min_verdicts=3&review_below=0.5", ""},
		{"feedback_summary", `{"days":"30"}`, "GET", "/v1/feedback/summary?days=30", ""},
		{"feedback_verify", `{}`, "GET", "/v1/feedback/verify", ""},
		{"competitive", `{}`, "GET", "/v1/world/competitive", ""},
		{"chains_list", `{"host":"h1","min_score":"2","limit":"5"}`, "GET", "/v1/chains?host=h1&limit=5&min_score=2", ""},
		{"chains_get", `{"id":"ch-1"}`, "GET", "/v1/chains/ch-1", ""},
		{"case_templates_list", `{}`, "GET", "/v1/case-templates", ""},
		{"case_template_get", `{"id":"tpl-1"}`, "GET", "/v1/case-templates/tpl-1", ""},
		{"case_workflow_get", `{"id":"c1"}`, "GET", "/v1/cases/c1/workflow", ""},
		{"content_versions", `{"items":"1"}`, "GET", "/v1/content/versions?items=1", ""},
		{"content_changes", `{"from":"1","to":"2"}`, "GET", "/v1/content/changes?from=1&to=2", ""},
		{"content_changelog", `{}`, "GET", "/v1/content/changelog", ""},
		{"coverage_blindspots", `{"validation":"0","stale_days":"14"}`, "GET", "/v1/coverage/blindspots?stale_days=14&validation=0", ""},
		{"coverage_telemetry", `{"stale_days":"3"}`, "GET", "/v1/coverage/telemetry?stale_days=3", ""},
		{"detections_scheduled_list", `{}`, "GET", "/v1/detections/scheduled", ""},
		{"detections_scheduled_get", `{"id":"sd-1"}`, "GET", "/v1/detections/scheduled/sd-1", ""},
		{"detections_scheduled_history", `{"id":"sd-1"}`, "GET", "/v1/detections/scheduled/sd-1/history", ""},
		{"detections_scheduled_dryrun", `{"id":"sd-1"}`, "POST", "/v1/detections/scheduled/sd-1/dryrun", ""},
		{"hunts_limits_get", `{}`, "GET", "/v1/hunts/limits", ""},
		{"exceptions_list", `{"status":"active"}`, "GET", "/v1/exceptions?status=active", ""},
		{"exceptions_suppressed", `{"exception":"ex-1"}`, "GET", "/v1/exceptions/suppressed?exception=ex-1", ""},
		{"exceptions_history", `{}`, "GET", "/v1/exceptions/history", ""},
		{"reports_scheduled_list", `{}`, "GET", "/v1/reports/scheduled", ""},
		{"reports_scheduled_runs", `{"id":"rs-1"}`, "GET", "/v1/reports/scheduled/rs-1/runs", ""},
		{"fleet_slo", `{}`, "GET", "/v1/fleet/slo", ""},
		{"fleet_slo_history", `{"window":"6h","agent":"a1"}`, "GET", "/v1/fleet/slo/history?agent=a1&window=6h", ""},
		{"fleet_slo_definitions", `{}`, "GET", "/v1/fleet/slo/definitions", ""},
		{"syslog_status", `{}`, "GET", "/v1/syslog/status", ""},
		{"syslog_samples", `{}`, "GET", "/v1/syslog/samples", ""},
		{"syslog_parse", `{"line":"<34>Oct 11 22:14:15 h su: x","sender":"10.0.0.1"}`, "POST", "/v1/syslog/parse", `{"line":"<34>Oct 11 22:14:15 h su: x","sender":"10.0.0.1"}`},
	}
	checkCalls(t, c, got, false, calls)
}

func TestObs2MutatingRequests(t *testing.T) {
	c, got := recorder(t)
	calls := []struct{ name, args, method, uri, body string }{
		{"feedback_record", `{"finding_id":"f1","verdict":"false_positive","note":"n"}`, "POST", "/v1/feedback", `{"finding_id":"f1","note":"n","verdict":"false_positive"}`},
		{"chain_create_case", `{"id":"ch-1"}`, "POST", "/v1/chains/ch-1/case", ""},
		{"case_assign", `{"id":"c1","assignee":"bob"}`, "POST", "/v1/cases/c1/assign", `{"assignee":"bob"}`},
		{"case_apply_template", `{"id":"c1","template_id":"tpl-1"}`, "POST", "/v1/cases/c1/apply-template", `{"template_id":"tpl-1"}`},
		{"case_checklist_set", `{"id":"c1","n":2,"done":true}`, "POST", "/v1/cases/c1/checklist/2", `{"done":true}`},
		{"detections_scheduled_create", `{"name":"d","source":{"kind":"seq","query":"q"},"severity":"low","interval_sec":120}`, "POST", "/v1/detections/scheduled", `{"interval_sec":120,"name":"d","severity":"low","source":{"kind":"seq","query":"q"}}`},
		{"detections_scheduled_update", `{"id":"sd-1","state":"testing"}`, "PUT", "/v1/detections/scheduled/sd-1", `{"state":"testing"}`},
		{"detections_scheduled_delete", `{"id":"sd-1"}`, "DELETE", "/v1/detections/scheduled/sd-1", ""},
		{"detections_scheduled_run", `{"id":"sd-1"}`, "POST", "/v1/detections/scheduled/sd-1/run", ""},
		{"exceptions_create", `{"rule":"r*","reason":"x","owner":"o","expires":"2030-01-01T00:00:00Z"}`, "POST", "/v1/exceptions", `{"expires":"2030-01-01T00:00:00Z","owner":"o","reason":"x","rule":"r*"}`},
		{"exceptions_update", `{"id":"ex-1","reason":"y"}`, "PUT", "/v1/exceptions/ex-1", `{"reason":"y"}`},
		{"exceptions_expire", `{"id":"ex-1","extra":"ignored"}`, "PUT", "/v1/exceptions/ex-1", `{"expire_now":true}`},
		{"exceptions_delete", `{"id":"ex-1"}`, "DELETE", "/v1/exceptions/ex-1", ""},
		{"reports_scheduled_create", `{"name":"n","template":"t","frequency":"daily","time":"03:00","params":{"a":"b"}}`, "POST", "/v1/reports/scheduled", `{"frequency":"daily","name":"n","params":{"a":"b"},"template":"t","time":"03:00"}`},
		{"reports_scheduled_update", `{"id":"rs-1","name":"n","template":"t","frequency":"hourly","minute":5}`, "PUT", "/v1/reports/scheduled/rs-1", `{"frequency":"hourly","minute":5,"name":"n","template":"t"}`},
		{"reports_scheduled_delete", `{"id":"rs-1"}`, "DELETE", "/v1/reports/scheduled/rs-1", ""},
		{"reports_scheduled_run", `{"id":"rs-1"}`, "POST", "/v1/reports/scheduled/rs-1/run", ""},
		{"fleet_slo_set", `{"heartbeat_target_pct":99.5,"window_hours":24}`, "PUT", "/v1/fleet/slo", `{"heartbeat_target_pct":99.5,"window_hours":24}`},
	}
	checkCalls(t, c, got, true, calls)
	// Without --allow-mutations none of these are callable.
	before := len(got())
	callTool(t, c, false, "exceptions_create", `{"rule":"r","reason":"x","owner":"o","expires":"2030-01-01T00:00:00Z"}`)
	if len(got()) != before {
		t.Fatal("mutating tool reached the server in read-only mode")
	}
}

func checkCalls(t *testing.T, c *client, got func() []recordedReq, mut bool, calls []struct{ name, args, method, uri, body string }) {
	t.Helper()
	for i, cl := range calls {
		before := len(got())
		if o := callTool(t, c, mut, cl.name, cl.args); !strings.Contains(o, "ok") {
			t.Fatalf("%s: %s", cl.name, o)
		}
		reqs := got()
		if len(reqs) != before+1 {
			t.Fatalf("%s: want exactly one request", cl.name)
		}
		r := reqs[len(reqs)-1]
		if r.method != cl.method || r.uri != cl.uri {
			t.Fatalf("#%d %s: got %s %s, want %s %s", i, cl.name, r.method, r.uri, cl.method, cl.uri)
		}
		if cl.body == "" {
			if len(r.body) != 0 {
				t.Fatalf("%s: unexpected body %s", cl.name, r.body)
			}
			continue
		}
		var a, b any
		if json.Unmarshal(r.body, &a) != nil || json.Unmarshal([]byte(cl.body), &b) != nil {
			t.Fatalf("%s: bad json body %s", cl.name, r.body)
		}
		ab, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		if !bytes.Equal(ab, bb) {
			t.Fatalf("%s: body %s, want %s", cl.name, ab, bb)
		}
	}
}

func TestInspectConfigB64(t *testing.T) {
	c, got := recorder(t)
	payload := []byte("PermitRootLogin yes\nPasswordAuthentication yes\n")
	enc := base64.StdEncoding.EncodeToString(payload)
	if o := callTool(t, c, false, "inspect_config_b64", `{"content_b64":"`+enc+`","name":"sshd_config"}`); !strings.Contains(o, "ok") {
		t.Fatalf("call: %s", o)
	}
	reqs := got()
	if len(reqs) != 1 || reqs[0].method != "POST" || reqs[0].uri != "/v1/inspect/config?name=sshd_config" ||
		reqs[0].ctype != "application/octet-stream" || !bytes.Equal(reqs[0].body, payload) {
		t.Fatalf("bad request: %+v", reqs)
	}
	atCap := base64.StdEncoding.EncodeToString(make([]byte, inspectConfigMaxBytes))
	if o := callTool(t, c, false, "inspect_config_b64", `{"content_b64":"`+atCap+`"}`); !strings.Contains(o, "ok") {
		t.Fatalf("at-cap rejected: %.200s", o)
	}
	over := base64.StdEncoding.EncodeToString(make([]byte, inspectConfigMaxBytes+1))
	if o := callTool(t, c, false, "inspect_config_b64", `{"content_b64":"`+over+`"}`); !strings.Contains(o, "too large") && !strings.Contains(o, "must be 1..") {
		t.Fatalf("over-cap not rejected: %.200s", o)
	}
	huge := strings.Repeat("A", 8<<20)
	if o := callTool(t, c, false, "inspect_config_b64", `{"content_b64":"`+huge+`"}`); !strings.Contains(o, "too large") {
		t.Fatalf("huge not rejected: %.200s", o)
	}
	if o := callTool(t, c, false, "inspect_config_b64", `{"content_b64":"not base64!!"}`); !strings.Contains(o, "not valid standard base64") {
		t.Fatalf("invalid: %s", o)
	}
	if o := callTool(t, c, false, "inspect_config_b64", `{"path":"/etc/passwd"}`); !strings.Contains(o, "required") {
		t.Fatalf("path arg: %s", o)
	}
	if n := len(got()); n != 2 {
		t.Fatalf("rejected calls must not reach the server, got %d requests", n)
	}
}
