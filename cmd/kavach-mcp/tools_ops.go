// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// complianceFrameworks mirrors the backend evidence framework IDs.
var complianceFrameworks = []string{"cis-v8", "nist-csf-2", "soc2", "iso27001", "rbi", "cert-in", "dpdp"}

func intProp(desc string, min, max int) map[string]any {
	return map[string]any{"type": "integer", "description": desc, "minimum": min, "maximum": max}
}

func frameworkProp() map[string]any {
	return enumProp("Compliance framework (omit for all)", complianceFrameworks...)
}

// registerOpsReadTools adds intel-feed, detection-lab, SOC-ops, posture and
// compliance READ tools. Feed/lab-rule/asset create+delete and posture
// baseline / feed refresh are deliberately NOT exposed (SSRF / state change);
// humans manage those.
func registerOpsReadTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{name: "kavach_intel_feeds", method: "GET", path: "/v1/intel/feeds", description: "Configured threat-intel feeds (read-only).", schema: emptySchema()},
		{name: "kavach_intel_feed_status", method: "GET", path: "/v1/intel/feeds/status", description: "Threat-intel feed fetch status.", schema: emptySchema()},
		{name: "kavach_lab_rules", method: "GET", path: "/v1/lab/rules", description: "Detection-lab rules (sandbox, read-only).", schema: emptySchema()},
		{name: "kavach_soc_metrics", method: "GET", path: "/v1/soc/metrics", description: "SOC metrics (MTTA/MTTR, volumes).", schema: objSchema(map[string]any{
			"days": intProp("Window in days (default 30, max 365)", 1, 365),
		}), queryParams: []string{"days"}},
		{name: "kavach_host_storyline", method: "GET", path: "/v1/storyline/host", description: "Chronological storyline of activity for one host.", schema: objSchema(map[string]any{
			"host":  strProp("Exact hostname"),
			"hours": intProp("Lookback hours (default 24, max 720)", 1, 720),
		}, "host"), queryParams: []string{"host", "hours"}},
		{name: "kavach_shift_report", method: "GET", path: "/v1/soc/shift-report", description: "SOC shift handoff report: counts, riskiest hosts, unresolved criticals.", schema: objSchema(map[string]any{
			"hours": intProp("Shift length in hours (default 12, max 168)", 1, 168),
		}), queryParams: []string{"hours"}},
		{name: "kavach_posture_summary", method: "GET", path: "/v1/posture/summary", description: "Posture summary: asset criticality distribution and drifting hosts.", schema: emptySchema()},
		{name: "kavach_vuln_priority", method: "GET", path: "/v1/posture/vuln-priority", description: "Prioritised vulnerabilities (CVSS, criticality, exposure, KEV).", schema: objSchema(map[string]any{
			"limit": intProp("Max items", 1, 500),
		}), queryParams: []string{"limit"}},
		{name: "kavach_posture_assets", method: "GET", path: "/v1/posture/assets", description: "Asset criticality register.", schema: emptySchema()},
		{name: "kavach_posture_drift", method: "GET", path: "/v1/posture/drift", description: "Configuration drift for a host versus its baseline.", schema: objSchema(map[string]any{
			"host": strProp("Exact hostname"),
		}, "host"), queryParams: []string{"host"}},
		{name: "kavach_compliance_controls", method: "GET", path: "/v1/compliance/controls", description: "Observation-based control results per framework (not a certification).", schema: objSchema(map[string]any{
			"framework": frameworkProp(),
		}), queryParams: []string{"framework"}},
		{name: "kavach_compliance_evidence", method: "GET", path: "/v1/compliance/evidence", description: "Compliance evidence pack as JSON (html is never served through MCP).", schema: objSchema(map[string]any{
			"framework": frameworkProp(),
			"format":    enumProp("Output format (json only)", "json"),
		}), queryParams: []string{"framework", "format"}},
		{name: "kavach_cert_in_clock", method: "GET", path: "/v1/compliance/cert-in-clock", description: "Informational CERT-In 6-hour reporting clock per incident (Kavach files nothing).", schema: emptySchema()},
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}

// registerOpsMutateTools: existing gating treats every POST as mutating
// (kavach_hunt_query is a read-in-effect POST yet lives behind the flag), so
// the sandbox-only detection-lab POSTs follow that convention. Feed, lab-rule
// and asset create/delete plus baseline/refresh are NOT exposed.
func registerOpsMutateTools(srv *mcpserver.Server, c *client) error {
	ruleProps := func() map[string]any {
		return map[string]any{
			"rule":    map[string]any{"type": "object", "description": "Inline lab rule definition"},
			"rule_id": strProp("ID of a saved lab rule (alternative to rule)"),
		}
	}
	testProps := ruleProps()
	testProps["events"] = map[string]any{"type": "array", "description": "1..N sample events", "items": map[string]any{"type": "object"}}
	tools := []endpointTool{
		{name: "kavach_lab_validate", method: "POST", path: "/v1/lab/rules/validate", description: "Validate a lab rule definition (sandbox; nothing persisted).", schema: objSchema(map[string]any{
			"rule": map[string]any{"type": "object", "description": "Lab rule definition"},
		}, "rule"), bodyFields: true},
		{name: "kavach_lab_test", method: "POST", path: "/v1/lab/rules/test", description: "Run a lab rule against supplied sample events (sandbox; nothing persisted).", schema: objSchema(testProps, "events"), bodyFields: true},
		{name: "kavach_lab_backtest", method: "POST", path: "/v1/lab/rules/backtest", description: "Backtest a lab rule against stored events (sandbox; nothing persisted).", schema: objSchema(ruleProps()), bodyFields: true},
		{name: "kavach_posture_asset_set", method: "POST", path: "/v1/posture/assets", description: "Set asset criticality for a host (ledger only; observation).", schema: objSchema(map[string]any{
			"host":        strProp("Hostname"),
			"criticality": intProp("Criticality 1 (low) to 5 (crown jewel)", 1, 5),
			"owner":       strProp("Owner"),
			"tags":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "host", "criticality"), bodyFields: true},
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
