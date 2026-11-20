// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"strings"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

// Surface-parity MCP tools: read-only GET routes that had no MCP tool.
// Every tool here is a plain GET with no body; nothing in this file is
// registered behind the mutation flag and nothing here may mutate.

const surfaceNote = " Read-only; observe-only platform, never takes action."

var surfaceSectorViews = []string{
	"air-cargo", "airport-security", "atc-it", "baggage", "cantonment", "cert-in", "citizen-services",
	"coast-guard", "courts", "customs", "defence-civil", "dgca", "digital-id", "drdo-labs", "e-office",
	"education", "elections", "electronics-mfg", "fids", "freight", "ground-handling", "health", "highways",
	"metro", "ministries", "oil-gas", "paramilitary", "passenger-apps", "pharma", "ports", "postal",
	"rail-signaling", "scada", "smart-city", "spectrum", "stations", "steel-cement", "tax", "telecom",
	"textiles", "transport-reg", "water",
}

var surfaceFinanceViews = []string{
	"algo", "atms", "branches", "cards", "core-banking", "kyc", "market-data", "mutual-funds", "nbfc",
	"payment-rails", "pci", "sanctions", "swift", "trading-desks", "treasury", "workstations",
}

func surfaceTools() []endpointTool {
	snake := func(s string) string { return strings.ReplaceAll(s, "-", "_") }
	ts := []endpointTool{
		{name: "kavach_events_summary", method: "GET", path: "/v1/events/summary",
			description: "Counts of retained typed telemetry events (auth, dns, module, registry)." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_census", method: "GET", path: "/v1/ebpf/census",
			description: "eBPF program/map census." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_coverage", method: "GET", path: "/v1/ebpf/coverage",
			description: "eBPF hook coverage versus the sensor expectation." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_drops", method: "GET", path: "/v1/ebpf/drops",
			description: "eBPF ringbuffer drop counters." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_processes", method: "GET", path: "/v1/ebpf/processes",
			description: "Processes observed by eBPF." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_summary", method: "GET", path: "/v1/ebpf/summary",
			description: "eBPF platform summary." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_netra_attachments", method: "GET", path: "/v1/ebpf/netra/attachments",
			description: "Netra eBPF attachment inventory." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_netra_drops", method: "GET", path: "/v1/ebpf/netra/drops",
			description: "Netra eBPF drop counters." + surfaceNote, schema: emptySchema()},
		{name: "kavach_ebpf_netra_flows", method: "GET", path: "/v1/ebpf/netra/flows",
			description: "Netra eBPF flow observations." + surfaceNote, schema: emptySchema()},
		{name: "kavach_case_workflow_journal", method: "GET", path: "/v1/case-workflow/journal",
			description: "Hash-chained case workflow journal with chain verification status." + surfaceNote, schema: emptySchema()},
		{name: "kavach_regression_status", method: "GET", path: "/v1/regression/status",
			description: "Latest detection-regression snapshot summary. Measured detection rates only; not a guarantee of coverage." + surfaceNote, schema: emptySchema()},
		{name: "kavach_regression_history", method: "GET", path: "/v1/regression/history",
			description: "Detection-regression run history (newest first)." + surfaceNote,
			schema:      objSchema(map[string]any{"limit": strProp("Max runs")}), queryParams: []string{"limit"}},
		{name: "kavach_regression_diff", method: "GET", path: "/v1/regression/diff",
			description: "Diff two regression snapshots (refs: latest, previous or a sequence number)." + surfaceNote,
			schema: objSchema(map[string]any{
				"from": strProp("Older ref, default previous"),
				"to":   strProp("Newer ref, default latest"),
			}), queryParams: []string{"from", "to"}},
		{name: "kavach_regression_trend", method: "GET", path: "/v1/regression/trend",
			description: "Detection-regression trend over a window such as 7d, 30d or 72h." + surfaceNote,
			schema:      objSchema(map[string]any{"window": strProp("Window like 7d, 30d, 72h (default 30d)")}), queryParams: []string{"window"}},
		{name: "kavach_regression_config", method: "GET", path: "/v1/regression/config",
			description: "Regression tracking configuration (read only)." + surfaceNote, schema: emptySchema()},
		{name: "kavach_regression_gate", method: "GET", path: "/v1/regression/gate",
			description: "Evaluate the latest regression snapshot against thresholds. Answers HTTP 412 on failure, which is returned as a tool error." + surfaceNote,
			schema: objSchema(map[string]any{
				"min_detected":        strProp("Minimum measured detected percent (0-100)"),
				"max_regressions":     strProp("Maximum allowed regressions"),
				"max_false_positives": strProp("Maximum allowed benign false positives"),
			}), queryParams: []string{"min_detected", "max_regressions", "max_false_positives"}},
		{name: "kavach_posture_trend_config", method: "GET", path: "/v1/posture/trend/config",
			description: "Posture trend settings (read only)." + surfaceNote, schema: emptySchema()},
		{name: "kavach_queries_library", method: "GET", path: "/v1/queries/library",
			description: "Built-in hunt query library, filterable by tactic, tag or text." + surfaceNote,
			schema: objSchema(map[string]any{
				"tactic": strProp("ATT&CK tactic"), "tag": strProp("Tag"), "q": strProp("Free text"),
			}), queryParams: []string{"tactic", "tag", "q"}},
		{name: "kavach_queries_library_get", method: "GET", path: "/v1/queries/library/{id}",
			description: "One hunt library query by id (does not save it)." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Query id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_guidance", method: "GET", path: "/v1/guidance",
			description: "Advisory guidance catalog (explanations only)." + surfaceNote,
			schema: objSchema(map[string]any{
				"kind": strProp("Entry kind"), "q": strProp("Free text"),
			}), queryParams: []string{"kind", "q"}},
		{name: "kavach_guidance_get", method: "GET", path: "/v1/guidance/{id}",
			description: "One guidance entry by id." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Guidance id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_evidence_cases", method: "GET", path: "/v1/evidence/cases",
			description: "Imported evidence cases (summaries)." + surfaceNote, schema: emptySchema()},
		{name: "kavach_evidence_case", method: "GET", path: "/v1/evidence/cases/{id}",
			description: "One imported evidence case." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Case id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_report_templates", method: "GET", path: "/v1/reports/templates",
			description: "Available report templates." + surfaceNote, schema: emptySchema()},
		{name: "kavach_report_template_render", method: "GET", path: "/v1/reports/templates/{id}/render",
			description: "Render a report template as markdown from current data (nothing is stored or sent)." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Template id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_enrich_geo", method: "GET", path: "/v1/enrich/geo",
			description: "Offline heuristic geo lookup for an IP; approximate, not authoritative." + surfaceNote,
			schema:      objSchema(map[string]any{"ip": strProp("IP address")}), queryParams: []string{"ip"}},
		{name: "kavach_rollback_advice", method: "GET", path: "/v1/rollback",
			description: "Rollback guidance only; never restores or changes files." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Finding or incident id")}), queryParams: []string{"id"}},
		{name: "kavach_rule_history", method: "GET", path: "/v1/rules/history/{id}",
			description: "Hash-chained lifecycle history for one rule." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Rule id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_rule_lifecycle", method: "GET", path: "/v1/rules/lifecycle/{id}",
			description: "Current lifecycle state of one rule." + surfaceNote,
			schema:      objSchema(map[string]any{"id": strProp("Rule id")}, "id"), pathParams: []string{"id"}},
		{name: "kavach_ransomware_host", method: "GET", path: "/v1/ransomware/host/{host}",
			description: "Ransomware risk for one host (heuristic, report-only)." + surfaceNote,
			schema:      objSchema(map[string]any{"host": strProp("Host name")}, "host"), pathParams: []string{"host"}},
		{name: "kavach_vulns_feeds_status", method: "GET", path: "/v1/vulns/feeds/status",
			description: "Vulnerability feed freshness and status." + surfaceNote, schema: emptySchema()},
	}
	for _, ty := range []string{"auth", "dns", "module", "registry"} {
		ts = append(ts, endpointTool{name: "kavach_events_" + ty, method: "GET", path: "/v1/events/" + ty,
			description: "Recent typed " + ty + " telemetry events." + surfaceNote,
			schema: objSchema(map[string]any{
				"host": strProp("Restrict to one host"), "limit": strProp("Max events, 1-1000 (default 100)"),
			}), queryParams: []string{"host", "limit"}})
	}
	for _, v := range surfaceSectorViews {
		ts = append(ts, endpointTool{name: "kavach_sectors_" + snake(v), method: "GET", path: "/v1/sectors/" + v,
			description: "Sector observe view: " + v + "." + surfaceNote, schema: emptySchema()})
	}
	for _, v := range surfaceFinanceViews {
		ts = append(ts, endpointTool{name: "kavach_finance_" + snake(v), method: "GET", path: "/v1/finance/" + v,
			description: "Finance observe view: " + v + " (never freezes or blocks)." + surfaceNote, schema: emptySchema()})
	}
	return ts
}

func registerSurfaceTools(srv *mcpserver.Server, c *client) error {
	for _, t := range surfaceTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
