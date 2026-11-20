// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// contentReadTools exposes the detection content library (rules, coverage,
// queries, guidance, report templates). All read-only.
func contentReadTools() []endpointTool {
	return []endpointTool{
		{name: "content_rules", method: "GET", path: "/v1/content/rules", description: "Browse detection content rules; filter by tactic, os, event_type, severity, batch, technique or text.",
			schema: objSchema(map[string]any{
				"tactic": strProp("MITRE tactic, e.g. execution"), "os": strProp("linux, macos, windows or any"),
				"event_type": strProp("process, network, file, registry, dns, auth or module"), "severity": strProp("critical, high, medium, low or info"),
				"batch": strProp("Content batch name"), "technique": strProp("ATT&CK technique id, e.g. T1059"), "q": strProp("Text search over id, name, description and tags"),
			}), queryParams: []string{"tactic", "os", "event_type", "severity", "batch", "technique", "q"}},
		{name: "content_rule", method: "GET", path: "/v1/content/rules/{id}", description: "One content rule with its match tree and positive/negative test samples.",
			schema: objSchema(map[string]any{"id": strProp("Rule id")}, "id"), pathParams: []string{"id"}},
		{name: "content_coverage", method: "GET", path: "/v1/content/coverage", description: "Content coverage counts by tactic, technique, OS, severity, event type and batch.", schema: emptySchema()},
		{name: "query_library", method: "GET", path: "/v1/queries/library", description: "Curated hunting query library.",
			schema: objSchema(map[string]any{"tactic": strProp("Tactic filter"), "tag": strProp("Tag filter"), "q": strProp("Text search")}), queryParams: []string{"tactic", "tag", "q"}},
		{name: "guidance_catalog", method: "GET", path: "/v1/guidance", description: "Advisory investigation and remediation guidance entries.",
			schema: objSchema(map[string]any{"kind": strProp("Entry kind, e.g. rule"), "q": strProp("Text search")}), queryParams: []string{"kind", "q"}},
		{name: "guidance_entry", method: "GET", path: "/v1/guidance/{id}", description: "One advisory guidance entry.",
			schema: objSchema(map[string]any{"id": strProp("Guidance id")}, "id"), pathParams: []string{"id"}},
		{name: "report_templates", method: "GET", path: "/v1/reports/templates", description: "Available report templates.", schema: emptySchema()},
	}
}

func registerContentTools(srv *mcpserver.Server, c *client) error {
	for _, t := range contentReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
