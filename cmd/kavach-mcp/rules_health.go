// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// ruleHealthReadTools are read-only; changing a rule's lifecycle state is not exposed over MCP.
func ruleHealthReadTools() []endpointTool {
	id := objSchema(map[string]any{"id": strProp("Rule id")}, "id")
	return []endpointTool{
		{name: "rules_health", method: "GET", path: "/v1/rules/health", description: "Per-rule health from stored findings: hits 24h/7d/30d, distinct hosts, last fired, trend, share of findings, noisy score, silent (never fired), lifecycle state. Filters: state, source, silent=1, noisy=1, limit.", schema: objSchema(map[string]any{
			"state": strProp("draft|testing|production|retired"), "source": strProp("custom|embedded|builtin"), "silent": strProp("1 for never-fired rules only"), "noisy": strProp("1 for noisy rules only"), "limit": strProp("Max rows (default 200)"),
		}), queryParams: []string{"state", "source", "silent", "noisy", "limit"}},
		{name: "rules_health_get", method: "GET", path: "/v1/rules/health/{id}", description: "Health of one detection rule plus its recent finding ids.", schema: id, pathParams: []string{"id"}},
		{name: "rules_lifecycle_get", method: "GET", path: "/v1/rules/lifecycle/{id}", description: "Lifecycle state (draft|testing|production|retired) of one rule.", schema: id, pathParams: []string{"id"}},
		{name: "rules_history", method: "GET", path: "/v1/rules/history/{id}", description: "Hash-chained change history (custom rule edits, lifecycle changes) of one rule, with chain verification.", schema: id, pathParams: []string{"id"}},
	}
}

func registerRuleHealthTools(srv *mcpserver.Server, c *client) error {
	for _, t := range ruleHealthReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
