// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// Typed schema helpers shared by the tools_*.go files added with the validation/SSVC/seq batch.
func numProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func objProp(desc string) map[string]any {
	return map[string]any{"type": "object", "description": desc}
}
func strsProp(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// mutNote is appended to every mutating tool description.
const mutNote = " Registered only with --allow-mutations. Needs an admin token on the server. Kavach stays observation-only: this changes Kavach's own stored records, never a host (nothing is blocked, killed, quarantined or contained)."

const validateNote = " The validation lab is SYNTHETIC: it replays built-in scenario events through Kavach's own detection rules inside the controller; it does not run attacks on any host or test real telemetry, so a pass shows rule logic fires on the scenario, not that production would catch the real technique. Read-only."

func validateTools() []endpointTool {
	return []endpointTool{
		{name: "validate_scenarios", method: "GET", path: "/v1/validate/scenarios",
			description: "List synthetic validation scenarios (id, kind, platform, techniques, benign flag, step count)." + validateNote,
			schema:      objSchema(map[string]any{"kind": strProp("Filter by scenario kind"), "platform": strProp("Filter by platform"), "technique": strProp("Filter by ATT&CK technique id")}),
			queryParams: []string{"kind", "platform", "technique"}},
		{name: "validate_scenario", method: "GET", path: "/v1/validate/scenarios/{id}",
			description: "Full definition of one synthetic validation scenario." + validateNote,
			schema:      objSchema(map[string]any{"id": strProp("Scenario id")}, "id"), pathParams: []string{"id"}},
		{name: "validate_run", method: "POST", path: "/v1/validate/run",
			description: "Run synthetic scenarios against the detection rules and return per-scenario results. This is a POST but a read-only computation: it records nothing (the response says recorded=false), creates no findings and changes no state. Give ids or all=true." + validateNote,
			schema:      objSchema(map[string]any{"ids": strsProp("Scenario ids to run"), "all": boolProp("Run every scenario"), "include_custom": boolProp("Also evaluate customer-authored custom rules")}),
			bodyFields:  true},
		{name: "validate_coverage", method: "GET", path: "/v1/validate/coverage",
			description: "Technique coverage derived from running the synthetic scenarios: which techniques have a scenario that triggers a rule, and which do not." + validateNote,
			schema:      objSchema(map[string]any{"include_custom": strProp("Set to true to include custom rules")}), queryParams: []string{"include_custom"}},
	}
}

func registerValidateTools(srv *mcpserver.Server, c *client) error {
	return regEndpoints(srv, c, validateTools())
}

func regEndpoints(srv *mcpserver.Server, c *client, ts []endpointTool) error {
	for _, t := range ts {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
