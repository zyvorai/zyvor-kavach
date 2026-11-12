// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

func moreIntProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func moreReadTools() []endpointTool {
	host := strProp("Host name")
	hours := moreIntProp("Lookback window in hours (default 24)")
	return []endpointTool{
		{name: "fleet_health", method: "GET", path: "/v1/fleet/health", description: "Fleet sensor health summary.", schema: emptySchema()},
		{name: "fleet_coverage_gaps", method: "GET", path: "/v1/fleet/coverage-gaps", description: "Hosts with sensor coverage gaps.", schema: emptySchema()},
		{name: "fleet_stale", method: "GET", path: "/v1/fleet/stale", description: "Hosts that have not reported recently.", schema: objSchema(map[string]any{"minutes": moreIntProp("Staleness threshold in minutes")}), queryParams: []string{"minutes"}},
		{name: "fleet_host_health", method: "GET", path: "/v1/fleet/health/{host}", description: "Health detail for one host.", schema: objSchema(map[string]any{"host": host}, "host"), pathParams: []string{"host"}},
		{name: "prevalence_executables", method: "GET", path: "/v1/prevalence/executables", description: "Executable prevalence across the fleet.", schema: objSchema(map[string]any{"min_hosts": moreIntProp("Minimum host count"), "max_hosts": moreIntProp("Maximum host count (0 = unbounded)"), "limit": moreIntProp("Max rows")}), queryParams: []string{"min_hosts", "max_hosts", "limit"}},
		{name: "prevalence_rare", method: "GET", path: "/v1/prevalence/rare", description: "Rarely seen executables in the window.", schema: objSchema(map[string]any{"hours": hours, "fraction": map[string]any{"type": "number", "description": "Rarity fraction (0,1]"}}), queryParams: []string{"hours", "fraction"}},
		{name: "prevalence_first_seen", method: "GET", path: "/v1/prevalence/first-seen", description: "New executables and destinations first seen on a host.", schema: objSchema(map[string]any{"host": host, "hours": hours}, "host"), queryParams: []string{"host", "hours"}},
		{name: "blast_radius", method: "GET", path: "/v1/graph/blast-radius", description: "Blast-radius graph from a host.", schema: objSchema(map[string]any{"host": host, "hours": hours, "depth": moreIntProp("Graph depth (default 2)")}, "host"), queryParams: []string{"host", "hours", "depth"}},
		{name: "canary_list", method: "GET", path: "/v1/deception/canaries", description: "List deception canaries.", schema: emptySchema()},
		{name: "canary_trips", method: "GET", path: "/v1/deception/trips", description: "List canary trips (tripwire events).", schema: emptySchema()},
		{name: "governance_inventory", method: "GET", path: "/v1/governance/inventory", description: "Data class inventory (observe-only).", schema: emptySchema()},
		{name: "governance_retention", method: "GET", path: "/v1/governance/retention", description: "Current retention policy.", schema: emptySchema()},
		{name: "governance_redaction", method: "GET", path: "/v1/governance/redaction", description: "Current redaction rules.", schema: emptySchema()},
		{name: "governance_subject", method: "GET", path: "/v1/governance/subject", description: "Subject data lookup.", schema: objSchema(map[string]any{"q": strProp("Subject identifier to search")}, "q"), queryParams: []string{"q"}},
		{name: "tuning_suggestions", method: "GET", path: "/v1/tuning/suggestions", description: "Detection tuning suggestions.", schema: emptySchema()},
		{name: "tuning_history", method: "GET", path: "/v1/tuning/history", description: "Applied tuning history.", schema: emptySchema()},
		{name: "digest_list", method: "GET", path: "/v1/digests", description: "List scheduled digests.", schema: emptySchema()},
		{name: "digest_deliveries", method: "GET", path: "/v1/digests/deliveries", description: "Digest delivery log.", schema: emptySchema()},
	}
}

func moreMutateTools() []endpointTool {
	return []endpointTool{
		{name: "canary_create", method: "POST", path: "/v1/deception/canaries", description: "Create a deception canary.", schema: objSchema(map[string]any{"kind": strProp("Canary kind (credential|document-beacon|dns-name)"), "name": strProp("Name"), "placement": strProp("Where it is planted"), "owner": strProp("Owner")}, "kind", "name"), bodyFields: true},
		{name: "canary_delete", method: "DELETE", path: "/v1/deception/canaries/{id}", description: "Delete a canary by id.", schema: objSchema(map[string]any{"id": strProp("Canary id")}, "id"), pathParams: []string{"id"}},
		{name: "tuning_apply", method: "POST", path: "/v1/tuning/apply", description: "Apply a tuning suppression (rule + specific pattern, no wildcards).", schema: objSchema(map[string]any{"rule": strProp("Rule name"), "pattern": strProp("Specific pattern (rule + host)"), "reason": strProp("Reason (max 256)")}, "rule", "pattern"), bodyFields: true},
		{name: "tuning_revert", method: "POST", path: "/v1/tuning/revert", description: "Revert an applied tuning by history id.", schema: objSchema(map[string]any{"id": strProp("History id")}, "id"), queryParams: []string{"id"}},
		{name: "digest_set", method: "POST", path: "/v1/digests", description: "Create a scheduled digest.", schema: objSchema(map[string]any{
			"name": strProp("Name (max 80)"), "schedule": strProp("daily|weekly"), "hour_utc": moreIntProp("0-23"),
			"content": strProp("shift-report|soc-metrics|top-risks"), "type": strProp("webhook|slack"), "url": strProp("Destination URL"),
		}, "name", "schedule", "content", "type", "url"), bodyFields: true},
		{name: "digest_send_now", method: "POST", path: "/v1/digests/send-now", description: "Send a digest immediately.", schema: objSchema(map[string]any{"id": strProp("Digest id")}, "id"), queryParams: []string{"id"}},
	}
}

func moreReadPrompts() []mcpserver.Prompt {
	return []mcpserver.Prompt{
		{
			Name:        "kavach_fleet_coverage_review",
			Description: "Review fleet sensor health and coverage gaps.",
			Messages:    []mcpserver.PromptMessage{{Role: "user", Text: "Use fleet_health, fleet_coverage_gaps and fleet_stale, then fleet_host_health for the worst hosts. Summarize gaps and priorities. Observation-only."}},
		},
		{
			Name:        "kavach_canary_trip_triage",
			Description: "Triage deception canary trips.",
			Messages:    []mcpserver.PromptMessage{{Role: "user", Text: "Use canary_trips and canary_list, then blast_radius and prevalence_first_seen for hosts involved. Assess likelihood of real intrusion. Observation-only."}},
		},
	}
}

func registerMoreTools(srv *mcpserver.Server, c *client, allowMutations bool) error {
	tools := moreReadTools()
	if allowMutations {
		tools = append(tools, moreMutateTools()...)
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	for _, p := range moreReadPrompts() {
		if err := srv.RegisterPrompt(p); err != nil {
			return err
		}
	}
	return nil
}
