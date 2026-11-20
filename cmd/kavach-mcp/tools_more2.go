// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

func more2ReadTools() []endpointTool {
	host := strProp("Host name")
	id := strProp("Case id")
	ro := func(name, path, desc string) endpointTool {
		return endpointTool{name: name, method: "GET", path: path, description: desc, schema: emptySchema()}
	}
	hostOpt := objSchema(map[string]any{"host": host})
	return []endpointTool{
		ro("itdr_summary", "/v1/identity/itdr/summary", "Identity threat detection summary."),
		{name: "itdr_indicators", method: "GET", path: "/v1/identity/itdr/indicators", description: "ITDR indicators, optionally filtered by kind.", schema: objSchema(map[string]any{"kind": strProp("Indicator kind filter")}), queryParams: []string{"kind"}},
		ro("itdr_risk", "/v1/identity/itdr/risk", "Per-user identity risk scores."),
		ro("itdr_privileged", "/v1/identity/itdr/privileged", "Privileged identity activity."),
		{name: "itdr_timeline", method: "GET", path: "/v1/identity/itdr/timeline", description: "Identity timeline for a user.", schema: objSchema(map[string]any{"user": strProp("User name")}, "user"), queryParams: []string{"user"}},
		{name: "vuln_software", method: "GET", path: "/v1/vulns/software", description: "Installed software inventory.", schema: hostOpt, queryParams: []string{"host"}},
		ro("vuln_advisories", "/v1/vulns/advisories", "Loaded vulnerability advisories."),
		{name: "vuln_findings", method: "GET", path: "/v1/vulns/findings", description: "Vulnerability findings matched to software.", schema: hostOpt, queryParams: []string{"host"}},
		ro("vuln_exposure", "/v1/vulns/exposure", "Fleet vulnerability exposure."),
		ro("vuln_top", "/v1/vulns/top", "Top vulnerabilities."),
		{name: "sbom_host", method: "GET", path: "/v1/sbom/{host}", description: "Software bill of materials for a host.", schema: objSchema(map[string]any{"host": host}, "host"), pathParams: []string{"host"}},
		{name: "incidents_correlated", method: "GET", path: "/v1/incidents/correlated", description: "Correlated incidents.", schema: objSchema(map[string]any{"window": strProp("Go duration, e.g. 30m (max 72h)")}), queryParams: []string{"window"}},
		{name: "case_list", method: "GET", path: "/v1/cases", description: "List cases.", schema: objSchema(map[string]any{"status": strProp("Status filter"), "assignee": strProp("Assignee filter")}), queryParams: []string{"status", "assignee"}},
		{name: "case_get", method: "GET", path: "/v1/cases/{id}", description: "Get one case.", schema: objSchema(map[string]any{"id": id}, "id"), pathParams: []string{"id"}},
		{name: "case_export", method: "GET", path: "/v1/cases/{id}/export", description: "Export a case.", schema: objSchema(map[string]any{"id": id}, "id"), pathParams: []string{"id"}},
		ro("hunt_packs", "/v1/hunts/packs", "Available hunt packs."),
		ro("hunt_history", "/v1/hunts/history", "Hunt run history."),
		ro("hunt_schedules", "/v1/hunts/schedules", "Scheduled hunts."),
		ro("devices_removable", "/v1/devices/removable", "Removable device activity."),
		ro("ransomware_risk", "/v1/ransomware/risk", "Fleet ransomware risk."),
		{name: "ransomware_host", method: "GET", path: "/v1/ransomware/host/{host}", description: "Ransomware risk for one host.", schema: objSchema(map[string]any{"host": host}, "host"), pathParams: []string{"host"}},
		ro("containers_risk", "/v1/containers/risk", "Container risk."),
		ro("lateral_edges", "/v1/lateral/edges", "Lateral movement edges."),
	}
}

func more2MutateTools() []endpointTool {
	id := strProp("Case id")
	strs := func(desc string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
	}
	return []endpointTool{
		{name: "case_create", method: "POST", path: "/v1/cases", description: "Create a case.", schema: objSchema(map[string]any{
			"title": strProp("Title"), "severity": strProp("Severity"), "assignee": strProp("Assignee"), "tags": strs("Tags"),
			"finding_ids": strs("Finding ids"), "incident_id": strProp("Incident id"), "notes": strProp("Notes"),
		}, "title"), bodyFields: true},
		{name: "case_update", method: "PATCH", path: "/v1/cases/{id}", description: "Update a case.", schema: objSchema(map[string]any{
			"id": id, "status": strProp("Status"), "severity": strProp("Severity"), "assignee": strProp("Assignee"), "tags": strs("Tags"),
			"link_findings": strs("Finding ids to link"), "resolution": strProp("Resolution"),
		}, "id"), pathParams: []string{"id"}, bodyFields: true},
		{name: "case_comment", method: "POST", path: "/v1/cases/{id}/comments", description: "Add a comment to a case.", schema: objSchema(map[string]any{"id": id, "author": strProp("Author"), "text": strProp("Comment text")}, "id", "text"), pathParams: []string{"id"}, bodyFields: true},
		{name: "hunt_run", method: "POST", path: "/v1/hunts/packs/{id}/run", description: "Run one hunt pack.", schema: objSchema(map[string]any{"id": strProp("Hunt pack id")}, "id"), pathParams: []string{"id"}},
		{name: "hunt_run_all", method: "POST", path: "/v1/hunts/run-all", description: "Run all hunt packs.", schema: emptySchema()},
		{name: "hunt_schedule_add", method: "POST", path: "/v1/hunts/schedules", description: "Schedule a hunt pack.", schema: objSchema(map[string]any{"pack_id": strProp("Hunt pack id"), "interval_sec": moreIntProp("Interval seconds (min 10)")}, "pack_id"), bodyFields: true},
		{name: "hunt_schedule_remove", method: "DELETE", path: "/v1/hunts/schedules", description: "Remove a hunt schedule.", schema: objSchema(map[string]any{"id": strProp("Schedule id")}, "id"), queryParams: []string{"id"}},
	}
}

func more2ReadPrompts() []mcpserver.Prompt {
	return []mcpserver.Prompt{
		{
			Name:        "kavach_ransomware_triage",
			Description: "Triage ransomware risk across the fleet.",
			Messages:    []mcpserver.PromptMessage{{Role: "user", Text: "Use ransomware_risk, then ransomware_host for the riskiest hosts, plus lateral_edges and devices_removable. Summarize likelihood and priorities. Observation-only."}},
		},
		{
			Name:        "kavach_case_review",
			Description: "Review open cases and correlated incidents.",
			Messages:    []mcpserver.PromptMessage{{Role: "user", Text: "Use case_list, case_get and case_export for open cases, and incidents_correlated for unlinked incidents. Summarize status and next steps. Observation-only."}},
		},
	}
}

func registerMore2Tools(srv *mcpserver.Server, c *client, allowMutations bool) error {
	tools := more2ReadTools()
	if allowMutations {
		tools = append(tools, more2MutateTools()...)
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	for _, p := range more2ReadPrompts() {
		if err := srv.RegisterPrompt(p); err != nil {
			return err
		}
	}
	return nil
}
