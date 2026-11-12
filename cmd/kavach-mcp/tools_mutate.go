// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// Mutating tools are only registered when KAVACH_MCP_ALLOW_MUTATIONS=true.
// Containment/RTR/Fusion remain observation-ledgers on the controller —
// nothing here isolates hosts or kills processes.
func registerMutateTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{name: "kavach_hunt_query", method: "POST", path: "/v1/hunt/query", description: "Run FQL-lite hunt query.", schema: objSchema(map[string]any{"query": strProp("e.g. host:demo severity:high")}, "query"), bodyFields: true},
		{name: "kavach_ai_chat", method: "POST", path: "/v1/ai/chat", description: "Send a message to the SOC copilot.", schema: objSchema(map[string]any{"message": strProp("Analyst message")}, "message"), bodyFields: true},
		{name: "kavach_ai_nl_hunt", method: "POST", path: "/v1/ai/nl-hunt", description: "Natural-language threat hunt.", schema: objSchema(map[string]any{"text": strProp("English hypothesis")}, "text"), bodyFields: true},
		{name: "kavach_ai_agents_run", method: "POST", path: "/v1/ai/agents/run", description: "Run a multi-agent SOC role (triage|hunt|intel|ir|reporter).", schema: objSchema(map[string]any{
			"agent": strProp("triage|hunt|intel|ir|reporter"),
			"input": strProp("Optional input for the agent"),
		}, "agent"), bodyFields: true},
		{name: "kavach_ai_what_if", method: "POST", path: "/v1/ai/what-if", description: "Simulate adversary what-if scenario (no host changes).", schema: objSchema(map[string]any{
			"scenario": strProp("e.g. ransomware"),
			"host":     strProp("Target host"),
		}, "scenario"), bodyFields: true},
		{name: "kavach_ai_autopilot", method: "POST", path: "/v1/ai/autopilot", description: "Triage autopilot suggestions (never auto-applies).", schema: emptySchema(), bodyFields: true},
		{name: "kavach_ai_assist", method: "POST", path: "/v1/ai/assist", description: "Assistive triage.", schema: objSchema(map[string]any{
			"question":   strProp("Question"),
			"finding_id": strProp("Finding ID"),
		}), bodyFields: true},
		{name: "kavach_ai_memory_set", method: "POST", path: "/v1/ai/memory", description: "Store analyst memory key/values.", schema: objSchema(map[string]any{"preferred_view": strProp("Example preference key")}), bodyFields: true},
		{name: "kavach_detections_triage", method: "POST", path: "/v1/detections/triage", description: "Triage a detection status/assignee.", schema: objSchema(map[string]any{
			"id":       strProp("Detection ID (det-...)"),
			"status":   strProp("new|in_progress|true_positive|false_positive|ignored|closed"),
			"assignee": strProp("Assignee"),
		}, "id", "status"), bodyFields: true},
		{name: "kavach_incident_transition", method: "POST", path: "/v1/incidents/transition", description: "Transition incident workflow status.", schema: objSchema(map[string]any{
			"finding_id": strProp("Finding ID"),
			"status":     strProp("open|investigating|resolved|false_positive"),
			"note":       strProp("Optional note"),
			"actor":      strProp("Actor (defaults via MCP actor)"),
		}, "finding_id", "status"), bodyFields: true},
		{name: "kavach_ioc_create", method: "POST", path: "/v1/ioc", description: "Create detect-only IOC (never prevent).", schema: objSchema(map[string]any{
			"type":        strProp("sha256|md5|sha1|domain|ipv4|ipv6"),
			"value":       strProp("IOC value"),
			"severity":    strProp("low|medium|high|critical"),
			"description": strProp("Description"),
		}, "type", "value"), bodyFields: true},
		{name: "kavach_ioc_delete", method: "DELETE", path: "/v1/ioc", description: "Delete an IOC by id.", schema: objSchema(map[string]any{"id": strProp("IOC id")}, "id"), queryParams: []string{"id"}},
		{name: "kavach_ioa_create", method: "POST", path: "/v1/ioa", description: "Create custom IOA rule.", schema: objSchema(map[string]any{
			"name":         strProp("Rule name"),
			"pattern":      strProp("Regex/pattern"),
			"severity":     strProp("Severity"),
			"technique_id": strProp("MITRE ID"),
			"description":  strProp("Description"),
		}, "name", "pattern"), bodyFields: true},
		{name: "kavach_prevention_policy_create", method: "POST", path: "/v1/prevention/policies", description: "Create detect-only prevention policy.", schema: objSchema(map[string]any{
			"name":            strProp("Policy name"),
			"ml_sensitivity":  strProp("aggressive|moderate|cautious"),
			"script_control":  map[string]any{"type": "boolean"},
			"ransomware_guard": map[string]any{"type": "boolean"},
		}, "name"), bodyFields: true},
		{name: "kavach_device_control_ingest", method: "POST", path: "/v1/device-control", description: "Ingest USB/device observation (never blocks).", schema: objSchema(map[string]any{
			"host":    strProp("Hostname"),
			"vendor":  strProp("Vendor"),
			"product": strProp("Product"),
			"serial":  strProp("Serial"),
			"action":  strProp("observed|allowed"),
		}, "host"), bodyFields: true},
		{name: "kavach_host_group_create", method: "POST", path: "/v1/host-groups", description: "Create host group.", schema: objSchema(map[string]any{"name": strProp("Group name"), "hosts": strProp("Comma-separated hosts")}, "name"), bodyFields: true},
		{name: "kavach_identity_event_ingest", method: "POST", path: "/v1/identity/events", description: "Ingest identity anomaly event.", schema: objSchema(map[string]any{
			"user":     strProp("User"),
			"host":     strProp("Host"),
			"rule":     strProp("Rule"),
			"severity": strProp("Severity"),
		}, "user"), bodyFields: true},
		{name: "kavach_overwatch_alert_create", method: "POST", path: "/v1/overwatch/alerts", description: "Add OverWatch hunting alert.", schema: objSchema(map[string]any{
			"title":    strProp("Title"),
			"host":     strProp("Host"),
			"severity": strProp("Severity"),
		}, "title"), bodyFields: true},
		{name: "kavach_spotlight_vuln_create", method: "POST", path: "/v1/spotlight/vulnerabilities", description: "Add Spotlight CVE inventory row.", schema: objSchema(map[string]any{
			"cve":      strProp("CVE id"),
			"host":     strProp("Host"),
			"severity": strProp("Severity"),
			"product":  strProp("Product"),
		}, "cve"), bodyFields: true},
		{name: "kavach_fusion_playbook_create", method: "POST", path: "/v1/fusion/playbooks", description: "Create Fusion playbook (ledger).", schema: objSchema(map[string]any{
			"name":    strProp("Playbook name"),
			"trigger": strProp("Trigger"),
		}, "name"), bodyFields: true},
		{name: "kavach_case_create", method: "POST", path: "/v1/cases", description: "Create an investigation case.", schema: objSchema(map[string]any{
			"title":    strProp("Case title"),
			"severity": strProp("Severity"),
			"notes":    strProp("Notes"),
		}, "title"), bodyFields: true},
		{name: "kavach_case_update", method: "POST", path: "/v1/cases/update", description: "Update investigation case status/notes.", schema: objSchema(map[string]any{
			"id":     strProp("Case ID"),
			"status": strProp("open|investigating|closed"),
			"notes":  strProp("Notes"),
		}, "id"), bodyFields: true},
		{name: "kavach_containment_request", method: "POST", path: "/v1/containment", description: "Record containment request (ledger only — never isolates).", schema: objSchema(map[string]any{
			"host":   strProp("Hostname"),
			"action": strProp("contain_request|lift_request"),
			"note":   strProp("Note"),
			"actor":  strProp("Actor"),
		}, "host", "action"), bodyFields: true},
		{name: "kavach_rtr_open", method: "POST", path: "/v1/rtr/sessions", description: "Open read-only RTR session.", schema: objSchema(map[string]any{
			"host":  strProp("Hostname"),
			"actor": strProp("Actor"),
		}, "host"), bodyFields: true},
		{name: "kavach_rtr_execute", method: "POST", path: "/v1/rtr/execute", description: "Execute allowlisted RTR diagnostic (ps|netstat|findings|sensor|help).", schema: objSchema(map[string]any{
			"session_id": strProp("RTR session ID"),
			"command":    strProp("Allowlisted command"),
		}, "session_id", "command"), bodyFields: true},
		{name: "kavach_fusion_run", method: "POST", path: "/v1/fusion/runs", description: "Record Fusion playbook run (ledger only).", schema: objSchema(map[string]any{
			"playbook_id": strProp("Playbook ID"),
			"trigger_ref": strProp("Trigger reference"),
		}, "playbook_id"), bodyFields: true},
		{name: "kavach_agents_enroll", method: "POST", path: "/v1/agents/enroll", description: "Enroll a host agent (returns one-time token).", schema: objSchema(map[string]any{"host": strProp("Hostname")}, "host"), bodyFields: true},
		{name: "kavach_agents_revoke", method: "POST", path: "/v1/agents/revoke", description: "Revoke an enrolled host agent.", schema: objSchema(map[string]any{"host": strProp("Hostname")}, "host"), bodyFields: true},
		{name: "kavach_hunt_kql", method: "POST", path: "/v1/hunt/kql", description: "Advanced hunting KQL-lite query.", schema: objSchema(map[string]any{"query": strProp("KQL-lite query")}, "query"), bodyFields: true},
		{name: "kavach_forensics_request", method: "POST", path: "/v1/forensics", description: "Request forensic package (ledger only).", schema: objSchema(map[string]any{"host": strProp("Hostname"), "scope": strProp("Scope")}, "host"), bodyFields: true},
		{name: "kavach_bas_run", method: "POST", path: "/v1/bas", description: "Schedule BAS simulation (ledger only).", schema: objSchema(map[string]any{"scenario": strProp("Scenario name")}, "scenario"), bodyFields: true},
		{name: "kavach_itsm_create", method: "POST", path: "/v1/itsm/tickets", description: "Create ITSM ticket ledger entry.", schema: objSchema(map[string]any{"title": strProp("Title"), "system": strProp("jira|servicenow")}, "title"), bodyFields: true},
		{name: "kavach_watchlist_create", method: "POST", path: "/v1/watchlists", description: "Create entity watchlist.", schema: objSchema(map[string]any{"name": strProp("Name"), "type": strProp("user|host|ip")}, "name"), bodyFields: true},
		{name: "kavach_exclusion_create", method: "POST", path: "/v1/exclusions", description: "Create detection exclusion.", schema: objSchema(map[string]any{"pattern": strProp("Pattern"), "reason": strProp("Reason")}, "pattern"), bodyFields: true},
		{name: "kavach_rule_create", method: "POST", path: "/v1/rules", description: "Create custom detection rule.", schema: objSchema(map[string]any{"name": strProp("Name"), "query": strProp("Query")}, "name", "query"), bodyFields: true},
		{name: "kavach_deception_trigger", method: "POST", path: "/v1/deception/trigger", description: "Mark deception decoy as triggered.", schema: objSchema(map[string]any{"id": strProp("Decoy ID")}, "id"), bodyFields: true},
		{name: "kavach_inventory_ingest", method: "POST", path: "/v1/inventory", description: "Ingest live domain inventory (casb|email|dlp|cnapp|fim|persistence|firewall|browser|sbom|cloud|mobile|ot|sandbox|…).", schema: objSchema(map[string]any{
			"domain":  strProp("Inventory domain"),
			"host":    strProp("Hostname"),
			"replace": map[string]any{"type": "boolean", "description": "Replace host rows"},
			"items":   map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		}, "domain"), bodyFields: true},
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	_ = c
	return nil
}
