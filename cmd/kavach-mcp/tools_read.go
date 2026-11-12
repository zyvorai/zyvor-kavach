// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

func registerReadTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{name: "kavach_health", method: "GET", path: "/healthz", description: "Controller health check.", schema: emptySchema()},
		{name: "kavach_summary", method: "GET", path: "/v1/summary", description: "Findings/host summary for the console overview.", schema: emptySchema()},
		{name: "kavach_findings", method: "GET", path: "/v1/findings", description: "List EDR findings (optional severity/rule/host filters).", schema: objSchema(map[string]any{
			"severity": strProp("low|medium|high|critical"),
			"rule":     strProp("Substring match on rule name"),
			"host":     strProp("Substring match on hostname"),
		}), queryParams: []string{"severity", "rule", "host"}},
		{name: "kavach_detections", method: "GET", path: "/v1/detections", description: "Falcon-style detections with MITRE mapping.", schema: objSchema(map[string]any{
			"severity": strProp("Filter severity"),
			"status":   strProp("new|in_progress|true_positive|false_positive|ignored|closed"),
			"host":     strProp("Hostname filter"),
		}), queryParams: []string{"severity", "status", "host"}},
		{name: "kavach_incidents", method: "GET", path: "/v1/incidents", description: "Incident workflow state for findings.", schema: emptySchema()},
		{name: "kavach_recent_events", method: "GET", path: "/v1/recent-events", description: "Recent process and network events.", schema: emptySchema()},
		{name: "kavach_fleet", method: "GET", path: "/v1/fleet", description: "Enrolled agent fleet status.", schema: emptySchema()},
		{name: "kavach_hosts", method: "GET", path: "/v1/hosts", description: "Host management inventory.", schema: emptySchema()},
		{name: "kavach_host_groups", method: "GET", path: "/v1/host-groups", description: "Host groups.", schema: emptySchema()},
		{name: "kavach_agents", method: "GET", path: "/v1/agents", description: "Agent credential registry status.", schema: emptySchema()},
		{name: "kavach_sensor", method: "GET", path: "/v1/sensor", description: "Sensor backend, Netra poller, SIEM probe.", schema: emptySchema()},
		{name: "kavach_siem_status", method: "GET", path: "/v1/siem/status", description: "SIEM export sink status.", schema: emptySchema()},
		{name: "kavach_siem_export", method: "GET", path: "/v1/siem/export", description: "Download SIEM NDJSON export.", schema: emptySchema()},
		{name: "kavach_ioc", method: "GET", path: "/v1/ioc", description: "IOC management list (detect-only).", schema: emptySchema()},
		{name: "kavach_ioa", method: "GET", path: "/v1/ioa", description: "Custom IOA rules.", schema: emptySchema()},
		{name: "kavach_prevention_policies", method: "GET", path: "/v1/prevention/policies", description: "Prevention policies (detect-only mode).", schema: emptySchema()},
		{name: "kavach_containment", method: "GET", path: "/v1/containment", description: "Containment request ledger (never enforced).", schema: emptySchema()},
		{name: "kavach_rtr_commands", method: "GET", path: "/v1/rtr/commands", description: "RTR read-only command allowlist.", schema: emptySchema()},
		{name: "kavach_rtr_sessions", method: "GET", path: "/v1/rtr/sessions", description: "Open RTR sessions.", schema: emptySchema()},
		{name: "kavach_device_control", method: "GET", path: "/v1/device-control", description: "USB/device control inventory.", schema: emptySchema()},
		{name: "kavach_firewall_rules", method: "GET", path: "/v1/firewall/rules", description: "Host firewall inventory.", schema: emptySchema()},
		{name: "kavach_discover_assets", method: "GET", path: "/v1/discover/assets", description: "Discover asset inventory.", schema: emptySchema()},
		{name: "kavach_discover_apps", method: "GET", path: "/v1/discover/apps", description: "Discover application inventory.", schema: emptySchema()},
		{name: "kavach_spotlight", method: "GET", path: "/v1/spotlight/vulnerabilities", description: "Spotlight CVE inventory.", schema: objSchema(map[string]any{"severity": strProp("Filter severity")}), queryParams: []string{"severity"}},
		{name: "kavach_overwatch", method: "GET", path: "/v1/overwatch/alerts", description: "OverWatch managed hunting alerts.", schema: emptySchema()},
		{name: "kavach_intel_actors", method: "GET", path: "/v1/intel/actors", description: "Threat actor profiles.", schema: emptySchema()},
		{name: "kavach_intel_indicators", method: "GET", path: "/v1/intel/indicators", description: "Threat intel indicators.", schema: objSchema(map[string]any{"q": strProp("Search query")}), queryParams: []string{"q"}},
		{name: "kavach_identity_events", method: "GET", path: "/v1/identity/events", description: "Identity threat events.", schema: emptySchema()},
		{name: "kavach_identity_entities", method: "GET", path: "/v1/identity/entities", description: "Identity entities with risk scores.", schema: emptySchema()},
		{name: "kavach_ueba", method: "GET", path: "/v1/ueba", description: "UEBA entity scores.", schema: emptySchema()},
		{name: "kavach_fusion_playbooks", method: "GET", path: "/v1/fusion/playbooks", description: "Fusion SOAR playbooks.", schema: emptySchema()},
		{name: "kavach_fusion_runs", method: "GET", path: "/v1/fusion/runs", description: "Fusion playbook run ledger.", schema: emptySchema()},
		{name: "kavach_cases", method: "GET", path: "/v1/cases", description: "Case management list.", schema: emptySchema()},
		{name: "kavach_threat_graph", method: "GET", path: "/v1/threat-graph", description: "Threat correlation graph nodes/edges.", schema: emptySchema()},
		{name: "kavach_audit", method: "GET", path: "/v1/audit", description: "Console audit log.", schema: emptySchema()},
		{name: "kavach_report_summary", method: "GET", path: "/v1/reports/summary", description: "SOC summary report.", schema: emptySchema()},
		{name: "kavach_modules", method: "GET", path: "/v1/modules", description: "Falcon/beyond-Falcon module capability map.", schema: emptySchema()},
		{name: "kavach_connectors", method: "GET", path: "/v1/connectors", description: "Connector registry.", schema: emptySchema()},
		{name: "kavach_cloud_posture", method: "GET", path: "/v1/cloud/posture", description: "Cloud CSPM posture (preview).", schema: emptySchema()},
		{name: "kavach_mobile_devices", method: "GET", path: "/v1/mobile/devices", description: "Mobile devices (preview).", schema: emptySchema()},

		// AI — beyond Falcon Charlotte
		{name: "kavach_ai_capabilities", method: "GET", path: "/v1/ai/capabilities", description: "List 22+ Kavach AI capabilities beyond Falcon.", schema: emptySchema()},
		{name: "kavach_ai_scores", method: "GET", path: "/v1/ai/scores", description: "Assistive risk scores for all findings.", schema: emptySchema()},
		{name: "kavach_ai_score", method: "GET", path: "/v1/ai/score", description: "Assistive risk score for one finding.", schema: objSchema(map[string]any{"id": strProp("Finding ID")}, "id"), queryParams: []string{"id"}},
		{name: "kavach_ai_chat_history", method: "GET", path: "/v1/ai/chat", description: "SOC copilot chat history.", schema: emptySchema()},
		{name: "kavach_ai_cluster", method: "GET", path: "/v1/ai/cluster", description: "AI alert clusters / dedup groups.", schema: emptySchema()},
		{name: "kavach_ai_forecast", method: "GET", path: "/v1/ai/forecast", description: "72h breach risk forecast.", schema: emptySchema()},
		{name: "kavach_ai_briefing", method: "GET", path: "/v1/ai/briefing", description: "Daily SOC AI briefing.", schema: emptySchema()},
		{name: "kavach_ai_agents", method: "GET", path: "/v1/ai/agents", description: "Multi-agent SOC roles (triage/hunt/intel/ir/reporter).", schema: emptySchema()},
		{name: "kavach_ai_narrative", method: "GET", path: "/v1/ai/narrative", description: "Incident narrative (omit id for environment brief).", schema: objSchema(map[string]any{"id": strProp("Finding ID (optional)")}), queryParams: []string{"id"}},
		{name: "kavach_ai_attack_path", method: "GET", path: "/v1/ai/attack-path", description: "Predicted adversary attack path.", schema: objSchema(map[string]any{"id": strProp("Finding ID"), "host": strProp("Host")}), queryParams: []string{"id", "host"}},
		{name: "kavach_ai_similarity", method: "GET", path: "/v1/ai/similarity", description: "Nearest-neighbor similar findings.", schema: objSchema(map[string]any{"id": strProp("Finding ID")}, "id"), queryParams: []string{"id"}},
		{name: "kavach_ai_classify", method: "GET", path: "/v1/ai/classify", description: "Behavior family classifier (optional id).", schema: objSchema(map[string]any{"id": strProp("Finding ID")}), queryParams: []string{"id"}},
		{name: "kavach_ai_fp_score", method: "GET", path: "/v1/ai/fp-score", description: "False-positive likelihood for a finding.", schema: objSchema(map[string]any{"id": strProp("Finding ID")}, "id"), queryParams: []string{"id"}},
		{name: "kavach_ai_remediation", method: "GET", path: "/v1/ai/remediation", description: "Remediation advisor (guidance only).", schema: objSchema(map[string]any{"id": strProp("Finding ID")}, "id"), queryParams: []string{"id"}},
		{name: "kavach_ai_report", method: "GET", path: "/v1/ai/report", description: "Auto-generated markdown incident/environment report.", schema: objSchema(map[string]any{"id": strProp("Finding ID (optional)")}), queryParams: []string{"id"}},
		{name: "kavach_ai_playbook_suggest", method: "GET", path: "/v1/ai/playbook-suggest", description: "Suggest Fusion playbooks for a finding.", schema: objSchema(map[string]any{"id": strProp("Finding ID")}), queryParams: []string{"id"}},
		{name: "kavach_ai_anomaly", method: "GET", path: "/v1/ai/anomaly", description: "Deep anomaly scores for recent entities.", schema: emptySchema()},
		{name: "kavach_ai_stream", method: "GET", path: "/v1/ai/stream", description: "Event stream analyst summary.", schema: emptySchema()},
		{name: "kavach_ai_guardian", method: "GET", path: "/v1/ai/guardian", description: "AI workload Guardian observations.", schema: emptySchema()},
		{name: "kavach_ai_xdr_fusion", method: "GET", path: "/v1/ai/xdr-fusion", description: "Netra×Kavach AI Fusion correlation.", schema: emptySchema()},
		{name: "kavach_ai_embeddings", method: "GET", path: "/v1/ai/embeddings", description: "Finding feature vectors (optional id).", schema: objSchema(map[string]any{"id": strProp("Finding ID")}), queryParams: []string{"id"}},
		{name: "kavach_ai_memory", method: "GET", path: "/v1/ai/memory", description: "Analyst memory preferences.", schema: emptySchema()},
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
