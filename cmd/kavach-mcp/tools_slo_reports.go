// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const repSchedNote = " Scheduled reports are rendered by Kavach and stored locally; delivery is pull-only (Kavach never emails or pushes them). Reports honour data-governance redaction, but host names in 'hosts' sections are only masked where they look like IP addresses."

const sloNote = " Fleet SLOs measure agent heartbeat freshness, telemetry continuity and coverage as seen by the controller (sampled every 5 minutes); they describe Kavach's own visibility of agents, not host security."

func reportFieldProps() map[string]any {
	return map[string]any{
		"name":         strProp("Schedule name"),
		"template":     strProp("Report template id"),
		"params":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Template parameters (string values)"},
		"frequency":    strProp("hourly, daily, weekly or monthly"),
		"time":         strProp("HH:MM UTC (daily, weekly, monthly)"),
		"minute":       numProp("Minute past the hour (hourly only)"),
		"weekday":      strProp("Weekday (weekly)"),
		"day_of_month": numProp("Day of month (monthly)"),
		"retention":    numProp("How many rendered runs to keep"),
		"format":       strProp("Output format"),
		"enabled":      boolProp("Defaults to true"),
	}
}

func sloReportsReadTools() []endpointTool {
	return []endpointTool{
		{name: "reports_scheduled_list", method: "GET", path: "/v1/reports/scheduled",
			description: "List scheduled reports, available host-name templates and limits." + repSchedNote + " Read-only.",
			schema:      emptySchema()},
		{name: "reports_scheduled_runs", method: "GET", path: "/v1/reports/scheduled/{id}/runs",
			description: "Recent runs of one scheduled report (with archive run ids)." + repSchedNote + " Read-only.",
			schema:      objSchema(map[string]any{"id": strProp("Schedule id")}, "id"), pathParams: []string{"id"}},
		{name: "fleet_slo", method: "GET", path: "/v1/fleet/slo",
			description: "Current fleet SLO report against the configured targets." + sloNote + " Read-only.",
			schema:      emptySchema()},
		{name: "fleet_slo_history", method: "GET", path: "/v1/fleet/slo/history",
			description: "SLO sample history for the fleet or one agent." + sloNote + " Read-only.",
			schema:      objSchema(map[string]any{"window": strProp("Duration 5m-72h, e.g. 6h or 2d (default 24h)"), "agent": strProp("Optional agent id")}),
			queryParams: []string{"window", "agent"}},
		{name: "fleet_slo_definitions", method: "GET", path: "/v1/fleet/slo/definitions",
			description: "How each fleet SLO is defined and computed." + sloNote + " Read-only.",
			schema:      emptySchema()},
	}
}

func sloReportsMutateTools() []endpointTool {
	f := reportFieldProps()
	fu := reportFieldProps()
	fu["id"] = strProp("Schedule id")
	return []endpointTool{
		{name: "reports_scheduled_create", method: "POST", path: "/v1/reports/scheduled",
			description: "Create a scheduled report. Stores the schedule; Kavach will render and archive reports locally on that schedule." + repSchedNote + mutNote,
			schema:      objSchema(f, "name", "template", "frequency"), bodyFields: true},
		{name: "reports_scheduled_update", method: "PUT", path: "/v1/reports/scheduled/{id}",
			description: "Replace a scheduled report's definition (a full replacement, not a patch: send every field you want kept)." + repSchedNote + mutNote,
			schema:      objSchema(fu, "id", "name", "template", "frequency"), pathParams: []string{"id"}, bodyFields: true},
		{name: "reports_scheduled_delete", method: "DELETE", path: "/v1/reports/scheduled/{id}",
			description: "Delete a scheduled report definition." + repSchedNote + mutNote,
			schema:      objSchema(map[string]any{"id": strProp("Schedule id")}, "id"), pathParams: []string{"id"}},
		{name: "reports_scheduled_run", method: "POST", path: "/v1/reports/scheduled/{id}/run",
			description: "Run a scheduled report now: renders it and stores it in the local report archive (counts against archive limits)." + repSchedNote + mutNote,
			schema:      objSchema(map[string]any{"id": strProp("Schedule id")}, "id"), pathParams: []string{"id"}},
		{name: "fleet_slo_set", method: "PUT", path: "/v1/fleet/slo",
			description: "Change fleet SLO targets and thresholds (omitted fields keep their current value). Only changes how Kavach scores its own agent visibility." + sloNote + mutNote,
			schema: objSchema(map[string]any{
				"heartbeat_fresh_minutes": numProp("1-1440"), "heartbeat_target_pct": map[string]any{"type": "number", "description": "(0,100]"},
				"continuity_gap_minutes": numProp("5-1440"), "continuity_target_pct": map[string]any{"type": "number", "description": "(0,100]"},
				"coverage_target_pct": map[string]any{"type": "number", "description": "(0,100]"}, "window_hours": numProp("1-72"),
			}), bodyFields: true},
	}
}

func registerSLOReportsTools(srv *mcpserver.Server, c *client, mut bool) error {
	if err := regEndpoints(srv, c, sloReportsReadTools()); err != nil {
		return err
	}
	if mut {
		return regEndpoints(srv, c, sloReportsMutateTools())
	}
	return nil
}
