// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

const schedNote = " Scheduled detections re-run a saved search or a kavach-seq query on an interval and RECORD findings; they never block, kill or contain anything. Runs are bounded by hunt limits (max scheduled, runs per hour, matches per run) and deduplicated; refused runs are counted in hunts_limits_get."

const excNote = " Exceptions suppress REPORTING of matching findings from the main findings list only; suppressed findings are kept in a separate list and detection itself is unchanged. They always expire (max 365 days) and every change is hash-chained in the exception history."

func detSourceProp() map[string]any {
	return map[string]any{"type": "object", "description": "Source: {kind: saved_search|seq, saved_search_id (kind saved_search), query and since (kind seq; since like 24h, 7d or RFC3339)}",
		"properties": map[string]any{
			"kind": strProp("saved_search or seq"), "saved_search_id": strProp("Saved search id (kind saved_search)"),
			"query": strProp("kavach-seq query (kind seq)"), "since": strProp("Lookback for seq, default 24h"),
		}}
}

func detFieldProps() map[string]any {
	return map[string]any{
		"name":             strProp("Name, max 120 chars"),
		"source":           detSourceProp(),
		"interval_sec":     numProp("60-86400, default 3600"),
		"severity":         strProp("info, low, medium or high (critical is not allowed)"),
		"technique":        strProp("Optional ATT&CK id like T1059 or T1059.004"),
		"state":            strProp("draft (default), testing, production or retired"),
		"max_matches":      numProp("Per-run match cap"),
		"max_runtime_ms":   numProp("100-30000"),
		"dedup_window_sec": numProp("60-2592000"),
	}
}

func schedReadTools() []endpointTool {
	id := map[string]any{"id": strProp("Scheduled detection id, e.g. sd-1")}
	return []endpointTool{
		{name: "detections_scheduled_list", method: "GET", path: "/v1/detections/scheduled",
			description: "List scheduled detections with the current hunt limits." + schedNote + " Read-only.",
			schema:      emptySchema()},
		{name: "detections_scheduled_get", method: "GET", path: "/v1/detections/scheduled/{id}",
			description: "One scheduled detection with running flag, shadow findings (draft/testing) and dedup key count." + schedNote + " Read-only.",
			schema:      objSchema(id, "id"), pathParams: []string{"id"}},
		{name: "detections_scheduled_history", method: "GET", path: "/v1/detections/scheduled/{id}/history",
			description: "Run history of one scheduled detection." + schedNote + " Read-only.",
			schema:      objSchema(id, "id"), pathParams: []string{"id"}},
		{name: "detections_scheduled_dryrun", method: "POST", path: "/v1/detections/scheduled/{id}/dryrun",
			description: "Execute one scheduled detection now as a dry run. It is a POST but records nothing: no findings are written; the result shows what WOULD be reported." + schedNote + " Treated as read-only; still needs an admin token on the server.",
			schema:      objSchema(id, "id"), pathParams: []string{"id"}},
		{name: "hunts_limits_get", method: "GET", path: "/v1/hunts/limits",
			description: "Hunt quotas (max scheduled detections, runs per hour, matches per run, history retention), current usage and recent refusals. The PUT that changes limits is not exposed. Read-only.",
			schema:      emptySchema()},
		{name: "exceptions_list", method: "GET", path: "/v1/exceptions",
			description: "List rule exceptions with status and chain verification." + excNote + " Read-only.",
			schema:      objSchema(map[string]any{"status": strProp("Filter by status, e.g. active or expired")}), queryParams: []string{"status"}},
		{name: "exceptions_suppressed", method: "GET", path: "/v1/exceptions/suppressed",
			description: "Findings whose reporting was suppressed by an exception (newest first, up to 200) with per-exception counts." + excNote + " Read-only.",
			schema:      objSchema(map[string]any{"exception": strProp("Filter by exception id")}), queryParams: []string{"exception"}},
		{name: "exceptions_history", method: "GET", path: "/v1/exceptions/history",
			description: "Hash-chained history of exception create/update/expire/delete with chain verification." + excNote + " Read-only.",
			schema:      emptySchema()},
	}
}

func schedMutateTools() []endpointTool {
	id := strProp("Scheduled detection id")
	upd := detFieldProps()
	upd["id"] = id
	exc := func(update bool) map[string]any {
		m := map[string]any{
			"rule":    strProp("Rule id or glob (a bare * is refused)"),
			"host":    strProp("Optional host (empty = all hosts)"),
			"path":    strProp("Optional path pattern"),
			"reason":  strProp("Why this is suppressed (required)"),
			"owner":   strProp("Who owns this exception (required)"),
			"expires": strProp("RFC3339 expiry, in the future and within 365 days (required on create)"),
		}
		if update {
			m["id"] = strProp("Exception id")
		}
		return m
	}
	return []endpointTool{
		{name: "detections_scheduled_create", method: "POST", path: "/v1/detections/scheduled",
			description: "Create a scheduled detection (defaults to state draft: findings stay shadow until promoted). Stores the schedule, adds a rule lifecycle entry and an audit record." + schedNote + mutNote,
			schema:      objSchema(detFieldProps(), "name", "source", "severity"), bodyFields: true},
		{name: "detections_scheduled_update", method: "PUT", path: "/v1/detections/scheduled/{id}",
			description: "Update fields of a scheduled detection (omitted fields keep their value). Changing state to production makes its matches real findings." + schedNote + mutNote,
			schema:      objSchema(upd, "id"), pathParams: []string{"id"}, bodyFields: true},
		{name: "detections_scheduled_delete", method: "DELETE", path: "/v1/detections/scheduled/{id}",
			description: "Delete one scheduled detection and its history, dedup keys and shadow findings; findings it already recorded are kept." + schedNote + mutNote,
			schema:      objSchema(map[string]any{"id": id}, "id"), pathParams: []string{"id"}},
		{name: "detections_scheduled_run", method: "POST", path: "/v1/detections/scheduled/{id}/run",
			description: "Run one scheduled detection now. Unlike the dry run this RECORDS findings (as shadow findings while draft/testing) and a history entry." + schedNote + mutNote,
			schema:      objSchema(map[string]any{"id": id}, "id"), pathParams: []string{"id"}},
		{name: "exceptions_create", method: "POST", path: "/v1/exceptions",
			description: "Create a rule exception. Matching findings stop being reported in the main list (they remain in the suppressed list) until it expires." + excNote + mutNote,
			schema:      objSchema(exc(false), "rule", "reason", "owner", "expires"), bodyFields: true},
		{name: "exceptions_update", method: "PUT", path: "/v1/exceptions/{id}",
			description: "Change fields of an exception (omitted fields keep their value). Widening a rule glob or extending expiry increases what is suppressed from reporting." + excNote + mutNote,
			schema:      objSchema(exc(true), "id"), pathParams: []string{"id"}, bodyFields: true},
		{name: "exceptions_delete", method: "DELETE", path: "/v1/exceptions/{id}",
			description: "Delete an exception record (already suppressed findings stay in the suppressed list). Reporting of matching findings resumes." + excNote + mutNote,
			schema:      objSchema(map[string]any{"id": strProp("Exception id")}, "id"), pathParams: []string{"id"}},
	}
}

// exceptionsExpireTool sends the fixed body {"expire_now":true} so the model cannot
// pass other fields through this tool.
func exceptionsExpireTool(c *client) mcpserver.Tool {
	return mcpserver.Tool{
		Name:        "exceptions_expire",
		Description: "Expire an exception immediately so reporting of matching findings resumes (the record and its history are kept)." + excNote + mutNote,
		InputSchema: objSchema(map[string]any{"id": strProp("Exception id")}, "id"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var args struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &args); err != nil || args.ID == "" {
				return "id is required", true, nil
			}
			out, status, err := c.do(ctx, "PUT", "/v1/exceptions/"+url.PathEscape(args.ID), []byte(`{"expire_now":true}`), nil)
			if err != nil {
				return nil, true, fmt.Errorf("exceptions_expire: %w", err)
			}
			return httpResultToToolResult(out, status)
		},
	}
}

func registerSchedTools(srv *mcpserver.Server, c *client, mut bool) error {
	if err := regEndpoints(srv, c, schedReadTools()); err != nil {
		return err
	}
	if mut {
		if err := regEndpoints(srv, c, schedMutateTools()); err != nil {
			return err
		}
		return srv.Register(exceptionsExpireTool(c))
	}
	return nil
}
