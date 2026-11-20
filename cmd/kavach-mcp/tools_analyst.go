// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/zyvorai/zyvor-kavach/internal/mcpserver"
)

const (
	exportDefaultRows = 200
	exportMaxRows     = 1000
)

func enumProp(desc string, vals ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": vals}
}

// registerAnalystReadTools adds risk, trend, export, analyst-workspace and
// alert-visibility read tools. Alert rule/webhook create/delete are
// deliberately NOT exposed (SSRF / notification risk); humans manage those.
func registerAnalystReadTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{name: "kavach_risk_hosts", method: "GET", path: "/v1/risk/hosts", description: "Per-host decayed risk scores and bands.", schema: emptySchema()},
		{name: "kavach_risk_summary", method: "GET", path: "/v1/risk/summary", description: "Fleet risk index, band and host counts per band.", schema: emptySchema()},
		{name: "kavach_trends", method: "GET", path: "/v1/trends", description: "Finding trends over time.", schema: objSchema(map[string]any{
			"days":   enumProp("Window in days", "7", "14", "30"),
			"bucket": enumProp("Bucket size", "hour", "day"),
		}), queryParams: []string{"days", "bucket"}},
		{name: "kavach_notes", method: "GET", path: "/v1/notes", description: "Analyst notes for a finding.", schema: objSchema(map[string]any{"finding_id": strProp("Finding ID")}, "finding_id"), queryParams: []string{"finding_id"}},
		{name: "kavach_saved_searches", method: "GET", path: "/v1/saved-searches", description: "Saved analyst searches.", schema: emptySchema()},
		{name: "kavach_alert_rules", method: "GET", path: "/v1/alerts/rules", description: "Configured alert rules (read-only; managed by humans).", schema: emptySchema()},
		{name: "kavach_alert_deliveries", method: "GET", path: "/v1/alerts/deliveries", description: "Recent alert delivery attempts.", schema: emptySchema()},
		{name: "kavach_journal", method: "GET", path: "/v1/journal", description: "Tamper-evident analyst activity journal.", schema: emptySchema()},
		{name: "kavach_journal_verify", method: "GET", path: "/v1/journal/verify", description: "Verify the journal hash chain.", schema: emptySchema()},
	}
	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return registerExportFindings(srv, c)
}

// registerExportFindings wraps /v1/export/findings with a small row cap so
// tool output stays bounded. CSV is intentionally not offered.
func registerExportFindings(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "kavach_export_findings",
		Description: "Export findings as json or ndjson rows (capped, default 200).",
		InputSchema: objSchema(map[string]any{
			"format":   enumProp("Output format", "json", "ndjson"),
			"severity": strProp("low|medium|high|critical"),
			"host":     strProp("Exact hostname"),
			"rule":     strProp("Exact rule name"),
			"since":    strProp("RFC3339 timestamp lower bound"),
			"limit":    map[string]any{"type": "integer", "description": "Max rows returned (default 200, max 1000)", "minimum": 1, "maximum": exportMaxRows},
		}),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			args := map[string]any{}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &args); err != nil {
					return fmt.Sprintf("invalid arguments: %v", err), true, nil
				}
			}
			format, _ := args["format"].(string)
			if format == "" {
				format = "json"
			}
			if format != "json" && format != "ndjson" {
				return "format must be json or ndjson", true, nil
			}
			limit := exportDefaultRows
			if v, ok := args["limit"].(float64); ok {
				limit = int(v)
			}
			if limit < 1 || limit > exportMaxRows {
				return fmt.Sprintf("limit must be between 1 and %d", exportMaxRows), true, nil
			}
			q := url.Values{"format": {format}}
			for _, k := range []string{"severity", "host", "rule", "since"} {
				if v, ok := args[k].(string); ok && v != "" {
					q.Set(k, v)
				}
			}
			out, status, err := c.do(ctx, "GET", "/v1/export/findings?"+q.Encode(), nil, nil)
			if err != nil {
				return nil, true, err
			}
			if status < 200 || status >= 300 {
				return httpResultToToolResult(out, status)
			}
			var rows []json.RawMessage
			if format == "json" {
				if err := json.Unmarshal(out, &rows); err != nil {
					return "unexpected export response: " + err.Error(), true, nil
				}
			} else {
				for _, line := range bytes.Split(out, []byte("\n")) {
					if len(bytes.TrimSpace(line)) > 0 {
						rows = append(rows, json.RawMessage(line))
					}
				}
			}
			total := len(rows)
			if total > limit {
				rows = rows[:limit]
			}
			return map[string]any{"format": format, "total": total, "returned": len(rows), "truncated": total > limit, "limit": limit, "rows": rows}, false, nil
		},
	})
}
