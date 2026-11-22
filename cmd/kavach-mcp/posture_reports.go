// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// postureReportTools are read-only. The snapshot interval is admin config and is not exposed over MCP;
// the auditor bundle zip is not returned over MCP, only its manifest.
func postureReportTools() []endpointTool {
	const note = " Read-only, observation-only, counts only; Kavach never sends or emails this."
	return []endpointTool{
		{name: "kavach_posture_trend", method: "GET", path: "/v1/posture/trend", description: "Capped history of posture snapshots: compliance score, ATT&CK coverage, findings by severity, SLO budget, rule health." + note, schema: objSchema(map[string]any{
			"days": numProp("Look-back window in days, 1..400 (default 30)"),
		}), queryParams: []string{"days"}},
		{name: "kavach_posture_diff", method: "GET", path: "/v1/posture/trend/diff", description: "Difference between the posture snapshots at or before two UTC dates." + note, schema: objSchema(map[string]any{
			"from": strProp("Start date YYYY-MM-DD"), "to": strProp("End date YYYY-MM-DD (default latest)"),
		}, "from"), queryParams: []string{"from", "to"}},
		{name: "kavach_exec_digest", method: "GET", path: "/v1/reports/digest", description: "Executive weekly digest; every statement lists the measured factors it rests on, unmeasured items are listed as not assessed." + note, schema: objSchema(map[string]any{
			"days": numProp("Comparison period in days, 1..90 (default 7)"), "format": enumProp("Output format", "json", "md", "html"),
		}), queryParams: []string{"days", "format"}},
		{name: "kavach_auditor_bundle_manifest", method: "GET", path: "/v1/compliance/auditor-bundle?manifest=1", description: "Manifest (files, sizes, SHA-256, caveats) of the auditor evidence bundle. Download the zip itself with kavachctl auditor-bundle or the console." + note, schema: emptySchema()},
	}
}

func registerPostureReportTools(srv *mcpserver.Server, c *client) error {
	for _, t := range postureReportTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
