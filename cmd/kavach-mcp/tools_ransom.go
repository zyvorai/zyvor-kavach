// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const ransomNote = " Metadata-only detector: it sees only file path, size and rate (no contents, no writing process) and has known evasions such as slow-and-low encryption spread over hours; thresholds are heuristics, not fleet-fitted. Report-only, never blocks. Read the returned cannot_see/note fields. Read-only."

func ransomTools() []endpointTool {
	return []endpointTool{
		{name: "ransom_status", method: "GET", path: "/v1/ransom/status",
			description: "Ransomware detector method, thresholds, alert rule and what it cannot see." + ransomNote,
			schema:      emptySchema()},
		{name: "ransom_hosts", method: "GET", path: "/v1/ransom/hosts",
			description: "Per-host ransomware behaviour scores from retained file events." + ransomNote,
			schema:      emptySchema()},
		{name: "ransom_host", method: "GET", path: "/v1/ransom/host",
			description: "Sliding-window indicator history for one host." + ransomNote,
			schema: objSchema(map[string]any{
				"host":  strProp("Host name (required)"),
				"limit": strProp("Max windows (latest kept), default and max 500"),
			}, "host"), queryParams: []string{"host", "limit"}},
	}
}

func registerRansomTools(srv *mcpserver.Server, c *client) error {
	for _, t := range ransomTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
