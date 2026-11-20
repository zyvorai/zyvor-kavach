// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const clusterNote = " Read-only. Clusters show shared indicators/digests among stored reports (no input bytes are kept); they are not proof of a common actor."

func inspectClusterTools() []endpointTool {
	return []endpointTool{
		{name: "inspect_clusters", method: "GET", path: "/v1/inspect/clusters",
			description: "Cluster stored inspector reports by shared IOCs, embedded hashes and similarity digests, with the shared factors that justify each cluster." + clusterNote,
			schema: objSchema(map[string]any{
				"min_score": strProp("Link threshold (sum of shared-factor weights), default 1"),
				"limit":     strProp("Max clusters, default 20, max 50"),
				"kind":      strProp("Restrict to one inspect kind (file, script, ...)"),
			}), queryParams: []string{"min_score", "limit", "kind"}},
		{name: "inspect_sarif", method: "GET", path: "/v1/inspect/sarif",
			description: "Export one stored inspector report as SARIF 2.1.0 JSON (pull-only; for CI code-scanning). Give id (a report id or \"latest\") or sha256." + clusterNote,
			schema: objSchema(map[string]any{
				"id":     strProp("Report id, or \"latest\""),
				"sha256": strProp("SHA-256 of an inspected input (alternative to id)"),
			}), queryParams: []string{"id", "sha256"}},
	}
}

func registerInspectClusterTools(srv *mcpserver.Server, c *client) error {
	for _, t := range inspectClusterTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
