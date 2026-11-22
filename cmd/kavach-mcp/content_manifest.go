// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// contentManifestTools are read-only; creating a snapshot (POST) is not exposed over MCP.
func contentManifestTools() []endpointTool {
	return []endpointTool{
		{name: "content_manifest", method: "GET", path: "/v1/content/manifest", description: "Rule-pack manifest: per-pack SHA-256, rule counts, batches, per-rule hashes, optional detached HMAC (integrity check, not a PKI).", schema: objSchema(map[string]any{})},
		{name: "content_snapshots", method: "GET", path: "/v1/content/snapshots", description: "Stored manifest snapshots (counts and hashes only), newest first.", schema: objSchema(map[string]any{})},
		{name: "content_diff", method: "GET", path: "/v1/content/diff", description: "Rule-level diff between manifest snapshots or the embedded set: added, removed, changed (severity, patterns, attack_mapping, enabled_state).", schema: objSchema(map[string]any{
			"from": strProp("Snapshot seq, latest or embedded (default latest)"), "to": strProp("Snapshot seq, latest or embedded (default embedded)")}), queryParams: []string{"from", "to"}},
	}
}

func registerContentManifestTools(srv *mcpserver.Server, c *client) error {
	for _, t := range contentManifestTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
