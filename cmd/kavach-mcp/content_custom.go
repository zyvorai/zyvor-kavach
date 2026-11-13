// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// contentCustomReadTools are the read-only custom-content tools. Export is a POST because it takes a
// filter body, but it never changes state, so it is available without --allow-mutations.
func contentCustomReadTools() []endpointTool {
	return []endpointTool{
		{name: "content_custom_list", method: "GET", path: "/v1/content/custom", description: "List customer-authored detection content rules (source=custom). Pass tests=1 to include samples.", schema: objSchema(map[string]any{"tests": strProp("Set to 1 to include positive/negative samples")}), queryParams: []string{"tests"}},
		{name: "content_custom_export", method: "POST", path: "/v1/content/export", description: "Export detection content as a JSON pack, custom rules by default (read-only).", schema: objSchema(map[string]any{
			"source": strProp("custom (default), embedded or all"), "ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Rule ids"},
			"tactic": strProp("ATT&CK tactic"), "technique": strProp("ATT&CK technique id"), "os": strProp("linux|macos|windows|any"), "batch": strProp("Batch label"), "event_type": strProp("Event type"),
		}), bodyFields: true},
	}
}

func registerContentCustomTools(srv *mcpserver.Server, c *client) error {
	for _, t := range contentCustomReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
