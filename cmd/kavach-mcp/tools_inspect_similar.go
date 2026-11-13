// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const similarNote = " Similarity digests are Kavach-native (kavach-ctph1 / kavach-lsh1), NOT ssdeep or TLSH compatible, and a match never proves maliciousness. Only digests are kept, no file bytes. Read-only."

func inspectSimilarTools() []endpointTool {
	return []endpointTool{
		{name: "inspect_similar", method: "GET", path: "/v1/inspect/similar",
			description: "Nearest earlier inspected files by similarity digest. Give sha256 of a known submission or a kavach-ctph1:/kavach-lsh1: digest." + similarNote,
			schema: objSchema(map[string]any{
				"sha256": strProp("SHA-256 of an earlier submission (use this or digest)"),
				"digest": strProp("kavach-ctph1:... or kavach-lsh1:... digest"),
				"limit":  strProp("Max matches, default 10, max 50"),
			}), queryParams: []string{"sha256", "digest", "limit"}},
	}
}

func registerInspectSimilarTools(srv *mcpserver.Server, c *client) error {
	for _, t := range inspectSimilarTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
