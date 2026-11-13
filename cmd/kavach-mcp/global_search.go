// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// globalSearchTools exposes cross-entity search. Read-only.
func globalSearchTools() []endpointTool {
	return []endpointTool{
		{name: "global_search", method: "GET", path: "/v1/search",
			description: "Search findings, hosts, content rules, hunt packs, queries, guidance, ATT&CK techniques, CVEs, IOCs, cases and saved searches. Results are typed and scored (exact id > prefix > substring) with a console route hint.",
			schema: objSchema(map[string]any{
				"q":     strProp("Search text, at least 2 characters (plain substring, not a regex)"),
				"types": strProp("Comma-separated filter: finding,host,rule,huntpack,query,guidance,technique,cve,ioc,case,saved"),
				"limit": strProp("Max results, default 20, max 100"),
			}, "q"), queryParams: []string{"q", "types", "limit"}},
	}
}

func registerGlobalSearchTools(srv *mcpserver.Server, c *client) error {
	for _, t := range globalSearchTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
