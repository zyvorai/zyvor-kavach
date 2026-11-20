// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// regulatoryReadTools are read-only. Changing the regime profile is deliberately not exposed over MCP.
func regulatoryReadTools() []endpointTool {
	const note = " Informational, not legal advice; Kavach does not file reports."
	return []endpointTool{
		{name: "kavach_regulatory_regimes", method: "GET", path: "/v1/regulatory/regimes", description: "Catalog of regional incident/breach reporting regimes with deadlines, sources and a verified flag (UNVERIFIED entries are not confirmed against an official source)." + note, schema: objSchema(map[string]any{
			"jurisdiction": strProp("Jurisdiction filter, e.g. India"), "verified": enumProp("Filter by verified flag", "true", "false"),
		}), queryParams: []string{"jurisdiction", "verified"}},
		{name: "kavach_regulatory_clocks", method: "GET", path: "/v1/regulatory/clocks", description: "Time remaining or overdue per regime for open high/critical incidents, measured from first detection. Defaults to the configured profile." + note, schema: objSchema(map[string]any{
			"regime": strProp("Comma-separated regime ids (default: configured profile)"),
		}), queryParams: []string{"regime"}},
		{name: "kavach_regulatory_profile", method: "GET", path: "/v1/regulatory/profile", description: "Regimes the operator selected as applicable (read-only)." + note, schema: emptySchema()},
	}
}

func registerRegulatoryTools(srv *mcpserver.Server, c *client) error {
	for _, t := range regulatoryReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
