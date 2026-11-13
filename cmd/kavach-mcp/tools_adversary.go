// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// adversaryReadTools are read-only threat-actor profile tools (public-reporting attribution).
func adversaryReadTools() []endpointTool {
	return []endpointTool{
		{name: "adversary_list", method: "GET", path: "/v1/adversaries", description: "List public threat-actor and ransomware profiles; filter by kind, technique or text. Attribution is from public reporting, not detection.",
			schema: objSchema(map[string]any{"kind": strProp("nation-state|cybercrime|ransomware"), "technique": strProp("ATT&CK technique id"), "q": strProp("Text search")}), queryParams: []string{"kind", "technique", "q"}},
		{name: "adversary_profile", method: "GET", path: "/v1/adversaries/{id}", description: "One adversary profile with per-technique Kavach content coverage, coverage percent and gaps.",
			schema: objSchema(map[string]any{"id": strProp("Adversary id, e.g. apt29")}, "id"), pathParams: []string{"id"}},
		{name: "adversary_coverage", method: "GET", path: "/v1/adversaries/coverage", description: "All adversaries ranked by Kavach coverage and by observed ATT&CK hits.", schema: emptySchema()},
	}
}

func registerAdversaryTools(srv *mcpserver.Server, c *client) error {
	for _, t := range adversaryReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
