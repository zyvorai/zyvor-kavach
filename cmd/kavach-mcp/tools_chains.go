// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const chainsNote = " Attack chains are heuristic groupings of related findings ranked by a score; they are NOT attribution of an actor, and the tactic-gap questions are hints, not findings."

func chainsReadTools() []endpointTool {
	return []endpointTool{
		{name: "chains_list", method: "GET", path: "/v1/chains",
			description: "List computed attack chains." + chainsNote + " Read-only.",
			schema:      objSchema(map[string]any{"host": strProp("Optional host filter"), "min_score": strProp("Minimum chain score"), "limit": strProp("1-200, default 50")}),
			queryParams: []string{"host", "min_score", "limit"}},
		{name: "chains_get", method: "GET", path: "/v1/chains/{id}",
			description: "One chain with members, timeline, links and suggested questions." + chainsNote + " Read-only.",
			schema:      objSchema(map[string]any{"id": strProp("Chain id")}, "id"), pathParams: []string{"id"}},
	}
}

func chainsMutateTools() []endpointTool {
	return []endpointTool{
		{name: "chain_create_case", method: "POST", path: "/v1/chains/{id}/case",
			description: "Create an investigation case from a chain (idempotent: returns the existing case with created=false when one was already made). Adds a case record and a comment in Kavach's case store only." + mutNote,
			schema:      objSchema(map[string]any{"id": strProp("Chain id")}, "id"), pathParams: []string{"id"}},
	}
}

func registerChainsTools(srv *mcpserver.Server, c *client, mut bool) error {
	if err := regEndpoints(srv, c, chainsReadTools()); err != nil {
		return err
	}
	if mut {
		return regEndpoints(srv, c, chainsMutateTools())
	}
	return nil
}
