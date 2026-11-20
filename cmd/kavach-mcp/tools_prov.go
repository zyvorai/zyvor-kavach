// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const provNote = " Provenance here is a heuristic story ranking over retained events, rebuilt in memory per request; it is NOT a kernel provenance system and lacks file read/write/exec syscall edges, IPC/injection edges and short-lived processes. Read the returned caveats/limitations/method/lacks fields. Read-only."

func provTools() []endpointTool {
	return []endpointTool{
		{name: "prov_graph", method: "GET", path: "/v1/prov/graph",
			description: "Process provenance graph (nodes, spawn/connect edges, missing data) for one host, built from retained events." + provNote,
			schema: objSchema(map[string]any{
				"host":  strProp("Host name (required; without it the API returns the host list)"),
				"limit": strProp("Node cap, default 500"),
			}, "host"), queryParams: []string{"host", "limit"}},
		{name: "prov_stories", method: "GET", path: "/v1/prov/stories",
			description: "Ranked attack stories (heuristic score from severity, rarity, tactic diversity and ordering) across hosts or for one host." + provNote,
			schema: objSchema(map[string]any{
				"host":      strProp("Optional host filter"),
				"min_score": strProp("Minimum story score, default 1"),
			}), queryParams: []string{"host", "min_score"}},
		{name: "prov_trace", method: "GET", path: "/v1/prov/trace",
			description: "Trace backward/forward from the process a finding is attached to. May return attached=false with a reason when no pid match exists." + provNote,
			schema: objSchema(map[string]any{
				"finding_id": strProp("Finding id (required)"),
				"dir":        strProp("back (default), fwd or both"),
				"hops":       strProp("Hop count, default 3"),
			}, "finding_id"), queryParams: []string{"finding_id", "dir", "hops"}},
		{name: "prov_status", method: "GET", path: "/v1/prov/status",
			description: "What the provenance graph includes, lacks, its input counts and caps." + provNote,
			schema:      emptySchema()},
	}
}

func registerProvTools(srv *mcpserver.Server, c *client) error {
	for _, t := range provTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
