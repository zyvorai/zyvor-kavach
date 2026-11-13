// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const seqNote = " kavach-seq is a sequence/EQL-style query over retained events with bounded scan, match and time budgets; results can be truncated, timed out or scan-capped (read truncated, timed_out, scan_capped, semantics). It cannot see events that were never collected. POST is used only to carry the query: nothing is recorded or changed. Read-only."

func seqTools() []endpointTool {
	query := strProp("kavach-seq query text (request body max 16 KiB)")
	since := strProp("Lookback: 24h, 7d or RFC3339; server default if omitted")
	return []endpointTool{
		{name: "hunt_seq", method: "POST", path: "/v1/hunt/seq",
			description: "Run a kavach-seq sequence hunt over retained events and return matches." + seqNote,
			schema:      objSchema(map[string]any{"query": query, "since": since, "limit": numProp("Max matches")}, "query"), bodyFields: true},
		{name: "hunt_seq_fields", method: "GET", path: "/v1/hunt/seq/fields",
			description: "Queryable event categories, fields, operators, join keys and query limits for kavach-seq." + seqNote,
			schema:      emptySchema()},
		{name: "hunt_seq_explain", method: "POST", path: "/v1/hunt/seq/explain",
			description: "Parse a kavach-seq query and return its tree and any unavailable fields without running it." + seqNote,
			schema:      objSchema(map[string]any{"query": query, "since": since}, "query"), bodyFields: true},
		{name: "hunt_seq_examples", method: "GET", path: "/v1/hunt/seq/examples",
			description: "Example kavach-seq queries." + seqNote,
			schema:      emptySchema()},
	}
}

func registerSeqTools(srv *mcpserver.Server, c *client) error {
	return regEndpoints(srv, c, seqTools())
}
