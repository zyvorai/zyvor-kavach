// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const mlNote = " Local statistical model trained on this deployment's own retained telemetry; it can return not_enough_data or low-confidence output and is advisory, not a verdict. Read-only."

// mlTools are the read-only local-model tools. Reset and replay are deliberately not exposed.
func mlTools() []endpointTool {
	return []endpointTool{
		{name: "ml_status", method: "GET", path: "/v1/ml/status",
			description: "Status of the local behaviour models (what they have learned, sample counts, readiness)." + mlNote,
			schema:      emptySchema()},
		{name: "ml_lineage", method: "GET", path: "/v1/ml/lineage",
			description: "Rarest parent-to-child process lineages seen in the fleet, optionally for one host." + mlNote,
			schema: objSchema(map[string]any{
				"host":  strProp("Optional host filter"),
				"limit": strProp("Max results, default 20, max 100"),
			}), queryParams: []string{"host", "limit"}},
		{name: "ml_similar", method: "GET", path: "/v1/ml/similar",
			description: "Find previously seen command lines similar to the given one (similarity model)." + mlNote,
			schema: objSchema(map[string]any{
				"q":    strProp("Command line to compare, 1-2048 bytes"),
				"host": strProp("Optional host filter"),
			}, "q"), queryParams: []string{"q", "host"}},
		{name: "ml_baseline", method: "GET", path: "/v1/ml/baseline",
			description: "Per-host behavioural baseline and deviations from it." + mlNote,
			schema:      objSchema(map[string]any{"host": strProp("Host name (required)")}, "host"), queryParams: []string{"host"}},
		{name: "ml_beacons", method: "GET", path: "/v1/ml/beacons",
			description: "Score outbound connection series for beaconing (periodicity and jitter). Series with too few events are counted as not_enough_data." + mlNote,
			schema: objSchema(map[string]any{
				"host":            strProp("Optional host filter"),
				"min_events":      strProp("Minimum events per series, 4-100000"),
				"min_score":       strProp("Only return suspects at or above this score"),
				"limit":           strProp("Max suspects, default 20, max 200"),
				"exclude_private": strProp("Set to 1 or true to exclude private destinations"),
			}), queryParams: []string{"host", "min_events", "min_score", "limit", "exclude_private"}},
		{name: "ml_synthesize", method: "POST", path: "/v1/ml/synthesize",
			description: "Propose a detection rule from exactly one source: a finding_id, a command line, or an event object. It only PROPOSES a rule and changes no state; the analyst reviews it and saves it separately through the content tools." + mlNote,
			schema: objSchema(map[string]any{
				"finding_id": strProp("Finding id to generalise (provide exactly one of finding_id, command, event)"),
				"command":    strProp("Command line, max 4096 bytes"),
				"event":      map[string]any{"type": "object", "description": "Event object (kind, host, executable, parent_exe, command, path, destination, ...)"},
			}), bodyFields: true},
		{name: "ml_priority", method: "GET", path: "/v1/ml/priority",
			description: "Advisory 0-100 priority score fusing severity, rarity, beaconing, asset criticality and rule trust, for one finding or a ranked list. Absent factors are listed as omitted." + mlNote,
			schema: objSchema(map[string]any{
				"finding_id": strProp("Score one finding"),
				"host":       strProp("Filter the ranked list by host"),
				"limit":      strProp("Max results, default 50, max 500"),
			}), queryParams: []string{"finding_id", "host", "limit"}},
	}
}

func registerMLTools(srv *mcpserver.Server, c *client) error {
	for _, t := range mlTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
