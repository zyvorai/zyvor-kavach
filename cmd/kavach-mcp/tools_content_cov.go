// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const contentCovNote = " Observation of Kavach's own content and telemetry; blind spots are inferred from which event categories were seen recently and which rules need them, so a quiet category may mean no activity rather than no coverage. Read-only."

func contentCovTools() []endpointTool {
	return []endpointTool{
		{name: "content_versions", method: "GET", path: "/v1/content/versions",
			description: "Snapshots of embedded detection content over time, newest first." + contentCovNote,
			schema:      objSchema(map[string]any{"items": strProp("Set to 1 to include per-rule items")}), queryParams: []string{"items"}},
		{name: "content_changes", method: "GET", path: "/v1/content/changes",
			description: "Diff between two content snapshots (from defaults to the snapshot before 'to'; 'to' defaults to the latest)." + contentCovNote,
			schema:      objSchema(map[string]any{"from": strProp("Snapshot ref to diff from"), "to": strProp("Snapshot ref to diff to")}), queryParams: []string{"from", "to"}},
		{name: "content_changelog", method: "GET", path: "/v1/content/changelog",
			description: "Changelog entries per content snapshot." + contentCovNote,
			schema:      emptySchema()},
		{name: "coverage_blindspots", method: "GET", path: "/v1/coverage/blindspots",
			description: "Detection blind spots: rules whose required telemetry is missing or stale, plus a synthetic validation of rules unless validation=0." + contentCovNote,
			schema:      objSchema(map[string]any{"validation": strProp("Set to 0 to skip the synthetic validation"), "stale_days": strProp("Days until a category counts as stale, 1-3650")}),
			queryParams: []string{"validation", "stale_days"}},
		{name: "coverage_telemetry", method: "GET", path: "/v1/coverage/telemetry",
			description: "Inventory of telemetry categories seen and when they were last seen." + contentCovNote,
			schema:      objSchema(map[string]any{"stale_days": strProp("Days until a category counts as stale, 1-3650")}), queryParams: []string{"stale_days"}},
	}
}

func registerContentCovTools(srv *mcpserver.Server, c *client) error {
	return regEndpoints(srv, c, contentCovTools())
}
