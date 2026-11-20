// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// siemReadTools are read-only SIEM/standards export tools.
func siemReadTools() []endpointTool {
	return []endpointTool{
		{name: "export_findings_siem", method: "GET", path: "/v1/export/findings",
			description: "Export findings (or process events) as NDJSON/lines in ocsf, ecs, cef, leef or splunk-hec. Use cursor from a previous response header for no-duplicate polling.",
			schema: objSchema(map[string]any{
				"format": strProp("ocsf|ecs|cef|leef|splunk-hec"), "kind": strProp("findings (default) or events"),
				"since": strProp("RFC3339 lower bound"), "limit": strProp("1..10000, default 1000"), "cursor": strProp("Opaque resume token"),
			}, "format"),
			queryParams: []string{"format", "kind", "since", "limit", "cursor"}},
		{name: "export_iocs_stix", method: "GET", path: "/v1/export/iocs?format=stix",
			description: "STIX 2.1 bundle of the enabled IOC store.", schema: emptySchema()},
		{name: "export_attack_layer", method: "GET", path: "/v1/export/attack-layer",
			description: "ATT&CK Navigator layer of detection coverage and observed hits.", schema: emptySchema()},
	}
}

func registerSIEMTools(srv *mcpserver.Server, c *client) error {
	for _, t := range siemReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
