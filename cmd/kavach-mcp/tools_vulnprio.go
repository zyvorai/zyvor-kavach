// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const vulnPrioNote = " Advisory SSVC-style decision (act/attend/track*/track) from CVE, EPSS and asset context. Several SSVC inputs are UNKNOWN to Kavach (exploitation, automatable, technical impact, mission prevalence for unregistered assets) and fall back to documented defaults; EPSS is used only when the opt-in feed is enabled. Read the returned limitations and epss status. The /refresh endpoint is deliberately not exposed. Read-only."

func vulnPrioTools() []endpointTool {
	return []endpointTool{
		{name: "vulns_priority", method: "GET", path: "/v1/vulns/priority",
			description: "Ranked vulnerability priority across hosts (SSVC outcome, then EPSS with unknown last, then CVSS)." + vulnPrioNote,
			schema:      objSchema(map[string]any{"host": strProp("Optional host filter"), "limit": strProp("1-500, default 50")}), queryParams: []string{"host", "limit"}},
		{name: "vulns_priority_cve", method: "GET", path: "/v1/vulns/priority/{cve}",
			description: "Priority of one CVE on every host where it matched (404 when it matches no host)." + vulnPrioNote,
			schema:      objSchema(map[string]any{"cve": strProp("CVE id, e.g. CVE-2024-3094")}, "cve"), pathParams: []string{"cve"}},
		{name: "vulns_priority_status", method: "GET", path: "/v1/vulns/priority/status",
			description: "SSVC tree version, EPSS feed status, thresholds, the defaults used for unknown inputs, and limitations." + vulnPrioNote,
			schema:      emptySchema()},
	}
}

func registerVulnPrioTools(srv *mcpserver.Server, c *client) error {
	return regEndpoints(srv, c, vulnPrioTools())
}
