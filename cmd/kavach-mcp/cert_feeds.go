// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// certFeedTools exposes worldwide CERT advisories. Read-only: refresh is
// deliberately not exposed.
func certFeedTools() []endpointTool {
	return []endpointTool{
		{name: "advisories_list", method: "GET", path: "/v1/advisories",
			description: "List normalised CERT advisories (CISA, NCSC UK, CERT-EU, JPCERT/JVN, CERT-Bund, CERT-FR, CCCS, SingCERT, ENISA EUVD) from the opt-in feed cache. Advisories mentioning CVEs present in the local software inventory are flagged matched with the affected hosts. Empty when KAVACH_CERT_FEEDS is unset.",
			schema: objSchema(map[string]any{
				"source":  strProp("Comma-separated feed ids, e.g. cisa,cert-eu"),
				"cve":     strProp("Only advisories mentioning this CVE id"),
				"since":   strProp("RFC 3339 time or YYYY-MM-DD"),
				"q":       strProp("Substring in title, id or CVEs"),
				"matched": strProp("true to return only advisories whose CVEs match the local inventory"),
				"limit":   strProp("Max results, default 100, max 500"),
			}), queryParams: []string{"source", "cve", "since", "q", "matched", "limit"}},
		{name: "advisories_feed_status", method: "GET", path: "/v1/advisories/feeds/status",
			description: "CERT advisory feed status: enabled feeds, available feed ids, per-feed counts, last refresh and errors. Read-only.",
			schema:      objSchema(map[string]any{})},
	}
}

func registerCertFeedTools(srv *mcpserver.Server, c *client) error {
	for _, t := range certFeedTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
