// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const ttpNote = " TTP similarity is NOT attribution: it compares observed ATT&CK techniques with public profiles and returns not_enough_evidence for thin input. Read the returned caveats/method/confidence_reason fields. Provide one of host, finding_ids or techniques (techniques takes precedence). Read-only."

func ttpInputProps() map[string]any {
	return map[string]any{
		"host":        strProp("Host whose findings supply the techniques"),
		"finding_ids": strProp("Comma-separated finding ids"),
		"techniques":  strProp("Comma-separated ATT&CK technique ids, max 100 (e.g. T1059,T1003.001)"),
	}
}

func ttpTools() []endpointTool {
	return []endpointTool{
		{name: "ttp_similar", method: "GET", path: "/v1/ttp/similar",
			description: "Public adversary profiles most similar to the observed techniques (TF-IDF cosine and weighted Jaccard), with a confidence label." + ttpNote,
			schema:      objSchema(ttpInputProps()), queryParams: []string{"host", "finding_ids", "techniques"}},
		{name: "ttp_next", method: "GET", path: "/v1/ttp/next",
			description: "Hunting hints for techniques that co-occur in similar profiles. Not a prediction." + ttpNote,
			schema:      objSchema(ttpInputProps()), queryParams: []string{"host", "finding_ids", "techniques"}},
		{name: "ttp_chains", method: "GET", path: "/v1/ttp/chains",
			description: "Observed technique chain for a host against known profiles." + ttpNote,
			schema:      objSchema(map[string]any{"host": strProp("Host name (required)")}, "host"), queryParams: []string{"host"}},
	}
}

func registerTTPTools(srv *mcpserver.Server, c *client) error {
	for _, t := range ttpTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
