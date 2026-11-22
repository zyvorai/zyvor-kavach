// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

// iocImportReadTools are read-only. Importing indicators (POST /v1/ioc/import) is deliberately not exposed over MCP.
func iocImportReadTools() []endpointTool {
	return []endpointTool{
		{name: "kavach_ioc_stats", method: "GET", path: "/v1/ioc/stats", description: "IOC lifecycle statistics: counts by type, source and TLP, active/expired/not-yet-valid totals, sighting counters (counts only) and the default expiry. Expired indicators no longer match but are retained for audit.", schema: emptySchema()},
	}
}

func registerIOCImportTools(srv *mcpserver.Server, c *client) error {
	for _, t := range iocImportReadTools() {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
