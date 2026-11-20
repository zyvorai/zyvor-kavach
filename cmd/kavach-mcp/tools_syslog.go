// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "github.com/zyvorai/zyvor-kavach/internal/mcpserver"

const syslogNote = " The syslog listener is opt-in and OFF by default (enabled only by the server operator via KAVACH_SYSLOG with a source allowlist), so enabled=false is the normal state. These tools only observe it; they cannot enable it or ingest anything."

func syslogTools() []endpointTool {
	return []endpointTool{
		{name: "syslog_status", method: "GET", path: "/v1/syslog/status",
			description: "Syslog listener status: enabled flag, listeners, allowlist, counters and any start error." + syslogNote + " Read-only.",
			schema:      emptySchema()},
		{name: "syslog_samples", method: "GET", path: "/v1/syslog/samples",
			description: "Recent UNPARSED syslog lines (redacted of obvious secrets, truncated to 512 chars, newest last) to help write parsers." + syslogNote + " Read-only.",
			schema:      emptySchema()},
		{name: "syslog_parse", method: "POST", path: "/v1/syslog/parse",
			description: "Parse one pasted syslog line and show the normalised events it would produce. DRY RUN: ingested is always false, nothing is stored and no finding is created." + syslogNote + " Needs an admin token on the server.",
			schema:      objSchema(map[string]any{"line": strProp("One syslog line, max 8 KiB"), "sender": strProp("Optional sender IP address; non-IP values are treated as 'pasted'")}, "line"),
			bodyFields:  true},
	}
}

func registerSyslogTools(srv *mcpserver.Server, c *client) error {
	return regEndpoints(srv, c, syslogTools())
}
