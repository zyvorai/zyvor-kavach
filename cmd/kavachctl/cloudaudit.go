// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
)

const cloudAuditUsage = `usage: kavachctl cloudaudit sources [--json]
  sources   supported cloud / SaaS audit-log sources and the loaded cld- rule count
Audit records are POSTed to /v1/cloud/audit/events with the admin token (see docs/cloud-audit.md).`

// cloudAuditDispatch handles `kavachctl cloudaudit ...`; other commands fall through.
func cloudAuditDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "cloudaudit" {
		return false, nil
	}
	if len(args) < 2 || args[1] != "sources" {
		return true, fmt.Errorf("%s", cloudAuditUsage)
	}
	_, _, b := omParse(args[2:])
	m, err := regGet("/v1/cloud/audit/sources")
	if err != nil {
		return true, err
	}
	if b["json"] {
		return true, regRaw(out, m)
	}
	fmt.Fprintf(out, "Cloud audit rules loaded: %v (prefix %v); observation only\n", m["rules"], m["rule_prefix"])
	fmt.Fprintf(out, "%-8s %-52s %s\n", "ID", "SOURCE", "NORMALIZED AS")
	for _, s := range listOf(m, "sources") {
		fmt.Fprintf(out, "%-8s %-52s %s\n", strFrom(s, "id"), truncate(strFrom(s, "name"), 52), strFrom(s, "normalized_sources"))
	}
	return true, nil
}
