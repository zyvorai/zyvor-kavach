// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"strings"
)

const inspectClustersUsage = "usage: kavachctl inspect clusters [--min-score F] [--limit N] [--kind K] [--json]"
const inspectSarifUsage = "usage: kavachctl inspect sarif (ID|latest | --sha256 X)   (prints SARIF 2.1.0 JSON to stdout; redirect to a file for CI)"

// inspectClustersRun serves `kavachctl inspect clusters` (read-only).
func inspectClustersRun(out io.Writer, args []string) error {
	pos, f, b := omParse(args, "min-score", "limit", "kind")
	if len(pos) > 0 {
		return fmt.Errorf("%s", inspectClustersUsage)
	}
	j := b["json"]
	m, err := p4Get(out, p4Query("/v1/inspect/clusters", "min_score", f["min-score"], "limit", f["limit"], "kind", f["kind"]), j)
	if err != nil || j {
		return err
	}
	fmt.Fprintf(out, "NOTE: %s\n", strFrom(m, "note"))
	fmt.Fprintf(out, "Considered %s reports, %s clusters, %s unlinked (link threshold %s)\n", num(m, "considered"), num(m, "count"), num(m, "singletons"), num(m, "min_score"))
	for _, c := range listOf(m, "clusters") {
		fmt.Fprintf(out, "\n%s  size=%s  max=%s/%s\n  %s\n", strFrom(c, "id"), num(c, "size"), num(c, "max_score"), strFrom(c, "max_level"), strFrom(c, "explanation"))
		for _, x := range listOf(c, "shared_factors") {
			fmt.Fprintf(out, "  shared  %-60s in %s reports\n", strFrom(x, "factor"), num(x, "count"))
		}
		for _, x := range listOf(c, "members") {
			fmt.Fprintf(out, "  member  %s  %s  %s  %s\n", strFrom(x, "id"), strFrom(x, "level"), strFrom(x, "kind"), strFrom(x, "name"))
		}
	}
	if l, ok := m["limits_hit"].([]any); ok && len(l) > 0 {
		parts := make([]string, 0, len(l))
		for _, x := range l {
			parts = append(parts, fmt.Sprint(x))
		}
		fmt.Fprintf(out, "\nLimits hit: %s\n", strings.Join(parts, ", "))
	}
	return nil
}

// inspectSarifRun serves `kavachctl inspect sarif` (read-only; pull-only export).
func inspectSarifRun(out io.Writer, args []string) error {
	pos, f, _ := omParse(args, "sha256")
	if (len(pos) == 1) == (f["sha256"] != "") {
		return fmt.Errorf("%s", inspectSarifUsage)
	}
	raw, err := mlCall("GET", p4Query("/v1/inspect/sarif", "id", strings.Join(pos, ""), "sha256", f["sha256"]), nil, nil)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, strings.TrimSpace(string(raw)))
	return nil
}
