// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
)

const inspectSimilarUsage = "usage: kavachctl inspect similar (--sha256 X | --digest D) [--limit N] [--json]"

// inspectSimilarRun serves `kavachctl inspect similar` (dispatched from p4Dispatch).
func inspectSimilarRun(out io.Writer, args []string) error {
	pos, f, b := omParse(args, "sha256", "digest", "limit")
	if len(pos) > 0 || (f["sha256"] == "") == (f["digest"] == "") {
		return fmt.Errorf("%s\n(give exactly one of --sha256 or --digest)", inspectSimilarUsage)
	}
	j := b["json"]
	m, err := p4Get(out, p4Query("/v1/inspect/similar", "sha256", f["sha256"], "digest", f["digest"], "limit", f["limit"]), j)
	if err != nil || j {
		return err
	}
	fmt.Fprintf(out, "NOTE: %s\n", strFrom(m, "note"))
	fmt.Fprintf(out, "Mode: %s   Thresholds: %v\n", strFrom(m, "mode"), m["thresholds"])
	ms := listOf(m, "matches")
	if len(ms) == 0 {
		fmt.Fprintln(out, "No similar earlier submissions found (digest index holds only what was inspected since start).")
		return nil
	}
	fmt.Fprintf(out, "%-16s %-8s %-6s %-8s %-8s %-6s %s\n", "SHA256", "CTPH", "LSH", "IMPHASH", "SYMHASH", "SIMILAR", "NAME / BASIS")
	for _, x := range ms {
		sha := strFrom(x, "sha256")
		if len(sha) > 16 {
			sha = sha[:16]
		}
		fmt.Fprintf(out, "%-16s %-8s %-6s %-8v %-8v %-7v %s  %s\n", sha, num(x, "ctph_score"), num(x, "lsh_distance"), x["imphash_match"], x["symhash_match"], x["similar"], strFrom(x, "name"), strFrom(x, "basis"))
	}
	fmt.Fprintf(out, "%s matches. Similarity is not maliciousness.\n", num(m, "count"))
	return nil
}
