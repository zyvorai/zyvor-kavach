// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"fmt"
	"io"
)

// printScoreControls renders the per-control table for `compliance score --framework X`.
func printScoreControls(out io.Writer, m map[string]any, ctls []map[string]any) error {
	fmt.Fprintf(out, "%s controls (observe-only, not a certification)\n", strFrom(m, "framework"))
	tw := newTab(out)
	fmt.Fprintln(tw, "ID\tSTATUS\tTITLE\tREASON")
	for _, c := range ctls {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strFrom(c, "id"), strFrom(c, "status"), truncate(strFrom(c, "title"), 44), truncate(strFrom(c, "reason"), 60))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d control(s)\n", len(ctls))
	return nil
}
