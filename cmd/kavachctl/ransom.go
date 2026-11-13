// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
)

const ransomUsage = `usage: kavachctl ransom <command>
  hosts [--json]                         per-host peak ransomware-indicator window
  host --host H [--limit N] [--json]     scored windows for one host
  status [--json]                        method, thresholds and what the detector cannot see
Report-only heuristic over file metadata; it cannot see file contents.`

const ransomNote = "NOTE: report-only metadata heuristic (no file contents, no writing process); thresholds are literature-guided, not fleet-fitted. Run `kavachctl ransom status` for method and blind spots."

func ransomRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", ransomUsage)
	}
	_, f, b := omParse(args[1:], "host", "limit")
	j := b["json"]
	switch args[0] {
	case "status":
		m, err := p4Get(out, "/v1/ransom/status", j)
		if err != nil || j {
			return err
		}
		fmt.Fprintf(out, "METHOD: %s\n", strFrom(m, "method"))
		fmt.Fprintf(out, "Window: %s  stride: %s\n", num(m, "window"), num(m, "stride"))
		fmt.Fprintf(out, "Alert rule: %s\n", strFrom(m, "alert_rule"))
		fmt.Fprintf(out, "Primary indicators: %v\nSecondary indicators: %v\n", m["primary"], m["secondary"])
		p4List(out, "CANNOT SEE", p4Strings(m, "cannot_see"))
		if s := strFrom(m, "note"); s != "" {
			fmt.Fprintf(out, "Note: %s\n", s)
		}
		fmt.Fprintf(out, "Report only: %v\n", m["report_only"])
		return nil
	case "hosts":
		m, err := p4Get(out, "/v1/ransom/hosts", j)
		if err != nil || j {
			return err
		}
		fmt.Fprintln(out, ransomNote)
		hs := listOf(m, "hosts")
		if len(hs) == 0 {
			fmt.Fprintln(out, "No hosts with file events.")
			return nil
		}
		fmt.Fprintf(out, "%-24s %-6s %-6s %-8s %-8s %s\n", "HOST", "LEVEL", "SCORE", "WINDOWS", "ALERTS", "PEAK START")
		for _, h := range hs {
			pk, _ := h["peak"].(map[string]any)
			fmt.Fprintf(out, "%-24s %-6s %-6s %-8s %-8s %s\n", truncate(strFrom(h, "host"), 24), strFrom(pk, "level"), num(pk, "score"), num(h, "windows"), num(h, "alert_windows"), fmtTime(strFrom(pk, "start")))
		}
		return nil
	case "host":
		if f["host"] == "" {
			return fmt.Errorf("usage: kavachctl ransom host --host H [--limit N] [--json]")
		}
		m, err := p4Get(out, p4Query("/v1/ransom/host", "host", f["host"], "limit", f["limit"]), j)
		if err != nil || j {
			return err
		}
		fmt.Fprintln(out, ransomNote)
		ws := listOf(m, "windows")
		fmt.Fprintf(out, "Host %s: %d windows\n", strFrom(m, "host"), len(ws))
		for _, w := range ws {
			fmt.Fprintf(out, "  %s  level=%s score=%s events=%s primary=%s secondary=%s\n", fmtTime(strFrom(w, "start")), strFrom(w, "level"), num(w, "score"), num(w, "events"), num(w, "primary_triggered"), num(w, "secondary_triggered"))
			for _, fc := range listOf(w, "factors") {
				if fc["triggered"] == true {
					fmt.Fprintf(out, "      triggered %-9s %s (%s)\n", strFrom(fc, "kind"), strFrom(fc, "name"), strFrom(fc, "detail"))
				}
			}
		}
		return nil
	}
	return fmt.Errorf("unknown ransom command %q\n%s", args[0], ransomUsage)
}
