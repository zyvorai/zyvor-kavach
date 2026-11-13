// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

const syslogMaxLine = 8 << 10

const syslogUsage = `usage: kavachctl syslog <command>
  status [--json]               listener state, counters and limits
  samples [--json]              recent UNPARSED lines (redacted, truncated)
  parse LINE|- [--sender IP] [--json]   dry run: parse one line; nothing is ingested`

func syslogRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", syslogUsage)
	}
	pos, f, b := omParse(args[1:], "sender")
	j := b["json"]
	switch args[0] {
	case "status", "samples":
		raw, err := schedCall("GET", "/v1/syslog/"+args[0], nil)
		if err != nil {
			return err
		}
		if j {
			schedShow(out, raw, true)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		if args[0] == "samples" {
			ss, _ := m["samples"].([]any)
			for _, s := range ss {
				fmt.Fprintf(out, "  %v\n", s)
			}
			fmt.Fprintf(out, "%d samples. %s\n", len(ss), strFrom(m, "note"))
			return nil
		}
		if m["enabled"] != true {
			fmt.Fprintln(out, "Syslog listener: DISABLED")
			if e := strFrom(m, "error"); e != "" {
				fmt.Fprintf(out, "Error: %s\n", e)
			}
			fmt.Fprintf(out, "%s\n", strFrom(m, "note"))
			return nil
		}
		fmt.Fprintf(out, "Syslog listener: ENABLED\nListeners: %v\nAllowlist: %v\n", m["listeners"], m["allowlist"])
		fmt.Fprintf(out, "Received: %s  Unparsed: %s  Rate-limited: %s  Queue: %s\n", num(m, "received"), num(m, "unparsed"), num(m, "rate_limited"), num(m, "queue_len"))
		for _, k := range []string{"parsed_by_format", "events_by_type", "dropped_by_reason"} {
			if mm, ok := m[k].(map[string]any); ok && len(mm) > 0 {
				fmt.Fprintf(out, "%s: %s\n", k, sloKV(mm))
			}
		}
		if w := strFrom(m, "warning"); w != "" {
			fmt.Fprintf(out, "WARNING: %s\n", w)
		}
		fmt.Fprintf(out, "%s\n", strFrom(m, "note"))
		return nil
	case "parse":
		var line string
		if len(pos) == 1 && pos[0] == "-" {
			d, err := io.ReadAll(io.LimitReader(omStdin, syslogMaxLine+1))
			if err != nil {
				return err
			}
			if len(d) > syslogMaxLine {
				return fmt.Errorf("stdin exceeds %d bytes (8 KiB)", syslogMaxLine)
			}
			line = strings.TrimRight(string(d), "\r\n")
		} else {
			line = strings.Join(pos, " ")
		}
		if strings.TrimSpace(line) == "" {
			return fmt.Errorf("usage: kavachctl syslog parse LINE|- [--sender IP]")
		}
		if len(line) > syslogMaxLine {
			return fmt.Errorf("line exceeds %d bytes (8 KiB)", syslogMaxLine)
		}
		body, _ := json.Marshal(map[string]string{"line": line, "sender": f["sender"]})
		raw, err := schedCall("POST", "/v1/syslog/parse", body)
		if err != nil {
			return err
		}
		if !j {
			fmt.Fprintln(out, "DRY RUN: nothing was ingested.")
		}
		schedShow(out, raw, j)
		return nil
	}
	return fmt.Errorf("unknown syslog command %q\n%s", args[0], syslogUsage)
}

// ---- inspect config ----

const inspectConfigUsage = "usage: kavachctl inspect config PATH|- [--json]   (reads a local config file, max 32 MiB; parse-only, never applied)"

func inspectConfigRun(out io.Writer, args []string) error {
	pos, _, b := omParse(args)
	if len(pos) != 1 {
		return fmt.Errorf("%s", inspectConfigUsage)
	}
	var data []byte
	name := "stdin"
	var err error
	if pos[0] == "-" {
		data, err = inspectReadStdin()
	} else {
		data, name, err = inspectReadFile(pos[0], inspectMaxFile, "32 MiB")
	}
	if err != nil {
		return err
	}
	raw, err := mlCall("POST", "/v1/inspect/config?name="+url.QueryEscape(name), data, map[string]string{"Content-Type": "text/plain"})
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	m, err := schedObj(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Configuration assessment (not a malware verdict)   Report: %s   Name: %s\n", strFrom(m, "id"), strFrom(m, "name"))
	meta, _ := m["meta"].(map[string]any)
	sum, _ := meta["config-assess.summary"].(map[string]any)
	if sum == nil {
		fmt.Fprintln(out, "No configuration summary returned (format not recognised).")
	} else {
		fmt.Fprintf(out, "Format: %s   Policies for this format: %s (others: %s)\n", strFrom(sum, "format"), num(sum, "policies_for_format"), num(sum, "policies_other_formats"))
		counts, _ := sum["counts"].(map[string]any)
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprint(out, "Counts by status:")
		for _, k := range keys {
			fmt.Fprintf(out, " %s=%v", k, counts[k])
		}
		fmt.Fprintln(out)
		if sum["compliance_pct"] != nil {
			fmt.Fprintf(out, "Compliance (this file, applicable policies only): %v%%\n", sum["compliance_pct"])
		}
		if pe := strFrom(sum, "parse_error"); pe != "" {
			fmt.Fprintf(out, "Parse error: %s\n", pe)
		}
		fails := 0
		for _, r := range listOf(sum, "results") {
			if strFrom(r, "status") != "fail" {
				continue
			}
			if fails == 0 {
				fmt.Fprintln(out, "\nFailing policies:")
			}
			fails++
			fmt.Fprintf(out, "  [%s] %s (%s)\n", strFrom(r, "severity"), strFrom(r, "title"), strFrom(r, "policy_id"))
			if rs := strFrom(r, "reason"); rs != "" {
				fmt.Fprintf(out, "      why: %s\n", rs)
			}
			if rm := strFrom(r, "remediation"); rm != "" {
				fmt.Fprintf(out, "      remediation: %s\n", rm)
			}
		}
		if fails == 0 {
			fmt.Fprintln(out, "\nNo failing policies.")
		}
		if n := strFrom(sum, "note"); n != "" {
			fmt.Fprintf(out, "\n%s\n", n)
		}
	}
	if fs, ok := m["factors"].([]any); ok {
		for _, x := range fs {
			fmt.Fprintf(out, "not_scored: %v\n", x)
		}
	}
	fmt.Fprintf(out, "\nVerdict level: %s. A configuration assessment is not scored: it reports per-policy results, not whether the file is malicious.\n", strFrom(m, "level"))
	return nil
}
