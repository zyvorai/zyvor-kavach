// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const prUsage = `usage: kavachctl posture-trend|digest|auditor-bundle ...
  posture-trend [--days N] [--json]                 capped counts-only posture snapshots
  posture-trend diff --from YYYY-MM-DD [--to YYYY-MM-DD] [--json]
  digest [--days N] [--format json|md|html]         executive digest (factor-backed; pull-only, never emailed)
  auditor-bundle [--out FILE.zip] [--manifest]      auditor evidence zip with SHA-256 manifest (secrets removed)
All read-only; Kavach never sends these anywhere.`

// prDispatch handles the posture trend, digest and auditor bundle commands.
func prDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 {
		return false, nil
	}
	switch args[0] {
	case "posture-trend", "digest", "auditor-bundle":
	default:
		return false, nil
	}
	pos, f, b := omParse(args[1:], "days", "from", "to", "format", "out")
	j := b["json"]
	switch args[0] {
	case "posture-trend":
		if len(pos) > 0 && pos[0] == "diff" {
			if f["from"] == "" {
				return true, fmt.Errorf("usage: kavachctl posture-trend diff --from YYYY-MM-DD [--to YYYY-MM-DD]")
			}
			q := url.Values{"from": {f["from"]}}
			if f["to"] != "" {
				q.Set("to", f["to"])
			}
			m, err := regGet("/v1/posture/trend/diff?" + q.Encode())
			if err != nil {
				return true, err
			}
			if j {
				return true, regRaw(out, m)
			}
			d, _ := m["delta"].(map[string]any)
			fr, _ := m["from"].(map[string]any)
			to, _ := m["to"].(map[string]any)
			fmt.Fprintf(out, "Posture change %s -> %s\n", strFrom(fr, "time"), strFrom(to, "time"))
			fmt.Fprintf(out, "  compliance score  %+d\n  tactics covered   %+d\n  findings          %+d\n  rules silent/noisy %+d / %+d\n",
				intFrom(d, "compliance_score"), intFrom(d, "attack_tactics_covered"), intFrom(d, "findings_total"), intFrom(d, "rules_silent"), intFrom(d, "rules_noisy"))
			return true, nil
		}
		path := "/v1/posture/trend"
		if f["days"] != "" {
			path += "?days=" + url.QueryEscape(f["days"])
		}
		m, err := regGet(path)
		if err != nil {
			return true, err
		}
		if j {
			return true, regRaw(out, m)
		}
		fmt.Fprintf(out, "Posture trend, %d snapshots (counts only; cap %d, every %dh)\n", intFrom(m, "count"), intFrom(m, "history_cap"), intFrom(m, "interval_hours"))
		fmt.Fprintf(out, "%-22s %-6s %-9s %-9s %-s\n", "TIME", "SCORE", "TACTICS", "FINDINGS", "RULES silent/noisy")
		for _, s := range listOf(m, "snapshots") {
			fmt.Fprintf(out, "%-22s %-6d %d/%-7d %-9d %d/%d\n", truncate(strFrom(s, "time"), 22), intFrom(s, "compliance_score"),
				intFrom(s, "attack_tactics_covered"), intFrom(s, "attack_tactics_total"), intFrom(s, "findings_total"), intFrom(s, "rules_silent"), intFrom(s, "rules_noisy"))
		}
		return true, nil
	case "digest":
		q := url.Values{}
		if f["days"] != "" {
			q.Set("days", f["days"])
		}
		format := f["format"]
		if format == "" && !j {
			format = "md"
		}
		if format == "" {
			format = "json"
		}
		q.Set("format", format)
		raw, code, err := doRequest("GET", "/v1/reports/digest?"+q.Encode(), nil, nil)
		if err != nil {
			return true, err
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
		}
		_, err = out.Write(raw)
		return true, err
	default: // auditor-bundle
		if b["manifest"] {
			m, err := regGet("/v1/compliance/auditor-bundle?manifest=1")
			if err != nil {
				return true, err
			}
			return true, regRaw(out, m)
		}
		dest := f["out"]
		if dest == "" {
			return true, fmt.Errorf("auditor-bundle needs --out FILE.zip (or --manifest to print the manifest only)")
		}
		raw, code, err := doRequest("GET", "/v1/compliance/auditor-bundle", nil, nil)
		if err != nil {
			return true, err
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
		}
		if err := os.WriteFile(dest, raw, 0o600); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "wrote %s (%d bytes); verify with: unzip then sha256sum -c MANIFEST.sha256\n", dest, len(raw))
		return true, nil
	}
}
