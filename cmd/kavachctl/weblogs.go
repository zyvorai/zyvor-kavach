// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

const webLogsUsage = `usage:
  kavachctl web analyze FILE [--openapi FILE.json] [--format auto|combined|json|logfmt] [--host NAME] [--json]
      offline web access-log detection, API inventory, shadow-API check (needs the OpenAPI JSON), flood and credential-abuse summary (admin token)
  kavachctl web sources [--json]     formats, web- rule count, analytic rules and limits
  kavachctl authlog analyze FILE [--host NAME] [--json]
      offline authentication-log analytics: credential stuffing, success after failures, impossible travel from geo fields in the log (admin token)
Nothing is fetched or blocked; see docs/web-detection.md.`

const webLogsCtlMax = 8 << 20 // mirrors the server body cap

// webLogsDispatch handles `kavachctl web ...` and `kavachctl authlog ...`; other commands fall through.
func webLogsDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || (args[0] != "web" && args[0] != "authlog") {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", webLogsUsage)
	}
	pos, f, b := omParse(args[2:], "openapi", "format", "host")
	switch {
	case args[0] == "web" && args[1] == "sources":
		return true, ccRaw(out, "GET", "/v1/web/sources", nil, b["json"])
	case (args[0] == "web" || args[0] == "authlog") && args[1] == "analyze":
		if len(pos) != 1 {
			return true, fmt.Errorf("%s", webLogsUsage)
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			return true, err
		}
		if len(data) > webLogsCtlMax {
			return true, fmt.Errorf("%s is %d bytes, over the %d byte limit", pos[0], len(data), webLogsCtlMax)
		}
		if args[0] == "authlog" {
			q := url.Values{}
			if f["host"] != "" {
				q.Set("host", f["host"])
			}
			return true, webLogsPost(out, "/v1/auth/logs?"+q.Encode(), data, b["json"])
		}
		env := map[string]any{"log": string(data), "format": f["format"], "host": f["host"]}
		if f["openapi"] != "" {
			spec, err := os.ReadFile(f["openapi"])
			if err != nil {
				return true, err
			}
			if !json.Valid(spec) {
				return true, fmt.Errorf("%s is not JSON (OpenAPI YAML must be converted to JSON first)", f["openapi"])
			}
			env["openapi"] = json.RawMessage(spec)
		}
		body, err := json.Marshal(env)
		if err != nil {
			return true, err
		}
		return true, webLogsPost(out, "/v1/web/analyze", body, b["json"])
	}
	return true, fmt.Errorf("%s", webLogsUsage)
}

// webLogsPost posts and prints either the raw JSON or a short human summary.
func webLogsPost(out io.Writer, path string, body []byte, raw bool) error {
	if raw {
		return ccRaw(out, "POST", path, body, true)
	}
	b, code, err := doRequest("POST", path, body, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	fmt.Fprintf(out, "observation only: parsed %v of %v, rejected %v, findings stored %v\n", m["parsed"], wlFirst(m, "lines", "received"), m["rejected"], m["findings"])
	if br, ok := m["by_rule"].(map[string]any); ok && len(br) > 0 {
		names := make([]string, 0, len(br))
		for k := range br {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Fprintln(out, "rules fired:")
		for _, k := range names {
			fmt.Fprintf(out, "  %-44s %v\n", k, br[k])
		}
	}
	if api, ok := m["api"].(map[string]any); ok {
		fmt.Fprintf(out, "api: %v endpoints", api["endpoints_total"])
		if api["spec_loaded"] == true {
			fmt.Fprintf(out, ", shadow %d, undocumented but protected %d, verb drift %d, parameter drift %d, spec operations not observed %d",
				wlLen(api["shadow_endpoints"]), wlLen(api["undocumented_protected"]), wlLen(api["verb_drift"]), wlLen(api["param_drift"]), wlLen(api["spec_operations_not_observed"]))
		}
		fmt.Fprintln(out)
	}
	if fl, ok := m["flood_windows"].([]any); ok && len(fl) > 0 {
		fmt.Fprintf(out, "flood windows: %d (peak %v req/s)\n", len(fl), m["peak_requests_per_second"])
	}
	fmt.Fprintln(out, "use --json for the full report")
	return nil
}

func wlFirst(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

func wlLen(v any) int {
	if l, ok := v.([]any); ok {
		return len(l)
	}
	return 0
}
