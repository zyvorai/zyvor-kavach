// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
)

const zscalerUsage = `usage:
  kavachctl zscaler logs FILE [--format auto|json|csv|tsv] [--host NAME] [--sanctioned FILE] [--work-start H] [--work-end H] [--json]
      offline analytics over exported ZIA NSS web, firewall and DNS logs and ZPA LSS user-activity logs:
      threat and sandbox allows, blocked-then-allowed, DLP, risky categories, shadow IT, ZPA denied bursts,
      impossible travel, off-hours, bypass tools; per-user and per-app risk (admin token)
  kavachctl zscaler policy FILE [--host NAME] [--json]
      posture review of an exported ZIA or ZPA policy set (JSON): any-any allows, broad SSL bypass, missing DLP,
      unsanctioned-app allows, stale rules, ZPA scope (admin token)
  kavachctl zscaler zdx FILE [--host NAME] [--json]
      ZDX-style experience score from exported probe metrics (CSV or JSON), per user, application and pair (admin token)
  kavachctl zscaler sources [--json]     formats, rules and limits
Nothing connects to Zscaler or fetches anything; see docs/zscaler-analytics.md.`

const zscalerCtlMax = 8 << 20 // mirrors the server body cap

// zscalerDispatch handles `kavachctl zscaler ...`; other commands fall through.
func zscalerDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "zscaler" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", zscalerUsage)
	}
	pos, f, b := omParse(args[2:], "format", "host", "sanctioned", "work-start", "work-end")
	if args[1] == "sources" {
		return true, ccRaw(out, "GET", "/v1/zscaler/sources", nil, b["json"])
	}
	if len(pos) != 1 || (args[1] != "logs" && args[1] != "policy" && args[1] != "zdx") {
		return true, fmt.Errorf("%s", zscalerUsage)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return true, err
	}
	if len(data) > zscalerCtlMax {
		return true, fmt.Errorf("%s is %d bytes, over the %d byte limit", pos[0], len(data), zscalerCtlMax)
	}
	q := url.Values{}
	if f["host"] != "" {
		q.Set("host", f["host"])
	}
	switch args[1] {
	case "policy":
		return true, webLogsPost(out, "/v1/zscaler/policy?"+q.Encode(), data, b["json"])
	case "zdx":
		return true, webLogsPost(out, "/v1/zscaler/zdx?"+q.Encode(), data, b["json"])
	}
	if f["format"] != "" {
		q.Set("format", f["format"])
	}
	if f["sanctioned"] == "" && f["work-start"] == "" && f["work-end"] == "" {
		return true, webLogsPost(out, "/v1/zscaler/logs?"+q.Encode(), data, b["json"])
	}
	env := map[string]any{"log": string(data), "format": f["format"], "host": f["host"]}
	if f["sanctioned"] != "" {
		l, err := os.ReadFile(f["sanctioned"])
		if err != nil {
			return true, err
		}
		if len(l) > 1<<20 {
			return true, fmt.Errorf("%s is over 1 MiB", f["sanctioned"])
		}
		env["sanctioned_apps"] = string(l)
	}
	for flag, key := range map[string]string{"work-start": "work_start_hour", "work-end": "work_end_hour"} {
		if f[flag] == "" {
			continue
		}
		n, err := strconv.Atoi(f[flag])
		if err != nil {
			return true, fmt.Errorf("--%s must be a whole hour", flag)
		}
		env[key] = n
	}
	body, err := json.Marshal(env)
	if err != nil {
		return true, err
	}
	if len(body) > zscalerCtlMax {
		return true, fmt.Errorf("request is over the %d byte limit", zscalerCtlMax)
	}
	return true, webLogsPost(out, "/v1/zscaler/logs", body, b["json"])
}
