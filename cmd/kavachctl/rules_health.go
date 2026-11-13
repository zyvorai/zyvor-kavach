// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const rhUsage = `usage: kavachctl rules <command>
  health [ID] [--state S] [--source custom|embedded|builtin] [--silent] [--noisy] [--limit N] [--json]
  lifecycle ID [--set draft|testing|production|retired] [--note TEXT]   show or set the lifecycle state
  history ID [--json]                                                   hash-chained change history`

// rhDispatch handles `kavachctl rules ...`; other commands fall through.
func rhDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "rules" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", rhUsage)
	}
	pos, f, b := omParse(args[2:], "state", "source", "limit", "set", "note")
	j := b["json"]
	switch args[1] {
	case "health":
		if len(pos) == 1 {
			return true, omDo(out, "GET", "/v1/rules/health/"+url.PathEscape(pos[0]), nil, j)
		}
		q := url.Values{}
		for _, k := range []string{"state", "source", "limit"} {
			if f[k] != "" {
				q.Set(k, f[k])
			}
		}
		if b["silent"] {
			q.Set("silent", "1")
		}
		if b["noisy"] {
			q.Set("noisy", "1")
		}
		path := "/v1/rules/health"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		if j {
			return true, omDo(out, "GET", path, nil, true)
		}
		raw, code, err := doRequest("GET", path, nil, nil)
		if err != nil {
			return true, err
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
		}
		var resp struct {
			Count int `json:"count"`
			Rules []struct {
				Rule       string `json:"rule"`
				State      string `json:"state"`
				Source     string `json:"source"`
				Hits24h    int    `json:"hits_24h"`
				Hits7d     int    `json:"hits_7d"`
				Hits30d    int    `json:"hits_30d"`
				Hosts      int    `json:"distinct_hosts_30d"`
				Trend      string `json:"trend"`
				NoisyScore int    `json:"noisy_score"`
				Silent     bool   `json:"silent"`
			} `json:"rules"`
		}
		if json.Unmarshal(raw, &resp) != nil {
			fmt.Fprintln(out, strings.TrimSpace(string(raw)))
			return true, nil
		}
		fmt.Fprintf(out, "%-36s %-10s %-8s %5s %5s %5s %5s %-5s %5s\n", "RULE", "STATE", "SOURCE", "24H", "7D", "30D", "HOSTS", "TREND", "NOISY")
		for _, r := range resp.Rules {
			flag := ""
			if r.Silent {
				flag = " silent"
			}
			fmt.Fprintf(out, "%-36s %-10s %-8s %5d %5d %5d %5d %-5s %5d%s\n", truncate(r.Rule, 36), r.State, r.Source, r.Hits24h, r.Hits7d, r.Hits30d, r.Hosts, r.Trend, r.NoisyScore, flag)
		}
		fmt.Fprintf(out, "%d rule(s)\n", resp.Count)
		return true, nil
	case "lifecycle":
		id, err := omNeed(pos, 0, "usage: kavachctl rules lifecycle ID [--set STATE] [--note TEXT]")
		if err != nil {
			return true, err
		}
		p := "/v1/rules/lifecycle/" + url.PathEscape(id)
		if f["set"] == "" {
			return true, omDo(out, "GET", p, nil, j)
		}
		return true, omDo(out, "PUT", p, map[string]string{"state": f["set"], "note": f["note"]}, j)
	case "history":
		id, err := omNeed(pos, 0, "usage: kavachctl rules history ID [--json]")
		if err != nil {
			return true, err
		}
		return true, omDo(out, "GET", "/v1/rules/history/"+url.PathEscape(id), nil, j)
	}
	return true, fmt.Errorf("%s", rhUsage)
}
