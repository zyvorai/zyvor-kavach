// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
)

const netLogUsage = `usage:
  kavachctl netlog analyze FILE [--format auto|zeek|eve|zeek-json|dns|dnscsv|vpc|nsg|flowcsv|panos|fortigate|asa] [--host NAME] [--bad-nets FILE] [--fingerprints FILE] [--json]
      offline network-log analytics: Zeek, Suricata EVE, DNS query logs, cloud flow logs, NetFlow/IPFIX CSV, firewall logs (admin token)
      --bad-nets: your own address/CIDR list; --fingerprints: your own JA3/JA3S/JA4 list (nothing is downloaded)
  kavachctl netlog sources [--json]     formats, rules, thresholds and limits
  kavachctl netlog timeline [--ip ADDR] [--host NAME] [--window-minutes N] [--json]
      join findings Kavach already holds by address, host and time into one ranked list
Nothing is captured, fetched or blocked; see docs/network-detection.md.`

const netLogCtlMax = 8 << 20 // mirrors the server body cap

// netLogDispatch handles `kavachctl netlog ...`; other commands fall through.
func netLogDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "netlog" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", netLogUsage)
	}
	pos, f, b := omParse(args[2:], "format", "host", "bad-nets", "fingerprints", "ip", "window-minutes")
	switch args[1] {
	case "sources":
		return true, ccRaw(out, "GET", "/v1/net/sources", nil, b["json"])
	case "timeline":
		q := url.Values{}
		for k, p := range map[string]string{"ip": "ip", "host": "host", "window-minutes": "window_minutes"} {
			if f[k] != "" {
				q.Set(p, f[k])
			}
		}
		return true, ccRaw(out, "GET", "/v1/net/timeline?"+q.Encode(), nil, true)
	case "analyze":
		if len(pos) != 1 {
			return true, fmt.Errorf("%s", netLogUsage)
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			return true, err
		}
		if len(data) > netLogCtlMax {
			return true, fmt.Errorf("%s is %d bytes, over the %d byte limit", pos[0], len(data), netLogCtlMax)
		}
		if f["bad-nets"] == "" && f["fingerprints"] == "" {
			q := url.Values{}
			if f["format"] != "" {
				q.Set("format", f["format"])
			}
			if f["host"] != "" {
				q.Set("host", f["host"])
			}
			return true, webLogsPost(out, "/v1/net/logs?"+q.Encode(), data, b["json"])
		}
		env := map[string]any{"log": string(data), "format": f["format"], "host": f["host"]}
		for flag, key := range map[string]string{"bad-nets": "bad_nets", "fingerprints": "fingerprints"} {
			if f[flag] == "" {
				continue
			}
			l, err := os.ReadFile(f[flag])
			if err != nil {
				return true, err
			}
			if len(l) > 1<<20 {
				return true, fmt.Errorf("%s is over 1 MiB", f[flag])
			}
			env[key] = string(l)
		}
		body, err := json.Marshal(env)
		if err != nil {
			return true, err
		}
		if len(body) > netLogCtlMax {
			return true, fmt.Errorf("request is over the %d byte limit", netLogCtlMax)
		}
		return true, webLogsPost(out, "/v1/net/analyze", body, b["json"])
	}
	return true, fmt.Errorf("%s", netLogUsage)
}
