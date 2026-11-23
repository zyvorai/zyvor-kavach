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

const netcfgUsage = `usage:
  kavachctl netcfg analyze FILE [--format auto|pan-xml|fortigate|asa|iptables|nft] [--host NAME] [--json]
      offline posture review of a network-device configuration export: rule-base shadowing and
      redundancy, any-any and risky permits, management exposure, weak crypto, credential patterns (admin token)
  kavachctl netcfg diff OLD NEW [--format F] [--json]
      compare two exports of the same device: permissive rules added, deny rules removed (admin token)
  kavachctl netcfg sources [--json]     formats, rules and limits
Nothing connects to a device or fetches anything; see docs/netcfg-posture.md.`

const netcfgCtlMax = 8 << 20 // mirrors the server body cap

// netcfgDispatch handles `kavachctl netcfg ...`; other commands fall through.
func netcfgDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "netcfg" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", netcfgUsage)
	}
	pos, f, b := omParse(args[2:], "format", "host")
	read := func(p string) ([]byte, error) {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if len(data) > netcfgCtlMax {
			return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", p, len(data), netcfgCtlMax)
		}
		return data, nil
	}
	switch args[1] {
	case "sources":
		return true, ccRaw(out, "GET", "/v1/netcfg/sources", nil, b["json"])
	case "analyze":
		if len(pos) != 1 {
			return true, fmt.Errorf("%s", netcfgUsage)
		}
		data, err := read(pos[0])
		if err != nil {
			return true, err
		}
		q := url.Values{}
		if f["format"] != "" {
			q.Set("format", f["format"])
		}
		if f["host"] != "" {
			q.Set("host", f["host"])
		}
		return true, webLogsPost(out, "/v1/netcfg/analyze?"+q.Encode(), data, b["json"])
	case "diff":
		if len(pos) != 2 {
			return true, fmt.Errorf("%s", netcfgUsage)
		}
		o, err := read(pos[0])
		if err != nil {
			return true, err
		}
		n, err := read(pos[1])
		if err != nil {
			return true, err
		}
		body, err := json.Marshal(map[string]string{"old": string(o), "new": string(n), "format": f["format"]})
		if err != nil {
			return true, err
		}
		if len(body) > netcfgCtlMax {
			return true, fmt.Errorf("request is over the %d byte limit", netcfgCtlMax)
		}
		return true, ccRaw(out, "POST", "/v1/netcfg/diff", body, true)
	}
	return true, fmt.Errorf("%s", netcfgUsage)
}
