// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"net/url"
)

const cmUsage = `usage: kavachctl content <command>
  manifest                                   rule-pack manifest (pack hashes, per-rule hashes, optional HMAC)
  snapshot [list]                            list stored manifest snapshots
  snapshot create [--label TEXT]             store a snapshot (admin token)
  diff [--from REF] [--to REF]               REF is a snapshot seq, latest or embedded (default latest -> embedded)`

// cmDispatch handles `kavachctl content manifest|snapshot|diff`; other commands fall through.
func cmDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "content" {
		return false, nil
	}
	switch args[1] {
	case "manifest":
		return true, omDo(out, "GET", "/v1/content/manifest", nil, false)
	case "snapshot":
		pos, f, _ := omParse(args[2:], "label")
		if len(pos) == 0 || pos[0] == "list" {
			return true, omDo(out, "GET", "/v1/content/snapshots", nil, false)
		}
		if pos[0] != "create" {
			return true, fmt.Errorf("%s", cmUsage)
		}
		return true, omDo(out, "POST", "/v1/content/snapshots", map[string]any{"label": f["label"]}, false)
	case "diff":
		_, f, _ := omParse(args[2:], "from", "to")
		q := url.Values{}
		for _, k := range []string{"from", "to"} {
			if f[k] != "" {
				q.Set(k, f[k])
			}
		}
		p := "/v1/content/diff"
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		return true, omDo(out, "GET", p, nil, false)
	}
	return false, nil
}
