// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
)

const saseUsage = `usage:
  kavachctl cloudflare logs FILE [--format auto|json|csv|tsv] [--host NAME] [--json]
      offline analytics over exported Cloudflare Logpush HTTP requests, firewall events, Gateway DNS and
      Gateway HTTP logs: attack-score and injection-score requests served, block bursts, leaked
      credentials, automated bots, Gateway threat DNS, untrusted-certificate passthrough, DLP (admin token)
  kavachctl cloudflare policy FILE [--host NAME] [--json]
      posture review of an exported ruleset list (JSON): no managed WAF, no rate limit, broad skip rules,
      log-only rules (admin token)
  kavachctl cloudflare sources [--json]
  kavachctl umbrella logs FILE [--format auto|json|csv|tsv] [--host NAME] [--json]
      offline analytics over exported Cisco Umbrella DNS and proxy CSV logs (headerless S3 form or with a
      header): threat-category allows, anonymisers, DNS tunnelling, NXDOMAIN and block bursts, proxy
      antivirus and AMP verdicts allowed (admin token)
  kavachctl umbrella sources [--json]
Nothing connects to either vendor or fetches anything; see docs/sase-log-analytics.md.`

const saseCtlMax = 8 << 20 // mirrors the server body cap

// saseDispatch handles `kavachctl cloudflare ...` and `kavachctl umbrella ...`; other commands fall through.
func saseDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || (args[0] != "cloudflare" && args[0] != "umbrella") {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", saseUsage)
	}
	vendor := args[0]
	pos, f, b := omParse(args[2:], "format", "host")
	if args[1] == "sources" {
		return true, ccRaw(out, "GET", "/v1/"+vendor+"/sources", nil, b["json"])
	}
	if len(pos) != 1 || (args[1] != "logs" && !(args[1] == "policy" && vendor == "cloudflare")) {
		return true, fmt.Errorf("%s", saseUsage)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return true, err
	}
	if len(data) > saseCtlMax {
		return true, fmt.Errorf("%s is %d bytes, over the %d byte limit", pos[0], len(data), saseCtlMax)
	}
	q := url.Values{}
	if f["host"] != "" {
		q.Set("host", f["host"])
	}
	if f["format"] != "" && args[1] == "logs" {
		q.Set("format", f["format"])
	}
	return true, webLogsPost(out, "/v1/"+vendor+"/"+args[1]+"?"+q.Encode(), data, b["json"])
}
