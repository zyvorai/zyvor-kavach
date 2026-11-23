// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const identityCmdsUsage = `usage:
  kavachctl idplog analyze FILE [--host NAME] [--dormant-days N] [--json]
      offline Okta / Microsoft Entra sign-in and audit log analytics (MFA fatigue, spray, role grants, ...) (admin token)
  kavachctl idplog sources [--json]
  kavachctl ransomlog analyze FILE [--host NAME] [--json]
      offline file-activity and backup-job log analytics: mass rename, extension churn, entropy flags, recovery inhibition (admin token)
  kavachctl ransomlog sources [--json]
  kavachctl exploitintel import FILE [--kind auto|kev|epss] [--source NAME] [--ttl-days N] [--min-epss X] [--json]
      import a CISA KEV file (JSON/CSV) or an EPSS file (CSV, CSV.gz, API JSON) you downloaded yourself (admin token)
  kavachctl exploitintel status|lookup CVE|withdraw kev|epss
  kavachctl tripwire list | add --kind account|ip|value|hostname|path --match M --label L [--owner O] | delete ID | scan FILE [--source NAME]
      declared decoys matched against logs you send (admin token for changes)
Nothing is fetched, blocked or contacted; see docs/identity-detection.md, docs/ransomware-logs.md, docs/exploit-intel.md and docs/tripwires.md.`

const identityCmdsMax = 8 << 20
const exploitIntelCtlMax = 16 << 20

func identityReadFile(p string, max int) ([]byte, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", p, len(data), max)
	}
	return data, nil
}

// identityCmdsDispatch handles idplog, ransomlog, exploitintel and tripwire; other commands fall through.
func identityCmdsDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 {
		return false, nil
	}
	switch args[0] {
	case "idplog", "ransomlog", "exploitintel", "tripwire":
	default:
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", identityCmdsUsage)
	}
	pos, f, b := omParse(args[2:], "host", "dormant-days", "kind", "source", "ttl-days", "min-epss", "match", "label", "owner")
	usage := func() (bool, error) { return true, fmt.Errorf("%s", identityCmdsUsage) }
	switch args[0] {
	case "idplog", "ransomlog":
		base, src := "/v1/idp/logs", "/v1/idp/sources"
		if args[0] == "ransomlog" {
			base, src = "/v1/ransom/logs", "/v1/ransom/logs/sources"
		}
		switch args[1] {
		case "sources":
			return true, ccRaw(out, "GET", src, nil, b["json"])
		case "analyze":
			if len(pos) != 1 {
				return usage()
			}
			data, err := identityReadFile(pos[0], identityCmdsMax)
			if err != nil {
				return true, err
			}
			q := url.Values{}
			if f["host"] != "" {
				q.Set("host", f["host"])
			}
			if f["dormant-days"] != "" && args[0] == "idplog" {
				q.Set("dormant_days", f["dormant-days"])
			}
			return true, webLogsPost(out, base+"?"+q.Encode(), data, b["json"])
		}
	case "exploitintel":
		switch args[1] {
		case "status":
			return true, ccRaw(out, "GET", "/v1/intel/exploit-feeds", nil, b["json"])
		case "lookup":
			if len(pos) != 1 {
				return usage()
			}
			return true, ccRaw(out, "GET", "/v1/intel/exploit-feeds/lookup?cve="+url.QueryEscape(pos[0]), nil, b["json"])
		case "withdraw":
			if len(pos) != 1 || (pos[0] != "kev" && pos[0] != "epss") {
				return usage()
			}
			return true, ccRaw(out, "DELETE", "/v1/intel/exploit-feeds/"+pos[0], nil, b["json"])
		case "import":
			if len(pos) != 1 {
				return usage()
			}
			data, err := identityReadFile(pos[0], exploitIntelCtlMax)
			if err != nil {
				return true, err
			}
			q := url.Values{}
			for _, k := range []string{"kind", "source", "min-epss", "ttl-days"} {
				if f[k] != "" {
					q.Set(strings.ReplaceAll(k, "-", "_"), f[k])
				}
			}
			return true, ccRaw(out, "POST", "/v1/intel/exploit-feeds?"+q.Encode(), data, b["json"])
		}
	case "tripwire":
		switch args[1] {
		case "list":
			return true, ccRaw(out, "GET", "/v1/deception/tripwires", nil, b["json"])
		case "add":
			if f["kind"] == "" || f["match"] == "" || f["label"] == "" {
				return usage()
			}
			body, err := json.Marshal(map[string]string{"kind": f["kind"], "match": f["match"], "label": f["label"], "owner": f["owner"]})
			if err != nil {
				return true, err
			}
			return true, ccRaw(out, "POST", "/v1/deception/tripwires", body, b["json"])
		case "delete":
			if len(pos) != 1 {
				return usage()
			}
			return true, ccRaw(out, "DELETE", "/v1/deception/tripwires/"+url.PathEscape(pos[0]), nil, b["json"])
		case "scan":
			if len(pos) != 1 {
				return usage()
			}
			data, err := identityReadFile(pos[0], identityCmdsMax)
			if err != nil {
				return true, err
			}
			q := url.Values{}
			if f["source"] != "" {
				q.Set("source", f["source"])
			}
			return true, ccRaw(out, "POST", "/v1/deception/tripwires/scan?"+q.Encode(), data, b["json"])
		}
	}
	return usage()
}
