// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

const exportSIEMUsage = "usage: kavachctl export findings [--format ocsf|ecs|cef|leef|splunk-hec|csv|json|ndjson] [--kind findings|events] [--since RFC3339] [--limit N] [--cursor TOKEN] [--out FILE] [--force]\n" +
	"       kavachctl export iocs [--format stix] [--out FILE]\n" +
	"       kavachctl export layer [--out FILE]\n" +
	"       kavachctl export report [--format html|json]"

var siemCLIFormats = map[string]bool{"ocsf": true, "ecs": true, "cef": true, "leef": true, "splunk-hec": true}

// exportCmdSIEM handles the SIEM/standards exports (SIEM finding formats, iocs, layer)
// and delegates everything else to exportCmd.
func exportCmdSIEM(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", exportSIEMUsage)
	}
	_, f := splitArgs(args[1:], "format", "severity", "host", "rule", "since", "out", "kind", "limit", "cursor")
	format := strings.ToLower(f["format"])
	var path string
	switch {
	case args[0] == "findings" && siemCLIFormats[format]:
		q := url.Values{"format": {format}}
		for _, k := range []string{"severity", "host", "rule", "since", "kind", "limit", "cursor"} {
			if f[k] != "" {
				q.Set(k, f[k])
			}
		}
		path = "/v1/export/findings?" + q.Encode()
	case args[0] == "iocs":
		if format != "" && format != "stix" {
			return fmt.Errorf("invalid --format %q (stix)", format)
		}
		path = "/v1/export/iocs?format=stix"
	case args[0] == "layer":
		path = "/v1/export/attack-layer"
	default:
		return exportCmd(out, args)
	}
	return streamTo(out, path, f["out"], hasFlag(args, "--force"))
}
