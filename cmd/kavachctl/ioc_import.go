// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
)

const iocImportUsage = `usage:
  kavachctl ioc import FILE [--format auto|stix|misp|csv|txt] [--source NAME] [--apply] [--json]
      offline threat-intel import (STIX 2.1 bundle, MISP JSON, CSV/TXT list); dry run unless --apply (admin token)
  kavachctl ioc stats [--json]      IOC counts by type, source, TLP and expiry state, plus sighting totals`

const iocImportCtlMaxBytes = 5 << 20 // mirrors the server limit

// iocImportDispatch handles `kavachctl ioc import|stats`; other ioc commands fall through.
func iocImportDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "ioc" || (args[1] != "import" && args[1] != "stats") {
		return false, nil
	}
	pos, f, b := omParse(args[2:], "format", "source")
	if args[1] == "stats" {
		return true, ccRaw(out, "GET", "/v1/ioc/stats", nil, b["json"])
	}
	if len(pos) != 1 {
		return true, fmt.Errorf("%s", iocImportUsage)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return true, err
	}
	if len(data) > iocImportCtlMaxBytes {
		return true, fmt.Errorf("%s is %d bytes, over the %d byte limit", pos[0], len(data), iocImportCtlMaxBytes)
	}
	q := url.Values{}
	q.Set("dry_run", "true")
	if b["apply"] {
		q.Set("dry_run", "false")
	} else {
		fmt.Fprintln(out, "dry run: nothing is stored (pass --apply to import)")
	}
	for _, k := range []string{"format", "source"} {
		if f[k] != "" {
			q.Set(k, f[k])
		}
	}
	return true, ccRaw(out, "POST", "/v1/ioc/import?"+q.Encode(), data, b["json"])
}
