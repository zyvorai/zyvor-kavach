// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const regUsage = `usage: kavachctl regulatory <command>
  regimes [--jurisdiction J] [--verified true|false] [--json]   regional incident-reporting regimes catalog
  clocks [--regime ID[,ID...]] [--json]                          time remaining per regime (default: your profile)
  profile [set ID[,ID...]] [--json]                              show or set the regimes that apply to you (set needs admin)
Informational, not legal advice; Kavach does not file reports.`

// regDispatch handles `kavachctl regulatory ...`; other commands fall through.
func regDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 1 || args[0] != "regulatory" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", regUsage)
	}
	pos, f, b := omParse(args[2:], "jurisdiction", "verified", "regime")
	j := b["json"]
	switch args[1] {
	case "regimes":
		q := url.Values{}
		for _, k := range []string{"jurisdiction", "verified"} {
			if f[k] != "" {
				q.Set(k, f[k])
			}
		}
		path := "/v1/regulatory/regimes"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		m, err := regGet(path)
		if err != nil {
			return true, err
		}
		if j {
			return true, regRaw(out, m)
		}
		fmt.Fprintln(out, "Regional incident-reporting regimes (informational, not legal advice; Kavach does not file reports)")
		fmt.Fprintf(out, "%-22s %-16s %-9s %-s\n", "ID", "JURISDICTION", "VERIFIED", "NAME / FIRST CLOCK")
		for _, r := range listOf(m, "regimes") {
			v := "UNVERIFIED"
			if r["verified"] == true {
				v = "yes"
			}
			first := ""
			if st := listOf(r, "stages"); len(st) > 0 {
				first = strFrom(st[0], "name")
			}
			fmt.Fprintf(out, "%-22s %-16s %-9s %s | %s\n", strFrom(r, "id"), truncate(strFrom(r, "jurisdiction"), 16), v, truncate(strFrom(r, "name"), 44), truncate(first, 30))
		}
		return true, nil
	case "clocks":
		path := "/v1/regulatory/clocks"
		if f["regime"] != "" {
			path += "?regime=" + url.QueryEscape(f["regime"])
		}
		m, err := regGet(path)
		if err != nil {
			return true, err
		}
		if j {
			return true, regRaw(out, m)
		}
		fmt.Fprintln(out, "Regulatory reporting clocks (informational, not legal advice; Kavach does not file reports)")
		regimes := listOf(m, "regimes")
		if len(regimes) == 0 {
			fmt.Fprintln(out, "No regimes selected. Use `kavachctl regulatory profile set ID,...` or pass --regime.")
		}
		for _, r := range regimes {
			tag := ""
			if r["verified"] != true {
				tag = " [UNVERIFIED]"
			}
			fmt.Fprintf(out, "\n%s (%s)%s, clock starts at %s; measured from first detection\n", strFrom(r, "name"), strFrom(r, "regime"), tag, strFrom(r, "start_event"))
			for _, st := range listOf(r, "stages") {
				if st["computable"] != true {
					fmt.Fprintf(out, "  - %s: not computed by Kavach (%s)\n", strFrom(st, "name"), strFrom(st, "description"))
					continue
				}
				fmt.Fprintf(out, "  - %s (%s)\n", strFrom(st, "name"), regWindow(st))
				for _, e := range listOf(st, "incidents") {
					rem := time.Duration(int64(floatFrom(e, "remaining_seconds"))) * time.Second
					left := fmtRemaining(rem)
					if e["overdue"] == true {
						left = "OVERDUE " + fmtRemaining(-rem)
					}
					fmt.Fprintf(out, "      %s\t%s\t%s\t%s\n", strFrom(e, "finding_id"), strFrom(e, "severity"), truncate(strFrom(e, "host"), 24), left)
				}
			}
		}
		return true, nil
	case "profile":
		if len(pos) >= 1 && pos[0] == "set" {
			if len(pos) < 2 {
				return true, fmt.Errorf("usage: kavachctl regulatory profile set ID[,ID...]")
			}
			ids := []string{}
			for _, p := range pos[1:] {
				for _, id := range strings.Split(p, ",") {
					if id = strings.TrimSpace(id); id != "" {
						ids = append(ids, id)
					}
				}
			}
			return true, omDo(out, "PUT", "/v1/regulatory/profile", map[string]any{"regimes": ids}, j)
		}
		return true, omDo(out, "GET", "/v1/regulatory/profile", nil, j)
	}
	return true, fmt.Errorf("%s", regUsage)
}

func regWindow(st map[string]any) string {
	if bd := intFrom(st, "business_days"); bd > 0 {
		return fmt.Sprintf("%d business days", bd)
	}
	return fmt.Sprintf("%dh", intFrom(st, "hours"))
}

func regGet(path string) (map[string]any, error) {
	raw, code, err := doRequest("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func regRaw(out io.Writer, m map[string]any) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(out, string(b))
	return nil
}
