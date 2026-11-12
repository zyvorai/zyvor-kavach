// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func om2In(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// om2Dispatch handles identity ITDR, vulns/sbom, correlated incidents, case
// management, hunt packs and ransomware/container/lateral risk. It only takes
// over when the subcommand matches; otherwise the legacy switch runs.
func om2Dispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 {
		switch args[0] {
		case "lateral":
			return true, omDo(out, "GET", "/v1/lateral/edges", nil, false)
		case "ransomware":
			return true, fmt.Errorf("usage: kavachctl ransomware risk|host HOST")
		}
		return false, nil
	}
	cmd, sub, rest := args[0], args[1], args[2:]
	_, _, bl := omParse(rest)
	j := bl["json"]
	switch cmd {
	case "identity":
		if om2In(sub, "summary", "indicators", "risk", "privileged", "timeline") {
			return true, om2Identity(out, sub, rest)
		}
	case "vulns":
		if om2In(sub, "software", "advisories", "findings", "exposure", "top") {
			_, f, b := omParse(rest, "host")
			return true, omDo(out, "GET", omQuery("/v1/vulns/"+sub, f, "host"), nil, b["json"])
		}
	case "sbom":
		if !strings.HasPrefix(sub, "-") {
			pos, f, b := omParse(args[1:], "out")
			if f["out"] != "" {
				return true, om2SBOM(out, pos[0], f["out"])
			}
			return true, omDo(out, "GET", "/v1/sbom/"+url.PathEscape(pos[0]), nil, b["json"])
		}
	case "incidents":
		if sub == "correlated" {
			_, f, b := omParse(rest, "window")
			return true, omDo(out, "GET", omQuery("/v1/incidents/correlated", f, "window"), nil, b["json"])
		}
	case "case", "cases":
		if om2In(sub, "list", "show", "create", "update", "comment", "close", "export") {
			return true, om2Case(out, sub, rest)
		}
	case "hunt":
		if om2In(sub, "packs", "run", "run-all", "schedules", "schedule-add", "schedule-rm", "history", "devices") {
			return true, om2Hunt(out, sub, rest)
		}
	case "ransomware":
		switch sub {
		case "risk":
			return true, omDo(out, "GET", "/v1/ransomware/risk", nil, j)
		case "host":
			pos, _, _ := omParse(rest)
			h, err := omNeed(pos, 0, "usage: kavachctl ransomware host HOST")
			if err != nil {
				return true, err
			}
			return true, omDo(out, "GET", "/v1/ransomware/host/"+url.PathEscape(h), nil, j)
		}
	case "containers":
		if sub == "risk" {
			return true, omDo(out, "GET", "/v1/containers/risk", nil, j)
		}
	case "lateral":
		_, _, b := omParse(args[1:])
		return true, omDo(out, "GET", "/v1/lateral/edges", nil, b["json"])
	}
	return false, nil
}

func om2SBOM(out io.Writer, host, file string) error {
	b, code, err := doRequest("GET", "/v1/sbom/"+url.PathEscape(host), nil, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %d bytes to %s\n", len(b), file)
	return nil
}

func om2Identity(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "kind")
	j := b["json"]
	switch sub {
	case "indicators":
		return omDo(out, "GET", omQuery("/v1/identity/itdr/indicators", f, "kind"), nil, j)
	case "timeline":
		u, err := omNeed(pos, 0, "usage: kavachctl identity timeline USER")
		if err != nil {
			return err
		}
		return omDo(out, "GET", "/v1/identity/itdr/timeline?user="+url.QueryEscape(u), nil, j)
	}
	return omDo(out, "GET", "/v1/identity/itdr/"+sub, nil, j)
}

func om2Case(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "title", "severity", "assignee", "tags", "incident", "notes", "status", "resolution", "author")
	j := b["json"]
	split := func(s string) []string {
		var r []string
		for _, t := range strings.Split(s, ",") {
			if t = strings.TrimSpace(t); t != "" {
				r = append(r, t)
			}
		}
		return r
	}
	id := func() (string, error) { return omNeed(pos, 0, "usage: kavachctl case "+sub+" ID") }
	switch sub {
	case "list":
		return omDo(out, "GET", "/v1/cases", nil, j)
	case "show", "export":
		i, err := id()
		if err != nil {
			return err
		}
		p := "/v1/cases/" + url.PathEscape(i)
		if sub == "export" {
			p += "/export"
		}
		return omDo(out, "GET", p, nil, j)
	case "create":
		if f["title"] == "" {
			return fmt.Errorf("usage: kavachctl case create --title T [--severity S] [--assignee A] [--tags a,b] [--incident ID] [--notes N]")
		}
		body := map[string]any{"title": f["title"]}
		for _, k := range []string{"severity", "assignee", "notes"} {
			if f[k] != "" {
				body[k] = f[k]
			}
		}
		if f["incident"] != "" {
			body["incident_id"] = f["incident"]
		}
		if f["tags"] != "" {
			body["tags"] = split(f["tags"])
		}
		return omDo(out, "POST", "/v1/cases", body, j)
	case "update", "close":
		i, err := id()
		if err != nil {
			return err
		}
		body := map[string]any{}
		for _, k := range []string{"status", "severity", "assignee", "resolution"} {
			if f[k] != "" {
				body[k] = f[k]
			}
		}
		if f["tags"] != "" {
			body["tags"] = split(f["tags"])
		}
		if sub == "close" {
			if f["resolution"] == "" {
				return fmt.Errorf("usage: kavachctl case close ID --resolution TEXT")
			}
			body["status"] = "closed"
		}
		return omDo(out, "PATCH", "/v1/cases/"+url.PathEscape(i), body, j)
	case "comment":
		i, err := id()
		if err != nil {
			return err
		}
		if len(pos) < 2 {
			return fmt.Errorf("usage: kavachctl case comment ID TEXT")
		}
		body := map[string]any{"text": strings.Join(pos[1:], " ")}
		if f["author"] != "" {
			body["author"] = f["author"]
		}
		return omDo(out, "POST", "/v1/cases/"+url.PathEscape(i)+"/comments", body, j)
	}
	return nil
}

func om2Hunt(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "pack", "interval")
	j := b["json"]
	switch sub {
	case "packs":
		return omDo(out, "GET", "/v1/hunts/packs", nil, j)
	case "run":
		i, err := omNeed(pos, 0, "usage: kavachctl hunt run ID")
		if err != nil {
			return err
		}
		return omDo(out, "POST", "/v1/hunts/packs/"+url.PathEscape(i)+"/run", map[string]any{}, j)
	case "run-all":
		return omDo(out, "POST", "/v1/hunts/run-all", map[string]any{}, j)
	case "schedules":
		return omDo(out, "GET", "/v1/hunts/schedules", nil, j)
	case "schedule-add":
		p := f["pack"]
		if p == "" && len(pos) > 0 {
			p = pos[0]
		}
		if p == "" {
			return fmt.Errorf("usage: kavachctl hunt schedule-add PACK_ID [--interval SECONDS]")
		}
		n := 3600
		if f["interval"] != "" {
			v, err := strconv.Atoi(f["interval"])
			if err != nil {
				return fmt.Errorf("--interval must be seconds")
			}
			n = v
		}
		return omDo(out, "POST", "/v1/hunts/schedules", map[string]any{"pack_id": p, "interval_sec": n}, j)
	case "schedule-rm":
		i, err := omNeed(pos, 0, "usage: kavachctl hunt schedule-rm ID")
		if err != nil {
			return err
		}
		return omDo(out, "DELETE", "/v1/hunts/schedules?id="+url.QueryEscape(i), nil, j)
	case "history":
		return omDo(out, "GET", "/v1/hunts/history", nil, j)
	case "devices":
		return omDo(out, "GET", "/v1/devices/removable", nil, j)
	}
	return nil
}
