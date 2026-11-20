// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// omStdin is where "-" text arguments read from (overridable in tests).
var omStdin io.Reader = os.Stdin

// omDispatch handles the fleet-health, prevalence, canary, governance,
// tuning and digest command groups. handled is false when args is not one
// of them, so run() falls through to the legacy switch.
func omDispatch(args []string, out io.Writer) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	rest := args[1:]
	switch args[0] {
	case "fleet":
		if len(rest) == 0 {
			return false, nil
		}
		switch rest[0] {
		case "health", "gaps", "stale", "host":
			return true, omFleet(out, rest)
		}
		return false, nil
	case "prevalence":
		return true, omPrevalence(out, rest)
	case "blast-radius":
		return true, omBlast(out, rest)
	case "canary", "canaries":
		return true, omCanary(out, rest)
	case "governance", "gov":
		return true, omGovernance(out, rest)
	case "tuning":
		return true, omTuning(out, rest)
	case "digest", "digests":
		return true, omDigest(out, rest)
	}
	return false, nil
}

// omParse splits args into positionals, value flags (valueKeys) and bool flags.
func omParse(args []string, valueKeys ...string) (pos []string, flags map[string]string, bools map[string]bool) {
	want := map[string]bool{}
	for _, k := range valueKeys {
		want[k] = true
	}
	flags, bools = map[string]string{}, map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") || a == "--" {
			pos = append(pos, a)
			continue
		}
		k, v, hasV := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch {
		case hasV && want[k]:
			flags[k] = v
		case want[k] && i+1 < len(args):
			flags[k] = args[i+1]
			i++
		default:
			bools[k] = true
		}
	}
	return
}

func omQuery(path string, flags map[string]string, keys ...string) string {
	v := url.Values{}
	for _, k := range keys {
		if flags[k] != "" {
			v.Set(k, flags[k])
		}
	}
	if e := v.Encode(); e != "" {
		return path + "?" + e
	}
	return path
}

// omDo calls the API and renders the response as indented JSON (compact with --json).
func omDo(out io.Writer, method, path string, body any, compact bool) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	b, code, err := doRequest(method, path, payload, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	if len(bytes.TrimSpace(b)) == 0 {
		fmt.Fprintln(out, "ok")
		return nil
	}
	if compact {
		fmt.Fprintln(out, strings.TrimSpace(string(b)))
		return nil
	}
	var buf bytes.Buffer
	if json.Indent(&buf, b, "", "  ") != nil {
		fmt.Fprintln(out, strings.TrimSpace(string(b)))
		return nil
	}
	fmt.Fprintln(out, buf.String())
	return nil
}

func omNeed(pos []string, i int, usage string) (string, error) {
	if len(pos) <= i || strings.TrimSpace(pos[i]) == "" {
		return "", fmt.Errorf("%s", usage)
	}
	return pos[i], nil
}

func omFleet(out io.Writer, args []string) error {
	pos, f, b := omParse(args[1:], "minutes")
	j := b["json"]
	switch args[0] {
	case "health":
		return omDo(out, "GET", "/v1/fleet/health", nil, j)
	case "gaps":
		return omDo(out, "GET", "/v1/fleet/coverage-gaps", nil, j)
	case "stale":
		return omDo(out, "GET", omQuery("/v1/fleet/stale", f, "minutes"), nil, j)
	default:
		h, err := omNeed(pos, 0, "usage: kavachctl fleet host HOST")
		if err != nil {
			return err
		}
		return omDo(out, "GET", "/v1/fleet/health/"+url.PathEscape(h), nil, j)
	}
}

const omPrevUsage = "usage: kavachctl prevalence executables [--min-hosts N] [--max-hosts N] [--limit N] | rare [--hours H] [--fraction F] | first-seen --host H [--hours H]"

func omPrevalence(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", omPrevUsage)
	}
	_, f, b := omParse(args[1:], "min-hosts", "max-hosts", "limit", "hours", "fraction", "host")
	if v, ok := f["min-hosts"]; ok {
		f["min_hosts"] = v
	}
	if v, ok := f["max-hosts"]; ok {
		f["max_hosts"] = v
	}
	switch args[0] {
	case "executables":
		return omDo(out, "GET", omQuery("/v1/prevalence/executables", f, "min_hosts", "max_hosts", "limit"), nil, b["json"])
	case "rare":
		return omDo(out, "GET", omQuery("/v1/prevalence/rare", f, "hours", "fraction"), nil, b["json"])
	case "first-seen":
		if f["host"] == "" {
			return fmt.Errorf("--host is required\n%s", omPrevUsage)
		}
		return omDo(out, "GET", omQuery("/v1/prevalence/first-seen", f, "host", "hours"), nil, b["json"])
	}
	return fmt.Errorf("%s", omPrevUsage)
}

func omBlast(out io.Writer, args []string) error {
	pos, f, b := omParse(args, "host", "hours", "depth")
	if f["host"] == "" && len(pos) > 0 {
		f["host"] = pos[0]
	}
	if f["host"] == "" {
		return fmt.Errorf("usage: kavachctl blast-radius --host H [--hours H] [--depth N]")
	}
	return omDo(out, "GET", omQuery("/v1/graph/blast-radius", f, "host", "hours", "depth"), nil, b["json"])
}

func omCanary(out io.Writer, args []string) error {
	const usage = "usage: kavachctl canary list | create --kind credential|document-beacon|dns-name --name N [--placement P] [--owner O] | delete ID | trips"
	if len(args) < 1 {
		return fmt.Errorf("%s", usage)
	}
	pos, f, b := omParse(args[1:], "kind", "name", "placement", "owner")
	switch args[0] {
	case "list":
		return omDo(out, "GET", "/v1/deception/canaries", nil, b["json"])
	case "trips":
		return omDo(out, "GET", "/v1/deception/trips", nil, b["json"])
	case "create":
		if f["name"] == "" || f["kind"] == "" {
			return fmt.Errorf("--kind and --name are required\n%s", usage)
		}
		return omDo(out, "POST", "/v1/deception/canaries", map[string]string{"kind": f["kind"], "name": f["name"],
			"placement": f["placement"], "owner": f["owner"]}, b["json"])
	case "delete":
		id, err := omNeed(pos, 0, "usage: kavachctl canary delete ID")
		if err != nil {
			return err
		}
		return omDo(out, "DELETE", "/v1/deception/canaries/"+url.PathEscape(id), nil, b["json"])
	}
	return fmt.Errorf("%s", usage)
}

// omParseDays turns CLASS=DAYS pairs into a retention body; DAYS "unlimited" means null.
func omParseDays(pairs []string) (map[string]any, error) {
	days := map[string]*int{}
	for _, p := range pairs {
		c, v, ok := strings.Cut(p, "=")
		if !ok || c == "" {
			return nil, fmt.Errorf("expected CLASS=DAYS (or CLASS=unlimited), got %q", p)
		}
		if v == "unlimited" || v == "null" {
			days[c] = nil
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid days %q for %s", v, c)
		}
		days[c] = &n
	}
	return map[string]any{"days": days}, nil
}

const omGovUsage = "usage: kavachctl governance inventory | retention [set CLASS=DAYS... | preview [CLASS=DAYS...] | apply --yes] | redaction [set on|off] | redact-preview TEXT|--file F|- | subject ID"

func omGovernance(out io.Writer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", omGovUsage)
	}
	pos, f, b := omParse(args[1:], "file")
	j := b["json"]
	switch args[0] {
	case "inventory":
		return omDo(out, "GET", "/v1/governance/inventory", nil, j)
	case "retention":
		if len(pos) == 0 {
			return omDo(out, "GET", "/v1/governance/retention", nil, j)
		}
		switch pos[0] {
		case "set":
			if len(pos) < 2 {
				return fmt.Errorf("usage: kavachctl governance retention set CLASS=DAYS...")
			}
			body, err := omParseDays(pos[1:])
			if err != nil {
				return err
			}
			return omDo(out, "POST", "/v1/governance/retention", body, j)
		case "preview":
			var body any
			if len(pos) > 1 {
				m, err := omParseDays(pos[1:])
				if err != nil {
					return err
				}
				body = m
			}
			return omDo(out, "POST", "/v1/governance/retention/preview", body, j)
		case "apply":
			if !b["yes"] {
				return fmt.Errorf("retention apply permanently purges data; run 'governance retention preview' first, then re-run with --yes")
			}
			return omDo(out, "POST", "/v1/governance/retention/apply", map[string]string{"confirm": "purge"}, j)
		}
		return fmt.Errorf("%s", omGovUsage)
	case "redaction":
		if len(pos) == 0 {
			return omDo(out, "GET", "/v1/governance/redaction", nil, j)
		}
		if pos[0] != "set" || len(pos) < 2 {
			return fmt.Errorf("usage: kavachctl governance redaction [set on|off]")
		}
		switch strings.ToLower(pos[1]) {
		case "on", "true", "enable", "enabled":
			return omDo(out, "POST", "/v1/governance/redaction", map[string]bool{"enabled": true}, j)
		case "off", "false", "disable", "disabled":
			return omDo(out, "POST", "/v1/governance/redaction", map[string]bool{"enabled": false}, j)
		}
		return fmt.Errorf("redaction set expects on|off")
	case "redact-preview":
		text := strings.Join(pos, " ")
		if file := f["file"]; file != "" || text == "-" {
			var data []byte
			var err error
			if file == "" || file == "-" {
				data, err = io.ReadAll(io.LimitReader(omStdin, 32<<10))
			} else {
				data, err = os.ReadFile(file)
			}
			if err != nil {
				return err
			}
			text = string(data)
		}
		if text == "" {
			return fmt.Errorf("usage: kavachctl governance redact-preview TEXT|--file F|-")
		}
		return omDo(out, "POST", "/v1/governance/redact/preview", map[string]string{"text": text}, j)
	case "subject":
		id, err := omNeed(pos, 0, "usage: kavachctl governance subject ID")
		if err != nil {
			return err
		}
		return omDo(out, "GET", "/v1/governance/subject?q="+url.QueryEscape(id), nil, j)
	}
	return fmt.Errorf("%s", omGovUsage)
}

func omTuning(out io.Writer, args []string) error {
	const usage = "usage: kavachctl tuning suggestions [--days N] | history | apply --rule R --pattern P [--reason T] | revert ID"
	if len(args) < 1 {
		return fmt.Errorf("%s", usage)
	}
	pos, f, b := omParse(args[1:], "days", "rule", "pattern", "reason")
	switch args[0] {
	case "suggestions":
		return omDo(out, "GET", omQuery("/v1/tuning/suggestions", f, "days"), nil, b["json"])
	case "history":
		return omDo(out, "GET", "/v1/tuning/history", nil, b["json"])
	case "apply":
		if f["rule"] == "" || f["pattern"] == "" {
			return fmt.Errorf("--rule and --pattern are required\n%s", usage)
		}
		return omDo(out, "POST", "/v1/tuning/apply", map[string]string{"rule": f["rule"], "pattern": f["pattern"], "reason": f["reason"]}, b["json"])
	case "revert":
		id, err := omNeed(pos, 0, "usage: kavachctl tuning revert ID")
		if err != nil {
			return err
		}
		return omDo(out, "POST", "/v1/tuning/revert?id="+url.QueryEscape(id), nil, b["json"])
	}
	return fmt.Errorf("%s", usage)
}

func omDigest(out io.Writer, args []string) error {
	const usage = "usage: kavachctl digest list | set --name N --schedule daily|weekly --hour 0-23 --content shift-report|soc-metrics|top-risks --type webhook|slack --url U | delete ID | send-now ID | deliveries"
	if len(args) < 1 {
		return fmt.Errorf("%s", usage)
	}
	pos, f, b := omParse(args[1:], "name", "schedule", "hour", "content", "type", "url")
	j := b["json"]
	switch args[0] {
	case "list":
		return omDo(out, "GET", "/v1/digests", nil, j)
	case "deliveries":
		return omDo(out, "GET", "/v1/digests/deliveries", nil, j)
	case "set", "create":
		if f["name"] == "" || f["schedule"] == "" || f["content"] == "" || f["type"] == "" || f["url"] == "" {
			return fmt.Errorf("--name, --schedule, --content, --type and --url are required\n%s", usage)
		}
		hour := 0
		if f["hour"] != "" {
			n, err := strconv.Atoi(f["hour"])
			if err != nil {
				return fmt.Errorf("--hour must be 0-23")
			}
			hour = n
		}
		return omDo(out, "POST", "/v1/digests", map[string]any{"name": f["name"], "schedule": f["schedule"], "hour_utc": hour,
			"content": f["content"], "type": f["type"], "url": f["url"]}, j)
	case "delete":
		id, err := omNeed(pos, 0, "usage: kavachctl digest delete ID")
		if err != nil {
			return err
		}
		return omDo(out, "DELETE", "/v1/digests?id="+url.QueryEscape(id), nil, j)
	case "send-now":
		id, err := omNeed(pos, 0, "usage: kavachctl digest send-now ID")
		if err != nil {
			return err
		}
		return omDo(out, "POST", "/v1/digests/send-now?id="+url.QueryEscape(id), nil, j)
	}
	return fmt.Errorf("%s", usage)
}
