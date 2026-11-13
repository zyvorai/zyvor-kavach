// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// schedFileMax caps local JSON definition files (the server accepts at most 32 KiB bodies).
const schedFileMax = 64 << 10

// schedDispatch is the single entry for: detections scheduled, hunts limits, exceptions,
// reports scheduled|archive, fleet slo, syslog, and `inspect config`. Everything else
// (including other `detections`, `fleet`, `report` and `inspect` subcommands) falls through.
func schedDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	rest := []string{}
	if len(args) > 2 {
		rest = args[2:]
	}
	switch args[0] {
	case "detections":
		if sub == "scheduled" {
			return true, detSchedRun(out, rest)
		}
	case "hunts":
		if sub == "limits" {
			return true, huntLimitsRun(out, rest)
		}
		return true, fmt.Errorf("%s", huntsUsage)
	case "exceptions":
		return true, excRun(out, args[1:])
	case "reports":
		switch sub {
		case "scheduled":
			return true, repSchedRun(out, rest)
		case "archive":
			return true, repArchiveRun(out, rest)
		}
	case "fleet":
		if sub == "slo" {
			return true, sloRun(out, rest)
		}
	case "syslog":
		return true, syslogRun(out, args[1:])
	case "inspect":
		if sub == "config" {
			return true, inspectConfigRun(out, rest)
		}
	}
	return false, nil
}

// schedCall performs a request. HTTP >= 300 becomes an error carrying the server's message; a 403
// is called out as an admin-token requirement. 204 yields an empty body.
func schedCall(method, path string, body []byte) ([]byte, error) {
	var h map[string]string
	if body != nil {
		h = map[string]string{"Content-Type": "application/json"}
	}
	b, code, err := doRequest(method, path, body, h)
	if err != nil {
		return nil, err
	}
	if code == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP 403 forbidden: %s\n(this change needs an admin token; set KAVACH_TOKEN to the admin key)", truncate(strings.TrimSpace(string(b)), 400))
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	return b, nil
}

// schedConfirm asks before a mutating command unless --yes was given.
func schedConfirm(yes bool, name, warn string) error {
	if yes {
		return nil
	}
	if !mlInteractive() {
		return fmt.Errorf("%s is mutating; re-run with --yes to confirm", name)
	}
	fmt.Fprintf(os.Stderr, "%s Continue? [y/N] ", warn)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

// schedReadJSON reads a JSON object from --file (a path, or - for stdin), capped at schedFileMax.
func schedReadJSON(file string) ([]byte, error) {
	var data []byte
	if file == "-" {
		d, err := io.ReadAll(io.LimitReader(omStdin, schedFileMax+1))
		if err != nil {
			return nil, err
		}
		if len(d) > schedFileMax {
			return nil, fmt.Errorf("stdin exceeds %d bytes (64 KiB)", schedFileMax)
		}
		data = d
	} else {
		d, _, err := inspectReadFile(file, schedFileMax, "64 KiB")
		if err != nil {
			return nil, err
		}
		data = d
	}
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %v", file, err)
	}
	return data, nil
}

// schedShow prints a raw response: compact with --json, indented otherwise ("ok" when empty).
func schedShow(out io.Writer, raw []byte, asJSON bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		fmt.Fprintln(out, "ok")
		return
	}
	if asJSON {
		fmt.Fprintln(out, string(raw))
		return
	}
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") != nil {
		fmt.Fprintln(out, string(raw))
		return
	}
	fmt.Fprintln(out, buf.String())
}

func schedObj(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func schedID(pos []string, usage string) (string, error) {
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		return "", fmt.Errorf("%s", usage)
	}
	return pos[0], nil
}

// schedWrite is the shared create/update path: read --file, confirm, send.
func schedWrite(out io.Writer, name, method, path, file string, yes, asJSON bool, warn string) error {
	if file == "" {
		return fmt.Errorf("--file F is required")
	}
	body, err := schedReadJSON(file)
	if err != nil {
		return err
	}
	if err := schedConfirm(yes, name, warn); err != nil {
		return err
	}
	raw, err := schedCall(method, path, body)
	if err != nil {
		return err
	}
	schedShow(out, raw, asJSON)
	return nil
}

// schedSimple is the confirm-then-call path for commands without a body file.
func schedSimple(out io.Writer, name, method, path string, body []byte, yes, asJSON bool, warn string) error {
	if err := schedConfirm(yes, name, warn); err != nil {
		return err
	}
	raw, err := schedCall(method, path, body)
	if err != nil {
		return err
	}
	schedShow(out, raw, asJSON)
	return nil
}

// ---- detections scheduled ----

const detSchedUsage = `usage: kavachctl detections scheduled <command>
  list [--json]                 scheduled detections and limits
  show ID [--json]
  create --file F [--yes]       admin; F is a JSON definition (name, source, interval_sec, severity, state...)
  update ID --file F [--yes]    admin; only fields present in F change
  delete ID [--yes]             admin; findings already recorded are kept
  dryrun ID [--json]            admin; runs the query, records NOTHING
  run ID [--yes]                admin; runs now and records findings
  history ID [--json]
Scheduled detections record findings; they never block, kill or contain anything.`

const huntsUsage = `usage: kavachctl hunts limits [--set key=value ...] [--yes] [--json]
  keys: max_scheduled, max_runs_per_hour, max_matches_per_run, history_retention (--set needs an admin token)`

func detSchedRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", detSchedUsage)
	}
	pos, f, b := omParse(args[1:], "file")
	j := b["json"]
	const base = "/v1/detections/scheduled"
	switch args[0] {
	case "list":
		raw, err := schedCall("GET", base, nil)
		if err != nil {
			return err
		}
		if j {
			schedShow(out, raw, true)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-8s %-28s %-10s %-9s %-9s %s\n", "ID", "NAME", "STATE", "SEVERITY", "INTERVAL", "SOURCE")
		for _, d := range listOf(m, "detections") {
			src, _ := d["source"].(map[string]any)
			fmt.Fprintf(out, "%-8s %-28s %-10s %-9s %-9s %s\n", strFrom(d, "id"), truncate(strFrom(d, "name"), 28), strFrom(d, "state"), strFrom(d, "severity"), strconv.Itoa(intFrom(d, "interval_sec"))+"s", strFrom(src, "kind"))
		}
		fmt.Fprintf(out, "%s scheduled detections. %s\n", num(m, "count"), strFrom(m, "semantics"))
		return nil
	case "show", "history":
		id, err := schedID(pos, "usage: kavachctl detections scheduled "+args[0]+" ID [--json]")
		if err != nil {
			return err
		}
		p := base + "/" + id
		if args[0] == "history" {
			p += "/history"
		}
		raw, err := schedCall("GET", p, nil)
		if err != nil {
			return err
		}
		if j || args[0] == "show" {
			schedShow(out, raw, j)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-26s %-9s %-8s %-8s %-8s %-8s %-8s %s\n", "TIME", "TRIGGER", "SCANNED", "MATCHED", "RECORDED", "SHADOW", "DEDUPED", "SUPPRESSED")
		for _, r := range listOf(m, "history") {
			fmt.Fprintf(out, "%-26s %-9s %-8s %-8s %-8s %-8s %-8s %s\n", strFrom(r, "time"), strFrom(r, "trigger"), num(r, "scanned"), num(r, "matched"), num(r, "recorded"), num(r, "shadow"), num(r, "deduped"), num(r, "suppressed"))
		}
		fmt.Fprintf(out, "Retention: %s runs. For dry runs, 'recorded' means 'would be reported'.\n", num(m, "retention"))
		return nil
	case "create":
		if len(pos) != 0 {
			return fmt.Errorf("usage: kavachctl detections scheduled create --file F [--yes]")
		}
		return schedWrite(out, "detections scheduled create", "POST", base, f["file"], b["yes"], j, "This creates a scheduled detection (admin only).")
	case "update":
		id, err := schedID(pos, "usage: kavachctl detections scheduled update ID --file F [--yes]")
		if err != nil {
			return err
		}
		return schedWrite(out, "detections scheduled update", "PUT", base+"/"+id, f["file"], b["yes"], j, "This updates scheduled detection "+id+" (admin only).")
	case "delete":
		id, err := schedID(pos, "usage: kavachctl detections scheduled delete ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "detections scheduled delete", "DELETE", base+"/"+id, nil, b["yes"], j, "This deletes scheduled detection "+id+" (recorded findings are kept).")
	case "dryrun":
		id, err := schedID(pos, "usage: kavachctl detections scheduled dryrun ID [--json]")
		if err != nil {
			return err
		}
		raw, err := schedCall("POST", base+"/"+id+"/dryrun", []byte("{}"))
		if err != nil {
			return err
		}
		if !j {
			fmt.Fprintln(out, "DRY RUN: nothing was recorded. In this result, 'recorded' means 'would be reported'.")
		}
		schedShow(out, raw, j)
		return nil
	case "run":
		id, err := schedID(pos, "usage: kavachctl detections scheduled run ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "detections scheduled run", "POST", base+"/"+id+"/run", []byte("{}"), b["yes"], j, "This runs "+id+" now and records any findings.")
	}
	return fmt.Errorf("unknown detections scheduled command %q\n%s", args[0], detSchedUsage)
}

// huntSetPairs pulls every --set key=value (and --set=key=value) out of args.
func huntSetPairs(args []string) (rest []string, sets map[string]int, err error) {
	sets = map[string]int{}
	valid := map[string]bool{"max_scheduled": true, "max_runs_per_hour": true, "max_matches_per_run": true, "history_retention": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		var kv string
		switch {
		case a == "--set" && i+1 < len(args):
			i++
			kv = args[i]
		case strings.HasPrefix(a, "--set="):
			kv = strings.TrimPrefix(a, "--set=")
		default:
			rest = append(rest, a)
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		n, cerr := strconv.Atoi(v)
		if !ok || cerr != nil || !valid[k] {
			return nil, nil, fmt.Errorf("bad --set %q: want key=INT with key one of max_scheduled, max_runs_per_hour, max_matches_per_run, history_retention", kv)
		}
		sets[k] = n
	}
	return rest, sets, nil
}

func huntLimitsRun(out io.Writer, args []string) error {
	rest, sets, err := huntSetPairs(args)
	if err != nil {
		return err
	}
	pos, _, b := omParse(rest)
	if len(pos) != 0 {
		return fmt.Errorf("%s", huntsUsage)
	}
	j := b["json"]
	if len(sets) == 0 {
		raw, err := schedCall("GET", "/v1/hunts/limits", nil)
		if err != nil {
			return err
		}
		schedShow(out, raw, j)
		return nil
	}
	body, _ := json.Marshal(sets)
	return schedSimple(out, "hunts limits --set", "PUT", "/v1/hunts/limits", body, b["yes"], j, "This changes the hunt quotas (admin only).")
}
