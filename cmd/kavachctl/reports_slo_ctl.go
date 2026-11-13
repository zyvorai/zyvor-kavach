// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const repSchedUsage = `usage: kavachctl reports scheduled <command>
  list [--json]                 schedules, limits and delivery note
  create --file F [--yes]       admin; F: template, frequency, time (HH:MM UTC), name, params, retention, format
  update ID --file F [--yes]    admin
  delete ID [--yes]             admin
  run ID [--yes]                admin; renders a report now into the local archive
  runs ID [--json]              run history for a schedule
  archive get RUN_ID [--out FILE]   (also: kavachctl reports archive get ...)
Delivery is pull-only: Kavach stores rendered reports locally and never emails or pushes them.`

const repArchiveUsage = `usage: kavachctl reports archive get RUN_ID [--out FILE] [--force] [--json]
  Without --out nothing is written; the size and SHA-256 are shown. --out writes only to that path
  (refuses to overwrite an existing file unless --force). Pull-only: Kavach never pushes reports.`

func repSchedRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", repSchedUsage)
	}
	pos, f, b := omParse(args[1:], "file", "out")
	j := b["json"]
	const base = "/v1/reports/scheduled"
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
		fmt.Fprintf(out, "%-8s %-22s %-18s %-9s %-8s %-8s %-22s %s\n", "ID", "NAME", "TEMPLATE", "FREQ", "FORMAT", "ENABLED", "NEXT RUN", "LAST")
		for _, s := range listOf(m, "schedules") {
			fmt.Fprintf(out, "%-8s %-22s %-18s %-9s %-8s %-8v %-22s %s\n", strFrom(s, "id"), truncate(strFrom(s, "name"), 22), truncate(strFrom(s, "template"), 18), strFrom(s, "frequency"), strFrom(s, "format"), s["enabled"], truncate(strFrom(s, "next_run"), 22), strFrom(s, "last_status"))
		}
		fmt.Fprintf(out, "Delivery: %s\n", strFrom(m, "delivery"))
		return nil
	case "runs":
		id, err := schedID(pos, "usage: kavachctl reports scheduled runs ID [--json]")
		if err != nil {
			return err
		}
		raw, err := schedCall("GET", base+"/"+id+"/runs", nil)
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
		fmt.Fprintf(out, "%-22s %-10s %-8s %-8s %-9s %s\n", "RUN ID", "TRIGGER", "STATUS", "BYTES", "FORMAT", "GENERATED / SHA256")
		for _, r := range listOf(m, "runs") {
			fmt.Fprintf(out, "%-22s %-10s %-8s %-8s %-9s %s %s\n", strFrom(r, "run_id"), strFrom(r, "trigger"), strFrom(r, "status"), num(r, "bytes"), strFrom(r, "format"), strFrom(r, "generated_at"), truncate(strFrom(r, "sha256"), 16))
		}
		fmt.Fprintln(out, "Fetch a stored report with: kavachctl reports archive get RUN_ID --out FILE (pull-only; nothing is pushed or emailed).")
		return nil
	case "create":
		if len(pos) != 0 {
			return fmt.Errorf("usage: kavachctl reports scheduled create --file F [--yes]")
		}
		return schedWrite(out, "reports scheduled create", "POST", base, f["file"], b["yes"], j, "This creates a report schedule (admin only).")
	case "update":
		id, err := schedID(pos, "usage: kavachctl reports scheduled update ID --file F [--yes]")
		if err != nil {
			return err
		}
		return schedWrite(out, "reports scheduled update", "PUT", base+"/"+id, f["file"], b["yes"], j, "This updates report schedule "+id+" (admin only).")
	case "delete":
		id, err := schedID(pos, "usage: kavachctl reports scheduled delete ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "reports scheduled delete", "DELETE", base+"/"+id, nil, b["yes"], j, "This deletes report schedule "+id+".")
	case "run":
		id, err := schedID(pos, "usage: kavachctl reports scheduled run ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "reports scheduled run", "POST", base+"/"+id+"/run", []byte("{}"), b["yes"], j, "This renders report "+id+" now into the local archive.")
	case "archive":
		return repArchiveRun(out, args[1:])
	}
	return fmt.Errorf("unknown reports scheduled command %q\n%s", args[0], repSchedUsage)
}

func repArchiveRun(out io.Writer, args []string) error {
	if len(args) == 0 || args[0] != "get" {
		return fmt.Errorf("%s", repArchiveUsage)
	}
	pos, f, b := omParse(args[1:], "out")
	id, err := schedID(pos, repArchiveUsage)
	if err != nil {
		return err
	}
	if strings.ContainsAny(id, "/\\?#") {
		return fmt.Errorf("invalid run id %q", id)
	}
	raw, code, err := doRequest("GET", "/v1/reports/archive/"+id, nil, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
	}
	sum := sha256.Sum256(raw)
	res := map[string]any{"run_id": id, "bytes": len(raw), "sha256": hex.EncodeToString(sum[:]), "written_to": nil}
	if f["out"] != "" {
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if b["force"] {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		fh, err := os.OpenFile(f["out"], flags, 0o600)
		if err != nil {
			return fmt.Errorf("%v (use --force to overwrite)", err)
		}
		if _, err := fh.Write(raw); err != nil {
			fh.Close()
			return err
		}
		if err := fh.Close(); err != nil {
			return err
		}
		res["written_to"] = f["out"]
	}
	if b["json"] {
		enc, _ := json.Marshal(res)
		fmt.Fprintln(out, string(enc))
		return nil
	}
	if f["out"] == "" {
		fmt.Fprintf(out, "Report %s: %d bytes, sha256 %s\nNothing was written: pass --out FILE to save it (pull-only; Kavach never pushes reports).\n", id, len(raw), res["sha256"])
		return nil
	}
	fmt.Fprintf(out, "Wrote %d bytes to %s (sha256 %s)\n", len(raw), f["out"], res["sha256"])
	return nil
}

// ---- fleet slo ----

const sloUsage = `usage: kavachctl fleet slo [status|history|definitions|set]
  slo [status] [--json]                  fleet and per-agent SLO status
  slo history [--agent A] [--window 24h] [--json]
  slo definitions [--json]
  slo set --file F [--yes]               admin; omitted fields keep their value`

func sloRun(out io.Writer, args []string) error {
	cmd := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		cmd, args = args[0], args[1:]
	}
	pos, f, b := omParse(args, "agent", "window", "file")
	j := b["json"]
	if len(pos) != 0 {
		return fmt.Errorf("%s", sloUsage)
	}
	switch cmd {
	case "status":
		raw, err := schedCall("GET", "/v1/fleet/slo", nil)
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
		fmt.Fprintf(out, "Fleet SLO (generated %s)\n", strFrom(m, "generated_at"))
		if t, ok := m["targets"].(map[string]any); ok {
			fmt.Fprintf(out, "Targets: %s\n", sloKV(t))
		}
		if fl, ok := m["fleet"].(map[string]any); ok {
			fmt.Fprintf(out, "Fleet: %s\n", sloKV(fl))
		}
		for _, c := range listOf(m, "coverage") {
			fmt.Fprintf(out, "Coverage: %s\n", sloKV(c))
		}
		fmt.Fprintf(out, "\n%-24s %-9s %-9s %-14s %s\n", "AGENT", "STATE", "HEARTBEAT", "SAMPLES", "LAST SEEN")
		for _, a := range listOf(m, "agents") {
			fmt.Fprintf(out, "%-24s %-9s %-9s %-14s %s\n", truncate(strFrom(a, "host"), 24), strFrom(a, "state"), strFrom(a, "heartbeat_current"), num(a, "samples_in_window"), strFrom(a, "last_seen"))
		}
		if br := listOf(m, "breaches"); len(br) > 0 {
			fmt.Fprintln(out, "\nBreaches:")
			for _, x := range br {
				fmt.Fprintf(out, "  - %s %s (%s): %s\n", strFrom(x, "agent"), strFrom(x, "indicator"), strFrom(x, "kind"), strFrom(x, "detail"))
			}
		} else {
			fmt.Fprintln(out, "\nNo SLO breaches.")
		}
		if nr, ok := m["not_reported_by_agent"].([]any); ok && len(nr) > 0 {
			fmt.Fprintln(out, "\nNot reported by agent (no value is estimated):")
			for _, x := range nr {
				fmt.Fprintf(out, "  - %v: not reported by agent\n", x)
			}
		}
		if ns, ok := m["notes"].([]any); ok {
			for _, n := range ns {
				fmt.Fprintf(out, "NOTE: %v\n", n)
			}
		}
		return nil
	case "history":
		raw, err := schedCall("GET", omQuery("/v1/fleet/slo/history", f, "agent", "window"), nil)
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
		pts, _ := m["points"].([]any)
		fmt.Fprintf(out, "SLO history: agent=%q window=%s step=%ss points=%d\n", strFrom(m, "agent"), strFrom(m, "window"), num(m, "step_seconds"), len(pts))
		schedShow(out, mustJSON(m["points"]), false)
		return nil
	case "definitions":
		raw, err := schedCall("GET", "/v1/fleet/slo/definitions", nil)
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
		fmt.Fprintf(out, "Sampling: %s\n\n", strFrom(m, "sampling"))
		for _, x := range listOf(m, "indicators") {
			fmt.Fprintf(out, "%s\n  %s\n  source: %s\n", strFrom(x, "name"), strFrom(x, "definition"), strFrom(x, "source"))
		}
		fmt.Fprintf(out, "\nError budget: %s\n", strFrom(m, "error_budget"))
		if nr, ok := m["not_reported_by_agent"].([]any); ok {
			fmt.Fprintln(out, "\nNot reported by agent:")
			for _, x := range nr {
				fmt.Fprintf(out, "  - %v: not reported by agent\n", x)
			}
		}
		fmt.Fprintf(out, "%s\n", strFrom(m, "agent_would_need_to_send"))
		return nil
	case "set":
		return schedWrite(out, "fleet slo set", "PUT", "/v1/fleet/slo", f["file"], b["yes"], j, "This changes the fleet SLO targets (admin only).")
	}
	return fmt.Errorf("unknown fleet slo command %q\n%s", cmd, sloUsage)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func sloKV(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, " ")
}
