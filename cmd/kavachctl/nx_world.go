// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ---- competitive ----

const competitiveNote = "Competitor cells come from public documentation, may be out of date or incomplete; 'Not documented' means not found, not absent."

func nxCompetitive(out io.Writer, args []string) error {
	_, _, b := omParse(args)
	raw, err := nxCall("GET", "/v1/world/competitive", nil)
	if err != nil {
		return err
	}
	if nxEmit(out, raw, b["json"]) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "NOTE: public documentation, may be out of date. %s\n", competitiveNote)
	fmt.Fprintf(out, "server note: %s\nlast researched: %s\n\n", nxS(m["note"]), nxS(m["last_researched"]))
	prods := nxList(m, "products")
	mat := nxSub(m, "matrix")
	abbr := map[string]string{"Has": "Has", "Partial": "Part", "Not documented": "n/d", "Out of scope by design": "N/A"}
	tw := newTab(out)
	head := "AREA"
	for _, p := range prods {
		head += "\t" + truncate(nxS(p["id"]), 12)
	}
	fmt.Fprintln(tw, head)
	for _, a := range nxList(m, "areas") {
		row := nxS(a["name"])
		cells := nxSub(mat, nxS(a["id"]))
		for _, p := range prods {
			st := nxS(nxSub(cells, nxS(p["id"]))["status"])
			if s, ok := abbr[st]; ok {
				st = s
			}
			row += "\t" + st
		}
		fmt.Fprintln(tw, row)
	}
	_ = tw.Flush()
	fmt.Fprintln(out, "legend: Has, Part=Partial, n/d=Not documented (not found, not absent), N/A=Out of scope by design")
	bl := nxList(m, "backlog")
	eff := map[string]int{}
	for _, it := range bl {
		eff[nxS(it["effort"])]++
	}
	ks := []string{}
	for k := range eff {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	parts := []string{}
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("%s=%d", k, eff[k]))
	}
	fmt.Fprintf(out, "\nbacklog: %d candidate observation-only features (effort %s)\n", len(bl), strings.Join(parts, " "))
	for _, it := range bl {
		fmt.Fprintf(out, "  %2g [%s] %s (telemetry: %s; conflicts with observation-only: %s)\n", nxNum(it, "id"), nxS(it["effort"]), nxS(it["title"]),
			truncate(nxS(it["telemetry_sufficient"]), 40), nxS(it["conflicts_with_observation_only"]))
	}
	fmt.Fprintf(out, "%d sources\n", len(nxList(m, "sources")))
	return nil
}

// ---- chains ----

const chainsUsage = "usage: kavachctl chains list [--host H] [--min-score S] [--limit N] [--json] | show ID | case ID [--yes]"

func nxChains(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", chainsUsage)
	}
	pos, f, b := omParse(args[1:], "host", "min-score", "limit")
	j := b["json"]
	switch args[0] {
	case "list":
		raw, err := nxCall("GET", nxQ("/v1/chains", f, "host", "host", "min-score", "min_score", "limit", "limit"), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tHOSTS\tSCORE\tSEV\tSIZE\tTACTICS\tCASE")
		for _, c := range nxList(m, "chains") {
			fmt.Fprintf(tw, "%s\t%s\t%.2f\t%s\t%g\t%s\t%s\n", nxS(c["id"]), nxJoin(c["hosts"]), nxNum(c, "score"), nxS(c["severity"]), nxNum(c, "size"),
				strings.ReplaceAll(nxJoin(c["tactics"]), ",", " > "), nxS(c["case_id"]))
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%g of %g chains\n", nxNum(m, "returned"), nxNum(m, "total"))
		nxChainFooter(out, m)
		return nil
	case "show":
		if len(pos) < 1 {
			return fmt.Errorf("usage: kavachctl chains show ID")
		}
		raw, err := nxCall("GET", nxPath("/v1/chains", pos[0]), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		c := nxSub(m, "chain")
		fmt.Fprintf(out, "chain %s  hosts %s  score %.2f  severity %s  %g findings  case %s\n", nxS(c["id"]), nxJoin(c["hosts"]), nxNum(c, "score"), nxS(c["severity"]),
			nxNum(c, "size"), nxS(c["case_id"]))
		fmt.Fprintf(out, "tactics in order: %s\nfirst %s  last %s  links %g\n", strings.ReplaceAll(nxJoin(m["tactics_in_order"]), ",", " > "), nxS(c["first"]), nxS(c["last"]), nxNum(c, "link_count"))
		for _, w := range nxList(c, "why_summary") {
			fmt.Fprintf(out, "  why: %s (%v)\n", nxS(w["reason"]), w["weight"])
		}
		fmt.Fprintln(out, "timeline:")
		for _, mem := range nxList(m, "members") {
			fmt.Fprintf(out, "  %s  %s  %s  %s  %s  %s\n", fmtTime(nxS(mem["time"])), nxS(mem["host"]), nxS(mem["severity"]), nxS(mem["rule"]), nxS(mem["tactic"]), nxS(mem["id"]))
		}
		if q := nxStrs(m, "suggested_questions"); len(q) > 0 {
			fmt.Fprintf(out, "suggested questions (%s):\n", nxS(m["questions_note"]))
			for _, x := range q {
				fmt.Fprintf(out, "  - %s\n", x)
			}
		}
		nxChainFooter(out, m)
		return nil
	case "case":
		if len(pos) < 1 {
			return fmt.Errorf("usage: kavachctl chains case ID [--yes]")
		}
		if err := nxConfirm(b["yes"], "chains case", "This creates (or returns the existing) incident case for the chain."); err != nil {
			return err
		}
		raw, err := nxCall("POST", nxPath("/v1/chains", pos[0], "case"), nxMap{})
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		c := nxSub(m, "case")
		verb := "case already existed"
		if m["created"] == true {
			verb = "case created"
		}
		fmt.Fprintf(out, "%s: %s  %s  (%s, %s)\n", verb, nxS(c["id"]), nxS(c["title"]), nxS(c["severity"]), nxS(c["status"]))
		return nil
	}
	return fmt.Errorf("%s", chainsUsage)
}

func nxChainFooter(out io.Writer, m nxMap) {
	fmt.Fprintf(out, "method: %s\n", nxS(m["method"]))
	for _, l := range nxStrs(m, "limitations") {
		fmt.Fprintf(out, "limitation: %s\n", l)
	}
}

// ---- case templates ----

const caseTemplatesUsage = "usage: kavachctl casetemplates list | show ID | create --file F [--yes] | update ID --file F [--yes] | delete ID [--yes]   (all take --json)"

func nxReadJSONFile(name string) (json.RawMessage, error) {
	bs, err := readInputFile(name)
	if err != nil {
		return nil, err
	}
	if !json.Valid(bs) {
		return nil, fmt.Errorf("%s is not valid JSON", name)
	}
	return json.RawMessage(bs), nil
}

func nxCaseTemplates(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", caseTemplatesUsage)
	}
	pos, f, b := omParse(args[1:], "file")
	j := b["json"]
	need := func() (string, error) {
		if len(pos) < 1 {
			return "", fmt.Errorf("%s", caseTemplatesUsage)
		}
		return pos[0], nil
	}
	switch args[0] {
	case "list":
		raw, err := nxCall("GET", "/v1/case-templates", nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		var ts []nxMap
		if err := json.Unmarshal(raw, &ts); err != nil {
			return err
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "ID\tNAME\tTYPE\tSEVERITY\tSTEPS\tBUILT-IN")
		for _, t := range ts {
			cl, _ := t["checklist"].([]any)
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%v\n", nxS(t["id"]), nxS(t["name"]), nxS(t["case_type"]), nxS(t["default_severity"]), len(cl), t["built_in"])
		}
		return tw.Flush()
	case "show":
		id, err := need()
		if err != nil {
			return err
		}
		raw, err := nxCall("GET", nxPath("/v1/case-templates", id), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		t, err := nxDecode(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s  %s\ntype: %s  default severity: %s  built-in: %v\nsla hours: %s\ntags: %s\nchecklist:\n", nxS(t["id"]), nxS(t["name"]), nxS(t["case_type"]),
			nxS(t["default_severity"]), t["built_in"], nxS(t["sla_hours"]), nxJoin(t["default_tags"]))
		for i, s := range nxStrs(t, "checklist") {
			fmt.Fprintf(out, "  %d. %s\n", i+1, s)
		}
		return nil
	case "create", "update":
		method, path, name := "POST", "/v1/case-templates", "casetemplates create"
		if args[0] == "update" {
			id, err := need()
			if err != nil {
				return err
			}
			method, path, name = "PUT", nxPath("/v1/case-templates", id), "casetemplates update"
		}
		if f["file"] == "" {
			return fmt.Errorf("%s needs --file F (JSON: name, case_type, default_severity, checklist, sla_hours, default_tags)", name)
		}
		body, err := nxReadJSONFile(f["file"])
		if err != nil {
			return err
		}
		if err := nxConfirm(b["yes"], name, "This changes the case template library (admin token required)."); err != nil {
			return err
		}
		raw, err := nxCall(method, path, body)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		t, err := nxDecode(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "saved template %s (%s)\n", nxS(t["id"]), nxS(t["name"]))
		return nil
	case "delete":
		id, err := need()
		if err != nil {
			return err
		}
		if err := nxConfirm(b["yes"], "casetemplates delete", "This deletes template "+id+" (admin token required)."); err != nil {
			return err
		}
		raw, err := nxCall("DELETE", nxPath("/v1/case-templates", id), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		fmt.Fprintf(out, "deleted template %s\n", id)
		return nil
	}
	return fmt.Errorf("%s", caseTemplatesUsage)
}

// ---- case workflow (claims only its own subcommands of `case`) ----

const caseWorkflowUsage = "usage: kavachctl case assign ID --to NAME [--yes] | apply-template ID --template T [--yes] | checklist ID N --done|--undo [--yes] | workflow ID | journal   (all take --json)"

func nxCaseWorkflow(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "to", "template")
	j := b["json"]
	switch sub {
	case "assign":
		if len(pos) < 1 || f["to"] == "" {
			return fmt.Errorf("%s", caseWorkflowUsage)
		}
		if err := nxConfirm(b["yes"], "case assign", "This sets the assignee of case "+pos[0]+"."); err != nil {
			return err
		}
		return nxWorkflowPost(out, nxPath("/v1/cases", pos[0], "assign"), nxMap{"assignee": f["to"]}, j)
	case "apply-template":
		if len(pos) < 1 || f["template"] == "" {
			return fmt.Errorf("%s", caseWorkflowUsage)
		}
		if err := nxConfirm(b["yes"], "case apply-template", "This applies a checklist template to case "+pos[0]+" (adds a comment and tags)."); err != nil {
			return err
		}
		return nxWorkflowPost(out, nxPath("/v1/cases", pos[0], "apply-template"), nxMap{"template_id": f["template"]}, j)
	case "checklist":
		if len(pos) < 2 {
			return fmt.Errorf("%s", caseWorkflowUsage)
		}
		if _, err := strconv.Atoi(pos[1]); err != nil {
			return fmt.Errorf("invalid step number %q (1-based)", pos[1])
		}
		if b["done"] == b["undo"] {
			return fmt.Errorf("case checklist needs exactly one of --done or --undo")
		}
		if err := nxConfirm(b["yes"], "case checklist", "This changes checklist step "+pos[1]+" of case "+pos[0]+"."); err != nil {
			return err
		}
		return nxWorkflowPost(out, nxPath("/v1/cases", pos[0], "checklist", pos[1]), nxMap{"done": b["done"]}, j)
	case "workflow":
		if len(pos) < 1 {
			return fmt.Errorf("%s", caseWorkflowUsage)
		}
		raw, err := nxCall("GET", nxPath("/v1/cases", pos[0], "workflow"), nil)
		if err != nil {
			return err
		}
		return nxWorkflowShow(out, raw, j)
	case "journal":
		raw, err := nxCall("GET", "/v1/case-workflow/journal", nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		if m["intact"] == true {
			fmt.Fprintln(out, "journal chain intact")
		} else {
			fmt.Fprintf(out, "journal chain BROKEN at seq %g: %s\n", nxNum(m, "first_broken_seq"), nxS(m["reason"]))
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tACTION\tDETAIL")
		for _, e := range nxList(m, "entries") {
			fmt.Fprintf(tw, "%g\t%s\t%s\t%s\t%s\n", nxNum(e, "seq"), fmtTime(nxS(e["time"])), nxS(e["actor"]), nxS(e["action"]), nxS(e["target"]))
		}
		return tw.Flush()
	}
	return fmt.Errorf("%s", caseWorkflowUsage)
}

func nxWorkflowPost(out io.Writer, path string, body nxMap, j bool) error {
	raw, err := nxCall("POST", path, body)
	if err != nil {
		return err
	}
	return nxWorkflowShow(out, raw, j)
}

func nxWorkflowShow(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "case %s  status %s  severity %s  assignee %s\n", nxS(m["case_id"]), nxS(m["status"]), nxS(m["severity"]), nxS(m["assignee"]))
	fmt.Fprintf(out, "(%s)\n", nxS(m["assignee_note"]))
	if t := nxS(m["template_name"]); t != "-" && t != "unknown" {
		fmt.Fprintf(out, "template: %s (%s) applied %s\n", t, nxS(m["template_id"]), nxS(m["applied_at"]))
	} else {
		fmt.Fprintln(out, "no template applied")
	}
	p := nxSub(m, "checklist_progress")
	fmt.Fprintf(out, "checklist %g of %g done\n", nxNum(p, "done"), nxNum(p, "total"))
	for i, it := range nxList(m, "checklist") {
		mark := "[ ]"
		by := ""
		if it["done"] == true {
			mark = "[x]"
			by = "  (" + nxS(it["by"]) + ")"
		}
		fmt.Fprintf(out, "  %d. %s %s%s\n", i+1, mark, nxS(it["text"]), by)
	}
	if s := nxSub(m, "template_sla"); s != nil {
		fmt.Fprintf(out, "template SLA: resolve within %gh, due %s, overdue %v, remaining %g min\n", nxNum(s, "resolve_hours"), nxS(s["resolve_due"]), s["overdue"], nxNum(s, "remaining_minutes"))
	}
	if s := nxSub(m, "builtin_sla"); s != nil {
		fmt.Fprintf(out, "built-in SLA: %s\n", nxS(s))
	}
	return nil
}

// ---- content versions and coverage blind spots ----

const contentUsageNx = "usage: kavachctl content versions [--items] | changes [--from X --to Y] | changelog   (all take --json)"

func nxContent(out io.Writer, sub string, args []string) error {
	_, f, b := omParse(args, "from", "to")
	j := b["json"]
	switch sub {
	case "versions":
		path := "/v1/content/versions"
		if b["items"] {
			path += "?items=1"
		}
		raw, err := nxCall("GET", path, nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		tw := newTab(out)
		fmt.Fprintln(tw, "SEQ\tTIME\tBUILD\tHASH\tITEMS\tPACKS")
		for _, s := range nxList(m, "snapshots") {
			fmt.Fprintf(tw, "%g\t%s\t%s\t%s\t%g\t%d\n", nxNum(s, "seq"), nxS(s["time"]), nxS(s["build"]), truncate(nxS(s["hash"]), 12), nxNum(s, "total_items"), len(nxList(s, "packs")))
			if b["items"] {
				for _, p := range nxList(s, "packs") {
					fmt.Fprintf(tw, "\t  pack %s\t%s\t%s\t%g items\t\n", nxS(p["name"]), nxS(p["kind"]), truncate(nxS(p["hash"]), 12), nxNum(p, "count"))
					for _, it := range nxList(p, "items") {
						fmt.Fprintf(tw, "\t    %s\t\t%s\t\t\n", nxS(it["id"]), truncate(nxS(it["hash"]), 12))
					}
				}
			}
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%g snapshots (history cap %g)\n%s\n", nxNum(m, "count"), nxNum(m, "history_cap"), nxS(m["note"]))
		return nil
	case "changes":
		raw, err := nxCall("GET", nxQ("/v1/content/changes", f, "from", "from", "to", "to"), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		if msg := nxS(m["message"]); msg != "-" && msg != "unknown" {
			fmt.Fprintln(out, msg)
		}
		d := nxSub(m, "diff")
		if d == nil {
			d = m
		}
		if fr := nxSub(m, "from"); fr != nil {
			fmt.Fprintf(out, "from snapshot %g (%s) to snapshot %g (%s)\n", nxNum(fr, "seq"), nxS(fr["time"]), nxNum(nxSub(m, "to"), "seq"), nxS(nxSub(m, "to")["time"]))
		}
		if d["identical"] == true {
			fmt.Fprintln(out, "no content differences")
		}
		for _, sec := range []string{"added", "removed", "modified"} {
			l := nxList(d, sec)
			fmt.Fprintf(out, "%s (%d):\n", sec, len(l))
			for _, c := range l {
				extra := ""
				if fc := nxJoin(c["fields_changed"]); fc != "" {
					extra = "  fields: " + fc
				}
				if hl := nxJoin(c["highlights"]); hl != "" {
					extra += "  HIGHLIGHT: " + hl
				}
				fmt.Fprintf(out, "  %-10s %-10s %s%s\n", nxS(c["pack"]), nxS(c["kind"]), nxS(c["id"]), extra)
			}
		}
		return nil
	case "changelog":
		raw, err := nxCall("GET", "/v1/content/changelog", nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		for _, e := range nxList(m, "changelog") {
			fmt.Fprintf(out, "#%g  %s  build %s  %g items\n    %s\n", nxNum(e, "seq"), nxS(e["time"]), nxS(e["build"]), nxNum(e, "total_items"), nxS(e["summary"]))
		}
		if msg := nxS(m["message"]); msg != "-" && msg != "unknown" {
			fmt.Fprintln(out, msg)
		}
		return nil
	}
	return fmt.Errorf("%s", contentUsageNx)
}

const coverageUsageNx = "usage: kavachctl coverage blindspots [--stale-days N] [--no-validation] | telemetry [--stale-days N]   (all take --json)"

const blindspotCaveatNx = "No events received may mean none happened, not that collection is broken."

func nxCoverage(out io.Writer, sub string, args []string) error {
	_, f, b := omParse(args, "stale-days")
	j := b["json"]
	if f["stale-days"] != "" {
		if n, err := strconv.Atoi(f["stale-days"]); err != nil || n < 1 || n > 3650 {
			return fmt.Errorf("invalid --stale-days %q (1-3650)", f["stale-days"])
		}
	}
	switch sub {
	case "telemetry":
		raw, err := nxCall("GET", nxQ("/v1/coverage/telemetry", f, "stale-days", "stale_days"), nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "CAVEAT: %s\n%s\n\n", blindspotCaveatNx, nxS(m["caveat"]))
		nxCategories(out, nxList(m, "categories"))
		fmt.Fprintf(out, "stale after %g hours\n", nxNum(m, "stale_after_hours"))
		return nil
	case "blindspots":
		path := nxQ("/v1/coverage/blindspots", f, "stale-days", "stale_days")
		if b["no-validation"] {
			if strings.Contains(path, "?") {
				path += "&validation=0"
			} else {
				path += "?validation=0"
			}
		}
		raw, err := nxCall("GET", path, nil)
		if err != nil {
			return err
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "CAVEAT: %s\n%s\n\n", blindspotCaveatNx, nxS(m["caveat"]))
		fmt.Fprintf(out, "techniques claimed by loaded rules: %g; unobservable here (no events for any needed category): %g\n", nxNum(m, "techniques_claimed"), nxNum(m, "techniques_unobservable_count"))
		fmt.Fprintf(out, "\ncollection gaps (stale after %gh):\n", nxNum(m, "stale_after_hours"))
		for _, g := range nxList(m, "collection_gaps") {
			fmt.Fprintf(out, "  %-14s %-10s %s\n", nxS(g["category"]), nxS(g["state"]), nxS(g["message"]))
		}
		if e := nxList(m, "enable_first"); len(e) > 0 {
			fmt.Fprintln(out, "\nenable first:")
			for _, p := range e {
				fmt.Fprintf(out, "  %g. %s\n", nxNum(p, "rank"), nxS(p["advice"]))
			}
		}
		for _, sec := range [][2]string{{"techniques_unobservable", "Unobservable techniques"}, {"techniques_at_risk_stale", "At-risk (stale) techniques"}} {
			l := nxList(m, sec[0])
			fmt.Fprintf(out, "\n%s (%d):\n", sec[1], len(l))
			for _, t := range l {
				fmt.Fprintf(out, "  %-12s needs %s  (%s)\n", nxS(t["technique"]), nxJoin(t["categories_required"]), nxS(t["reason"]))
			}
		}
		if v := nxSub(m, "validation"); v != nil {
			if v["available"] == true {
				fmt.Fprintf(out, "\nvalidation lab (synthetic, not a guarantee): %d missed, %d not testable. %s\n", len(nxList(v, "missed")), len(nxList(v, "not_testable")), nxS(v["note"]))
			} else {
				fmt.Fprintln(out, "\nvalidation lab: not available")
			}
		}
		if t := nxList(m, "telemetry"); len(t) > 0 {
			fmt.Fprintln(out, "\ntelemetry inventory:")
			nxCategories(out, t)
		}
		return nil
	}
	return fmt.Errorf("%s", coverageUsageNx)
}

func nxCategories(out io.Writer, cats []nxMap) {
	tw := newTab(out)
	fmt.Fprintln(tw, "CATEGORY\tSTATE\tEVENTS\tLAST-SEEN\tAGE-H")
	for _, c := range cats {
		fmt.Fprintf(tw, "%s\t%s\t%g\t%s\t%s\n", nxS(c["category"]), nxS(c["state"]), nxNum(c, "events_held"), nxS(c["last_seen"]), nxS(c["age_hours"]))
	}
	_ = tw.Flush()
}
