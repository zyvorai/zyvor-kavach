// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const huntSeqUsage = "usage: kavachctl hunt seq QUERY|--file F [--since 24h] [--limit N] [--json] | seq fields | seq explain QUERY|--file F [--since 24h] | seq examples"

func nxHuntSeq(out io.Writer, args []string) error {
	pos, f, b := omParse(args, "file", "since", "limit")
	j := b["json"]
	if len(pos) > 0 {
		switch pos[0] {
		case "fields":
			raw, err := nxCall("GET", "/v1/hunt/seq/fields", nil)
			if err != nil {
				return err
			}
			return nxSeqFields(out, raw, j)
		case "examples":
			raw, err := nxCall("GET", "/v1/hunt/seq/examples", nil)
			if err != nil {
				return err
			}
			return nxSeqExamples(out, raw, j)
		}
	}
	explain := len(pos) > 0 && pos[0] == "explain"
	if explain {
		pos = pos[1:]
	}
	query := strings.TrimSpace(strings.Join(pos, " "))
	if f["file"] != "" {
		bs, err := readInputFile(f["file"])
		if err != nil {
			return err
		}
		query = strings.TrimSpace(string(bs))
	}
	if query == "" {
		return fmt.Errorf("%s", huntSeqUsage)
	}
	body := nxMap{"query": query}
	if f["since"] != "" {
		body["since"] = f["since"]
	}
	if f["limit"] != "" {
		n, err := strconv.Atoi(f["limit"])
		if err != nil || n < 0 {
			return fmt.Errorf("invalid --limit %q", f["limit"])
		}
		body["limit"] = n
	}
	path := "/v1/hunt/seq"
	if explain {
		path += "/explain"
	}
	raw, code, err := nxDo("POST", path, body)
	if err != nil {
		return err
	}
	if code >= 300 {
		if j {
			fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		}
		if m, derr := nxDecode(raw); derr == nil {
			return nxSeqError(out, m, code)
		}
		return nxHTTPErr(code, raw)
	}
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	if explain {
		return nxSeqExplain(out, m)
	}
	fmt.Fprintf(out, "%s sequence: %g match(es)\n", nxS(m["kind"]), nxNum(m, "count"))
	for i, mt := range nxList(m, "matches") {
		fmt.Fprintf(out, "\nmatch %d", i+1)
		if k := nxS(mt["key"]); k != "-" {
			fmt.Fprintf(out, "  key=%s", k)
		}
		if _, ok := mt["span_ms"]; ok {
			fmt.Fprintf(out, "  span=%gms", nxNum(mt, "span_ms"))
		}
		fmt.Fprintln(out)
		for _, e := range nxList(mt, "events") {
			fmt.Fprintf(out, "  step %g  %s  %s  %s  %s\n", nxNum(e, "step"), nxS(e["time"]), nxS(e["category"]), nxS(e["id"]), nxS(e["fields"]))
		}
	}
	fmt.Fprintf(out, "\nscanned %g of %g events in %gms\n", nxNum(m, "scanned"), nxNum(m, "scanned_total"), nxNum(m, "elapsed_ms"))
	if m["truncated"] == true {
		fmt.Fprintln(out, "TRUNCATED: more matches exist than were returned; narrow the query or raise --limit.")
	}
	if m["timed_out"] == true {
		fmt.Fprintln(out, "TIMED OUT: the time budget was hit; results are partial.")
	}
	if m["scan_capped"] == true {
		fmt.Fprintln(out, "SCAN CAPPED: only the most recent events were scanned; older events were not searched.")
	}
	fmt.Fprintf(out, "semantics: %s\n", nxS(m["semantics"]))
	return nil
}

func nxSeqError(out io.Writer, m nxMap, code int) error {
	if ps := nxList(m, "problems"); len(ps) > 0 {
		fmt.Fprintln(out, "Unavailable fields in this query:")
		for _, p := range ps {
			fmt.Fprintf(out, "  line %g col %g  %s.%s: %s\n", nxNum(p, "line"), nxNum(p, "col"), nxS(p["category"]), nxS(p["field"]), nxS(p["reason"]))
		}
	}
	msg := nxS(m["error"])
	if _, ok := m["line"]; ok {
		msg += fmt.Sprintf(" (line %g col %g)", nxNum(m, "line"), nxNum(m, "col"))
	}
	return fmt.Errorf("HTTP %d: %s", code, msg)
}

func nxSeqExplain(out io.Writer, m nxMap) error {
	if m["ok"] == false && m["error"] != nil {
		fmt.Fprintf(out, "query does not parse: %s (line %g col %g)\n", nxS(m["error"]), nxNum(m, "line"), nxNum(m, "col"))
		return nil
	}
	fmt.Fprintf(out, "kind: %s  ok: %v\n", nxS(m["kind"]), m["ok"])
	for _, p := range nxList(m, "unavailable_fields") {
		fmt.Fprintf(out, "unavailable field: %s.%s (line %g col %g): %s\n", nxS(p["category"]), nxS(p["field"]), nxNum(p, "line"), nxNum(p, "col"), nxS(p["reason"]))
	}
	if t, ok := m["tree"]; ok {
		fmt.Fprintln(out, "tree:")
		nxPretty(out, t)
	}
	if _, ok := m["scanned"]; ok {
		fmt.Fprintf(out, "scanned %g of %g events; has match: %v; step match counts: %s\n", nxNum(m, "scanned"), nxNum(m, "scanned_total"), m["has_match"], nxS(m["step_match_counts"]))
		if m["timed_out"] == true {
			fmt.Fprintln(out, "TIMED OUT: the time budget was hit; counts are partial.")
		}
		if m["scan_capped"] == true {
			fmt.Fprintln(out, "SCAN CAPPED: only the most recent events were scanned.")
		}
	}
	fmt.Fprintf(out, "semantics: %s\n", nxS(m["semantics"]))
	return nil
}

func nxSeqFields(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	for _, c := range nxList(m, "categories") {
		cat := nxS(firstOf(c, "category", "Category"))
		fmt.Fprintf(out, "%s  %s\n", cat, nxS(firstOf(c, "source")))
		for _, fl := range nxList(c, "fields") {
			opt := ""
			if fl["optional"] == true {
				opt = " (optional)"
			}
			fmt.Fprintf(out, "  %-16s %-8s%s %s\n", nxS(fl["name"]), nxS(fl["type"]), opt, nxS(fl["note"]))
		}
		for _, a := range nxList(c, "absent") {
			fmt.Fprintf(out, "  not available: %s: %s\n", nxS(a["name"]), nxS(firstOf(a, "reason", "why", "note")))
		}
	}
	fmt.Fprintf(out, "join keys: %s\n", nxJoin(m["join_keys"]))
	fmt.Fprintf(out, "operators: %s\n", nxS(m["operators"]))
	for _, n := range nxStrs(m, "notes") {
		fmt.Fprintf(out, "note: %s\n", n)
	}
	fmt.Fprintf(out, "limits: %s\n", nxS(m["limits"]))
	return nil
}

func firstOf(m nxMap, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" {
			return v
		}
	}
	return nil
}

func nxSeqExamples(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	for _, e := range nxList(m, "examples") {
		noisy := ""
		if e["noisy"] == true {
			noisy = "  [noisy: may fire on benign activity]"
		}
		fmt.Fprintf(out, "%s  %s  (%s %s)%s\n  %s\n  %s\n\n", nxS(e["id"]), nxS(e["name"]), nxS(e["tactic"]), nxS(e["technique"]), noisy,
			nxS(e["description"]), strings.ReplaceAll(nxS(e["query"]), "\n", "\n  "))
	}
	fmt.Fprintf(out, "%g examples\n", nxNum(m, "count"))
	return nil
}

// ---- feedback ----

const feedbackUsage = "usage: kavachctl feedback record --finding ID --verdict true_positive|false_positive|benign_expected|needs_more_data [--note T] [--yes] | list [--finding ID] [--rule R] [--host H] [--limit N] | rules [--min-verdicts N] [--review-below X] | summary [--days N] | verify | export [--redact] [--out FILE]   (all take --json)"

var nxVerdicts = map[string]bool{"true_positive": true, "false_positive": true, "benign_expected": true, "needs_more_data": true}

func nxFeedback(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", feedbackUsage)
	}
	_, f, b := omParse(args[1:], "finding", "verdict", "note", "rule", "host", "limit", "min-verdicts", "review-below", "days", "out")
	j := b["json"]
	switch args[0] {
	case "record":
		if f["finding"] == "" {
			return fmt.Errorf("feedback record needs --finding ID\n%s", feedbackUsage)
		}
		if !nxVerdicts[f["verdict"]] {
			return fmt.Errorf("--verdict must be true_positive, false_positive, benign_expected or needs_more_data")
		}
		if err := nxConfirm(b["yes"], "feedback record", "This appends an analyst verdict to the tamper-evident feedback ledger; it cannot be deleted."); err != nil {
			return err
		}
		body := nxMap{"finding_id": f["finding"], "verdict": f["verdict"]}
		if f["note"] != "" {
			body["note"] = f["note"]
		}
		raw, err := nxCall("POST", "/v1/feedback", body)
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
		fmt.Fprintf(out, "recorded #%g: finding %s verdict %s by %s (rule %s, host %s)\n", nxNum(m, "seq"), nxS(m["finding_id"]), nxS(m["verdict"]), nxS(m["actor"]), nxS(m["rule"]), nxS(m["host"]))
		return nil
	case "list":
		raw, err := nxCall("GET", nxQ("/v1/feedback", f, "finding", "finding_id", "rule", "rule", "host", "host", "limit", "limit"), nil)
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
		fmt.Fprintln(tw, "SEQ\tTIME\tFINDING\tVERDICT\tRULE\tHOST\tACTOR\tNOTE")
		for _, e := range nxList(m, "entries") {
			fmt.Fprintf(tw, "%g\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", nxNum(e, "seq"), fmtTime(nxS(e["time"])), nxS(e["finding_id"]), nxS(e["verdict"]), nxS(e["rule"]),
				nxS(e["host"]), nxS(e["actor"]), truncate(nxS(e["note"]), 50))
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%d entries (newest first)\n", len(nxList(m, "entries")))
		return nil
	case "rules":
		raw, err := nxCall("GET", nxQ("/v1/feedback/rules", f, "min-verdicts", "min_verdicts", "review-below", "review_below"), nil)
		if err != nil {
			return err
		}
		return nxFeedbackRules(out, raw, j)
	case "summary":
		raw, err := nxCall("GET", nxQ("/v1/feedback/summary", f, "days", "days"), nil)
		if err != nil {
			return err
		}
		return nxFeedbackSummary(out, raw, j)
	case "verify":
		raw, err := nxCall("GET", "/v1/feedback/verify", nil)
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
		if m["ok"] == true {
			fmt.Fprintf(out, "feedback ledger intact: %g entries verified\n", nxNum(m, "entries"))
			return nil
		}
		fmt.Fprintf(out, "feedback ledger BROKEN at seq %g: %s\n", nxNum(m, "first_broken_seq"), nxS(m["reason"]))
		return nil
	case "export":
		path := "/v1/feedback/export"
		if b["redact"] {
			path += "?redact=1"
		}
		raw, err := nxCall("POST", path, nil)
		if err != nil {
			return err
		}
		if f["out"] != "" {
			if err := os.WriteFile(f["out"], raw, 0o600); err != nil {
				return err
			}
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		if f["out"] == "" {
			nxPretty(out, m)
			return nil
		}
		fmt.Fprintf(out, "wrote %s: %d labels, %d entries, redacted=%v, chain_ok=%v\nlabel rule: %s\ncaveat: %s\n", f["out"], len(nxList(m, "labels")), len(nxList(m, "entries")),
			m["redacted"], m["chain_ok"], nxS(m["label_rule"]), nxS(m["caveat"]))
		return nil
	}
	return fmt.Errorf("%s", feedbackUsage)
}

func nxFeedbackRules(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	meth := nxSub(m, "method")
	fmt.Fprintf(out, "per-rule precision from analyst verdicts (min %s decided verdicts; review below %s). Advisory only: nothing acts on it.\n", nxS(meth["min_verdicts"]), nxS(meth["review_below"]))
	tw := newTab(out)
	fmt.Fprintln(tw, "RULE\tDECIDED\tTP\tOBSERVED\tWILSON95\tSHRUNK\tREVIEW")
	for _, r := range nxList(m, "ranked_by_shrunk_precision") {
		fmt.Fprintf(tw, "%s\t%g\t%s\t%s\t%s-%s\t%s\t%v\n", nxS(r["rule"]), nxNum(r, "decided_findings"), nxS(r["true_positives"]), nxS(r["observed_precision"]),
			nxS(r["wilson95_low"]), nxS(r["wilson95_high"]), nxS(r["shrunk_precision"]), r["review_candidate"])
	}
	_ = tw.Flush()
	ne := nxList(m, "not_enough_verdicts")
	fmt.Fprintf(out, "\nnot_enough_verdicts (%d rules): no precision estimate is shown for these.\n", len(ne))
	for _, r := range ne {
		fmt.Fprintf(out, "  %-40s decided %g, contested %g, undecided %g  %s\n", nxS(r["rule"]), nxNum(r, "decided_findings"), nxNum(r, "contested_findings"), nxNum(r, "undecided_findings"), nxS(r["note"]))
	}
	if rc := nxStrs(m, "review_candidates"); len(rc) > 0 {
		fmt.Fprintf(out, "\nreview candidates (a prompt for a human, never an action): %s\n", strings.Join(rc, ", "))
	}
	return nil
}

func nxFeedbackSummary(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "entries: %g  findings with a verdict: %g\n", nxNum(m, "entries_total"), nxNum(m, "findings_with_verdict"))
	fmt.Fprintf(out, "verdicts (all entries): %s\n", nxS(m["counts_all_entries"]))
	fmt.Fprintf(out, "verdicts (latest per actor): %s\n", nxS(m["counts_latest_per_actor"]))
	fmt.Fprintf(out, "last %g days: %g findings, %g covered by a verdict (coverage %s)\n", nxNum(m, "recent_days"), nxNum(m, "recent_findings"), nxNum(m, "recent_findings_covered"), nxS(m["verdict_coverage"]))
	fmt.Fprintf(out, "mean seconds to first verdict: %s\n", nxS(m["mean_seconds_to_first_verdict"]))
	fmt.Fprintf(out, "top false-positive rules: %s\ntop true-positive rules: %s\n", nxS(m["top_false_positive_rules"]), nxS(m["top_true_positive_rules"]))
	fmt.Fprintf(out, "note: %s\n", nxS(m["note"]))
	return nil
}
