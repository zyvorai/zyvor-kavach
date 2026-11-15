// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

const validateUsage = "usage: kavachctl validate scenarios [--kind K] [--platform P] [--technique T] [--json] | show ID | run (--ids A,B | --all) [--include-custom] | coverage [--include-custom]"

const validateNote = "Synthetic data, not a guarantee: scenarios are replayed in memory against Kavach's own rules; a pass says nothing certain about real attacks."

func nxValidate(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "kind", "platform", "technique", "ids")
	j := b["json"]
	switch sub {
	case "scenarios":
		raw, err := nxCall("GET", nxQ("/v1/validate/scenarios", f, "kind", "kind", "platform", "platform", "technique", "technique"), nil)
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
		fmt.Fprintln(tw, "ID\tKIND\tPLATFORM\tSTEPS\tBENIGN\tTECHNIQUES\tNAME")
		for _, s := range nxList(m, "scenarios") {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%g\t%s\t%s\t%s\n", nxS(s["id"]), nxS(s["kind"]), nxS(s["platform"]), nxNum(s, "steps"),
				nxS(s["benign"]), nxJoin(s["techniques"]), truncate(nxS(s["name"]), 60))
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%g scenarios\n%s\n", nxNum(m, "count"), validateNote)
		return nil
	case "show":
		if len(pos) < 1 {
			return fmt.Errorf("usage: kavachctl validate show ID")
		}
		raw, err := nxCall("GET", nxPath("/v1/validate/scenarios", pos[0]), nil)
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
		s := nxSub(m, "scenario")
		fmt.Fprintf(out, "%s  %s\nkind: %s  platform: %s  benign: %s\ntechniques: %s\ntactics: %s\n%s\n", nxS(s["id"]), nxS(s["name"]),
			nxS(s["kind"]), nxS(s["platform"]), nxS(s["benign"]), nxJoin(s["techniques"]), nxJoin(s["tactics"]), nxS(s["description"]))
		if e := nxJoin(s["expect"]); e != "" {
			fmt.Fprintf(out, "expect: %s\n", e)
		}
		steps, _ := s["steps"].([]any)
		fmt.Fprintf(out, "%d steps\n", len(steps))
		for i, st := range steps {
			fmt.Fprintf(out, "  %d. %s\n", i+1, nxS(st))
		}
		fmt.Fprintln(out, validateNote)
		return nil
	case "run":
		body := nxMap{}
		switch {
		case b["all"]:
			body["all"] = true
		case f["ids"] != "":
			ids := []string{}
			for _, id := range strings.Split(f["ids"], ",") {
				if id = strings.TrimSpace(id); id != "" {
					ids = append(ids, id)
				}
			}
			body["ids"] = ids
		default:
			return fmt.Errorf("validate run needs --ids A,B or --all\n%s", validateUsage)
		}
		if b["include-custom"] {
			body["include_custom"] = true
		}
		raw, err := nxCall("POST", "/v1/validate/run", body)
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
		fmt.Fprintln(tw, "ID\tKIND\tRESULT\tFIRED\tOUTCOMES")
		pass := 0
		for _, r := range nxList(m, "results") {
			res := "FAIL"
			if r["pass"] == true {
				res = "pass"
				pass++
			}
			if r["false_positive"] == true {
				res = "FALSE-POSITIVE"
			}
			oc := []string{}
			for _, o := range nxList(r, "outcomes") {
				oc = append(oc, nxS(o["expect"])+"="+nxS(o["status"]))
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", nxS(r["id"]), nxS(r["kind"]), res, len(nxList(r, "fired")), strings.Join(oc, " "))
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%d of %g scenarios passed (recorded: %v)\n%s\n", pass, nxNum(m, "count"), m["recorded"], validateNote)
		return nil
	case "coverage":
		path := "/v1/validate/coverage"
		if b["include-custom"] {
			path += "?include_custom=true"
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
		fmt.Fprintf(out, "%s\n\n", validateNote)
		if n := nxS(m["note"]); n != "-" && n != "unknown" {
			fmt.Fprintf(out, "server note: %s\n", n)
		}
		c := nxSub(m, "counts")
		fmt.Fprintf(out, "claimed techniques: %g  tested: %g\n", nxNum(m, "claimed_techniques"), nxNum(m, "tested_techniques"))
		fmt.Fprintf(out, "detected %g  partial %g  missed %g  not testable %g  untested %g\n", nxNum(c, "detected"), nxNum(c, "partial"),
			nxNum(c, "missed"), nxNum(c, "not_testable"), nxNum(c, "untested"))
		fmt.Fprintf(out, "measured detected: %g%%  detected or partial: %g%%\n", nxNum(m, "measured_detected_pct"), nxNum(m, "measured_detected_or_partial_pct"))
		if sc := nxSub(m, "scenarios"); sc != nil {
			fmt.Fprintf(out, "scenarios passed %g of %g; benign false positives %g\n", nxNum(sc, "passed"), nxNum(sc, "non_benign"), nxNum(sc, "benign_false_positives"))
		}
		if bt := nxList(m, "by_tactic"); len(bt) > 0 {
			tw := newTab(out)
			fmt.Fprintln(tw, "\nTACTIC\tCLAIMED\tDETECTED\tPARTIAL\tMISSED\tNOT-TESTABLE\tUNTESTED\tMEASURED%")
			for _, t := range bt {
				fmt.Fprintf(tw, "%s\t%g\t%g\t%g\t%g\t%g\t%g\t%g\n", nxS(t["tactic"]), nxNum(t, "claimed"), nxNum(t, "detected"), nxNum(t, "partial"),
					nxNum(t, "missed"), nxNum(t, "not_testable"), nxNum(t, "untested"), nxNum(t, "measured_pct"))
			}
			_ = tw.Flush()
		}
		for _, sec := range [][2]string{{"missed", "Missed"}, {"partial", "Partial"}, {"not_testable", "Not testable"}} {
			l := nxList(m, sec[0])
			fmt.Fprintf(out, "\n%s (%d):\n", sec[1], len(l))
			if len(l) == 0 {
				fmt.Fprintln(out, "  none")
			}
			for _, t := range l {
				r := nxS(t["reason"])
				if r == "-" {
					r = ""
				}
				fmt.Fprintf(out, "  %-12s %-34s %s\n", nxS(t["id"]), truncate(nxS(t["name"]), 34), r)
			}
		}
		return nil
	}
	return fmt.Errorf("%s", validateUsage)
}

const vulnsUsage = "usage: kavachctl vulns priority [--host H] [--limit N] [--json] | show CVE | status | refresh"

func nxVulns(out io.Writer, sub string, args []string) error {
	pos, f, b := omParse(args, "host", "limit")
	j := b["json"]
	switch sub {
	case "priority":
		if f["limit"] != "" {
			if n, err := strconv.Atoi(f["limit"]); err != nil || n < 1 || n > 500 {
				return fmt.Errorf("invalid --limit %q (1-500)", f["limit"])
			}
		}
		raw, err := nxCall("GET", nxQ("/v1/vulns/priority", f, "host", "host", "limit", "limit"), nil)
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
		fmt.Fprintln(tw, "RANK\tHOST\tCVE\tSSVC\tEPSS\tCVSS\tKEV\tUNKNOWN-INPUTS\tPACKAGE")
		for _, it := range nxList(m, "items") {
			fmt.Fprintf(tw, "%g\t%s\t%s\t%s\t%s\t%g\t%v\t%s\t%s %s\n", nxNum(it, "rank"), nxS(it["host"]), nxS(it["cve"]), nxS(it["ssvc_outcome"]),
				nxS(it["epss"]), nxNum(it, "cvss"), it["known_exploited"], unknownInputs(it), nxS(it["package"]), nxS(it["version"]))
		}
		_ = tw.Flush()
		fmt.Fprintf(out, "%g of %g items; ssvc tree %s\nranking: %s\n", nxNum(m, "count"), nxNum(m, "total"), nxS(m["tree_version"]), nxS(m["ranking"]))
		nxEPSSLine(out, nxSub(m, "epss"))
		nxLimits(out, m)
		return nil
	case "show":
		if len(pos) < 1 {
			return fmt.Errorf("usage: kavachctl vulns show CVE")
		}
		raw, err := nxCall("GET", nxPath("/v1/vulns/priority", pos[0]), nil)
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
		fmt.Fprintf(out, "%s  top SSVC outcome: %s  on %g host(s)  (tree %s)\n", nxS(m["cve"]), nxS(m["top_outcome"]), nxNum(m, "hosts"), nxS(m["tree_version"]))
		for _, it := range nxList(m, "items") {
			fmt.Fprintf(out, "\nhost %s  %s %s  outcome %s  EPSS %s  CVSS %g  known-exploited %v\n", nxS(it["host"]), nxS(it["package"]), nxS(it["version"]),
				nxS(it["ssvc_outcome"]), nxS(it["epss"]), nxNum(it, "cvss"), it["known_exploited"])
			tw := newTab(out)
			fmt.Fprintln(tw, "  FACTOR\tVALUE\tSOURCE\tKNOWN\tASSUMED\tEVIDENCE")
			for _, fa := range nxList(it, "factors") {
				v := nxS(fa["value"])
				if fa["known"] == false {
					v = "unknown"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%v\t%s\t%s\n", nxS(fa["decision_point"]), v, nxS(fa["source"]), fa["known"], nxS(fa["assumed_value"]), nxS(fa["evidence"]))
			}
			_ = tw.Flush()
			ss := nxSub(it, "ssvc")
			if u := unknownInputs(it); u != "-" {
				fmt.Fprintf(out, "  unknown inputs: %s (best case %s, worst case %s; outcome depends on unknowns: %v)\n", u, nxS(ss["outcome_if_unknowns_favourable"]),
					nxS(ss["outcome_if_unknowns_adverse"]), ss["outcome_depends_on_unknowns"])
			}
			for _, e := range nxStrs(it, "explanation") {
				fmt.Fprintf(out, "  - %s\n", e)
			}
		}
		nxEPSSLine(out, nxSub(m, "epss"))
		nxLimits(out, m)
		return nil
	case "status":
		raw, err := nxCall("GET", "/v1/vulns/priority/status", nil)
		if err != nil {
			return err
		}
		return nxVulnStatus(out, raw, j)
	case "refresh":
		raw, code, err := nxDo("POST", "/v1/vulns/priority/refresh", nil)
		if err != nil {
			return err
		}
		if code == 409 {
			return fmt.Errorf("EPSS feed is disabled on the server; set KAVACH_EPSS_FEED=on and restart")
		}
		if code >= 300 {
			return nxHTTPErr(code, raw)
		}
		if nxEmit(out, raw, j) {
			return nil
		}
		m, err := nxDecode(raw)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "EPSS refresh result:")
		nxPretty(out, m)
		return nil
	}
	return fmt.Errorf("%s", vulnsUsage)
}

func unknownInputs(it nxMap) string {
	u := nxStrs(nxSub(it, "ssvc"), "unknown_inputs")
	if len(u) == 0 {
		return "-"
	}
	return strings.Join(u, ",")
}

func nxEPSSLine(out io.Writer, e nxMap) {
	if e != nil {
		fmt.Fprintf(out, "EPSS feed: %s\n", nxS(e))
	}
}

func nxLimits(out io.Writer, m nxMap) {
	for _, l := range nxStrs(m, "limitations") {
		fmt.Fprintf(out, "limitation: %s\n", l)
	}
}

func nxVulnStatus(out io.Writer, raw []byte, j bool) error {
	if nxEmit(out, raw, j) {
		return nil
	}
	m, err := nxDecode(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ssvc tree: %s\n", nxS(m["tree_version"]))
	fmt.Fprintf(out, "EPSS feed: %s\n", nxS(m["epss_feed"]))
	fmt.Fprintf(out, "thresholds: %s\n", nxS(m["thresholds"]))
	fmt.Fprintf(out, "defaults used for unknown inputs: %s\n", nxS(m["defaults_for_unknown"]))
	nxLimits(out, m)
	return nil
}
