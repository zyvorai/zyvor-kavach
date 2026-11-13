// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
)

const ttpUsage = `usage: kavachctl ttp <command>
  similar (--host H | --finding-ids A,B | --techniques T1059,T1003) [--json]   resemblance to public adversary profiles
  next    (--host H | --finding-ids A,B | --techniques T1059,T1003) [--json]   hunting hints (not a prediction)
  chains --host H [--json]                                                     tactic progression and gaps worth hunting
Similarity is NOT attribution.`

func ttpInputQuery(path string, f map[string]string) (string, error) {
	n := 0
	for _, k := range []string{"host", "finding-ids", "techniques"} {
		if f[k] != "" {
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("give exactly one of --host, --finding-ids or --techniques")
	}
	return p4Query(path, "host", f["host"], "finding_ids", f["finding-ids"], "techniques", f["techniques"]), nil
}

// ttpCaveats prints the mandatory caveats prominently, before any result.
func ttpPrintCaveats(out io.Writer, m map[string]any) {
	fmt.Fprintln(out, "=== CAVEATS: SIMILARITY IS NOT ATTRIBUTION ===")
	cv := p4Strings(m, "caveats")
	if len(cv) == 0 {
		fmt.Fprintln(out, "  (server sent no caveats) Overlap with a public profile is weak evidence and never identifies an actor.")
	}
	for _, c := range cv {
		fmt.Fprintf(out, "  ! %s\n", c)
	}
	fmt.Fprintln(out, "==============================================")
}

func ttpPrintObserved(out io.Writer, m map[string]any) {
	obs := listOf(m, "observed")
	fmt.Fprintf(out, "Source: %s   Observed techniques: %d   Distinct (parent level): %s   Profiles compared: %s\n", strFrom(m, "source"), len(obs), num(m, "distinct_techniques"), num(m, "profiles"))
	for _, o := range obs {
		fmt.Fprintf(out, "  %-10s %-24s %s\n", strFrom(o, "technique"), truncate(strFrom(o, "tactic"), 24), truncate(strFrom(o, "name"), 40))
	}
}

func ttpRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", ttpUsage)
	}
	_, f, b := omParse(args[1:], "host", "finding-ids", "techniques")
	j := b["json"]
	switch args[0] {
	case "similar":
		path, err := ttpInputQuery("/v1/ttp/similar", f)
		if err != nil {
			return err
		}
		m, err := p4Get(out, path, j)
		if err != nil || j {
			return err
		}
		ttpPrintCaveats(out, m)
		fmt.Fprintf(out, "METHOD: %s\n", strFrom(m, "method"))
		ttpPrintObserved(out, m)
		conf := strFrom(m, "confidence")
		fmt.Fprintf(out, "Confidence: %s", conf)
		if r := strFrom(m, "confidence_reason"); r != "" {
			fmt.Fprintf(out, "  (%s)", r)
		}
		fmt.Fprintln(out)
		ms := listOf(m, "matches")
		if conf == "not_enough_evidence" || len(ms) == 0 {
			fmt.Fprintln(out, "No matches reported: not enough evidence to rank profiles.")
			return nil
		}
		fmt.Fprintln(out, "Resemblance to public profiles (NOT an attribution):")
		for _, x := range ms {
			fmt.Fprintf(out, "  %-12s %-28s %-10s score=%s cosine=%s wjaccard=%s\n", strFrom(x, "id"), truncate(strFrom(x, "name"), 28), strFrom(x, "kind"), num(x, "score"), num(x, "tfidf_cosine"), num(x, "weighted_jaccard"))
			fmt.Fprintf(out, "      overlap: %v\n      not observed: %v\n", x["overlap"], x["missing_techniques"])
		}
		return nil
	case "next":
		path, err := ttpInputQuery("/v1/ttp/next", f)
		if err != nil {
			return err
		}
		m, err := p4Get(out, path, j)
		if err != nil || j {
			return err
		}
		ttpPrintCaveats(out, m)
		ttpPrintObserved(out, m)
		fmt.Fprintf(out, "Confidence: %s\n", strFrom(m, "confidence"))
		fmt.Fprintf(out, "%s\n", strFrom(m, "label"))
		hs := listOf(m, "hints")
		if strFrom(m, "confidence") == "not_enough_evidence" || len(hs) == 0 {
			fmt.Fprintln(out, "No hints: not enough evidence.")
			return nil
		}
		if s := strFrom(m, "hint_basis"); s != "" {
			fmt.Fprintf(out, "Basis: %s\n", s)
		}
		for _, h := range hs {
			c := ""
			if h["commodity"] == true {
				c = "  [commodity technique]"
			}
			fmt.Fprintf(out, "  hunt %-10s %-24s supporting_profiles=%s weight=%s%s\n", strFrom(h, "technique"), strFrom(h, "tactic"), num(h, "supporting_profiles"), num(h, "weight"), c)
		}
		return nil
	case "chains":
		if f["host"] == "" {
			return fmt.Errorf("usage: kavachctl ttp chains --host H [--json]")
		}
		m, err := p4Get(out, p4Query("/v1/ttp/chains", "host", f["host"]), j)
		if err != nil || j {
			return err
		}
		ttpPrintCaveats(out, m)
		fmt.Fprintf(out, "Host %s: %s observed techniques; tactics reached: %v\n", strFrom(m, "host"), num(m, "observed_techniques"), m["tactics_reached"])
		if s := strFrom(m, "earliest_tactic"); s != "" {
			fmt.Fprintf(out, "Earliest: %s   Latest: %s   Span: %s\n", s, strFrom(m, "latest_tactic"), num(m, "progression_span"))
		} else {
			fmt.Fprintln(out, "No mapped techniques observed on this host; nothing to chain.")
		}
		fmt.Fprintf(out, "Order check: %s\n", strFrom(m, "killchain_order_check"))
		gaps := listOf(m, "gaps_worth_hunting")
		for _, g := range gaps {
			fmt.Fprintf(out, "  gap %-22s hunt: %v\n", strFrom(g, "tactic"), g["hunt_techniques"])
		}
		if s := strFrom(m, "gap_note"); s != "" && len(gaps) > 0 {
			fmt.Fprintf(out, "Gap note: %s\n", s)
		}
		return nil
	}
	return fmt.Errorf("unknown ttp command %q\n%s", args[0], ttpUsage)
}
