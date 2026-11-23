// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

const chUsage = `usage: kavachctl content <command>
  test FILE... [--pack PACK.json] [--json]     run kavach-content-tests/1 files (JSON lines) through the real detection paths; exit 1 on any failure
  selftest [--rules] [--pack PACK.json] [--json]
                                               every web-* content rule and built-in analytic rule must fire on its own positive example and stay quiet on its own negative one
  fp-report --benign PATH... [--builtin] [--kind web|auth|idp|ransom|event] [--threshold N] [--fail-on-noisy] [--json]
                                               replay clean logs you supply (files or directories) and report per-rule hit counts and rates
  tested-coverage [--json]                     ATT&CK techniques covered by rules that pass their own positive example
All four run offline in this process: nothing is fetched, nothing is sent to a server, nothing is blocked. See docs/content-testing.md.`

// chDispatch handles the detection-as-code commands under `kavachctl content`; others fall through.
func chDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "content" {
		return false, nil
	}
	switch args[1] {
	case "test", "selftest", "fp-report", "tested-coverage":
	default:
		return false, nil
	}
	o, err := chParse(args[2:])
	if err != nil {
		return true, err
	}
	reg, err := chRegistry(o.packs)
	if err != nil {
		return true, err
	}
	hopts := edr.HarnessOptions{Registry: reg}
	switch args[1] {
	case "test":
		if len(o.pos) == 0 {
			return true, fmt.Errorf("%s", chUsage)
		}
		rep := &edr.HarnessReport{}
		first := true
		for _, f := range o.pos {
			r, err := edr.RunHarnessFile(f, hopts)
			if err != nil {
				return true, err
			}
			if first {
				rep, first = r, false
			} else {
				rep.Merge(r)
			}
		}
		if o.json {
			if err := chJSON(out, rep); err != nil {
				return true, err
			}
		} else {
			chPrintCases(out, rep, true)
		}
		if rep.Failed > 0 {
			return true, fmt.Errorf("%d of %d case(s) failed", rep.Failed, rep.Cases)
		}
		return true, nil
	case "selftest":
		st, err := edr.SelfTest(hopts)
		if err != nil {
			return true, err
		}
		if o.json {
			if err := chJSON(out, st); err != nil {
				return true, err
			}
		} else {
			chPrintSelfTest(out, st, o.rules)
		}
		if !st.OK() {
			return true, fmt.Errorf("selftest failed: %d rule(s) not ok, %d case(s) failed", st.RulesFailing, st.Failed)
		}
		return true, nil
	case "tested-coverage":
		st, err := edr.SelfTest(hopts)
		if err != nil {
			return true, err
		}
		cov := edr.CoverageByTestedRule(st)
		if o.json {
			return true, chJSON(out, cov)
		}
		chPrintCoverage(out, cov)
		return true, nil
	case "fp-report":
		if len(o.benign) == 0 && !o.builtin {
			return true, fmt.Errorf("%s", chUsage)
		}
		rep, err := edr.ReplayBenign(o.benign, edr.FPOptions{Registry: reg, Threshold: o.threshold, Kind: o.kind, Builtin: o.builtin})
		if err != nil {
			return true, err
		}
		if o.json {
			if err := chJSON(out, rep); err != nil {
				return true, err
			}
		} else {
			chPrintFP(out, rep)
		}
		if o.failNoisy && len(rep.Noisy) > 0 {
			return true, fmt.Errorf("%d noisy rule(s) over the threshold of %.2f hits per 1000 records", len(rep.Noisy), rep.Threshold)
		}
		return true, nil
	}
	return false, nil
}

type chOpts struct {
	pos       []string
	packs     []string
	benign    []string
	kind      string
	threshold float64
	json      bool
	rules     bool
	builtin   bool
	failNoisy bool
}

func chParse(args []string) (chOpts, error) {
	var o chOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "--json":
			o.json = true
		case "--rules":
			o.rules = true
		case "--builtin":
			o.builtin = true
		case "--fail-on-noisy":
			o.failNoisy = true
		case "--pack":
			v, err := val()
			if err != nil {
				return o, err
			}
			o.packs = append(o.packs, v)
		case "--kind":
			v, err := val()
			if err != nil {
				return o, err
			}
			o.kind = v
		case "--threshold":
			v, err := val()
			if err != nil {
				return o, err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f <= 0 || f > 1000 {
				return o, fmt.Errorf("--threshold must be a number of hits per 1000 records, above 0 and at most 1000")
			}
			o.threshold = f
		case "--benign":
			v, err := val()
			if err != nil {
				return o, err
			}
			o.benign = append(o.benign, v)
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				o.benign = append(o.benign, args[i])
			}
		default:
			if strings.HasPrefix(a, "--") {
				return o, fmt.Errorf("unknown flag %s\n%s", a, chUsage)
			}
			o.pos = append(o.pos, a)
		}
	}
	return o, nil
}

// chRegistry returns nil (embedded packs) or a registry with extra pack files merged in.
func chRegistry(packs []string) (*edr.ContentRegistry, error) {
	if len(packs) == 0 {
		return nil, nil
	}
	extra := map[string][]byte{}
	for i, p := range packs {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() || st.Size() > 4<<20 {
			return nil, fmt.Errorf("%s: pack must be a regular file of at most 4 MiB", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		extra[strconv.Itoa(i)] = b
	}
	reg, err := edr.HarnessRegistryWithPacks(extra)
	if reg == nil {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("pack rejected: %v", err)
	}
	return reg, nil
}

func chJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func chPrintCases(out io.Writer, rep *edr.HarnessReport, showPass bool) {
	for _, c := range rep.Results {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		if c.Pass && !showPass {
			continue
		}
		fmt.Fprintf(out, "%s  %s:%d  %s\n", mark, c.File, c.Line, c.Case)
		for _, d := range c.Diff {
			fmt.Fprintf(out, "      %s\n", d)
		}
	}
	fmt.Fprintf(out, "%d case(s): %d passed, %d failed (observation only, offline)\n", rep.Cases, rep.Passed, rep.Failed)
}

func chPrintSelfTest(out io.Writer, st *edr.SelfTestReport, all bool) {
	bad := st.Failing()
	for _, c := range st.Results {
		if !c.Pass {
			fmt.Fprintf(out, "FAIL  %s:%d  %s\n", c.File, c.Line, c.Case)
			for _, d := range c.Diff {
				fmt.Fprintf(out, "      %s\n", d)
			}
		}
	}
	if all {
		for _, r := range st.Rules {
			fmt.Fprintf(out, "%-9s %-44s %-15s pos %d/%d neg %d/%d\n", r.Status, r.ID, r.Family, r.PositivePass, r.Positive, r.NegativePass, r.Negative)
		}
	} else {
		for _, r := range bad {
			fmt.Fprintf(out, "%-20s %-44s %-15s pos %d/%d neg %d/%d\n", r.Status, r.ID, r.Family, r.PositivePass, r.Positive, r.NegativePass, r.Negative)
		}
	}
	fams := make([]string, 0, len(st.ByFamily))
	for f := range st.ByFamily {
		fams = append(fams, f)
	}
	sort.Strings(fams)
	for _, f := range fams {
		v := st.ByFamily[f]
		fmt.Fprintf(out, "  %-16s %d of %d rules ok\n", f, v[0], v[1])
	}
	fmt.Fprintf(out, "%d of %d rules fire on their own positive example and stay quiet on their own negative example; %d example case(s), %d failed\n", st.RulesOK, st.RulesTotal, st.Cases, st.Failed)
}

func chPrintCoverage(out io.Writer, cov *edr.TestedCoverage) {
	fmt.Fprintf(out, "ATT&CK techniques with at least one passing positive example: %d of %d (%d of %d rules tested)\n", cov.TechniquesTested, cov.TechniquesTotal, cov.RulesTested, cov.RulesTotal)
	for _, t := range cov.Techniques {
		if len(t.Untested) > 0 {
			fmt.Fprintf(out, "  %-12s tested %d, untested %d: %s\n", t.ID, len(t.Tested), len(t.Untested), strings.Join(t.Untested, ","))
		}
	}
	fmt.Fprintln(out, cov.Note)
	fmt.Fprintln(out, "use --json for the full technique list")
}

func chPrintFP(out io.Writer, rep *edr.FPReport) {
	fmt.Fprintf(out, "benign-corpus replay (observation only, offline): %d file(s), threshold %.2f hits per 1000 records\n", len(rep.Files), rep.Threshold)
	for _, f := range rep.Files {
		extra := ""
		if f.Note != "" {
			extra = "  [" + f.Note + "]"
		}
		fmt.Fprintf(out, "  %-6s %-48s records %d parsed %d rejected %d hits %d%s\n", f.Kind, f.Path, f.Records, f.Parsed, f.Rejected, f.Hits, extra)
	}
	if len(rep.Rules) == 0 {
		fmt.Fprintln(out, "no rule fired on this corpus")
	}
	for _, r := range rep.Rules {
		mark := "  "
		if r.Noisy {
			mark = "! "
		}
		fmt.Fprintf(out, "%s%-44s %-8s hits %-5d in %d file(s), %.2f per 1000 %s records\n", mark, r.Rule, r.Severity, r.Hits, r.Files, r.RatePer1000, r.Kind)
		for _, s := range r.Samples {
			fmt.Fprintf(out, "      sample (redacted): %s\n", s)
		}
	}
	if len(rep.Noisy) > 0 {
		fmt.Fprintf(out, "noisy rules (! above): %s\n", strings.Join(rep.Noisy, ", "))
	}
	for _, s := range rep.Skipped {
		fmt.Fprintf(out, "skipped: %s\n", s)
	}
	if rep.Truncated {
		fmt.Fprintln(out, "some input was truncated or skipped (size, file-count or time limits)")
	}
	fmt.Fprintln(out, rep.Note)
}
