// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"text/tabwriter"
)

const adversaryUsage = "usage: kavachctl adversary list [--kind K] [--technique ID] [--q TEXT] [--json] | show ID [--json] | coverage [--json]"

// advDispatch handles the read-only `adversary` command group (public-reporting threat actor profiles).
func advDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "adversary" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", adversaryUsage)
	}
	switch args[1] {
	case "list":
		return true, advList(out, args[2:])
	case "show":
		return true, advShow(out, args[2:])
	case "coverage":
		return true, advCoverage(out, args[2:])
	}
	return true, fmt.Errorf("%s", adversaryUsage)
}

func advList(out io.Writer, args []string) error {
	_, f, b := omParse(args, "kind", "technique", "q")
	path := omQuery("/v1/adversaries", f, "kind", "technique", "q")
	var resp struct {
		Count       int `json:"count"`
		Adversaries []struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Kind       string   `json:"kind"`
			Motivation string   `json:"motivation"`
			Confidence string   `json:"confidence"`
			Techniques []string `json:"techniques"`
		} `json:"adversaries"`
	}
	raw, err := ocGet(path, &resp)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tCONFIDENCE\tTECHNIQUES\tNAME\tMOTIVATION")
	for _, a := range resp.Adversaries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", a.ID, a.Kind, a.Confidence, len(a.Techniques), a.Name, a.Motivation)
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "%d adversaries (public-reporting attribution, not detection of the actor)\n", resp.Count)
	return nil
}

func advShow(out io.Writer, args []string) error {
	pos, _, b := omParse(args)
	id, err := omNeed(pos, 0, "usage: kavachctl adversary show ID [--json]")
	if err != nil {
		return err
	}
	var resp struct {
		Profile struct {
			Name       string   `json:"name"`
			Aliases    []string `json:"aliases"`
			Kind       string   `json:"kind"`
			Origin     string   `json:"attributed_origin"`
			Motivation string   `json:"motivation"`
			Targets    string   `json:"targets"`
			Confidence string   `json:"confidence"`
			Sources    []struct {
				URL string `json:"url"`
			} `json:"sources"`
		} `json:"profile"`
		Coverage struct {
			Total       int      `json:"total"`
			Exact       int      `json:"exact"`
			Related     int      `json:"related"`
			CoveragePct int      `json:"coverage_pct"`
			Gaps        []string `json:"gaps"`
			Techniques  []struct {
				Technique string   `json:"technique"`
				Status    string   `json:"status"`
				Rules     []string `json:"rules"`
				Hits      int      `json:"hits"`
			} `json:"techniques"`
		} `json:"coverage"`
	}
	raw, err := ocGet("/v1/adversaries/"+url.PathEscape(id), &resp)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	p, c := resp.Profile, resp.Coverage
	fmt.Fprintf(out, "%s (%s) aliases: %s\n", p.Name, p.Kind, strings.Join(p.Aliases, ", "))
	fmt.Fprintf(out, "origin: %s | motivation: %s | confidence: %s\ntargets: %s\n", p.Origin, p.Motivation, p.Confidence, p.Targets)
	fmt.Fprintf(out, "coverage: %d%% (%d exact, %d related, %d gaps of %d techniques)\n", c.CoveragePct, c.Exact, c.Related, len(c.Gaps), c.Total)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TECHNIQUE\tSTATUS\tHITS\tRULES")
	for _, t := range c.Techniques {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", t.Technique, t.Status, t.Hits, strings.Join(t.Rules, ","))
	}
	_ = tw.Flush()
	for _, s := range p.Sources {
		fmt.Fprintf(out, "source: %s\n", s.URL)
	}
	return nil
}

func advCoverage(out io.Writer, args []string) error {
	_, _, b := omParse(args)
	var resp struct {
		Count      int `json:"count"`
		ByCoverage []struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			CoveragePct  int      `json:"coverage_pct"`
			ExactPct     int      `json:"exact_pct"`
			ObservedHits int      `json:"observed_hits"`
			Gaps         []string `json:"gaps"`
		} `json:"by_coverage"`
	}
	raw, err := ocGet("/v1/adversaries/coverage", &resp)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCOVERAGE\tEXACT\tHITS\tGAPS\tNAME")
	for _, a := range resp.ByCoverage {
		fmt.Fprintf(tw, "%s\t%d%%\t%d%%\t%d\t%d\t%s\n", a.ID, a.CoveragePct, a.ExactPct, a.ObservedHits, len(a.Gaps), a.Name)
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "%d adversaries ranked by coverage\n", resp.Count)
	return nil
}
