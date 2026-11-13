// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const advisoriesUsage = "usage: kavachctl advisories list [--source S[,S]] [--cve CVE] [--since DATE] [--q TEXT] [--matched] [--limit N] [--json] | status | refresh"

// cfDispatch handles `advisories list|status|refresh` (worldwide CERT feeds,
// opt-in server-side via KAVACH_CERT_FEEDS). Observation only.
func cfDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "advisories" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", advisoriesUsage)
	}
	switch args[1] {
	case "list":
		return true, cfList(out, args[2:])
	case "status":
		raw, err := ocGet("/v1/advisories/feeds/status", nil)
		if err != nil {
			return true, err
		}
		return true, cfPrintStatus(out, raw, hasFlag(args[2:], "--json"))
	case "refresh":
		raw, code, err := doRequest("POST", "/v1/advisories/feeds/refresh", nil, nil)
		if err != nil {
			return true, err
		}
		if code == 409 {
			return true, fmt.Errorf("CERT advisory feeds are disabled on the server; set KAVACH_CERT_FEEDS=cisa,ncsc-uk,... and restart")
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
		}
		return true, cfPrintStatus(out, raw, hasFlag(args[2:], "--json"))
	}
	return true, fmt.Errorf("%s", advisoriesUsage)
}

func cfPrintStatus(out io.Writer, raw []byte, asJSON bool) error {
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var st struct {
		Enabled     []string       `json:"enabled"`
		LastRefresh string         `json:"last_refresh"`
		Counts      map[string]int `json:"counts"`
		FeedErrors  []string       `json:"feed_errors"`
		Note        string         `json:"note"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	fmt.Fprintf(out, "enabled: %s\nlast refresh: %s\n", strings.Join(st.Enabled, ","), st.LastRefresh)
	for _, id := range st.Enabled {
		fmt.Fprintf(out, "  %-16s %d advisories\n", id, st.Counts[id])
	}
	for _, e := range st.FeedErrors {
		fmt.Fprintf(out, "error: %s\n", e)
	}
	fmt.Fprintln(out, st.Note)
	return nil
}

func cfList(out io.Writer, args []string) error {
	_, f, b := omParse(args, "source", "cve", "since", "q", "limit")
	if b["matched"] {
		f["matched"] = "true"
	}
	raw, err := ocGet(omQuery("/v1/advisories", f, "source", "cve", "since", "q", "matched", "limit"), nil)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var resp struct {
		Count      int      `json:"count"`
		Total      int      `json:"total"`
		Enabled    []string `json:"enabled_feeds"`
		FeedErrors []string `json:"feed_errors"`
		Advisories []struct {
			Source       string   `json:"source"`
			ID           string   `json:"id"`
			Title        string   `json:"title"`
			Published    string   `json:"published"`
			Severity     string   `json:"severity"`
			CVEs         []string `json:"cves"`
			Matched      bool     `json:"matched"`
			MatchedHosts []string `json:"matched_hosts"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	if len(resp.Enabled) == 0 {
		fmt.Fprintln(out, "CERT advisory feeds are disabled (server env KAVACH_CERT_FEEDS is unset).")
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tID\tPUBLISHED\tSEV\tMATCH\tCVES\tTITLE")
	for _, a := range resp.Advisories {
		m := ""
		if a.Matched {
			m = "YES " + strings.Join(a.MatchedHosts, ",")
		}
		pub := a.Published
		if len(pub) > 10 {
			pub = pub[:10]
		}
		cves := strings.Join(a.CVEs, ",")
		if len(cves) > 40 {
			cves = cves[:40] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Source, a.ID, pub, a.Severity, m, cves, truncate(a.Title, 70))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d of %d advisories\n", resp.Count, resp.Total)
	for _, e := range resp.FeedErrors {
		fmt.Fprintf(out, "feed error: %s\n", e)
	}
	return nil
}
