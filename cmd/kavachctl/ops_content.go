// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"
)

const contentUsage = "usage: kavachctl content list [--tactic T] [--os O] [--event-type E] [--severity S] [--batch B] [--technique ID] [--q TEXT] [--json] | show RULE_ID | coverage [--json]"

// ocDispatch handles the read-only `content` command group (detection content library).
func ocDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "content" {
		return false, nil
	}
	if len(args) < 2 {
		return true, fmt.Errorf("%s", contentUsage)
	}
	switch args[1] {
	case "list":
		return true, ocList(out, args[2:])
	case "show":
		return true, ocShow(out, args[2:])
	case "coverage":
		return true, ocCoverage(out, args[2:])
	}
	return true, fmt.Errorf("%s", contentUsage)
}

func ocGet(path string, v any) ([]byte, error) {
	b, code, err := doRequest("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(b)), 400))
	}
	if v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func ocList(out io.Writer, args []string) error {
	_, f, b := omParse(args, "tactic", "os", "event-type", "severity", "batch", "technique", "q")
	f["event_type"] = f["event-type"]
	path := omQuery("/v1/content/rules", f, "tactic", "os", "event_type", "severity", "batch", "technique", "q")
	var resp struct {
		Count int `json:"count"`
		Rules []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Tactic    string `json:"tactic"`
			Technique string `json:"technique"`
			Severity  string `json:"severity"`
			OS        string `json:"os"`
			EventType string `json:"event_type"`
		} `json:"rules"`
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
	fmt.Fprintln(tw, "ID\tSEVERITY\tTACTIC\tTECHNIQUE\tOS\tEVENT\tNAME")
	for _, r := range resp.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Tactic, r.Technique, r.OS, r.EventType, r.Name)
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "%d rules\n", resp.Count)
	return nil
}

func ocShow(out io.Writer, args []string) error {
	pos, _, b := omParse(args)
	id, err := omNeed(pos, 0, "usage: kavachctl content show RULE_ID [--json]")
	if err != nil {
		return err
	}
	return omDo(out, "GET", "/v1/content/rules/"+url.PathEscape(id), nil, b["json"])
}

func ocCoverage(out io.Writer, args []string) error {
	_, _, b := omParse(args)
	var cov map[string]any
	raw, err := ocGet("/v1/content/coverage", &cov)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	fmt.Fprintf(out, "rules: %v total, %v active; techniques covered: %v\n", cov["total_rules"], cov["active_rules"], cov["techniques_covered_count"])
	for _, k := range []string{"by_tactic", "by_severity", "by_os", "by_event_type", "by_batch"} {
		m, _ := cov[k].(map[string]any)
		keys := make([]string, 0, len(m))
		for n := range m {
			keys = append(keys, n)
		}
		sort.Strings(keys)
		fmt.Fprintf(out, "%s:\n", strings.TrimPrefix(k, "by_"))
		for _, n := range keys {
			fmt.Fprintf(out, "  %-24s %v\n", n, m[n])
		}
	}
	return nil
}
