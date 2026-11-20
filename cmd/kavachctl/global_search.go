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

const searchUsage = "usage: kavachctl search QUERY [--type T[,T...]] [--limit N] [--json]"

// gsDispatch handles the read-only `search` command (GET /v1/search).
func gsDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "search" {
		return false, nil
	}
	return true, gsSearch(out, args[1:])
}

func gsSearch(out io.Writer, args []string) error {
	pos, f, b := omParse(args, "type", "limit")
	q := strings.TrimSpace(strings.Join(pos, " "))
	if len(q) < 2 {
		return fmt.Errorf("%s", searchUsage)
	}
	f["q"], f["types"] = q, f["type"]
	path := omQuery("/v1/search", f, "q", "types", "limit")
	raw, err := ocGet(path, nil)
	if err != nil {
		return err
	}
	if b["json"] {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil
	}
	var resp struct {
		Count   int `json:"count"`
		Results []struct {
			Type  string `json:"type"`
			ID    string `json:"id"`
			Title string `json:"title"`
			Score int    `json:"score"`
			Route string `json:"route"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tID\tTITLE\tSCORE\tROUTE")
	for _, r := range resp.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", r.Type, r.ID, r.Title, r.Score, r.Route)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d results\n", resp.Count)
	return nil
}
