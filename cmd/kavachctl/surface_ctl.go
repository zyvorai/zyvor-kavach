// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Surface-parity commands: read-only GET routes that previously had no named
// kavachctl command. All are table-driven; every one is a plain GET.

type surfCmd struct {
	words []string // leading argv words, e.g. {"regression", "status"}
	path  string   // route without positional ID
	// idPath is used instead of path when a positional ID is given; "{id}" is
	// replaced with the escaped ID.
	idPath string
	// flags lists --flag names that become query parameters. "a-b=a_b" maps the
	// flag a-b to the parameter a_b.
	flags []string
	gate  bool // exit non-zero when the server answers 412 (CI gate)
}

var surfCmds = []surfCmd{
	{words: []string{"events", "auth"}, path: "/v1/events/auth", flags: []string{"host", "limit"}},
	{words: []string{"events", "dns"}, path: "/v1/events/dns", flags: []string{"host", "limit"}},
	{words: []string{"events", "module"}, path: "/v1/events/module", flags: []string{"host", "limit"}},
	{words: []string{"events", "registry"}, path: "/v1/events/registry", flags: []string{"host", "limit"}},
	{words: []string{"events", "summary"}, path: "/v1/events/summary"},
	{words: []string{"enrich", "geo"}, path: "/v1/enrich/geo", flags: []string{"ip"}},
	{words: []string{"evidence", "cases"}, path: "/v1/evidence/cases", idPath: "/v1/evidence/cases/{id}"},
	{words: []string{"guidance"}, path: "/v1/guidance", idPath: "/v1/guidance/{id}", flags: []string{"kind", "q"}},
	{words: []string{"posture", "trend-config"}, path: "/v1/posture/trend/config"},
	{words: []string{"queries", "library"}, path: "/v1/queries/library", idPath: "/v1/queries/library/{id}", flags: []string{"tactic", "tag", "q"}},
	{words: []string{"exposure", "report"}, path: "/v1/exposure/report", flags: []string{"host", "min_score=min_score"}},
	{words: []string{"exposure", "advisories"}, path: "/v1/exposure/advisories"},
	{words: []string{"exposure", "sboms"}, path: "/v1/exposure/sboms", idPath: "/v1/exposure/sboms/{id}"},
	{words: []string{"regression", "status"}, path: "/v1/regression/status"},
	{words: []string{"regression", "history"}, path: "/v1/regression/history", flags: []string{"limit"}},
	{words: []string{"regression", "diff"}, path: "/v1/regression/diff", flags: []string{"from", "to"}},
	{words: []string{"regression", "trend"}, path: "/v1/regression/trend", flags: []string{"window"}},
	{words: []string{"regression", "config"}, path: "/v1/regression/config"},
	{words: []string{"regression", "gate"}, path: "/v1/regression/gate", gate: true,
		flags: []string{"min-detected=min_detected", "max-regressions=max_regressions", "max-false-positives=max_false_positives"}},
	{words: []string{"reports", "templates"}, path: "/v1/reports/templates", idPath: "/v1/reports/templates/{id}/render"},
	{words: []string{"rollback"}, path: "/v1/rollback", flags: []string{"id"}},
}

// surfDispatch handles the surface-parity commands.
func surfDispatch(args []string, out io.Writer) (bool, error) {
	for _, c := range surfCmds {
		if len(args) < len(c.words) {
			continue
		}
		match := true
		for i, w := range c.words {
			if args[i] != w {
				match = false
				break
			}
		}
		if match {
			return true, surfRun(out, c, args[len(c.words):])
		}
	}
	return false, nil
}

func surfRun(out io.Writer, c surfCmd, rest []string) error {
	keys := []string{"token"}
	for _, f := range c.flags {
		name, _, _ := strings.Cut(f, "=")
		keys = append(keys, name)
	}
	pos, f, b := omParse(rest, keys...)
	if tok := f["token"]; tok != "" {
		// Convenience only; prefer KAVACH_TOKEN so the secret stays out of argv.
		_ = os.Setenv("KAVACH_TOKEN", tok)
	}
	path := c.path
	byID := c.idPath != "" && len(pos) > 0
	if byID {
		path = strings.ReplaceAll(c.idPath, "{id}", url.PathEscape(pos[0]))
	}
	q := url.Values{}
	if !byID {
		for _, fl := range c.flags {
			name, param, ok := strings.Cut(fl, "=")
			if !ok {
				param = name
			}
			if v := f[name]; v != "" {
				q.Set(param, v)
			}
		}
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	raw, code, err := doRequest("GET", path, nil, nil)
	if err != nil {
		return err
	}
	if code >= 300 && !(c.gate && code == 412) {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
	}
	switch {
	case b["json"]:
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
	case !json.Valid(raw):
		fmt.Fprintln(out, strings.TrimRight(string(raw), "\n")) // e.g. markdown render
	default:
		surfTable(out, raw)
	}
	if c.gate && code == 412 {
		return fmt.Errorf("gate failed (HTTP 412)")
	}
	return nil
}

// surfTable renders a JSON object as header lines plus a table for its first
// list-of-objects field; a bare list becomes a table; anything else is
// pretty-printed JSON.
func surfTable(out io.Writer, raw []byte) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		fmt.Fprintln(out, string(raw))
		return
	}
	switch t := v.(type) {
	case []any:
		surfRows(out, surfObjs(t))
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var listKey string
		for _, k := range keys {
			if l, ok := t[k].([]any); ok && len(surfObjs(l)) > 0 {
				listKey = k
				break
			}
		}
		for _, k := range keys {
			if k == listKey {
				continue
			}
			switch s := t[k].(type) {
			case map[string]any, []any:
				b, _ := json.Marshal(s)
				fmt.Fprintf(out, "%s: %s\n", k, truncate(string(b), 200))
			default:
				fmt.Fprintf(out, "%s: %v\n", k, s)
			}
		}
		if listKey != "" {
			fmt.Fprintf(out, "\n%s:\n", listKey)
			surfRows(out, surfObjs(t[listKey].([]any)))
		}
	default:
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(out, string(b))
	}
}

func surfObjs(l []any) []map[string]any {
	var rows []map[string]any
	for _, e := range l {
		if m, ok := e.(map[string]any); ok {
			rows = append(rows, m)
		}
	}
	return rows
}

func surfRows(out io.Writer, rows []map[string]any) {
	if len(rows) == 0 {
		fmt.Fprintln(out, "(none)")
		return
	}
	var cols []string
	seen := map[string]bool{}
	for _, r := range rows {
		ks := make([]string, 0, len(r))
		for k := range r {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			switch r[k].(type) {
			case map[string]any, []any:
				continue
			}
			if !seen[k] && len(cols) < 8 {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	tw := newTab(out)
	hdr := make([]string, len(cols))
	for i, c := range cols {
		hdr[i] = strings.ToUpper(c)
	}
	fmt.Fprintln(tw, strings.Join(hdr, "\t"))
	for _, r := range rows {
		cells := make([]string, len(cols))
		for i, c := range cols {
			if r[c] != nil {
				cells[i] = truncate(fmt.Sprint(r[c]), 48)
			}
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	_ = tw.Flush()
}
