// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const provUsage = `usage: kavachctl prov <command>
  graph --host H [--limit N] [--json]                       provenance graph for one host
  stories [--host H] [--min-score S] [--json]               scored attack stories
  trace --finding-id ID [--dir back|fwd|both] [--hops N] [--json]   bounded trace from a finding
  status [--json]                                           inputs, caps, what the graph lacks
Observation only. Always read the printed method and limitations.`

// p4Dispatch is the single entry for prov, ransom, ttp and `inspect similar`.
// It runs before inspectDispatch so `inspect similar` is claimed here without
// editing inspect.go; every other inspect command falls through.
func p4Dispatch(args []string, out io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "prov":
		return true, provRun(out, args[1:])
	case "ransom":
		return true, ransomRun(out, args[1:])
	case "ttp":
		return true, ttpRun(out, args[1:])
	case "inspect":
		if len(args) > 1 && args[1] == "similar" {
			return true, inspectSimilarRun(out, args[2:])
		}
	}
	return false, nil
}

// p4Get performs a GET and decodes the JSON object. With asJSON the body is
// echoed verbatim and the returned map is nil.
func p4Get(out io.Writer, path string, asJSON bool) (map[string]any, error) {
	raw, err := mlCall("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if asJSON {
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func p4Query(path string, kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			v.Set(kv[i], kv[i+1])
		}
	}
	if len(v) == 0 {
		return path
	}
	return path + "?" + v.Encode()
}

// p4Strings converts a JSON array to []string.
func p4Strings(m map[string]any, key string) []string {
	l, _ := m[key].([]any)
	var out []string
	for _, e := range l {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

func p4List(out io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(out, "%s:\n", title)
	for _, s := range items {
		fmt.Fprintf(out, "  - %s\n", s)
	}
}

// p4Header prints the mandatory method and limitations/caveats block.
func p4Header(out io.Writer, m map[string]any, listKey, listTitle string) {
	s := strFrom(m, "method")
	items := p4Strings(m, listKey)
	if s != "" {
		fmt.Fprintf(out, "METHOD: %s\n", s)
	}
	p4List(out, listTitle, items)
	if s != "" || len(items) > 0 {
		fmt.Fprintln(out)
	}
}

func num(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return "-"
}

func provRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", provUsage)
	}
	_, f, b := omParse(args[1:], "host", "limit", "min-score", "finding-id", "dir", "hops")
	j := b["json"]
	switch args[0] {
	case "graph":
		if f["host"] == "" {
			return fmt.Errorf("usage: kavachctl prov graph --host H [--limit N] [--json]")
		}
		m, err := p4Get(out, p4Query("/v1/prov/graph", "host", f["host"], "limit", f["limit"]), j)
		if err != nil || j {
			return err
		}
		p4Header(out, m, "limitations", "LIMITATIONS")
		if e := strFrom(m, "error"); e != "" {
			fmt.Fprintf(out, "Error: %s\n", e)
			p4List(out, "Known hosts", p4Strings(m, "hosts"))
			return nil
		}
		fmt.Fprintf(out, "Host %s: %d nodes, %d edges (node cap %s, truncated: %v)\n", strFrom(m, "host"), len(listOf(m, "nodes")), len(listOf(m, "edges")), num(m, "node_cap"), m["truncated"])
		provNodes(out, m)
		if mm, ok := m["missing"].(map[string]any); ok {
			fmt.Fprintf(out, "Missing (could not be linked): %v\n", mm)
		}
		return nil
	case "stories":
		m, err := p4Get(out, p4Query("/v1/prov/stories", "host", f["host"], "min_score", f["min-score"]), j)
		if err != nil || j {
			return err
		}
		p4Header(out, m, "limitations", "LIMITATIONS")
		st := listOf(m, "stories")
		fmt.Fprintf(out, "Stories (%d), min score %s, rarity source %s. Scores rank attention; they are not verdicts.\n", len(st), num(m, "min_score"), num(m, "rarity_source"))
		for _, s := range st {
			fmt.Fprintf(out, "  %s  host=%s  score=%s  ordered_steps=%s  max_rarity_bits=%s  tactics=%v\n", strFrom(s, "id"), strFrom(s, "host"), num(s, "score"), num(s, "kill_chain_ordered_steps"), num(s, "max_path_rarity_bits"), s["tactics"])
		}
		if len(st) == 0 {
			fmt.Fprintln(out, "  none above threshold")
		}
		return nil
	case "trace":
		if f["finding-id"] == "" {
			return fmt.Errorf("usage: kavachctl prov trace --finding-id ID [--dir back|fwd|both] [--hops N] [--json]")
		}
		m, err := p4Get(out, p4Query("/v1/prov/trace", "finding_id", f["finding-id"], "dir", f["dir"], "hops", f["hops"]), j)
		if err != nil || j {
			return err
		}
		p4Header(out, m, "limitations", "LIMITATIONS")
		if m["attached"] == false {
			fmt.Fprintf(out, "Finding %s NOT attached: %s\n", strFrom(m, "finding_id"), strFrom(m, "reason"))
			return nil
		}
		fmt.Fprintf(out, "Trace from finding %s on %s (dir %s, hops %s, truncated: %v): %d nodes, %d edges\n", strFrom(m, "finding_id"), strFrom(m, "host"), strFrom(m, "dir"), num(m, "hops"), m["truncated"], len(listOf(m, "nodes")), len(listOf(m, "edges")))
		provNodes(out, m)
		return nil
	case "status":
		m, err := p4Get(out, "/v1/prov/status", j)
		if err != nil || j {
			return err
		}
		p4Header(out, m, "limitations", "LIMITATIONS")
		fmt.Fprintf(out, "Hosts: %s\n", strings.Join(p4Strings(m, "hosts"), ", "))
		fmt.Fprintf(out, "Inputs: %v\n", m["inputs"])
		p4List(out, "Includes", p4Strings(m, "includes"))
		p4List(out, "Lacks", p4Strings(m, "lacks"))
		fmt.Fprintf(out, "State: %s\n", strFrom(m, "state"))
		return nil
	}
	return fmt.Errorf("unknown prov command %q\n%s", args[0], provUsage)
}

func provNodes(out io.Writer, m map[string]any) {
	for _, n := range listOf(m, "nodes") {
		what := strFrom(n, "exe", "label", "command")
		fmt.Fprintf(out, "  node %-28s %-8s pid=%s %s findings=%v\n", truncate(strFrom(n, "id"), 28), strFrom(n, "kind"), num(n, "pid"), truncate(what, 60), n["finding_ids"])
	}
	for _, e := range listOf(m, "edges") {
		fmt.Fprintf(out, "  edge %s -[%s]-> %s\n", truncate(strFrom(e, "from"), 28), strFrom(e, "kind"), truncate(strFrom(e, "to"), 28))
	}
}
