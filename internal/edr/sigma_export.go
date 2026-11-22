// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"sort"
	"strings"
)

// Export of Kavach custom rules to Sigma YAML, only where the result is lossless: the exported YAML
// converts back (sigmaConvertDocument) to an equivalent rule. Rules that cannot be expressed exactly
// are skipped with the reason instead of being approximated.

var sigmaExportCat = map[string]struct {
	category string
	fields   map[string]string
}{
	"process":  {"process_creation", map[string]string{"executable": "Image", "command": "CommandLine", "parent_exe": "ParentImage"}},
	"network":  {"network_connection", map[string]string{"destination": "DestinationHostname"}},
	"file":     {"file_event", map[string]string{"path": "TargetFilename"}},
	"registry": {"registry_set", map[string]string{"key": "TargetObject", "value_data": "Details"}},
	"dns":      {"dns_query", map[string]string{"query": "QueryName", "answers": "QueryResults"}},
	"auth":     {"authentication", map[string]string{"user": "TargetUserName", "source_ip": "IpAddress", "method": "AuthenticationPackageName"}},
}

var sigmaExportOp = map[string]string{"equals": "", "contains": "|contains", "prefix": "|startswith", "suffix": "|endswith", "regex": "|re"}

type sigmaSkip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

func sigmaQuote(s string) (string, error) {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("value contains a control character or newline")
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}

type sigmaExporter struct {
	cat   string
	fmap  map[string]string
	sels  []string // rendered selection blocks, in order
	count int
	err   error
}

func (e *sigmaExporter) fail(f string, a ...any) string {
	if e.err == nil {
		e.err = fmt.Errorf(f, a...)
	}
	return ""
}

// entry renders one "Field|op: values" selection entry.
func (e *sigmaExporter) entry(n *ContentMatch) (key string, vals []string) {
	fld, ok := e.fmap[n.Field]
	if !ok {
		e.fail("field %q has no Sigma field mapping for event type %s", n.Field, e.cat)
		return
	}
	suffix, ok := sigmaExportOp[n.Op]
	if !ok {
		e.fail("operator %q has no lossless Sigma form", n.Op)
		return
	}
	if n.Pattern != "" && len(n.Patterns) > 0 {
		e.fail("both pattern and patterns set")
		return
	}
	pats := n.Patterns
	if n.Pattern != "" {
		pats = []string{n.Pattern}
	}
	if len(pats) == 0 {
		e.fail("leaf on %q has no pattern", n.Field)
		return
	}
	for _, p := range pats {
		if n.Op != "regex" && strings.ContainsAny(p, "*?") {
			e.fail("pattern %q contains * or ?, which Sigma treats as wildcards (no lossless escape)", p)
			return
		}
		if n.Op == "regex" && len(p) > sigmaMaxRegexLen {
			e.fail("regex is longer than the importer limit")
			return
		}
		q, err := sigmaQuote(p)
		if err != nil {
			e.fail("pattern %q: %v", p, err)
			return
		}
		vals = append(vals, q)
	}
	key = fld + suffix
	if n.CaseSensitive {
		key += "|cased"
	}
	return
}

func isLeaf(n *ContentMatch) bool {
	return len(n.All) == 0 && len(n.Any) == 0 && n.Not == nil
}

func (e *sigmaExporter) addSel(entries map[string][]string, order []string) string {
	e.count++
	name := fmt.Sprintf("sel_%d", e.count)
	var b strings.Builder
	fmt.Fprintf(&b, "    %s:\n", name)
	for _, k := range order {
		vs := entries[k]
		if len(vs) == 1 {
			fmt.Fprintf(&b, "        %s: %s\n", k, vs[0])
			continue
		}
		fmt.Fprintf(&b, "        %s:\n", k)
		for _, v := range vs {
			fmt.Fprintf(&b, "            - %s\n", v)
		}
	}
	e.sels = append(e.sels, b.String())
	return name
}

// expr returns the condition expression for n, and whether it is a compound (needs parentheses).
func (e *sigmaExporter) expr(n *ContentMatch) (string, bool) {
	switch {
	case len(n.All) > 0:
		// A group of plain leaves with distinct keys becomes one Sigma selection map.
		allLeaf, seen := true, map[string]bool{}
		entries, order := map[string][]string{}, []string{}
		for i := range n.All {
			c := &n.All[i]
			if !isLeaf(c) {
				allLeaf = false
				break
			}
			k, v := e.entry(c)
			if e.err != nil {
				return "", false
			}
			if seen[k] {
				allLeaf = false
				break
			}
			seen[k] = true
			entries[k], order = v, append(order, k)
		}
		if allLeaf && len(n.All) > 1 {
			return e.addSel(entries, order), false
		}
		parts := make([]string, len(n.All))
		for i := range n.All {
			s, compound := e.expr(&n.All[i])
			if compound && len(n.All[i].Any) > 0 {
				s = "(" + s + ")"
			}
			parts[i] = s
		}
		return strings.Join(parts, " and "), len(parts) > 1
	case len(n.Any) > 0:
		parts := make([]string, len(n.Any))
		for i := range n.Any {
			s, compound := e.expr(&n.Any[i])
			if compound {
				s = "(" + s + ")"
			}
			parts[i] = s
		}
		return strings.Join(parts, " or "), len(parts) > 1
	case n.Not != nil:
		s, compound := e.expr(n.Not)
		if compound {
			s = "(" + s + ")"
		}
		return "not " + s, true
	}
	k, v := e.entry(n)
	if e.err != nil {
		return "", false
	}
	return e.addSel(map[string][]string{k: v}, []string{k}), false
}

var sigmaTacticRev = func() map[string]string {
	m := map[string]string{}
	for k, v := range sigmaTactics {
		m[v] = k
	}
	return m
}()

// sigmaExportRule renders one rule as a Sigma YAML document, or explains why it is not lossless.
func sigmaExportRule(r *ContentRule) (string, error) {
	cat, ok := sigmaExportCat[r.EventType]
	if !ok {
		return "", fmt.Errorf("event type %q has no Sigma logsource category", r.EventType)
	}
	tactic, ok := sigmaTacticRev[r.Tactic]
	if !ok {
		return "", fmt.Errorf("tactic %q has no Sigma tag", r.Tactic)
	}
	if strings.ContainsRune(r.Description, '\n') || strings.ContainsRune(r.Name, '\n') {
		return "", fmt.Errorf("multi-line name or description")
	}
	e := &sigmaExporter{cat: r.EventType, fmap: cat.fields}
	cond, _ := e.expr(&r.Match)
	if e.err != nil {
		return "", e.err
	}
	var b strings.Builder
	q := func(s string) string {
		v, err := sigmaQuote(s)
		if err != nil && e.err == nil {
			e.err = fmt.Errorf("%v", err)
		}
		return v
	}
	fmt.Fprintf(&b, "title: %s\n", q(r.Name))
	fmt.Fprintf(&b, "kavach_id: %s\n", r.ID)
	fmt.Fprintf(&b, "description: %s\n", q(r.Description))
	fmt.Fprintf(&b, "level: %s\n", r.Severity)
	b.WriteString("tags:\n")
	fmt.Fprintf(&b, "    - attack.%s\n", tactic)
	fmt.Fprintf(&b, "    - attack.%s\n", strings.ToLower(r.Technique))
	for _, t := range r.Tags {
		if t != strings.ToLower(t) || strings.HasPrefix(t, "attack.") || strings.ContainsAny(t, " \t'\"") {
			return "", fmt.Errorf("tag %q cannot be exported unchanged", t)
		}
		fmt.Fprintf(&b, "    - %s\n", q(t))
	}
	b.WriteString("logsource:\n")
	fmt.Fprintf(&b, "    category: %s\n", cat.category)
	if r.OS != "any" {
		fmt.Fprintf(&b, "    product: %s\n", r.OS)
	}
	b.WriteString("detection:\n")
	for _, s := range e.sels {
		b.WriteString(s)
	}
	fmt.Fprintf(&b, "    condition: %s\n", cond)
	if r.TechniqueName != "" {
		fmt.Fprintf(&b, "kavach_technique_name: %s\n", q(r.TechniqueName))
	}
	if r.Batch != "" && r.Batch != "sigma" {
		fmt.Fprintf(&b, "kavach_batch: %s\n", q(r.Batch))
	}
	if r.Tests != nil && (len(r.Tests.Positive) > 0 || len(r.Tests.Negative) > 0) {
		b.WriteString("tests:\n")
		for _, grp := range []struct {
			name string
			evs  []LabEvent
		}{{"positive", r.Tests.Positive}, {"negative", r.Tests.Negative}} {
			fmt.Fprintf(&b, "    %s:\n", grp.name)
			for i, ev := range grp.evs {
				lines, err := sigmaSampleLines(ev)
				if err != nil {
					return "", fmt.Errorf("%s sample #%d: %v", grp.name, i, err)
				}
				for j, ln := range lines {
					if j == 0 {
						fmt.Fprintf(&b, "        - %s\n", ln)
					} else {
						fmt.Fprintf(&b, "          %s\n", ln)
					}
				}
			}
		}
	}
	if e.err != nil {
		return "", e.err
	}
	return b.String(), nil
}

// sigmaSampleLines renders a lab event as "key: 'value'" lines; fields the importer cannot read back
// (kind, time, uid, rule, severity) make the rule non-lossless.
func sigmaSampleLines(ev LabEvent) ([]string, error) {
	if !ev.Time.IsZero() || ev.UID != nil || ev.Rule != "" || ev.Severity != "" {
		return nil, fmt.Errorf("sample carries time, uid, rule or severity, which Sigma tests cannot express here")
	}
	var lines []string
	add := func(k, v string) error {
		if v == "" {
			return nil
		}
		q, err := sigmaQuote(v)
		if err != nil {
			return err
		}
		lines = append(lines, k+": "+q)
		return nil
	}
	for _, kv := range [][2]string{{"executable", ev.Executable}, {"command", ev.Command}, {"parent_exe", ev.ParentExe}, {"path", ev.Path},
		{"destination", ev.Destination}, {"operation", ev.Operation}, {"host", ev.Host}} {
		if err := add(kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	if len(ev.Attrs) > 0 {
		lines = append(lines, "attrs:")
		keys := make([]string, 0, len(ev.Attrs))
		for k := range ev.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" || strings.ContainsAny(k, ":#'\" ") {
				return nil, fmt.Errorf("attribute name %q cannot be exported", k)
			}
			q, err := sigmaQuote(ev.Attrs[k])
			if err != nil {
				return nil, err
			}
			if ev.Attrs[k] == "" {
				return nil, fmt.Errorf("empty attribute value for %q", k)
			}
			lines = append(lines, "    "+k+": "+q)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty sample")
	}
	return lines, nil
}

// sigmaExportAll exports every losslessly expressible rule as one multi-document YAML string.
func sigmaExportAll(rules []*ContentRule) (yaml string, exported []string, skipped []sigmaSkip) {
	var docs []string
	exported, skipped = []string{}, []sigmaSkip{}
	for _, r := range rules {
		y, err := sigmaExportRule(r)
		if err != nil {
			skipped = append(skipped, sigmaSkip{ID: r.ID, Reason: err.Error()})
			continue
		}
		docs = append(docs, y)
		exported = append(exported, r.ID)
	}
	return strings.Join(docs, "---\n"), exported, skipped
}
