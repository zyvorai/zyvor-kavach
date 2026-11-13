// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Sigma-subset importer. It converts Sigma-like rules (YAML or JSON) into Kavach content rules and
// reports every construct outside the supported subset instead of guessing. Supported: categories
// process_creation, network_connection, file_event, registry_set, dns_query; selections as maps
// (fields ANDed) or lists of maps (ORed); field modifiers contains, startswith, endswith, re, all,
// cased; conditions built from selection names with and / or / not and parentheses.
// Optional extensions: `kavach_id` (rule id) and `tests: {positive: [...], negative: [...]}` with
// Kavach sample events (required by the harness, Sigma itself carries none).

type sigmaResult struct {
	ID          string
	Rule        *ContentRule
	Errors      []string
	Unsupported []string
}

var sigmaCategories = map[string]struct {
	eventType string
	fields    map[string]string
}{
	"process_creation":   {"process", map[string]string{"image": "executable", "commandline": "command", "parentimage": "parent_exe"}},
	"network_connection": {"network", map[string]string{"destinationhostname": "destination", "destinationip": "destination"}},
	"network":            {"network", map[string]string{"destinationhostname": "destination", "destinationip": "destination"}},
	"file_event":         {"file", map[string]string{"targetfilename": "path"}},
	"file":               {"file", map[string]string{"targetfilename": "path"}},
	"registry_set":       {"registry", map[string]string{"targetobject": "key", "details": "value_data"}},
	"registry":           {"registry", map[string]string{"targetobject": "key", "details": "value_data"}},
	"dns_query":          {"dns", map[string]string{"queryname": "query", "queryresults": "answers"}},
	"dns":                {"dns", map[string]string{"queryname": "query", "queryresults": "answers"}},
}

var sigmaTactics = map[string]string{
	"reconnaissance": "Reconnaissance", "resource_development": "Resource Development", "initial_access": "Initial Access",
	"execution": "Execution", "persistence": "Persistence", "privilege_escalation": "Privilege Escalation",
	"defense_evasion": "Defense Evasion", "credential_access": "Credential Access", "discovery": "Discovery",
	"lateral_movement": "Lateral Movement", "collection": "Collection", "command_and_control": "Command and Control",
	"exfiltration": "Exfiltration", "impact": "Impact",
}

var sigmaLevels = map[string]string{"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

var sigmaSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

// sigmaConvertDocument parses a body of one or more Sigma rules (YAML documents separated by ---,
// a JSON object, or a JSON array) and converts each.
func sigmaConvertDocument(raw []byte) ([]sigmaResult, error) {
	var docs []map[string]any
	trim := strings.TrimSpace(string(raw))
	if trim == "" {
		return nil, fmt.Errorf("empty body")
	}
	if trim[0] == '{' || trim[0] == '[' {
		var v any
		if err := json.Unmarshal([]byte(trim), &v); err != nil {
			return nil, err
		}
		switch t := v.(type) {
		case map[string]any:
			docs = append(docs, t)
		case []any:
			for i, x := range t {
				m, ok := x.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("array element %d is not an object", i)
				}
				docs = append(docs, m)
			}
		}
	} else {
		var chunks []string
		cur := []string{}
		for _, ln := range strings.Split(strings.ReplaceAll(trim, "\r\n", "\n"), "\n") {
			if strings.TrimSpace(ln) == "---" {
				chunks, cur = append(chunks, strings.Join(cur, "\n")), nil
				continue
			}
			cur = append(cur, ln)
		}
		chunks = append(chunks, strings.Join(cur, "\n"))
		for i, c := range chunks {
			if strings.TrimSpace(c) == "" {
				continue
			}
			v, err := miniYAMLParse(c)
			if err != nil {
				return nil, fmt.Errorf("document %d: %v", i+1, err)
			}
			m, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("document %d: top level must be a mapping", i+1)
			}
			docs = append(docs, m)
		}
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no rules found")
	}
	if len(docs) > 200 {
		return nil, fmt.Errorf("at most 200 rules per import")
	}
	out := make([]sigmaResult, len(docs))
	for i, d := range docs {
		out[i] = sigmaConvert(d, i)
	}
	return out, nil
}

func sigmaStr(m map[string]any, k string) string {
	if s, ok := m[k].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func sigmaConvert(doc map[string]any, idx int) sigmaResult {
	res := sigmaResult{ID: fmt.Sprintf("(rule %d)", idx+1)}
	bad := func(f string, a ...any) { res.Errors = append(res.Errors, fmt.Sprintf(f, a...)) }
	unsup := func(f string, a ...any) { res.Unsupported = append(res.Unsupported, fmt.Sprintf(f, a...)) }

	title := sigmaStr(doc, "title")
	id := sigmaStr(doc, "kavach_id")
	if id == "" && title != "" {
		id = "sigma-" + strings.Trim(sigmaSlugRe.ReplaceAllString(strings.ToLower(title), "-"), "-")
		if len(id) > 64 {
			id = strings.TrimRight(id[:64], "-")
		}
	}
	if id != "" {
		res.ID = id
	}
	if title == "" {
		bad("title is required")
	}
	r := &ContentRule{ID: id, Name: title, Description: sigmaStr(doc, "description"), OS: "any", Batch: "sigma"}
	if r.Description == "" {
		r.Description = title
	}
	if sev, ok := sigmaLevels[strings.ToLower(sigmaStr(doc, "level"))]; ok {
		r.Severity = sev
	} else {
		bad("level %q must be informational|low|medium|high|critical", sigmaStr(doc, "level"))
	}

	// ATT&CK tags.
	tags, _ := doc["tags"].([]any)
	for _, t := range tags {
		ts, _ := t.(string)
		ts = strings.ToLower(strings.TrimSpace(ts))
		switch {
		case strings.HasPrefix(ts, "attack.t"):
			if r.Technique == "" {
				r.Technique = strings.ToUpper(strings.TrimPrefix(ts, "attack."))
			} else {
				unsup("multiple ATT&CK technique tags (Kavach rules carry one technique)")
			}
		case strings.HasPrefix(ts, "attack."):
			if tac, ok := sigmaTactics[strings.TrimPrefix(ts, "attack.")]; ok && r.Tactic == "" {
				r.Tactic = tac
			} else if r.Tactic != "" {
				unsup("multiple ATT&CK tactic tags (Kavach rules carry one tactic)")
			}
		default:
			if len(ts) > 0 && len(ts) <= 32 && len(r.Tags) < contentMaxTags {
				r.Tags = append(r.Tags, ts)
			}
		}
	}
	if r.Technique == "" {
		bad("no attack.tNNNN technique tag (technique is required)")
	}
	if r.Tactic == "" {
		bad("no attack.<tactic> tag such as attack.execution (tactic is required)")
	}

	// logsource.
	ls, _ := doc["logsource"].(map[string]any)
	cat := strings.ToLower(sigmaStr(ls, "category"))
	catInfo, okCat := sigmaCategories[cat]
	if !okCat {
		unsup("logsource category %q (supported: process_creation, network_connection, file_event, registry_set, dns_query)", cat)
	} else {
		r.EventType = catInfo.eventType
	}
	switch p := strings.ToLower(sigmaStr(ls, "product")); p {
	case "":
	case "windows", "linux", "macos":
		r.OS = p
	default:
		unsup("logsource product %q", p)
	}
	for k := range ls {
		if k != "category" && k != "product" {
			unsup("logsource key %q", k)
		}
	}
	detection, _ := doc["detection"].(map[string]any)
	handled := map[string]bool{"title": true, "description": true, "level": true, "tags": true, "logsource": true, "detection": true,
		"tests": true, "kavach_id": true, "id": true, "status": true, "author": true, "date": true, "modified": true,
		"references": true, "falsepositives": true}
	var extra []string
	for k := range doc {
		if !handled[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		unsup("top-level key %q is not supported", k)
	}

	if t, ok := doc["tests"]; ok {
		b, _ := json.Marshal(t)
		var ct ContentTests
		if err := json.Unmarshal(b, &ct); err != nil {
			bad("tests: %v", err)
		} else {
			r.Tests = &ct
		}
	}

	if detection == nil {
		bad("detection is required")
		return res
	}
	var fields map[string]string
	if okCat {
		fields = catInfo.fields
	}
	cond, isStr := detection["condition"].(string)
	if !isStr || strings.TrimSpace(cond) == "" {
		unsup("condition must be a single string expression")
		return res
	}
	cv := &sigmaCond{toks: sigmaTokenize(cond), sels: detection, fields: fields, cache: map[string]*ContentMatch{}, bad: bad, unsup: unsup}
	if _, has := detection["timeframe"]; has {
		unsup("timeframe / aggregation is not supported")
	}
	node := cv.parseOr()
	if cv.pos < len(cv.toks) && !cv.failed {
		bad("condition: unexpected token %q", cv.toks[cv.pos])
	}
	if node != nil && len(res.Errors) == 0 && len(res.Unsupported) == 0 {
		r.Match = *node
		res.Rule = r
	}
	return res
}

type sigmaCond struct {
	toks   []string
	pos    int
	sels   map[string]any
	fields map[string]string
	cache  map[string]*ContentMatch
	failed bool
	bad    func(string, ...any)
	unsup  func(string, ...any)
}

var sigmaTokRe = regexp.MustCompile(`\(|\)|[^\s()]+`)

func sigmaTokenize(s string) []string { return sigmaTokRe.FindAllString(s, -1) }

func (c *sigmaCond) peek() string {
	if c.pos < len(c.toks) {
		return strings.ToLower(c.toks[c.pos])
	}
	return ""
}

func (c *sigmaCond) fail(unsupported bool, f string, a ...any) *ContentMatch {
	if !c.failed {
		if unsupported {
			c.unsup(f, a...)
		} else {
			c.bad(f, a...)
		}
	}
	c.failed = true
	return nil
}

func sigmaJoin(kind string, nodes []ContentMatch) *ContentMatch {
	if len(nodes) == 1 {
		return &nodes[0]
	}
	if kind == "all" {
		return &ContentMatch{All: nodes}
	}
	return &ContentMatch{Any: nodes}
}

func (c *sigmaCond) parseOr() *ContentMatch {
	first := c.parseAnd()
	if first == nil || c.peek() != "or" {
		return first
	}
	nodes := []ContentMatch{*first}
	for c.peek() == "or" {
		c.pos++
		n := c.parseAnd()
		if n == nil {
			return nil
		}
		nodes = append(nodes, *n)
	}
	return sigmaJoin("any", nodes)
}

func (c *sigmaCond) parseAnd() *ContentMatch {
	first := c.parseNot()
	if first == nil || c.peek() != "and" {
		return first
	}
	nodes := []ContentMatch{*first}
	for c.peek() == "and" {
		c.pos++
		n := c.parseNot()
		if n == nil {
			return nil
		}
		nodes = append(nodes, *n)
	}
	return sigmaJoin("all", nodes)
}

func (c *sigmaCond) parseNot() *ContentMatch {
	if c.peek() == "not" {
		c.pos++
		n := c.parseNot()
		if n == nil {
			return nil
		}
		return &ContentMatch{Not: n}
	}
	return c.parsePrimary()
}

func (c *sigmaCond) parsePrimary() *ContentMatch {
	if c.pos >= len(c.toks) {
		return c.fail(false, "condition ends unexpectedly")
	}
	tok := c.toks[c.pos]
	switch strings.ToLower(tok) {
	case "(":
		c.pos++
		n := c.parseOr()
		if n == nil {
			return nil
		}
		if c.peek() != ")" {
			return c.fail(false, "condition: missing closing parenthesis")
		}
		c.pos++
		return n
	case ")", "and", "or":
		return c.fail(false, "condition: unexpected %q", tok)
	case "|":
		return c.fail(true, "condition aggregation (| count / near) is not supported")
	}
	if strings.Contains(tok, "|") {
		return c.fail(true, "condition aggregation (%s) is not supported", tok)
	}
	if c.pos+1 < len(c.toks) && strings.ToLower(c.toks[c.pos+1]) == "of" {
		return c.fail(true, "quantifier condition %q (\"N of\" / \"all of\") is not supported; list the selections with and/or", tok+" of ...")
	}
	if strings.Contains(tok, "*") {
		return c.fail(true, "wildcard selection reference %q is not supported", tok)
	}
	c.pos++
	if n, ok := c.cache[tok]; ok {
		return n
	}
	v, ok := c.sels[tok]
	if !ok || tok == "condition" || tok == "timeframe" {
		return c.fail(false, "condition references unknown selection %q", tok)
	}
	n := c.selection(tok, v)
	if n == nil {
		c.failed = true
		return nil
	}
	c.cache[tok] = n
	return n
}

func (c *sigmaCond) selection(name string, v any) *ContentMatch {
	switch t := v.(type) {
	case map[string]any:
		return c.selMap(name, t)
	case []any:
		var alts []ContentMatch
		for _, e := range t {
			m, ok := e.(map[string]any)
			if !ok {
				c.unsup("selection %s: keyword/plain-value lists are not supported (use field maps)", name)
				return nil
			}
			n := c.selMap(name, m)
			if n == nil {
				return nil
			}
			alts = append(alts, *n)
		}
		if len(alts) == 0 {
			c.bad("selection %s: empty", name)
			return nil
		}
		return sigmaJoin("any", alts)
	}
	c.unsup("selection %s: unsupported selection shape", name)
	return nil
}

func (c *sigmaCond) selMap(name string, m map[string]any) *ContentMatch {
	if len(m) == 0 {
		c.bad("selection %s: empty", name)
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var leaves []ContentMatch
	ok := true
	for _, k := range keys {
		n := c.leaf(name, k, m[k])
		if n == nil {
			ok = false
			continue
		}
		leaves = append(leaves, *n)
	}
	if !ok {
		return nil
	}
	return sigmaJoin("all", leaves)
}

func sigmaScalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

func (c *sigmaCond) leaf(sel, key string, val any) *ContentMatch {
	parts := strings.Split(key, "|")
	field, ok := c.fields[strings.ToLower(parts[0])]
	if !ok {
		c.unsup("selection %s: field %q is not supported for this logsource category", sel, parts[0])
		return nil
	}
	op, all, cased := "equals", false, false
	for _, m := range parts[1:] {
		switch strings.ToLower(m) {
		case "contains", "startswith", "endswith", "re":
			if op != "equals" {
				c.unsup("selection %s: field %q combines several match modifiers", sel, key)
				return nil
			}
			op = strings.ToLower(m)
		case "all":
			all = true
		case "cased":
			cased = true
		default:
			c.unsup("selection %s: modifier %q (in %q) is not supported", sel, m, key)
			return nil
		}
	}
	var raw []any
	if l, isList := val.([]any); isList {
		raw = l
	} else {
		raw = []any{val}
	}
	if len(raw) == 0 {
		c.bad("selection %s: field %q has no values", sel, key)
		return nil
	}
	var vals []string
	for _, x := range raw {
		s, okv := sigmaScalar(x)
		if !okv {
			c.unsup("selection %s: field %q has a null, empty or non-scalar value", sel, key)
			return nil
		}
		if op != "re" && strings.ContainsAny(s, "*?") {
			c.unsup("selection %s: wildcard in value %q (use |contains, |startswith or |endswith instead)", sel, s)
			return nil
		}
		vals = append(vals, s)
	}
	kop := map[string]string{"equals": "equals", "contains": "contains", "startswith": "prefix", "endswith": "suffix", "re": "regex"}[op]
	if len(vals) == 1 {
		return &ContentMatch{Field: field, Op: kop, Pattern: vals[0], CaseSensitive: cased}
	}
	if all {
		nodes := make([]ContentMatch, len(vals))
		for i, s := range vals {
			nodes[i] = ContentMatch{Field: field, Op: kop, Pattern: s, CaseSensitive: cased}
		}
		return &ContentMatch{All: nodes}
	}
	return &ContentMatch{Field: field, Op: kop, Patterns: vals, CaseSensitive: cased}
}

// ---- minimal YAML subset (block mappings, block sequences, flow lists, quoted/plain scalars,
// | and > block scalars, comments). Anything else is an error. ----

type yamlLine struct {
	indent int
	text   string // trimmed content
	raw    string
}

type yamlParser struct {
	lines []yamlLine
	i     int
}

func miniYAMLParse(src string) (any, error) {
	p := &yamlParser{}
	for _, ln := range strings.Split(src, "\n") {
		if strings.Contains(ln, "\t") && strings.TrimLeft(ln, " ") != strings.TrimLeft(ln, " \t") {
			return nil, fmt.Errorf("tabs are not allowed for indentation")
		}
		p.lines = append(p.lines, yamlLine{indent: len(ln) - len(strings.TrimLeft(ln, " ")), text: strings.TrimSpace(ln), raw: ln})
	}
	p.skip()
	if p.i >= len(p.lines) {
		return nil, fmt.Errorf("empty document")
	}
	v, err := p.block(p.lines[p.i].indent)
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected content %q", p.i+1, p.lines[p.i].text)
	}
	return v, nil
}

func (p *yamlParser) skip() {
	for p.i < len(p.lines) && (p.lines[p.i].text == "" || strings.HasPrefix(p.lines[p.i].text, "#")) {
		p.i++
	}
}

func yamlIsSeq(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yamlParser) block(indent int) (any, error) {
	if yamlIsSeq(p.lines[p.i].text) {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

// yamlSplitKey splits "key: value" honoring a quoted key; ok is false when the text is not a mapping entry.
func yamlSplitKey(t string) (key, val string, ok bool) {
	if t == "" {
		return
	}
	start := 0
	if t[0] == '\'' || t[0] == '"' {
		q := t[0]
		j := 1
		for j < len(t) {
			if t[j] == q {
				if q == '\'' && j+1 < len(t) && t[j+1] == '\'' {
					j += 2
					continue
				}
				break
			}
			if q == '"' && t[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(t) {
			return
		}
		start = j + 1
		if start >= len(t) || t[start] != ':' || (start+1 < len(t) && t[start+1] != ' ') {
			return
		}
		k, err := yamlScalar(t[:start])
		if err != nil {
			return
		}
		ks, _ := k.(string)
		return ks, strings.TrimSpace(t[start+1:]), true
	}
	for j := 0; j < len(t); j++ {
		if t[j] == ':' && (j+1 == len(t) || t[j+1] == ' ') {
			return t[:j], strings.TrimSpace(t[j+1:]), true
		}
	}
	return
}

func (p *yamlParser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent < indent {
			return out, nil
		}
		ln := p.lines[p.i]
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", p.i+1)
		}
		key, val, ok := yamlSplitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\", got %q", p.i+1, ln.text)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", p.i+1, key)
		}
		p.i++
		switch {
		case val == "" || strings.HasPrefix(val, "#"):
			p.skip()
			if p.i < len(p.lines) && (p.lines[p.i].indent > indent || (p.lines[p.i].indent == indent && yamlIsSeq(p.lines[p.i].text))) {
				v, err := p.block(p.lines[p.i].indent)
				if err != nil {
					return nil, err
				}
				out[key] = v
			} else {
				out[key] = nil
			}
		case val == "|" || val == ">" || val == "|-" || val == ">-":
			out[key] = p.blockScalar(indent, val[0] == '>')
		default:
			v, err := yamlScalar(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", p.i, err)
			}
			out[key] = v
		}
	}
}

func (p *yamlParser) blockScalar(parent int, fold bool) string {
	var parts []string
	for p.i < len(p.lines) {
		ln := p.lines[p.i]
		if ln.text != "" && ln.indent <= parent {
			break
		}
		parts = append(parts, ln.text)
		p.i++
	}
	sep := "\n"
	if fold {
		sep = " "
	}
	return strings.TrimSpace(strings.Join(parts, sep))
}

func (p *yamlParser) seq(indent int) (any, error) {
	out := []any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent || !yamlIsSeq(p.lines[p.i].text) {
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				return nil, fmt.Errorf("line %d: unexpected indentation in list", p.i+1)
			}
			return out, nil
		}
		ln := p.lines[p.i]
		rest := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		switch {
		case rest == "":
			p.i++
			p.skip()
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				v, err := p.block(p.lines[p.i].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
		default:
			if _, _, isMap := yamlSplitKey(rest); isMap && !strings.HasPrefix(rest, "[") {
				// "- key: value": re-read this line as a mapping entry two columns deeper.
				off := strings.Index(ln.raw, rest)
				p.lines[p.i] = yamlLine{indent: off, text: rest, raw: strings.Repeat(" ", off) + rest}
				v, err := p.mapping(off)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
				continue
			}
			v, err := yamlScalar(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", p.i+1, err)
			}
			out = append(out, v)
			p.i++
		}
	}
}

func yamlStripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'' && !inD:
			inS = !inS
		case s[i] == '"' && !inS:
			inD = !inD
		case s[i] == '#' && !inS && !inD && (i == 0 || s[i-1] == ' '):
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func yamlScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '\'':
		end := -1
		for j := 1; j < len(s); j++ {
			if s[j] == '\'' {
				if j+1 < len(s) && s[j+1] == '\'' {
					j++
					continue
				}
				end = j
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated single-quoted string")
		}
		if rest := strings.TrimSpace(s[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, fmt.Errorf("unexpected text after quoted string")
		}
		return strings.ReplaceAll(s[1:end], "''", "'"), nil
	case '"':
		end := -1
		for j := 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
			} else if s[j] == '"' {
				end = j
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated double-quoted string")
		}
		if rest := strings.TrimSpace(s[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, fmt.Errorf("unexpected text after quoted string")
		}
		u, err := strconv.Unquote(s[:end+1])
		if err != nil {
			return nil, fmt.Errorf("bad double-quoted string: %v", err)
		}
		return u, nil
	case '[':
		s = yamlStripComment(s)
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unterminated flow list")
		}
		inner := s[1 : len(s)-1]
		out := []any{}
		var cur strings.Builder
		inS, inD := false, false
		flush := func() error {
			t := strings.TrimSpace(cur.String())
			cur.Reset()
			if t == "" {
				return nil
			}
			v, err := yamlScalar(t)
			out = append(out, v)
			return err
		}
		for j := 0; j < len(inner); j++ {
			ch := inner[j]
			switch {
			case ch == '\'' && !inD:
				inS = !inS
			case ch == '"' && !inS:
				inD = !inD
			case ch == ',' && !inS && !inD:
				if err := flush(); err != nil {
					return nil, err
				}
				continue
			}
			cur.WriteByte(ch)
		}
		if err := flush(); err != nil {
			return nil, err
		}
		return out, nil
	case '{', '&', '*', '!', '|', '>', '%', '@', '`':
		return nil, fmt.Errorf("unsupported YAML construct starting with %q", string(s[0]))
	}
	s = yamlStripComment(s)
	if s == "~" || s == "null" {
		return nil, nil
	}
	return s, nil
}
