// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"
)

// Value handling for the Sigma importer: wildcards, the windash / base64 / base64offset modifiers,
// regex safety, and leaf conversion. Observation-only: nothing here evaluates live events.

const (
	sigmaMaxBytes    = 1 << 20 // max size of one imported file / request body
	sigmaMaxRules    = 200     // max rules per import
	sigmaMaxRegexLen = 256     // matches the detection-lab regex limit
	sigmaMaxVariants = 64      // max expanded values per field after windash / base64offset
)

type sigmaAlt struct{ op, pat string }

type sigmaTok struct {
	lit  string
	kind byte // 'l' literal, '*' any run, '?' any one char
}

// sigmaWildTokens splits a Sigma value into literals and wildcards. A backslash escapes * and ?;
// a doubled backslash directly before a wildcard is one literal backslash. Other backslashes are literal.
func sigmaWildTokens(s string) []sigmaTok {
	var out []sigmaTok
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, sigmaTok{lit: cur.String(), kind: 'l'})
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?'):
			cur.WriteByte(s[i+1])
			i++
		case ch == '\\' && i+2 < len(s) && s[i+1] == '\\' && (s[i+2] == '*' || s[i+2] == '?'):
			cur.WriteByte('\\')
			i++
		case ch == '*' || ch == '?':
			flush()
			out = append(out, sigmaTok{kind: ch})
		default:
			cur.WriteByte(ch)
		}
	}
	flush()
	return out
}

func sigmaHasWild(toks []sigmaTok) bool {
	for _, t := range toks {
		if t.kind != 'l' {
			return true
		}
	}
	return false
}

func sigmaLiteral(toks []sigmaTok) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(t.lit)
	}
	return b.String()
}

// sigmaWildAlt maps a wildcard-bearing equals value onto a Kavach op: *x* contains, x* prefix, *x suffix,
// anything else an anchored regex. ok is false for a bare "*" (matches everything).
func sigmaWildAlt(toks []sigmaTok) (alt sigmaAlt, ok bool) {
	switch {
	case len(toks) == 3 && toks[0].kind == '*' && toks[1].kind == 'l' && toks[2].kind == '*':
		return sigmaAlt{"contains", toks[1].lit}, true
	case len(toks) == 2 && toks[0].kind == 'l' && toks[1].kind == '*':
		return sigmaAlt{"prefix", toks[0].lit}, true
	case len(toks) == 2 && toks[0].kind == '*' && toks[1].kind == 'l':
		return sigmaAlt{"suffix", toks[1].lit}, true
	}
	if len(toks) == 1 && toks[0].kind == '*' {
		return alt, false
	}
	var b strings.Builder
	b.WriteString("(?s)^")
	for _, t := range toks {
		switch t.kind {
		case 'l':
			b.WriteString(regexp.QuoteMeta(t.lit))
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		}
	}
	b.WriteString("$")
	return sigmaAlt{"regex", b.String()}, true
}

var sigmaDashRe = regexp.MustCompile(`(^|\s)-`)

// sigmaWindash expands leading dashes of arguments ("-enc", " -enc") to the usual Windows alternatives.
// The replacement is uniform across the value (all dashes become the same character).
func sigmaWindash(s string) []string {
	if !sigmaDashRe.MatchString(s) {
		return []string{s}
	}
	var out []string
	for _, r := range []string{"-", "/", "–", "—", "―"} {
		out = append(out, sigmaDashRe.ReplaceAllString(s, "${1}"+r))
	}
	return out
}

// sigmaBase64Offset returns the three base64 alignments of v (same algorithm as pySigma).
func sigmaBase64Offset(v string) []string {
	start := [3]int{0, 2, 3}
	end := [3]int{0, -3, -2}
	var out []string
	for i := 0; i < 3; i++ {
		e := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", i) + v))
		stop := len(e)
		if k := end[(len(v)+i)%3]; k != 0 {
			stop = len(e) + k
		}
		if start[i] <= stop && stop <= len(e) {
			if p := e[start[i]:stop]; p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// sigmaCheckRegex rejects regexes the importer will not carry: too long, invalid for RE2 (lookaround,
// backreferences), nested unbounded quantifiers (the classic ReDoS shape, rejected as a defence in depth
// even though Go's RE2 engine is linear time), huge repetition counts, or a probe match that does not
// finish quickly.
func sigmaCheckRegex(p string) error {
	if len(p) > sigmaMaxRegexLen {
		return fmt.Errorf("regex is %d chars; the limit is %d", len(p), sigmaMaxRegexLen)
	}
	if err := sigmaNestedQuantifier(p); err != nil {
		return err
	}
	re, err := regexp.Compile("(?i)" + p)
	if err != nil {
		return fmt.Errorf("not valid RE2 (Go regexp has no lookaround or backreferences): %v", err)
	}
	done := make(chan struct{})
	go func() {
		probe := strings.Repeat("a", 2048) + "!"
		re.MatchString(probe)
		re.MatchString(strings.ToUpper(probe))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		return fmt.Errorf("probe match exceeded 250ms; rejected as a possible ReDoS")
	}
	return nil
}

var sigmaRepeatRe = regexp.MustCompile(`\{(\d*)(,(\d*))?\}`)

func sigmaNestedQuantifier(p string) error {
	type grp struct{ quant bool }
	var stack []grp
	inClass := false
	isQuant := func(i int) (bool, bool) { // quantifier at i? (is, unbounded)
		if i >= len(p) {
			return false, false
		}
		switch p[i] {
		case '*', '+':
			return true, true
		case '?':
			return true, false
		case '{':
			if m := sigmaRepeatRe.FindStringSubmatchIndex(p[i:]); m != nil && m[0] == 0 {
				body := p[i : i+m[1]]
				return true, strings.HasSuffix(body, ",}")
			}
		}
		return false, false
	}
	if m := sigmaRepeatRe.FindAllStringSubmatch(p, -1); m != nil {
		for _, x := range m {
			for _, d := range []string{x[1], x[3]} {
				if len(d) > 3 {
					return fmt.Errorf("repetition count %q is too large", x[0])
				}
			}
		}
	}
	for i := 0; i < len(p); i++ {
		ch := p[i]
		switch {
		case ch == '\\':
			i++
		case inClass:
			if ch == ']' {
				inClass = false
			}
		case ch == '[':
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				i++
			}
		case ch == '(':
			stack = append(stack, grp{})
		case ch == ')':
			if len(stack) == 0 {
				break
			}
			g := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			isQ, unb := isQuant(i + 1)
			if isQ && unb && g.quant {
				return fmt.Errorf("nested unbounded quantifiers (ReDoS shape) near offset %d", i)
			}
			if len(stack) > 0 && (g.quant || (isQ && unb)) {
				stack[len(stack)-1].quant = true
			}
		default:
			if q, unb := isQuant(i); q && unb && len(stack) > 0 {
				stack[len(stack)-1].quant = true
			}
		}
	}
	return nil
}

// leaf converts one "Field|modifier|...: value(s)" entry of a selection.
func (c *sigmaCond) leaf(sel, key string, val any) *ContentMatch {
	parts := strings.Split(key, "|")
	field, ok := c.fields[strings.ToLower(parts[0])]
	if !ok {
		c.gap("field", parts[0], "selection %s: field %q has no Kavach mapping for this logsource category (mapped: %s)", sel, parts[0], c.mapped())
		return nil
	}
	op, all, cased, bad := "equals", false, false, false
	var xf []string
	for _, m := range parts[1:] {
		switch lm := strings.ToLower(m); lm {
		case "contains", "startswith", "endswith", "re":
			if op != "equals" {
				c.gap("modifier", lm, "selection %s: field %q combines several match modifiers", sel, key)
				bad = true
			}
			op = lm
		case "all":
			all = true
		case "cased":
			cased = true
		case "windash", "base64", "base64offset":
			xf = append(xf, lm)
		default:
			c.gap("modifier", lm, "selection %s: modifier %q (in %q) is not supported (supported: contains, startswith, endswith, re, all, cased, windash, base64, base64offset)", sel, m, key)
			bad = true
		}
	}
	if len(xf) > 1 {
		c.gap("modifier", strings.Join(xf, "|"), "selection %s: field %q combines %s, which is not supported", sel, key, strings.Join(xf, " and "))
		bad = true
	}
	if op == "re" && len(xf) > 0 {
		c.gap("modifier", xf[0], "selection %s: |re cannot be combined with |%s", sel, xf[0])
		bad = true
	}
	if bad {
		return nil
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
	kop := map[string]string{"equals": "equals", "contains": "contains", "startswith": "prefix", "endswith": "suffix", "re": "regex"}[op]
	var perValue [][]sigmaAlt
	for _, x := range raw {
		s, okv := sigmaScalar(x)
		if !okv {
			c.gap("value", parts[0], "selection %s: field %q has a null, empty or non-scalar value", sel, key)
			return nil
		}
		var alts []sigmaAlt
		switch {
		case op == "re":
			if err := sigmaCheckRegex(s); err != nil {
				c.gap("regex", s, "selection %s: field %q regex %q rejected: %v", sel, key, truncateStr(s, 60), err)
				return nil
			}
			alts = []sigmaAlt{{"regex", s}}
		default:
			toks := sigmaWildTokens(s)
			if sigmaHasWild(toks) {
				if op != "equals" || len(xf) > 0 {
					c.gap("value", parts[0], "selection %s: wildcard in value %q combined with |%s is not supported (escape literal * and ? with a backslash)", sel, truncateStr(s, 60), strings.Join(parts[1:], "|"))
					return nil
				}
				a, okw := sigmaWildAlt(toks)
				if !okw {
					c.gap("value", parts[0], "selection %s: value %q matches everything and is not converted", sel, s)
					return nil
				}
				if a.op == "regex" {
					if err := sigmaCheckRegex(a.pat); err != nil {
						c.gap("regex", s, "selection %s: wildcard value %q becomes a regex that was rejected: %v", sel, truncateStr(s, 60), err)
						return nil
					}
				}
				alts = []sigmaAlt{a}
				break
			}
			lit := sigmaLiteral(toks)
			vals := []string{lit}
			aop := kop
			if len(xf) == 1 {
				switch xf[0] {
				case "windash":
					vals = sigmaWindash(lit)
				case "base64":
					vals = []string{base64.StdEncoding.EncodeToString([]byte(lit))}
				case "base64offset":
					vals = sigmaBase64Offset(lit)
					aop = "contains"
				}
			}
			for _, v := range vals {
				alts = append(alts, sigmaAlt{aop, v})
			}
		}
		perValue = append(perValue, alts)
	}
	leaf := func(a sigmaAlt) ContentMatch {
		return ContentMatch{Field: field, Op: a.op, Pattern: a.pat, CaseSensitive: cased}
	}
	if !all {
		var flat []sigmaAlt
		same := true
		for _, alts := range perValue {
			for _, a := range alts {
				flat = append(flat, a)
				if a.op != flat[0].op {
					same = false
				}
			}
		}
		if len(flat) > sigmaMaxVariants {
			c.gap("modifier", key, "selection %s: field %q expands to %d values (limit %d)", sel, key, len(flat), sigmaMaxVariants)
			return nil
		}
		if len(flat) == 1 {
			n := leaf(flat[0])
			return &n
		}
		if same {
			pats := make([]string, len(flat))
			for i, a := range flat {
				pats[i] = a.pat
			}
			return &ContentMatch{Field: field, Op: flat[0].op, Patterns: pats, CaseSensitive: cased}
		}
		nodes := make([]ContentMatch, len(flat))
		for i, a := range flat {
			nodes[i] = leaf(a)
		}
		return &ContentMatch{Any: nodes}
	}
	var nodes []ContentMatch
	for _, alts := range perValue {
		if len(alts) == 1 {
			nodes = append(nodes, leaf(alts[0]))
			continue
		}
		sub := make([]ContentMatch, len(alts))
		for i, a := range alts {
			sub[i] = leaf(a)
		}
		nodes = append(nodes, ContentMatch{Any: sub})
	}
	return sigmaJoin("all", nodes)
}

func (c *sigmaCond) mapped() string {
	var names []string
	for k := range c.fields {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func sigmaDedupGaps(g []sigmaGap) []sigmaGap {
	seen := map[string]bool{}
	var out []sigmaGap
	for _, x := range g {
		k := x.Kind + "\x00" + x.Name + "\x00" + x.Detail
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}

// ---- sample derivation ----

// sigmaAttachTests keeps the rule's own `tests:` when present. Otherwise it derives positive and
// negative samples from the match tree where that is possible (verified against the compiled rule);
// when it is not, the rule is flagged Unverified and the importer starts it in the "testing" lifecycle.
func sigmaAttachTests(res *sigmaResult, r *ContentRule) {
	if r.Tests != nil {
		res.Samples = "provided"
		return
	}
	if t := sigmaDeriveSamples(r); t != nil {
		r.Tests, res.Samples = t, "derived"
		return
	}
	r.Unverified, res.Samples = true, "none"
}

func sigmaSetField(ev *LabEvent, f, v string) {
	switch f {
	case "executable":
		ev.Executable = v
	case "command":
		ev.Command = v
	case "parent_exe":
		ev.ParentExe = v
	case "path":
		ev.Path = v
	case "destination":
		ev.Destination = v
	case "operation":
		ev.Operation = v
	case "host":
		ev.Host = v
	default:
		if ev.Attrs == nil {
			ev.Attrs = map[string]string{}
		}
		ev.Attrs[f] = v
	}
}

func sigmaEvent(m map[string]string) LabEvent {
	var ev LabEvent
	for f, v := range m {
		sigmaSetField(&ev, f, v)
	}
	return ev
}

const sigmaSynthCap = 6

// sigmaLeafValue builds a string a leaf accepts; ok is false when it cannot (complex regex).
func sigmaLeafValue(op, pat string) (string, bool) {
	switch op {
	case "equals", "contains":
		return pat, true
	case "prefix":
		return pat + " x", true
	case "suffix":
		return "x " + pat, true
	case "regex":
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			return "", false
		}
		return sigmaRegexGen(re.Simplify(), 0)
	}
	return "", false
}

func sigmaRegexGen(re *syntax.Regexp, depth int) (string, bool) {
	if depth > 20 {
		return "", false
	}
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune), true
	case syntax.OpEmptyMatch, syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return "", true
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return "a", true
	case syntax.OpCharClass:
		if len(re.Rune) >= 2 {
			return string(re.Rune[0]), true
		}
		return "", false
	case syntax.OpCapture:
		return sigmaRegexGen(re.Sub[0], depth+1)
	case syntax.OpStar, syntax.OpQuest:
		return "", true
	case syntax.OpPlus:
		return sigmaRegexGen(re.Sub[0], depth+1)
	case syntax.OpRepeat:
		s, ok := sigmaRegexGen(re.Sub[0], depth+1)
		return strings.Repeat(s, re.Min), ok
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if s, ok := sigmaRegexGen(sub, depth+1); ok {
				return s, true
			}
		}
		return "", false
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			s, ok := sigmaRegexGen(sub, depth+1)
			if !ok {
				return "", false
			}
			b.WriteString(s)
		}
		return b.String(), true
	}
	return "", false
}

// sigmaSynth returns candidate field assignments that try to satisfy the node. "not" contributes an
// empty assignment (it is satisfied by absence); the final verification catches the cases where it is not.
func sigmaSynth(n *ContentMatch) []map[string]string {
	switch {
	case len(n.All) > 0:
		cur := []map[string]string{{}}
		for i := range n.All {
			sub := sigmaSynth(&n.All[i])
			if len(sub) == 0 {
				return nil
			}
			var next []map[string]string
			for _, a := range cur {
				for _, b := range sub {
					m := map[string]string{}
					for k, v := range a {
						m[k] = v
					}
					for k, v := range b {
						if old, ok := m[k]; ok && old != v {
							m[k] = old + " " + v
						} else {
							m[k] = v
						}
					}
					next = append(next, m)
					if len(next) >= sigmaSynthCap {
						break
					}
				}
				if len(next) >= sigmaSynthCap {
					break
				}
			}
			cur = next
		}
		return cur
	case len(n.Any) > 0:
		var out []map[string]string
		for i := range n.Any {
			out = append(out, sigmaSynth(&n.Any[i])...)
			if len(out) >= sigmaSynthCap {
				break
			}
		}
		return out
	case n.Not != nil:
		return []map[string]string{{}}
	}
	pat := n.Pattern
	if len(n.Patterns) > 0 {
		pat = n.Patterns[0]
	}
	v, ok := sigmaLeafValue(n.Op, pat)
	if !ok {
		return nil
	}
	return []map[string]string{{n.Field: v}}
}

// sigmaDeriveSamples returns verified samples or nil. Positives come from the match tree; negatives
// are near-misses (one constrained field replaced) plus a fully unrelated event.
func sigmaDeriveSamples(r *ContentRule) *ContentTests {
	probe := *r
	probe.Tests, probe.Unverified, probe.allowUnverified = nil, true, true
	if probe.validateAndCompile() != nil {
		return nil
	}
	var pos []LabEvent
	var posMaps []map[string]string
	for _, m := range sigmaSynth(&r.Match) {
		if len(m) == 0 {
			continue
		}
		ev := sigmaEvent(m)
		ev.Kind = r.EventType
		if probe.Matches(ev) {
			pos = append(pos, ev)
			posMaps = append(posMaps, m)
		}
		if len(pos) == 3 {
			break
		}
	}
	if len(pos) == 0 {
		return nil
	}
	var neg []LabEvent
	add := func(ev LabEvent) {
		ev.Kind = r.EventType
		if len(neg) < 3 && !probe.Matches(ev) {
			neg = append(neg, ev)
		}
	}
	for _, m := range posMaps {
		fields := make([]string, 0, len(m))
		for f := range m {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		if len(fields) > 1 {
			for _, f := range fields {
				mm := map[string]string{}
				for k, v := range m {
					mm[k] = v
				}
				mm[f] = "unrelated-" + f
				add(sigmaEvent(mm))
			}
		}
		un := map[string]string{}
		for _, f := range fields {
			un[f] = "unrelated-" + f
		}
		add(sigmaEvent(un))
	}
	if len(neg) == 0 {
		return nil
	}
	for i := range pos {
		pos[i].Kind = ""
	}
	for i := range neg {
		neg[i].Kind = ""
	}
	return &ContentTests{Positive: pos, Negative: neg}
}
