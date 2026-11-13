// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

// Literal prefilter for content rules. At load time each rule is reduced to a conjunction of
// clauses; a clause is a short list of alternatives and is satisfied when ANY alternative's literal
// occurs in the named event field. If a clause is unsatisfied the rule cannot match, so its full
// evaluation (regexes included) is skipped. The prefilter is a pure necessary condition derived
// from the match tree, so results are identical to unfiltered evaluation; it only ever says "this
// rule certainly does not match". Anything not provably required (not, star, classes, ...) simply
// contributes no clause.

const (
	preExact      uint8 = iota // literal must occur byte-for-byte in the (truncated) field
	preLower                   // literal is pre-lowercased; searched in strings.ToLower(field) (the matcher's own case-insensitive form)
	preFoldASCII               // case-folded regex literal (ASCII only); searched in the lowered field, skipped (treated as satisfied) for non-ASCII fields
	preMaxAlts    = 16         // a clause with more alternatives is not worth checking
	preMaxClauses = 6          // keep the most selective clauses per rule
	preMinRegexLn = 2          // shorter regex literals are not selective enough
)

type preAlt struct {
	field string
	lit   string
	mode  uint8
}

type preClause []preAlt

// ---- extraction ----

// preSelect keeps the cheapest, most selective clauses.
func preSelect(cl []preClause) []preClause {
	sort.SliceStable(cl, func(i, j int) bool {
		if len(cl[i]) != len(cl[j]) {
			return len(cl[i]) < len(cl[j])
		}
		return preMinLen(cl[i]) > preMinLen(cl[j])
	})
	if len(cl) > preMaxClauses {
		cl = cl[:preMaxClauses]
	}
	return cl
}

func preMinLen(c preClause) int {
	m := 1 << 30
	for _, a := range c {
		if len(a.lit) < m {
			m = len(a.lit)
		}
	}
	return m
}

// preAnyOf combines the clause lists of alternatives (any / regex alternation): when every branch
// requires something, the union of one required clause per branch is required.
func preAnyOf(branches [][]preClause) []preClause {
	if len(branches) == 0 {
		return nil
	}
	var merged preClause
	for _, b := range branches {
		if len(b) == 0 {
			return nil
		}
		best := b[0]
		for _, c := range b[1:] {
			if len(c) < len(best) || (len(c) == len(best) && preMinLen(c) > preMinLen(best)) {
				best = c
			}
		}
		merged = append(merged, best...)
		if len(merged) > preMaxAlts {
			return nil
		}
	}
	return []preClause{merged}
}

func preExtract(n *LabNode) []preClause {
	switch {
	case len(n.All) > 0:
		var out []preClause
		for i := range n.All {
			out = append(out, preExtract(&n.All[i])...)
		}
		return out
	case len(n.Any) > 0:
		br := make([][]preClause, 0, len(n.Any))
		for i := range n.Any {
			br = append(br, preExtract(&n.Any[i]))
		}
		return preAnyOf(br)
	case n.Not != nil:
		return nil
	}
	lowerMode := preExact
	if !n.CaseSensitive {
		lowerMode = preLower
	}
	lit := func(s string) string {
		if !n.CaseSensitive {
			return strings.ToLower(s)
		}
		return s
	}
	switch n.Op {
	case "equals", "contains", "startswith", "endswith":
		if n.Value == "" {
			return nil
		}
		return []preClause{{{field: n.Field, lit: lit(n.Value), mode: lowerMode}}}
	case "in":
		if len(n.Values) == 0 || len(n.Values) > preMaxAlts {
			return nil
		}
		c := make(preClause, 0, len(n.Values))
		for _, v := range n.Values {
			if v == "" {
				return nil
			}
			c = append(c, preAlt{field: n.Field, lit: lit(v), mode: lowerMode})
		}
		return []preClause{c}
	case "regex":
		p := n.Value
		if !n.CaseSensitive {
			p = "(?i)" + p
		}
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			return nil
		}
		return preRegex(n.Field, re)
	}
	return nil
}

func preRegex(field string, re *syntax.Regexp) []preClause {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if len(s) < preMinRegexLn || strings.ContainsRune(s, utf8.RuneError) {
			return nil
		}
		if re.Flags&syntax.FoldCase != 0 {
			for _, r := range re.Rune {
				if r >= utf8.RuneSelf {
					return nil
				}
			}
			return []preClause{{{field: field, lit: strings.ToLower(s), mode: preFoldASCII}}}
		}
		return []preClause{{{field: field, lit: s, mode: preExact}}}
	case syntax.OpCapture, syntax.OpPlus:
		return preRegex(field, re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return preRegex(field, re.Sub[0])
		}
	case syntax.OpConcat:
		var out []preClause
		for _, s := range re.Sub {
			out = append(out, preRegex(field, s)...)
		}
		return out
	case syntax.OpAlternate:
		br := make([][]preClause, 0, len(re.Sub))
		for _, s := range re.Sub {
			br = append(br, preRegex(field, s))
		}
		return preAnyOf(br)
	}
	return nil
}

// buildPrefilter returns the rule's required-literal clauses (nil when nothing is provably required).
func buildPrefilter(n *LabNode) []preClause {
	cl := preExtract(n)
	if len(cl) == 0 {
		return nil
	}
	return preSelect(cl)
}

// ---- per-event evaluation context ----

type fieldVal struct {
	name     string
	present  bool
	orig     string // truncated exactly as the matcher truncates
	lower    string
	lowered  bool
	asciiSet bool
	ascii    bool
}

// evalCtx caches per-event field lookups and their lowercase form so a field is lowered once
// no matter how many rules inspect it.
type evalCtx struct {
	ev     LabEvent
	fields []fieldVal
}

func newEvalCtx(ev LabEvent) *evalCtx { return &evalCtx{ev: ev, fields: make([]fieldVal, 0, 4)} }

func (c *evalCtx) get(name string) *fieldVal {
	for i := range c.fields {
		if c.fields[i].name == name {
			return &c.fields[i]
		}
	}
	v, ok := c.ev.field(name)
	if ok && len(v) > labMaxInputLen {
		v = v[:labMaxInputLen]
	}
	c.fields = append(c.fields, fieldVal{name: name, present: ok, orig: v})
	return &c.fields[len(c.fields)-1]
}

func (f *fieldVal) lowerStr() string {
	if !f.lowered {
		f.lower, f.lowered = strings.ToLower(f.orig), true
	}
	return f.lower
}

func (f *fieldVal) isASCII() bool {
	if !f.asciiSet {
		f.ascii, f.asciiSet = true, true
		for i := 0; i < len(f.orig); i++ {
			if f.orig[i] >= utf8.RuneSelf {
				f.ascii = false
				break
			}
		}
	}
	return f.ascii
}

// prefilterPasses reports whether every required clause may be satisfied (true = run full evaluation).
func prefilterPasses(pre []preClause, c *evalCtx) bool {
	for _, cl := range pre {
		ok := false
		for _, a := range cl {
			f := c.get(a.field)
			if !f.present {
				continue
			}
			switch a.mode {
			case preExact:
				ok = strings.Contains(f.orig, a.lit)
			case preLower:
				ok = strings.Contains(f.lowerStr(), a.lit)
			default: // preFoldASCII
				ok = !f.isASCII() || strings.Contains(f.lowerStr(), a.lit)
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchCtx evaluates the rule against a prepared event context, optionally using the prefilter.
func (r *ContentRule) matchCtx(c *evalCtx, usePrefilter bool) bool {
	if r.node == nil {
		return false
	}
	if usePrefilter && len(r.pre) > 0 && !prefilterPasses(r.pre, c) {
		return false
	}
	m, _ := r.node.eval(c.ev, false)
	return m
}
