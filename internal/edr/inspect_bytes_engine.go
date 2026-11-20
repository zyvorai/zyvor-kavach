// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Byte-pattern rule engine for the artifact inspector (kinds file and script).
//
// A rule names a few byte patterns (ascii, wide, hex with ?? wildcards, RE2
// regex) and a small condition tree over those names. Matching is linear and
// bounded: literals use bytes.Index, regexes use Go's RE2 (no backtracking),
// scanned bytes are capped per input, occurrences are capped per pattern and
// rule/pattern counts are capped at load. The engine only reads the bytes it is
// given. Observation only.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

const (
	byteMaxRules        = 1000
	byteMaxPatterns     = 16
	byteMaxLiteralLen   = 512
	byteMaxRegexLen     = 256
	byteMaxOccurrences  = 64   // cap on counted occurrences per pattern
	byteMaxHexCandidate = 4096 // anchor hits verified per hex pattern
	byteMaxCondDepth    = 8
	byteMaxCondNodes    = 64
	byteMaxSampleBytes  = 256 << 10
	byteLiteralHead     = 3 << 20 // literal scan window: head + tail
	byteLiteralTail     = 1 << 20
	byteRegexHead       = 512 << 10 // regex scan window: head + tail
	byteRegexTail       = 128 << 10
)

var (
	byteIDRe       = regexp.MustCompile(`^byte-[a-z0-9]+(-[a-z0-9]+)*$`)
	byteNameRe     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	byteSeverities = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	byteFormats    = map[string]bool{"pe": true, "elf": true, "macho": true, "script": true, "any": true}
	byteApplies    = map[string]bool{"file": true, "script": true, "both": true}
)

// ByteOffset restricts where a pattern may start (inclusive bounds).
type ByteOffset struct {
	Min *int64 `json:"min,omitempty"`
	Max *int64 `json:"max,omitempty"`
}

// BytePattern is one named pattern. Type: ascii | wide | hex | regex.
type BytePattern struct {
	Name   string      `json:"name"`
	Type   string      `json:"type"`
	Value  string      `json:"value"`
	Nocase bool        `json:"nocase,omitempty"`
	Offset *ByteOffset `json:"offset,omitempty"`
	Min    int         `json:"min,omitempty"` // required occurrences (default 1, max 64)

	lit    []byte // ascii/wide: needle (lower-cased when nocase)
	hexTok []int16
	anchor int // start index of the longest literal run in hexTok
	anchLn int
	re     *regexp.Regexp
	reLit  [][]byte // a match must contain one of these (prefilter); lower-cased when reFold
	reFold bool
}

// ByteCond is the condition tree: exactly one member per node.
type ByteCond struct {
	All []ByteCond `json:"all,omitempty"`
	Any []ByteCond `json:"any,omitempty"`
	NOf *ByteNOf   `json:"n_of,omitempty"`
	Not *ByteCond  `json:"not,omitempty"`
	Str string     `json:"str,omitempty"`
}

// ByteNOf is true when at least Count of the named strings matched.
type ByteNOf struct {
	Count int      `json:"count"`
	Of    []string `json:"of"`
}

// ByteSample is a fixture: literal text or base64 bytes.
type ByteSample struct {
	Text string `json:"text,omitempty"`
	B64  string `json:"b64,omitempty"`
}

func (s ByteSample) bytes() ([]byte, error) {
	if (s.Text == "") == (s.B64 == "") {
		return nil, fmt.Errorf("sample needs exactly one of text or b64")
	}
	if s.Text != "" {
		return []byte(s.Text), nil
	}
	return base64.StdEncoding.DecodeString(s.B64)
}

// ByteSamples are positive (must match) and negative (must not match) fixtures.
type ByteSamples struct {
	Positive []ByteSample `json:"positive"`
	Negative []ByteSample `json:"negative"`
}

// ByteRule is one byte-pattern rule.
type ByteRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Tactic      string        `json:"tactic"`
	Technique   string        `json:"technique"`
	Severity    string        `json:"severity"`
	Weight      int           `json:"weight"`
	AppliesTo   string        `json:"applies_to"`
	Format      string        `json:"format"`
	Tags        []string      `json:"tags,omitempty"`
	Strings     []BytePattern `json:"strings"`
	Condition   ByteCond      `json:"condition"`
	MinSize     int64         `json:"min_size,omitempty"`
	MaxSize     int64         `json:"max_size,omitempty"`
	Magic       string        `json:"magic,omitempty"` // hex prefix the file must start with
	Samples     ByteSamples   `json:"samples"`

	magic  []byte
	byName map[string]*BytePattern
}

// Noisy reports whether the rule carries the noisy-risk tag.
func (r *ByteRule) Noisy() bool {
	for _, t := range r.Tags {
		if t == "noisy-risk" {
			return true
		}
	}
	return false
}

// ---- compile ----

func (p *BytePattern) compile() error {
	if !byteNameRe.MatchString(p.Name) {
		return fmt.Errorf("pattern name %q must match %s", p.Name, byteNameRe)
	}
	if p.Min < 0 || p.Min > byteMaxOccurrences {
		return fmt.Errorf("pattern %s: min must be 0..%d", p.Name, byteMaxOccurrences)
	}
	if p.Offset != nil {
		o := p.Offset
		if (o.Min != nil && *o.Min < 0) || (o.Max != nil && *o.Max < 0) || (o.Min != nil && o.Max != nil && *o.Min > *o.Max) {
			return fmt.Errorf("pattern %s: invalid offset range", p.Name)
		}
	}
	switch p.Type {
	case "ascii", "wide":
		if len(p.Value) < 2 || len(p.Value) > byteMaxLiteralLen {
			return fmt.Errorf("pattern %s: %s value must be 2..%d bytes", p.Name, p.Type, byteMaxLiteralLen)
		}
		v := []byte(p.Value)
		if p.Nocase {
			v = asciiLower(v)
		}
		if p.Type == "wide" {
			w := make([]byte, 0, len(v)*2)
			for _, c := range v {
				w = append(w, c, 0)
			}
			v = w
		}
		p.lit = v
	case "hex":
		if p.Nocase {
			return fmt.Errorf("pattern %s: nocase is not valid for hex", p.Name)
		}
		s := strings.Join(strings.Fields(p.Value), "")
		if len(s) == 0 || len(s)%2 != 0 || len(s) > 2*byteMaxLiteralLen {
			return fmt.Errorf("pattern %s: hex must be an even number of digits (max %d bytes)", p.Name, byteMaxLiteralLen)
		}
		tok := make([]int16, 0, len(s)/2)
		for i := 0; i < len(s); i += 2 {
			pair := s[i : i+2]
			if pair == "??" {
				tok = append(tok, -1)
				continue
			}
			b, err := hex.DecodeString(pair)
			if err != nil {
				return fmt.Errorf("pattern %s: bad hex byte %q", p.Name, pair)
			}
			tok = append(tok, int16(b[0]))
		}
		best, bestLen, cur, curStart := 0, 0, 0, 0
		for i, t := range tok {
			if t < 0 {
				cur = 0
				continue
			}
			if cur == 0 {
				curStart = i
			}
			cur++
			if cur > bestLen {
				bestLen, best = cur, curStart
			}
		}
		if bestLen < 3 {
			return fmt.Errorf("pattern %s: hex needs a literal run of at least 3 bytes (too broad)", p.Name)
		}
		p.hexTok, p.anchor, p.anchLn = tok, best, bestLen
	case "regex":
		if len(p.Value) < 4 || len(p.Value) > byteMaxRegexLen {
			return fmt.Errorf("pattern %s: regex length must be 4..%d", p.Name, byteMaxRegexLen)
		}
		expr := p.Value
		if p.Nocase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("pattern %s: regex: %v", p.Name, err)
		}
		if re.Match(nil) {
			return fmt.Errorf("pattern %s: regex matches the empty input", p.Name)
		}
		p.re = re
		if t, err := syntax.Parse(expr, syntax.Perl); err == nil {
			ls := requiredLiterals(t.Simplify())
			if ls.minLen() >= 3 {
				if ls.fold {
					for i := range ls.alts {
						ls.alts[i] = bytes.ToLower(ls.alts[i])
					}
				}
				p.reLit, p.reFold = ls.alts, ls.fold
			}
		}
	default:
		return fmt.Errorf("pattern %s: unknown type %q (ascii|wide|hex|regex)", p.Name, p.Type)
	}
	return nil
}

// litSet is a set of literals of which every match of a regex must contain at
// least one; fold marks case-insensitive literals.
type litSet struct {
	alts [][]byte
	fold bool
}

func (l litSet) minLen() int {
	if len(l.alts) == 0 {
		return 0
	}
	m := len(l.alts[0])
	for _, a := range l.alts[1:] {
		if len(a) < m {
			m = len(a)
		}
	}
	return m
}

// better prefers the longer shortest-literal, then fewer alternatives.
func (l litSet) better(o litSet) bool {
	if l.minLen() != o.minLen() {
		return l.minLen() > o.minLen()
	}
	return len(l.alts) < len(o.alts)
}

// requiredLiterals derives a must-contain-one-of literal set for t (nil if none
// can be proven). It is only a prefilter: a miss means the regex cannot match,
// a hit still runs the regex.
func requiredLiterals(t *syntax.Regexp) litSet {
	switch t.Op {
	case syntax.OpLiteral:
		return litSet{alts: [][]byte{[]byte(string(t.Rune))}, fold: t.Flags&syntax.FoldCase != 0}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(t.Sub[0])
	case syntax.OpRepeat:
		if t.Min >= 1 {
			return requiredLiterals(t.Sub[0])
		}
	case syntax.OpAlternate:
		var out litSet
		for _, sub := range t.Sub {
			l := requiredLiterals(sub)
			if len(l.alts) == 0 {
				return litSet{}
			}
			out.alts = append(out.alts, l.alts...)
			out.fold = out.fold || l.fold
		}
		if len(out.alts) > 16 {
			return litSet{}
		}
		return out
	case syntax.OpConcat:
		var best litSet
		var run []rune
		runFold := false
		flush := func() {
			if len(run) > 0 {
				c := litSet{alts: [][]byte{[]byte(string(run))}, fold: runFold}
				if c.better(best) {
					best = c
				}
			}
			run = nil
		}
		for _, sub := range t.Sub {
			if sub.Op == syntax.OpLiteral {
				f := sub.Flags&syntax.FoldCase != 0
				if len(run) > 0 && f != runFold {
					flush()
				}
				run, runFold = append(run, sub.Rune...), f
				continue
			}
			flush()
			if c := requiredLiterals(sub); len(c.alts) > 0 && c.better(best) {
				best = c
			}
		}
		flush()
		return best
	}
	return litSet{}
}

func (c *ByteCond) validate(names map[string]bool, used map[string]bool, depth int, nodes *int) error {
	*nodes++
	if depth > byteMaxCondDepth || *nodes > byteMaxCondNodes {
		return fmt.Errorf("condition too deep or too large (depth %d, nodes %d)", byteMaxCondDepth, byteMaxCondNodes)
	}
	k := 0
	if len(c.All) > 0 {
		k++
	}
	if len(c.Any) > 0 {
		k++
	}
	if c.NOf != nil {
		k++
	}
	if c.Not != nil {
		k++
	}
	if c.Str != "" {
		k++
	}
	if k != 1 {
		return fmt.Errorf("condition node must have exactly one of all|any|n_of|not|str")
	}
	for i := range c.All {
		if err := c.All[i].validate(names, used, depth+1, nodes); err != nil {
			return err
		}
	}
	for i := range c.Any {
		if err := c.Any[i].validate(names, used, depth+1, nodes); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.validate(names, used, depth+1, nodes)
	}
	if c.Str != "" {
		if !names[c.Str] {
			return fmt.Errorf("condition references unknown string %q", c.Str)
		}
		used[c.Str] = true
	}
	if c.NOf != nil {
		if c.NOf.Count < 1 || c.NOf.Count > len(c.NOf.Of) {
			return fmt.Errorf("n_of count %d out of range for %d names", c.NOf.Count, len(c.NOf.Of))
		}
		for _, n := range c.NOf.Of {
			if !names[n] {
				return fmt.Errorf("n_of references unknown string %q", n)
			}
			used[n] = true
		}
	}
	return nil
}

// compile validates the structural parts of a rule and prepares its matchers.
func (r *ByteRule) compile() error {
	fail := func(f string, a ...any) error { return fmt.Errorf("rule %q: %s", r.ID, fmt.Sprintf(f, a...)) }
	if !byteIDRe.MatchString(r.ID) || len(r.ID) > 64 {
		return fail("id must be kebab-case starting with byte- (max 64)")
	}
	if r.Name == "" || len(r.Name) > 120 {
		return fail("name required, max 120 chars")
	}
	if r.Description == "" || len(r.Description) > 1000 {
		return fail("description required, max 1000 chars")
	}
	if r.Tactic == "" || len(r.Tactic) > 40 {
		return fail("tactic required")
	}
	if !labTechRe.MatchString(r.Technique) {
		return fail("technique %q is not an ATT&CK id like T1059 or T1059.004", r.Technique)
	}
	if _, ok := byteSeverities[r.Severity]; !ok {
		return fail("severity must be low|medium|high|critical")
	}
	if r.Weight < 1 || r.Weight > 100 {
		return fail("weight must be 1..100")
	}
	if !byteApplies[r.AppliesTo] {
		return fail("applies_to must be file|script|both")
	}
	if !byteFormats[r.Format] {
		return fail("format must be pe|elf|macho|script|any")
	}
	if (r.Format == "pe" || r.Format == "elf" || r.Format == "macho") && r.AppliesTo != "file" {
		return fail("format %s requires applies_to file", r.Format)
	}
	if len(r.Tags) > 16 {
		return fail("max 16 tags")
	}
	if len(r.Strings) == 0 || len(r.Strings) > byteMaxPatterns {
		return fail("1..%d strings required", byteMaxPatterns)
	}
	if r.MinSize < 0 || r.MaxSize < 0 || (r.MaxSize > 0 && r.MinSize > r.MaxSize) {
		return fail("invalid size bounds")
	}
	if r.Magic != "" {
		m, err := hex.DecodeString(r.Magic)
		if err != nil || len(m) == 0 || len(m) > 16 {
			return fail("magic must be 1..16 bytes of hex")
		}
		r.magic = m
	}
	r.byName = map[string]*BytePattern{}
	names := map[string]bool{}
	for i := range r.Strings {
		p := &r.Strings[i]
		if err := p.compile(); err != nil {
			return fail("%v", err)
		}
		if names[p.Name] {
			return fail("duplicate string name %q", p.Name)
		}
		names[p.Name] = true
		r.byName[p.Name] = p
	}
	used := map[string]bool{}
	nodes := 0
	if err := r.Condition.validate(names, used, 1, &nodes); err != nil {
		return fail("%v", err)
	}
	for n := range names {
		if !used[n] {
			return fail("string %q is defined but not used in the condition", n)
		}
	}
	return nil
}

// ---- matching ----

type byteSeg struct {
	base  int64
	data  []byte
	lower []byte // lazily built ASCII-lowered copy
}

func (s *byteSeg) lowered() []byte {
	if s.lower == nil {
		s.lower = asciiLower(s.data)
	}
	return s.lower
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

// byteScan is the per-input scan state shared by every rule: bounded windows
// and lazily built lower-case copies.
type byteScan struct {
	data      []byte
	lit       []*byteSeg
	rx        []*byteSeg
	truncated bool
	format    string
	kind      string
}

func makeSegs(data []byte, head, tail int) []*byteSeg {
	if len(data) <= head+tail {
		return []*byteSeg{{base: 0, data: data}}
	}
	return []*byteSeg{
		{base: 0, data: data[:head]},
		{base: int64(len(data) - tail), data: data[len(data)-tail:]},
	}
}

func newByteScan(kind string, data []byte) *byteScan {
	s := &byteScan{data: data, kind: kind}
	s.lit = makeSegs(data, byteLiteralHead, byteLiteralTail)
	s.rx = makeSegs(data, byteRegexHead, byteRegexTail)
	s.truncated = len(data) > byteLiteralHead+byteLiteralTail
	s.format = detectByteFormat(kind, data)
	return s
}

// detectByteFormat names the container: pe, elf, macho, script (text) or "".
func detectByteFormat(kind string, data []byte) string {
	if kind == InspectKindScript {
		return "script"
	}
	if len(data) >= 0x40 && data[0] == 'M' && data[1] == 'Z' {
		off := int(data[0x3c]) | int(data[0x3d])<<8 | int(data[0x3e])<<16 | int(data[0x3f])<<24
		if off >= 0 && off+4 <= len(data) && bytes.Equal(data[off:off+4], []byte("PE\x00\x00")) {
			return "pe"
		}
	}
	if len(data) >= 4 {
		m := string(data[:4])
		if m == "\x7fELF" {
			return "elf"
		}
		for _, mm := range []string{"\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe"} {
			if m == mm {
				return "macho"
			}
		}
	}
	n := len(data)
	if n > 1024 {
		n = 1024
	}
	if n == 0 || bytes.IndexByte(data[:n], 0) >= 0 {
		return ""
	}
	return "script"
}

// clipSeg narrows a buffer to a pattern's offset window; ok=false when empty.
func clipSeg(seg *byteSeg, buf []byte, o *ByteOffset, slack int) (view []byte, shift int64, ok bool) {
	lo, hi := int64(0), int64(len(buf))
	if o != nil {
		if o.Min != nil && *o.Min-seg.base > lo {
			lo = *o.Min - seg.base
		}
		if o.Max != nil && *o.Max-seg.base+int64(slack) < hi {
			hi = *o.Max - seg.base + int64(slack)
		}
	}
	if lo >= hi || lo >= int64(len(buf)) {
		return nil, 0, false
	}
	return buf[lo:hi], lo, true
}

func inOffset(o *ByteOffset, abs int64) bool {
	if o == nil {
		return true
	}
	return (o.Min == nil || abs >= *o.Min) && (o.Max == nil || abs <= *o.Max)
}

// count returns occurrences (capped at need / byteMaxOccurrences) and the first
// absolute offset (-1 if none).
func (p *BytePattern) count(s *byteScan, need int) (int, int64) {
	if need < 1 {
		need = 1
	}
	first := int64(-1)
	total := 0
	add := func(abs int64) bool {
		if first < 0 {
			first = abs
		}
		total++
		return total >= need || total >= byteMaxOccurrences
	}
	switch p.Type {
	case "ascii", "wide":
		for _, seg := range s.lit {
			buf := seg.data
			if p.Nocase {
				buf = seg.lowered()
			}
			view, shift, ok := clipSeg(seg, buf, p.Offset, len(p.lit))
			if !ok {
				continue
			}
			pos := 0
			for pos <= len(view)-len(p.lit) {
				i := bytes.Index(view[pos:], p.lit)
				if i < 0 {
					break
				}
				abs := seg.base + shift + int64(pos+i)
				if inOffset(p.Offset, abs) && add(abs) {
					return total, first
				}
				pos += i + 1
			}
		}
	case "hex":
		anchor := make([]byte, p.anchLn)
		for i := range anchor {
			anchor[i] = byte(p.hexTok[p.anchor+i])
		}
		cands := 0
		for _, seg := range s.lit {
			view, shift, ok := clipSeg(seg, seg.data, p.Offset, len(p.hexTok))
			if !ok {
				continue
			}
			pos := 0
			for pos < len(view) {
				i := bytes.Index(view[pos:], anchor)
				if i < 0 {
					break
				}
				cands++
				if cands > byteMaxHexCandidate {
					return total, first
				}
				start := pos + i - p.anchor
				pos += i + 1
				if start < 0 || start+len(p.hexTok) > len(view) {
					continue
				}
				match := true
				for j, t := range p.hexTok {
					if t >= 0 && view[start+j] != byte(t) {
						match = false
						break
					}
				}
				abs := seg.base + shift + int64(start)
				if match && inOffset(p.Offset, abs) && add(abs) {
					return total, first
				}
			}
		}
	case "regex":
		for _, seg := range s.rx {
			view, shift, ok := clipSeg(seg, seg.data, p.Offset, byteMaxRegexLen)
			if !ok {
				continue
			}
			if p.reLit != nil {
				probe := view
				if p.reFold {
					// the lowered copy is index-aligned with seg.data
					probe = seg.lowered()[shift : shift+int64(len(view))]
				}
				found := false
				for _, l := range p.reLit {
					if bytes.Contains(probe, l) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			for _, m := range p.re.FindAllIndex(view, byteMaxOccurrences) {
				abs := seg.base + shift + int64(m[0])
				if inOffset(p.Offset, abs) && add(abs) {
					return total, first
				}
			}
		}
	}
	return total, first
}

type byteEval struct {
	s      *byteScan
	r      *ByteRule
	hit    map[string]bool
	offset map[string]int64
}

func (e *byteEval) strHit(name string) bool {
	if v, ok := e.hit[name]; ok {
		return v
	}
	p := e.r.byName[name]
	need := p.Min
	if need < 1 {
		need = 1
	}
	n, first := p.count(e.s, need)
	v := n >= need
	e.hit[name] = v
	if v {
		e.offset[name] = first
	}
	return v
}

func (e *byteEval) eval(c *ByteCond) bool {
	switch {
	case c.Str != "":
		return e.strHit(c.Str)
	case len(c.All) > 0:
		for i := range c.All {
			if !e.eval(&c.All[i]) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for i := range c.Any {
			if e.eval(&c.Any[i]) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !e.eval(c.Not)
	case c.NOf != nil:
		n := 0
		for _, name := range c.NOf.Of {
			if e.strHit(name) {
				n++
				if n >= c.NOf.Count {
					return true
				}
			}
		}
	}
	return false
}

// ByteHit is one rule match.
type ByteHit struct {
	Rule    *ByteRule
	Matched []string // matched string names, sorted
	Offsets map[string]int64
}

// applicable is the cheap pre-check (kind, format, size, magic).
func (r *ByteRule) applicable(s *byteScan) bool {
	if r.AppliesTo != "both" && r.AppliesTo != s.kind {
		return false
	}
	if r.Format != "any" && r.Format != s.format {
		return false
	}
	n := int64(len(s.data))
	if n < r.MinSize || (r.MaxSize > 0 && n > r.MaxSize) {
		return false
	}
	if len(r.magic) > 0 && !bytes.HasPrefix(s.data, r.magic) {
		return false
	}
	return true
}

func (r *ByteRule) match(s *byteScan) (ByteHit, bool) {
	if !r.applicable(s) {
		return ByteHit{}, false
	}
	e := &byteEval{s: s, r: r, hit: map[string]bool{}, offset: map[string]int64{}}
	if !e.eval(&r.Condition) {
		return ByteHit{}, false
	}
	h := ByteHit{Rule: r, Offsets: e.offset}
	for n, v := range e.hit {
		if v {
			h.Matched = append(h.Matched, n)
		}
	}
	sort.Strings(h.Matched)
	return h, true
}

// ByteRuleSet is an immutable, id-sorted rule set.
type ByteRuleSet struct {
	Rules []*ByteRule
	byID  map[string]*ByteRule
}

// Scan evaluates every rule against data in id order. It returns early (with
// what it has) when ctx is done. truncated reports that the scan windows were
// capped for a large input.
func (set *ByteRuleSet) Scan(ctx context.Context, kind string, data []byte) (hits []ByteHit, truncated bool) {
	s := newByteScan(kind, data)
	for _, r := range set.Rules {
		if ctx.Err() != nil {
			return hits, s.truncated
		}
		if h, ok := r.match(s); ok {
			hits = append(hits, h)
		}
	}
	return hits, s.truncated
}
