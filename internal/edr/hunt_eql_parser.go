// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"regexp"
	"strings"
	"time"
)

// kavach-seq grammar (keywords are case-insensitive, field names lower-case):
//
//	query    := single | sequence
//	single   := cat "where" expr
//	sequence := "sequence" [ "by" key {"," key} ] [ "with" "maxspan" "=" duration ]
//	            step step {step} [ "until" step ]
//	step     := "[" cat "where" expr "]"
//	key      := "host" | "pid"
//	expr     := orx ; orx := andx {"or" andx} ; andx := notx {"and" notx}
//	notx     := "not" notx | primary
//	primary  := "(" expr ")" | "true" | "false" | cmp
//	cmp      := field ("=="|"!="|"<"|"<="|">"|">=") literal
//	          | field ["not"] (":"|"like"|"startswith"|"endswith"|"contains") (string | "(" strings ")")
//	          | field ["not"] "regex" string
//	          | field ["not"] "in" "(" literals ")"
//	cat      := process|network|file|registry|dns|auth|module
//
// "#" starts a comment to end of line.

type seqNode struct {
	Op    string
	Pos   int
	Args  []*seqNode
	Field string
	Strs  []string
	Ints  []int64
	Bools []bool
	Re    *regexp.Regexp
	pred  func(*seqEvent) bool
}

type seqStep struct {
	Cat    string
	CatPos int
	Cond   *seqNode
}

// SeqFieldProblem is a field that is not available for a category.
type SeqFieldProblem struct {
	Pos      int    `json:"pos"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Category string `json:"category"`
	Field    string `json:"field"`
	Reason   string `json:"reason"`
}

type seqQuery struct {
	Text     string
	Kind     string // "single" | "sequence"
	Keys     []string
	MaxSpan  time.Duration
	Steps    []seqStep
	Until    *seqStep
	Problems []SeqFieldProblem
}

type seqParser struct {
	src   string
	toks  []seqTok
	i     int
	q     *seqQuery
	nodes int
	depth int
	cat   *seqCatalog
}

// parseSeq parses a kavach-seq query. Syntax errors are returned as *SeqError;
// unavailable fields are collected in q.Problems (a query with problems must
// not be executed).
func parseSeq(src string) (*seqQuery, *SeqError) {
	toks, err := seqLex(src)
	if err != nil {
		return nil, err
	}
	p := &seqParser{src: src, toks: toks, q: &seqQuery{Text: src}}
	if err := p.parseQuery(); err != nil {
		return nil, err
	}
	return p.q, nil
}

func (p *seqParser) peek() seqTok { return p.toks[p.i] }
func (p *seqParser) next() seqTok {
	t := p.toks[p.i]
	if t.Kind != tEOF {
		p.i++
	}
	return t
}
func (p *seqParser) errAt(t seqTok, f string, a ...any) *SeqError {
	return newSeqErr(p.src, t.Pos, f, a...)
}
func (p *seqParser) isKw(kw string) bool {
	t := p.peek()
	return t.Kind == tIdent && t.Text == kw
}
func (p *seqParser) expectKw(kw string) (seqTok, *SeqError) {
	t := p.peek()
	if t.Kind != tIdent || t.Text != kw {
		return t, p.errAt(t, "expected %q, found %s", kw, describeTok(t))
	}
	return p.next(), nil
}
func (p *seqParser) expect(k seqTokKind) (seqTok, *SeqError) {
	t := p.peek()
	if t.Kind != k {
		return t, p.errAt(t, "expected %s, found %s", k, describeTok(t))
	}
	return p.next(), nil
}
func describeTok(t seqTok) string {
	if t.Kind == tIdent {
		return "'" + t.Text + "'"
	}
	return t.Kind.String()
}

func (p *seqParser) parseQuery() *SeqError {
	t := p.peek()
	if t.Kind == tEOF {
		return p.errAt(t, "empty query")
	}
	if p.isKw("sequence") {
		p.next()
		p.q.Kind = "sequence"
		if err := p.parseSeqHead(); err != nil {
			return err
		}
		for p.peek().Kind == tLBrack {
			if len(p.q.Steps) >= seqMaxSteps {
				return p.errAt(p.peek(), "too many sequence steps (max %d)", seqMaxSteps)
			}
			st, err := p.parseBracketStep()
			if err != nil {
				return err
			}
			p.q.Steps = append(p.q.Steps, *st)
		}
		if len(p.q.Steps) < 2 {
			return p.errAt(p.peek(), "a sequence needs at least 2 steps, found %d", len(p.q.Steps))
		}
		if p.isKw("until") {
			p.next()
			st, err := p.parseBracketStep()
			if err != nil {
				return err
			}
			p.q.Until = st
		}
		if t := p.peek(); t.Kind != tEOF {
			return p.errAt(t, "unexpected %s after sequence", describeTok(t))
		}
		return p.checkKeys()
	}
	p.q.Kind = "single"
	cat, err := p.parseCategory()
	if err != nil {
		return err
	}
	if _, err := p.expectKw("where"); err != nil {
		return err
	}
	cond, err := p.parseExprFor(cat)
	if err != nil {
		return err
	}
	p.q.Steps = []seqStep{{Cat: cat, CatPos: t.Pos, Cond: cond}}
	if t := p.peek(); t.Kind != tEOF {
		return p.errAt(t, "unexpected %s after condition", describeTok(t))
	}
	return nil
}

func (p *seqParser) parseSeqHead() *SeqError {
	if p.isKw("by") {
		p.next()
		for {
			t, err := p.expect(tIdent)
			if err != nil {
				return err
			}
			if t.Text != "host" && t.Text != "pid" {
				return p.errAt(t, "unsupported join key %q (supported: host, pid)", t.Text)
			}
			for _, k := range p.q.Keys {
				if k == t.Text {
					return p.errAt(t, "duplicate join key %q", t.Text)
				}
			}
			p.q.Keys = append(p.q.Keys, t.Text)
			if p.peek().Kind != tComma {
				break
			}
			p.next()
		}
	}
	if p.isKw("with") {
		p.next()
		if _, err := p.expectKw("maxspan"); err != nil {
			return err
		}
		if _, err := p.expect(tAssign); err != nil {
			return err
		}
		d := p.peek()
		if d.Kind != tDuration {
			return p.errAt(d, "expected duration such as 5m, found %s", describeTok(d))
		}
		p.next()
		if d.Dur <= 0 || d.Dur > seqMaxSpan {
			return p.errAt(d, "maxspan must be > 0 and <= %s", seqMaxSpan)
		}
		p.q.MaxSpan = d.Dur
	}
	return nil
}

// checkKeys verifies every step category has the join keys (all of them do in
// the current catalogue; kept explicit so catalogue changes stay safe).
func (p *seqParser) checkKeys() *SeqError {
	for _, st := range append(append([]seqStep(nil), p.q.Steps...), untilSlice(p.q.Until)...) {
		c, _ := seqLookupCat(st.Cat)
		for _, k := range p.q.Keys {
			if f, ok := c.field(k); !ok || !f.Joinable {
				return newSeqErr(p.src, st.CatPos, "category %s cannot join on %q", st.Cat, k)
			}
		}
	}
	return nil
}

func untilSlice(s *seqStep) []seqStep {
	if s == nil {
		return nil
	}
	return []seqStep{*s}
}

func (p *seqParser) parseCategory() (string, *SeqError) {
	t := p.peek()
	if t.Kind != tIdent {
		return "", p.errAt(t, "expected event category, found %s", describeTok(t))
	}
	if _, ok := seqLookupCat(t.Text); !ok {
		return "", p.errAt(t, "unknown category %q (one of %s)", t.Text, strings.Join(SeqCategories, ", "))
	}
	p.next()
	return t.Text, nil
}

func (p *seqParser) parseBracketStep() (*seqStep, *SeqError) {
	if _, err := p.expect(tLBrack); err != nil {
		return nil, err
	}
	ct := p.peek()
	cat, err := p.parseCategory()
	if err != nil {
		return nil, err
	}
	if _, err := p.expectKw("where"); err != nil {
		return nil, err
	}
	cond, err := p.parseExprFor(cat)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tRBrack); err != nil {
		return nil, err
	}
	return &seqStep{Cat: cat, CatPos: ct.Pos, Cond: cond}, nil
}

func (p *seqParser) parseExprFor(cat string) (*seqNode, *SeqError) {
	p.cat, _ = seqLookupCat(cat)
	p.depth = 0
	return p.parseOr()
}

func (p *seqParser) newNode(op string, pos int) (*seqNode, *SeqError) {
	p.nodes++
	if p.nodes > seqMaxNodes {
		return nil, newSeqErr(p.src, pos, "query too complex (more than %d expression nodes)", seqMaxNodes)
	}
	return &seqNode{Op: op, Pos: pos}, nil
}

func (p *seqParser) parseOr() (*seqNode, *SeqError) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKw("or") {
		t := p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		n, err := p.newNode("or", t.Pos)
		if err != nil {
			return nil, err
		}
		n.Args = []*seqNode{l, r}
		a, b := l.pred, r.pred
		if a != nil && b != nil {
			n.pred = func(e *seqEvent) bool { return a(e) || b(e) }
		}
		l = n
	}
	return l, nil
}

func (p *seqParser) parseAnd() (*seqNode, *SeqError) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isKw("and") {
		t := p.next()
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		n, err := p.newNode("and", t.Pos)
		if err != nil {
			return nil, err
		}
		n.Args = []*seqNode{l, r}
		a, b := l.pred, r.pred
		if a != nil && b != nil {
			n.pred = func(e *seqEvent) bool { return a(e) && b(e) }
		}
		l = n
	}
	return l, nil
}

func (p *seqParser) parseNot() (*seqNode, *SeqError) {
	if p.isKw("not") {
		t := p.next()
		p.depth++
		if p.depth > seqMaxDepth {
			return nil, p.errAt(t, "expression nested too deeply (max %d)", seqMaxDepth)
		}
		defer func() { p.depth-- }()
		c, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return p.wrapNot(c, t.Pos)
	}
	return p.parsePrimary()
}

func (p *seqParser) wrapNot(c *seqNode, pos int) (*seqNode, *SeqError) {
	n, err := p.newNode("not", pos)
	if err != nil {
		return nil, err
	}
	n.Args = []*seqNode{c}
	if f := c.pred; f != nil {
		n.pred = func(e *seqEvent) bool { return !f(e) }
	}
	return n, nil
}

func (p *seqParser) parsePrimary() (*seqNode, *SeqError) {
	t := p.peek()
	switch {
	case t.Kind == tLParen:
		p.next()
		p.depth++
		if p.depth > seqMaxDepth {
			return nil, p.errAt(t, "expression nested too deeply (max %d)", seqMaxDepth)
		}
		e, err := p.parseOr()
		p.depth--
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return e, nil
	case t.Kind == tIdent && (t.Text == "true" || t.Text == "false"):
		p.next()
		n, err := p.newNode(t.Text, t.Pos)
		if err != nil {
			return nil, err
		}
		v := t.Text == "true"
		n.pred = func(*seqEvent) bool { return v }
		return n, nil
	case t.Kind == tIdent:
		return p.parseCmp()
	}
	return nil, p.errAt(t, "expected a condition, found %s", describeTok(t))
}

func (p *seqParser) fieldType(ft seqTok) (seqFType, bool) {
	if f, ok := p.cat.field(ft.Text); ok {
		return f.Type, true
	}
	reason := p.cat.absentReason(ft.Text)
	if reason == "" {
		reason = "no such field for " + p.cat.Category + " events (see GET /v1/hunt/seq/fields)"
	}
	e := newSeqErr(p.src, ft.Pos, "")
	p.q.Problems = append(p.q.Problems, SeqFieldProblem{Pos: ft.Pos, Line: e.Line, Col: e.Col, Category: p.cat.Category, Field: ft.Text, Reason: reason})
	return "", false
}

var seqOpWords = map[string]bool{"like": true, "startswith": true, "endswith": true, "contains": true, "regex": true, "in": true}

func (p *seqParser) parseCmp() (*seqNode, *SeqError) {
	ft := p.next()
	typ, known := p.fieldType(ft)
	negate := false
	ot := p.peek()
	var op string
	switch ot.Kind {
	case tEq:
		op = "=="
	case tNe:
		op = "!="
	case tLt:
		op = "<"
	case tLe:
		op = "<="
	case tGt:
		op = ">"
	case tGe:
		op = ">="
	case tColon:
		op = ":"
	case tIdent:
		if ot.Text == "not" {
			p.next()
			negate = true
			ot = p.peek()
		}
		if ot.Kind == tIdent && seqOpWords[ot.Text] {
			op = ot.Text
		} else if ot.Kind == tColon && negate {
			op = ":"
		}
	}
	if op == "" {
		return nil, p.errAt(ot, "expected a comparison operator after field %q, found %s", ft.Text, describeTok(ot))
	}
	p.next()
	n, err := p.newNode(op, ft.Pos)
	if err != nil {
		return nil, err
	}
	n.Field = ft.Text
	if known {
		allowed := map[seqFType]string{
			ftString: "== != : like regex in startswith endswith contains",
			ftInt:    "== != < <= > >= in",
			ftBool:   "== !=",
		}[typ]
		ok := false
		for _, w := range strings.Fields(allowed) {
			if w == op {
				ok = true
			}
		}
		if !ok {
			return nil, p.errAt(ot, "operator %q is not valid for %s field %q (valid: %s)", op, typ, ft.Text, allowed)
		}
	}
	// operands
	multi := op == "in" || ((op == ":" || op == "like") && p.peek().Kind == tLParen)
	if op == "startswith" || op == "endswith" || op == "contains" || op == "regex" {
		multi = false
	}
	var lits []seqTok
	if multi {
		if _, err := p.expect(tLParen); err != nil {
			return nil, err
		}
		for {
			l, err := p.literalTok()
			if err != nil {
				return nil, err
			}
			lits = append(lits, l)
			if len(lits) > seqMaxListItems {
				return nil, p.errAt(l, "list too long (max %d items)", seqMaxListItems)
			}
			if p.peek().Kind != tComma {
				break
			}
			p.next()
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
	} else {
		l, err := p.literalTok()
		if err != nil {
			return nil, err
		}
		lits = []seqTok{l}
	}
	if !known {
		return n, nil // field problem recorded; no predicate
	}
	// type check literals
	for _, l := range lits {
		switch typ {
		case ftString:
			if l.Kind != tString {
				return nil, p.errAt(l, "field %q is a string; expected a quoted string", ft.Text)
			}
			n.Strs = append(n.Strs, l.Text)
		case ftInt:
			if l.Kind != tNumber {
				return nil, p.errAt(l, "field %q is an int; expected a number", ft.Text)
			}
			n.Ints = append(n.Ints, l.Num)
		case ftBool:
			if l.Kind != tIdent || (l.Text != "true" && l.Text != "false") {
				return nil, p.errAt(l, "field %q is a bool; expected true or false", ft.Text)
			}
			n.Bools = append(n.Bools, l.Text == "true")
		}
	}
	if op == "regex" {
		pat := n.Strs[0]
		if len(pat) > seqMaxRegexLen {
			return nil, p.errAt(lits[0], "regex too long (%d bytes, max %d)", len(pat), seqMaxRegexLen)
		}
		re, rerr := regexp.Compile(pat) // RE2: linear-time, no backtracking
		if rerr != nil {
			return nil, p.errAt(lits[0], "invalid regex: %v", rerr)
		}
		n.Re = re
	}
	pred := compileLeaf(n, typ)
	if negate {
		n.pred = pred
		return p.wrapNot(n, ot.Pos)
	}
	n.pred = pred
	return n, nil
}

func (p *seqParser) literalTok() (seqTok, *SeqError) {
	t := p.peek()
	switch {
	case t.Kind == tString, t.Kind == tNumber:
		return p.next(), nil
	case t.Kind == tIdent && (t.Text == "true" || t.Text == "false"):
		return p.next(), nil
	}
	return t, p.errAt(t, "expected a literal (string, number, true/false), found %s", describeTok(t))
}
