// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"strings"
	"time"
)

// Hard limits of kavach-seq.
const (
	seqMaxQueryLen   = 4096
	seqMaxSteps      = 6
	seqMaxNodes      = 256
	seqMaxDepth      = 32
	seqMaxListItems  = 64
	seqMaxLiteralLen = 512
	seqMaxRegexLen   = 256
	seqMaxMatches    = 500
	seqMaxScan       = 200000
	seqMaxSpan       = 24 * time.Hour
	seqValueCap      = 4096 // longest field value regex/glob inspects (longer values are truncated)
)

// SeqError is a syntax/semantic error with a byte offset into the query.
type SeqError struct {
	Pos       int    `json:"pos"`
	Line      int    `json:"line"`
	Col       int    `json:"col"`
	Msg       string `json:"error"`
	formatted string
}

func (e *SeqError) Error() string { return e.formatted }

func newSeqErr(src string, pos int, format string, a ...any) *SeqError {
	if pos > len(src) {
		pos = len(src)
	}
	if pos < 0 {
		pos = 0
	}
	line, col := 1, 1
	for i := 0; i < pos; i++ {
		if src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	msg := fmt.Sprintf(format, a...)
	return &SeqError{Pos: pos, Line: line, Col: col, Msg: msg,
		formatted: fmt.Sprintf("offset %d (line %d, col %d): %s", pos, line, col, msg)}
}

type seqTokKind int

const (
	tEOF seqTokKind = iota
	tIdent
	tString
	tNumber
	tDuration
	tLBrack
	tRBrack
	tLParen
	tRParen
	tComma
	tAssign // =
	tEq     // ==
	tNe
	tLt
	tLe
	tGt
	tGe
	tColon
)

type seqTok struct {
	Kind seqTokKind
	Pos  int
	Text string // ident (lower-cased) or decoded string
	Num  int64
	Dur  time.Duration
}

func (k seqTokKind) String() string {
	return [...]string{"end of query", "identifier", "string", "number", "duration", "'['", "']'", "'('", "')'", "','", "'='", "'=='", "'!='", "'<'", "'<='", "'>'", "'>='", "':'"}[k]
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func seqLex(src string) ([]seqTok, *SeqError) {
	if len(src) > seqMaxQueryLen {
		return nil, newSeqErr(src, seqMaxQueryLen, "query too long (%d bytes, max %d)", len(src), seqMaxQueryLen)
	}
	var out []seqTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#': // comment to end of line
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case isIdentStart(c):
			j := i
			for j < len(src) && (isIdentStart(src[j]) || isDigit(src[j])) {
				j++
			}
			out = append(out, seqTok{Kind: tIdent, Pos: i, Text: strings.ToLower(src[i:j])})
			i = j
		case isDigit(c):
			j := i
			var n int64
			for j < len(src) && isDigit(src[j]) {
				if n > (1<<62)/10 {
					return nil, newSeqErr(src, i, "number too large")
				}
				n = n*10 + int64(src[j]-'0')
				j++
			}
			if j < len(src) && isIdentStart(src[j]) { // duration like 5m
				k := j
				for k < len(src) && isIdentStart(src[k]) {
					k++
				}
				var unit time.Duration
				switch src[j:k] {
				case "ms":
					unit = time.Millisecond
				case "s":
					unit = time.Second
				case "m":
					unit = time.Minute
				case "h":
					unit = time.Hour
				case "d":
					unit = 24 * time.Hour
				default:
					return nil, newSeqErr(src, j, "unknown duration unit %q (use ms, s, m, h, d)", src[j:k])
				}
				if n > int64(seqMaxSpan/unit)+1 {
					return nil, newSeqErr(src, i, "duration too large (max %s)", seqMaxSpan)
				}
				out = append(out, seqTok{Kind: tDuration, Pos: i, Dur: time.Duration(n) * unit})
				i = k
				continue
			}
			out = append(out, seqTok{Kind: tNumber, Pos: i, Num: n})
			i = j
		case c == '"':
			var sb strings.Builder
			j := i + 1
			closed := false
			for j < len(src) {
				d := src[j]
				if d == '"' {
					closed = true
					j++
					break
				}
				if d == '\\' {
					if j+1 >= len(src) {
						return nil, newSeqErr(src, j, "unterminated escape")
					}
					switch src[j+1] {
					case '"', '\\':
						sb.WriteByte(src[j+1])
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					default:
						return nil, newSeqErr(src, j, "unknown escape \\%c", src[j+1])
					}
					j += 2
					continue
				}
				sb.WriteByte(d)
				j++
				if sb.Len() > seqMaxLiteralLen {
					return nil, newSeqErr(src, i, "string literal too long (max %d)", seqMaxLiteralLen)
				}
			}
			if !closed {
				return nil, newSeqErr(src, i, "unterminated string")
			}
			if sb.Len() > seqMaxLiteralLen {
				return nil, newSeqErr(src, i, "string literal too long (max %d)", seqMaxLiteralLen)
			}
			out = append(out, seqTok{Kind: tString, Pos: i, Text: sb.String()})
			i = j
		default:
			two := ""
			if i+1 < len(src) {
				two = src[i : i+2]
			}
			switch {
			case two == "==":
				out = append(out, seqTok{Kind: tEq, Pos: i})
				i += 2
			case two == "!=":
				out = append(out, seqTok{Kind: tNe, Pos: i})
				i += 2
			case two == "<=":
				out = append(out, seqTok{Kind: tLe, Pos: i})
				i += 2
			case two == ">=":
				out = append(out, seqTok{Kind: tGe, Pos: i})
				i += 2
			default:
				k := map[byte]seqTokKind{'[': tLBrack, ']': tRBrack, '(': tLParen, ')': tRParen, ',': tComma, '=': tAssign, '<': tLt, '>': tGt, ':': tColon}[c]
				if k == 0 {
					return nil, newSeqErr(src, i, "unexpected character %q", string(c))
				}
				out = append(out, seqTok{Kind: k, Pos: i})
				i++
			}
		}
	}
	out = append(out, seqTok{Kind: tEOF, Pos: len(src)})
	return out, nil
}
