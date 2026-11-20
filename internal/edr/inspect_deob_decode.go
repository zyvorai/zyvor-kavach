// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Script and command-line deobfuscation: the decoder chain.
//
// Everything here is pure string/byte processing. Nothing is executed, fetched
// or written. The chain runs in rounds; each round applies every decoder once
// and a round that changed the text is one "layer". Work is bounded by the
// round limit (InspectMaxDepth), a per-text cap, a per-blob cap, a hard cap on
// decompressed bytes and a total byte budget.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	deobMaxText     = 2 << 20  // longest text carried between layers
	deobMaxBlob     = 1 << 20  // longest decoded blob / decompressed output
	deobMaxXORBlob  = 64 << 10 // XOR brute force only on small blobs
	deobWorkBudget  = 64 << 20 // total bytes the chain may process or produce
	deobMaxMatches  = 200      // replacements per decoder per pass
	deobMaxConcatIt = 60
)

type deobLayer struct {
	Depth   int
	Methods []string
	Text    string
}

type deobResult struct {
	Layers []deobLayer
	Limits []string
}

type deobWork struct {
	ctx    context.Context
	spent  int
	limits []string
	used   []string
	bomb   bool
}

func (w *deobWork) limit(n string) {
	for _, x := range w.limits {
		if x == n {
			return
		}
	}
	w.limits = append(w.limits, n)
}

func (w *deobWork) spend(n int) bool {
	w.spent += n
	if w.spent > deobWorkBudget {
		w.limit("work-budget")
		return false
	}
	return w.ctx.Err() == nil
}

func (w *deobWork) note(m string) {
	for _, x := range w.used {
		if x == m {
			return
		}
	}
	w.used = append(w.used, m)
}

func clipText(w *deobWork, s string) string {
	if len(s) > deobMaxText {
		w.limit("text-cap")
		s = s[:deobMaxText]
	}
	return s
}

// deobRun decodes text layer by layer and returns each changed layer. Every
// decoder application that changes the text is one layer; at most
// InspectMaxDepth layers are produced.
func deobRun(ctx context.Context, text string) *deobResult {
	w := &deobWork{ctx: ctx}
	res := &deobResult{}
	cur := clipText(w, text)
	seen := map[string]bool{cur: true}
	depth := 0
outer:
	for round := 0; round < InspectMaxDepth+1; round++ {
		progressed := false
		for _, d := range deobDecoders {
			if ctx.Err() != nil {
				w.limit("time")
				break outer
			}
			if w.spent > deobWorkBudget {
				break outer
			}
			w.used = nil
			out, ok := d.fn(w, cur)
			if !ok || out == cur {
				continue
			}
			out = clipText(w, out)
			if seen[out] {
				continue
			}
			if depth >= InspectMaxDepth {
				w.limit("max-depth")
				break outer
			}
			w.note(d.name)
			seen[out] = true
			cur = out
			depth++
			progressed = true
			res.Layers = append(res.Layers, deobLayer{Depth: depth, Methods: append([]string(nil), w.used...), Text: cur})
		}
		if !progressed {
			break
		}
	}
	if w.bomb {
		w.limit("decompression-cap")
	}
	res.Limits = w.limits
	return res
}

type deobDecoder struct {
	name string
	fn   func(w *deobWork, s string) (string, bool)
}

var deobDecoders = []deobDecoder{
	{"url-decode", decURL},
	{"backtick-insertion", decBacktick},
	{"caret-insertion", decCaret},
	{"quote-insertion", decQuoteInsert},
	{"concat", decConcat},
	{"join", decJoin},
	{"format-operator", decFormat},
	{"charcode", decCharCodes},
	{"hex-escape", decHexEscapes},
	{"reverse", decReverse},
	{"ps-encodedcommand", decPSEnc},
	{"shell-base64", decShellB64},
	{"shell-eval", decEval},
	{"python-exec", decPython},
	{"ps-frombase64", decPSFromB64},
	{"base64", decBase64},
	{"hex", decHexRun},
}

// ---------- shared helpers ----------

func (w *deobWork) replace(re *regexp.Regexp, s string, fn func(m []string) (string, bool)) (string, bool) {
	idx := re.FindAllStringSubmatchIndex(s, deobMaxMatches)
	if idx == nil {
		return s, false
	}
	var sb strings.Builder
	last := 0
	changed := false
	for _, loc := range idx {
		if w.ctx.Err() != nil {
			break
		}
		m := make([]string, len(loc)/2)
		for i := range m {
			if loc[2*i] >= 0 {
				m[i] = s[loc[2*i]:loc[2*i+1]]
			}
		}
		rep, ok := fn(m)
		if !ok || !w.spend(len(rep)+len(m[0])) {
			continue
		}
		sb.WriteString(s[last:loc[0]])
		sb.WriteString(rep)
		last = loc[1]
		changed = true
		if sb.Len() > deobMaxText {
			w.limit("text-cap")
			break
		}
	}
	if !changed {
		return s, false
	}
	sb.WriteString(s[last:])
	return sb.String(), true
}

func quoteLit(s string) string {
	if !strings.Contains(s, "'") {
		return "'" + s + "'"
	}
	if !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

var deobKnownTokens = []string{
	"iex", "invoke-", "http://", "https://", "powershell", "downloadstring", "downloadfile", "new-object",
	"net.webclient", "cmd.exe", "/bin/sh", "/bin/bash", "curl ", "wget ", "base64", "frombase64string",
	"-nop", "hidden", "bypass", "system.", "wscript", "shell", "exec", "import ", "eval", "echo ",
	"start-process", "function", "$env:", "certutil", "regsvr32", "socket", "payload", "stream",
}

func knownScore(s string) int {
	l := strings.ToLower(s)
	n := 0
	for _, t := range deobKnownTokens {
		if strings.Contains(l, t) {
			n++
		}
	}
	return n
}

// asText returns raw as text when it is UTF-8 or UTF-16LE and looks like text.
func asText(raw []byte) (string, bool) {
	if len(raw) < 4 {
		return "", false
	}
	if len(raw)%2 == 0 {
		zeros := 0
		for i := 1; i < len(raw); i += 2 {
			if raw[i] == 0 {
				zeros++
			}
		}
		if zeros*10 >= (len(raw)/2)*4 {
			u := make([]uint16, 0, len(raw)/2)
			for i := 0; i+1 < len(raw); i += 2 {
				u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
			}
			if len(u) > 0 && u[0] == 0xFEFF {
				u = u[1:]
			}
			s := string(utf16.Decode(u))
			if textish(s) {
				return s, true
			}
			return "", false
		}
	}
	if !utf8.Valid(raw) {
		return "", false
	}
	s := strings.TrimPrefix(string(raw), string(rune(0xFEFF)))
	if textish(s) {
		return s, true
	}
	return "", false
}

func textish(s string) bool {
	if len(s) < 4 {
		return false
	}
	total, ok, alpha := 0, 0, 0
	for _, r := range s {
		total++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			ok++
		case r >= 32 && r < 127:
			ok++
			if r == ' ' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				alpha++
			}
		case r > 160 && r != utf8.RuneError && r < 0x3000:
			ok++
			alpha++
		}
	}
	return ok*100 >= total*95 && alpha*100 >= total*55
}

func b64Decode(tok string) ([]byte, bool) {
	tok = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, tok)
	tok = strings.TrimRight(tok, "=")
	if len(tok) < 8 || len(tok)%4 == 1 || len(tok) > deobMaxBlob*4/3+8 {
		return nil, false
	}
	if strings.ContainsAny(tok, "-_") {
		tok = strings.NewReplacer("-", "+", "_", "/").Replace(tok)
	}
	out, err := base64.RawStdEncoding.DecodeString(tok)
	if err != nil {
		return nil, false
	}
	return out, true
}

// inflateCapped reads at most deobMaxBlob bytes; more is treated as a bomb.
func (w *deobWork) inflateCapped(r io.Reader) ([]byte, bool) {
	out, err := io.ReadAll(io.LimitReader(r, deobMaxBlob+1))
	if len(out) > deobMaxBlob {
		w.bomb = true
		w.limit("decompression-cap")
		return nil, false // a bomb is flagged, never expanded or analysed further
	}
	if err != nil && len(out) == 0 {
		return nil, false
	}
	return out, true
}

// blob turns decoded bytes into text: plain text, decompressed text or
// single-byte-XOR text. The second result names the extra step used.
func (w *deobWork) blob(raw []byte) (string, string, bool) {
	if len(raw) == 0 || !w.spend(len(raw)) {
		return "", "", false
	}
	if s, ok := asText(raw); ok {
		return s, "", true
	}
	var inflated []byte
	method := ""
	switch {
	case len(raw) > 18 && raw[0] == 0x1f && raw[1] == 0x8b:
		if gr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if d, ok := w.inflateCapped(gr); ok {
				inflated, method = d, "gzip"
			}
		}
	case len(raw) > 6 && raw[0]&0x0f == 8 && (uint16(raw[0])<<8|uint16(raw[1]))%31 == 0:
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			if d, ok := w.inflateCapped(zr); ok {
				inflated, method = d, "zlib"
			}
		}
	}
	if inflated == nil && len(raw) > 4 {
		if d, ok := w.inflateCapped(flate.NewReader(bytes.NewReader(raw))); ok && len(d) > 0 {
			inflated, method = d, "deflate"
		}
	}
	if inflated != nil {
		w.spend(len(inflated))
		if s, ok := asText(inflated); ok {
			return s, method, true
		}
		if s, k, ok := w.xorBrute(inflated); ok {
			return s, method + "+" + k, true
		}
		if method != "deflate" { // real gzip/zlib header that yields nothing useful
			return "", "", false
		}
	}
	if s, k, ok := w.xorBrute(raw); ok {
		return s, k, true
	}
	return "", "", false
}

// xorBrute tries every single-byte key and accepts only printable output that
// contains a known token, so random data does not decode "successfully".
func (w *deobWork) xorBrute(raw []byte) (string, string, bool) {
	if len(raw) < 8 || len(raw) > deobMaxXORBlob {
		return "", "", false
	}
	buf := make([]byte, len(raw))
	bestBad, bestScore, bestKey := 1<<30, 0, 0
	var best string
	limit := len(raw) / 20
	for k := 1; k < 256; k++ {
		if !w.spend(16) {
			return "", "", false
		}
		bad := 0
		for i, c := range raw {
			x := c ^ byte(k)
			buf[i] = x
			if (x < 32 || x > 126) && x != '\n' && x != '\r' && x != '\t' {
				bad++
				if bad > limit {
					break
				}
			}
		}
		if bad > limit {
			continue
		}
		w.spend(len(raw))
		s, ok := asText(buf)
		if !ok {
			continue
		}
		sc := knownScore(s)
		if sc < 1 {
			continue
		}
		if bad < bestBad || (bad == bestBad && sc > bestScore) {
			bestBad, bestScore, bestKey, best = bad, sc, k, s
		}
	}
	if bestKey == 0 {
		return "", "", false
	}
	return best, fmt.Sprintf("xor-0x%02x", bestKey), true
}

func (w *deobWork) noteBlob(base, extra string) {
	w.note(base)
	if extra != "" {
		for _, p := range strings.Split(extra, "+") {
			w.note(p)
		}
	}
}

// ---------- decoders ----------

var (
	reURLEsc  = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reTick    = regexp.MustCompile("[A-Za-z0-9]`[A-Za-z0-9]")
	reTickAny = regexp.MustCompile("`([A-Za-z0-9])")
	reCaret   = regexp.MustCompile(`[A-Za-z0-9]\^[A-Za-z0-9]`)
)

func decURL(w *deobWork, s string) (string, bool) {
	if len(reURLEsc.FindAllStringIndex(s, 8)) < 4 {
		return s, false
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				sb.WriteByte(b[0])
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	if !w.spend(len(s)) {
		return s, false
	}
	out := sb.String()
	if !utf8.ValidString(out) {
		return s, false
	}
	return out, out != s
}

func decBacktick(w *deobWork, s string) (string, bool) {
	if len(reTick.FindAllStringIndex(s, 4)) < 3 {
		return s, false
	}
	return reTickAny.ReplaceAllString(s, "$1"), true
}

var reCaretAny = regexp.MustCompile(`(?s)\^(.)`)

func decCaret(w *deobWork, s string) (string, bool) {
	if len(reCaret.FindAllStringIndex(s, 4)) < 3 {
		return s, false
	}
	return reCaretAny.ReplaceAllString(s, "$1"), true
}

var reQuoteTok = regexp.MustCompile(`[A-Za-z0-9_.\-]+(?:["'][A-Za-z0-9_.\-]*["'][A-Za-z0-9_.\-]*)+`)

func decQuoteInsert(w *deobWork, s string) (string, bool) {
	return w.replace(reQuoteTok, s, func(m []string) (string, bool) {
		t := m[0]
		inner := 0
		for i := 1; i+1 < len(t); i++ {
			if (t[i] == '"' || t[i] == '\'') && isWordB(t[i-1]) && isWordB(t[i+1]) {
				inner++
			}
		}
		if inner < 2 || strings.Count(t, `"`)%2 != 0 || strings.Count(t, "'")%2 != 0 {
			return "", false
		}
		return strings.NewReplacer(`"`, "", "'", "").Replace(t), true
	})
}

func isWordB(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

var (
	reConcatSQ = regexp.MustCompile(`'([^'\r\n]*)'\s*\+\s*'([^'\r\n]*)'`)
	reConcatDQ = regexp.MustCompile(`"([^"\r\n]*)"\s*[+&]\s*"([^"\r\n]*)"`)
)

func decConcat(w *deobWork, s string) (string, bool) {
	changed := false
	for i := 0; i < deobMaxConcatIt && w.ctx.Err() == nil; i++ {
		n := reConcatSQ.ReplaceAllString(s, "'$1$2'")
		n = reConcatDQ.ReplaceAllString(n, `"$1$2"`)
		if n == s {
			break
		}
		if !w.spend(len(n)) {
			break
		}
		s, changed = n, true
	}
	return s, changed
}

const reStrItem = `(?:'[^'\r\n]*'|"[^"\r\n]*")`

var (
	reJoinPost = regexp.MustCompile(`(?i)\(?\s*(` + reStrItem + `(?:\s*,\s*` + reStrItem + `)+)\s*\)?\s*-join\s*(?:''|"")`)
	reJoinPre  = regexp.MustCompile(`(?i)-join\s*\(\s*(` + reStrItem + `(?:\s*,\s*` + reStrItem + `)+)\s*\)`)
	reJoinStr  = regexp.MustCompile(`(?i)\[string\]::join\(\s*(?:''|"")\s*,\s*\(?\s*(` + reStrItem + `(?:\s*,\s*` + reStrItem + `)+)\s*\)?\s*\)`)
	reStrPart  = regexp.MustCompile(`'([^'\r\n]*)'|"([^"\r\n]*)"`)
	reFmtSQ    = regexp.MustCompile(`'((?:[^'{}\r\n]|\{\d+\})*\{\d+\}(?:[^'{}\r\n]|\{\d+\})*)'\s*-f\s*(` + reStrItem + `(?:\s*,\s*` + reStrItem + `)*)`)
	reFmtDQ    = regexp.MustCompile(`"((?:[^"{}\r\n]|\{\d+\})*\{\d+\}(?:[^"{}\r\n]|\{\d+\})*)"\s*-f\s*(` + reStrItem + `(?:\s*,\s*` + reStrItem + `)*)`)
)

func strParts(list string) []string {
	var out []string
	for _, m := range reStrPart.FindAllStringSubmatch(list, 500) {
		if strings.HasPrefix(m[0], "'") {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

func decJoin(w *deobWork, s string) (string, bool) {
	changed := false
	for _, re := range []*regexp.Regexp{reJoinPost, reJoinPre, reJoinStr} {
		var ok bool
		s, ok = w.replace(re, s, func(m []string) (string, bool) {
			return quoteLit(strings.Join(strParts(m[1]), "")), true
		})
		changed = changed || ok
	}
	return s, changed
}

var reFmtIdx = regexp.MustCompile(`\{(\d+)\}`)

func decFormat(w *deobWork, s string) (string, bool) {
	changed := false
	for _, re := range []*regexp.Regexp{reFmtSQ, reFmtDQ} {
		var ok bool
		s, ok = w.replace(re, s, func(m []string) (string, bool) {
			args := strParts(m[2])
			bad := false
			out := reFmtIdx.ReplaceAllStringFunc(m[1], func(t string) string {
				n, _ := strconv.Atoi(t[1 : len(t)-1])
				if n >= len(args) {
					bad = true
					return t
				}
				return args[n]
			})
			if bad {
				return "", false
			}
			return quoteLit(out), true
		})
		changed = changed || ok
	}
	return s, changed
}

const reCharOne = `(?:\[char\]\s*\(?\s*(?:0x[0-9a-f]+|\d+)\s*\)?|chrw?\$?\(\s*(?:&h[0-9a-f]+|\d+)\s*\))`

var (
	reCharSeq  = regexp.MustCompile(`(?i)` + reCharOne + `(?:\s*[+&]\s*` + reCharOne + `)+`)
	reNum      = regexp.MustCompile(`(?i)0x[0-9a-f]+|&h[0-9a-f]+|\d+`)
	reCharList = regexp.MustCompile(`(?i)(\[char\[\]\]\s*)?\(?\s*((?:(?:0x[0-9a-f]{1,2}|\d{1,3})\s*,\s*){5,}(?:0x[0-9a-f]{1,2}|\d{1,3}))\s*\)?((?:\s*\|\s*(?:%|foreach(?:-object)?)\s*\{\s*\[char\]\s*\$_\s*\})?)(\s*-join\s*(?:''|""))?`)
)

func parseNum(t string) (int, bool) {
	t = strings.ToLower(t)
	var n int64
	var err error
	switch {
	case strings.HasPrefix(t, "0x"), strings.HasPrefix(t, "&h"):
		n, err = strconv.ParseInt(t[2:], 16, 32)
	default:
		n, err = strconv.ParseInt(t, 10, 32)
	}
	return int(n), err == nil
}

func codesToString(nums []string) (string, bool) {
	var sb strings.Builder
	for _, t := range nums {
		n, ok := parseNum(t)
		if !ok || n < 9 || n > 0x2fff || (n > 126 && n < 160) || n == 11 || n == 12 || (n < 32 && n != 9 && n != 10 && n != 13) {
			return "", false
		}
		sb.WriteRune(rune(n))
	}
	return sb.String(), true
}

func decCharCodes(w *deobWork, s string) (string, bool) {
	changed := false
	var ok bool
	s, ok = w.replace(reCharSeq, s, func(m []string) (string, bool) {
		out, good := codesToString(reNum.FindAllString(m[0], -1))
		if !good {
			return "", false
		}
		return quoteLit(out), true
	})
	changed = changed || ok
	s, ok = w.replace(reCharList, s, func(m []string) (string, bool) {
		nums := reNum.FindAllString(m[2], -1)
		out, good := codesToString(nums)
		if !good {
			return "", false
		}
		hinted := m[1] != "" || m[3] != "" || m[4] != ""
		if !hinted && !(len(nums) >= 10 && textish(out)) {
			return "", false
		}
		return quoteLit(out), true
	})
	return s, changed || ok
}

var (
	reHexEsc  = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){3,}`)
	reHex0x   = regexp.MustCompile(`(?i)(?:0x[0-9a-f]{2}\s*,\s*){3,}0x[0-9a-f]{2}`)
	reHexRun  = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}){8,}\b`)
	reHexPair = regexp.MustCompile(`(?i)[0-9a-f]{2}`)
)

func decHexEscapes(w *deobWork, s string) (string, bool) {
	changed := false
	for _, re := range []*regexp.Regexp{reHexEsc, reHex0x} {
		var ok bool
		s, ok = w.replace(re, s, func(m []string) (string, bool) {
			var raw []byte
			for _, p := range reHexPair.FindAllString(strings.ReplaceAll(strings.ReplaceAll(m[0], `\x`, ""), "0x", ""), -1) {
				b, _ := hex.DecodeString(p)
				raw = append(raw, b...)
			}
			text, extra, good := w.blob(raw)
			if !good {
				return "", false
			}
			w.noteBlob("hex-escape", extra)
			return quoteLit(text), true
		})
		changed = changed || ok
	}
	return s, changed
}

func decHexRun(w *deobWork, s string) (string, bool) {
	return w.replace(reHexRun, s, func(m []string) (string, bool) {
		raw, err := hex.DecodeString(m[0])
		if err != nil {
			return "", false
		}
		text, extra, ok := w.blob(raw)
		if !ok {
			return "", false
		}
		w.noteBlob("hex", extra)
		return text, true
	})
}

var (
	reStrRev   = regexp.MustCompile(`(?i)StrReverse\(\s*"((?:[^"\r\n]|"")*)"\s*\)`)
	rePyRev    = regexp.MustCompile(`(['"])([^'"\r\n]{4,})['"]\s*\[\s*::\s*-1\s*\]`)
	rePSRev    = regexp.MustCompile(`(?i)(['"])([^'"\r\n]{4,})['"]\s*\[\s*-1\s*\.\.\s*-[^\]\r\n]*\]\s*(?:-join\s*(?:''|""))?`)
	reAnyQuote = regexp.MustCompile(`'[^'\r\n]{8,}'|"[^"\r\n]{8,}"`)
)

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func decReverse(w *deobWork, s string) (string, bool) {
	changed := false
	var ok bool
	s, ok = w.replace(reStrRev, s, func(m []string) (string, bool) {
		return `"` + reverseStr(strings.ReplaceAll(m[1], `""`, `"`)) + `"`, true
	})
	changed = changed || ok
	for _, re := range []*regexp.Regexp{rePyRev, rePSRev} {
		s, ok = w.replace(re, s, func(m []string) (string, bool) {
			return m[1] + reverseStr(m[2]) + m[1], true
		})
		changed = changed || ok
	}
	// quoted literals that only make sense reversed
	s, ok = w.replace(reAnyQuote, s, func(m []string) (string, bool) {
		lit := m[0]
		inner := lit[1 : len(lit)-1]
		if knownScore(inner) == 0 && knownScore(reverseStr(inner)) >= 1 {
			return lit[:1] + reverseStr(inner) + lit[:1], true
		}
		return "", false
	})
	changed = changed || ok
	// whole text reversed (a script written backwards for a reverse-and-IEX trick)
	if len(s) < 1<<18 {
		if r := reverseStr(s); knownScore(r) >= 2 && knownScore(r) > knownScore(s)+1 {
			return r, true
		}
	}
	return s, changed
}

var rePSEnc = regexp.MustCompile(`(?i)(?:^|[\s/])-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+['"]?([A-Za-z0-9+/]{12,}={0,2})['"]?`)

func decPSEnc(w *deobWork, s string) (string, bool) {
	return w.replace(rePSEnc, s, func(m []string) (string, bool) {
		raw, ok := b64Decode(m[1])
		if !ok {
			return "", false
		}
		text, extra, ok := w.blob(raw)
		if !ok {
			return "", false
		}
		w.noteBlob("ps-encodedcommand", extra)
		return "\n" + text + "\n", true
	})
}

var (
	reShellB64 = regexp.MustCompile(`(?i)echo\s+(?:-[ne]+\s+)?['"]?([A-Za-z0-9+/=_-]{8,})['"]?\s*\|\s*(?:base64|openssl\s+base64|openssl\s+enc\s+-base64)\s+(?:-d|--decode|-D|-di)\b(?:\s+-A)?`)
	reShellHS  = regexp.MustCompile(`(?i)base64\s+(?:-d|--decode|-D)\s*<<<\s*['"]?([A-Za-z0-9+/=_-]{8,})['"]?`)
	reEval     = regexp.MustCompile("(?m)\\beval\\s+\"?(?:\\$\\(\\s*(.+?)\\s*\\)|`([^`\\r\\n]+)`)\"?\\s*$")
)

func decShellB64(w *deobWork, s string) (string, bool) {
	changed := false
	for _, re := range []*regexp.Regexp{reShellB64, reShellHS} {
		var ok bool
		s, ok = w.replace(re, s, func(m []string) (string, bool) {
			raw, good := b64Decode(m[1])
			if !good {
				return "", false
			}
			text, extra, good := w.blob(raw)
			if !good {
				return "", false
			}
			w.noteBlob("shell-base64", extra)
			return strings.TrimRight(text, "\r\n"), true
		})
		changed = changed || ok
	}
	return s, changed
}

func decEval(w *deobWork, s string) (string, bool) {
	return w.replace(reEval, s, func(m []string) (string, bool) {
		inner := m[1]
		if inner == "" {
			inner = m[2]
		}
		return inner, inner != ""
	})
}

var rePyExec = regexp.MustCompile(`(?m)^.*\b(?:exec|eval)\s*\(.*?(?:b64decode|decodebytes|decompress|fromhex)\b.*?['"]([A-Za-z0-9+/=_\-]{16,})['"].*$`)

func decPython(w *deobWork, s string) (string, bool) {
	return w.replace(rePyExec, s, func(m []string) (string, bool) {
		raw, ok := b64Decode(m[1])
		if !ok {
			if b, err := hex.DecodeString(m[1]); err == nil {
				raw, ok = b, true
			}
		}
		if !ok {
			return "", false
		}
		text, extra, ok := w.blob(raw)
		if !ok {
			return "", false
		}
		w.noteBlob("python-exec", extra)
		return text, true
	})
}

var (
	rePSB64      = regexp.MustCompile(`(?is)(\[(?:system\.)?(?:text\.)?encoding\]::\w+\.getstring\(\s*)?\[(?:system\.)?convert\]::frombase64string\(\s*['"]([A-Za-z0-9+/=_-]+)['"]\s*\)(\s*\))?`)
	rePSStream   = regexp.MustCompile(`(?i)deflatestream|gzipstream|inflat`)
	rePSExecWrap = regexp.MustCompile(`(?i)streamreader|iex|invoke-expression`)
)

func decPSFromB64(w *deobWork, s string) (string, bool) {
	if rePSStream.MatchString(s) && rePSExecWrap.MatchString(s) {
		if m := rePSB64.FindStringSubmatch(s); m != nil {
			if raw, ok := b64Decode(m[2]); ok {
				if text, extra, ok := w.blob(raw); ok {
					w.noteBlob("ps-frombase64", extra)
					return text, true
				}
			}
		}
	}
	return w.replace(rePSB64, s, func(m []string) (string, bool) {
		raw, ok := b64Decode(m[2])
		if !ok {
			return "", false
		}
		text, extra, ok := w.blob(raw)
		if !ok {
			return "", false
		}
		w.noteBlob("ps-frombase64", extra)
		rep := quoteLit(text)
		if m[1] == "" && m[3] != "" {
			rep += ")"
		}
		return rep, true
	})
}

var reB64Tok = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

func decBase64(w *deobWork, s string) (string, bool) {
	return w.replace(reB64Tok, s, func(m []string) (string, bool) {
		tok := m[0]
		if distinct(tok) < 10 {
			return "", false
		}
		raw, ok := b64Decode(tok)
		if !ok {
			return "", false
		}
		text, extra, ok := w.blob(raw)
		if !ok {
			return "", false
		}
		w.noteBlob("base64", extra)
		return text, true
	})
}

func distinct(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
