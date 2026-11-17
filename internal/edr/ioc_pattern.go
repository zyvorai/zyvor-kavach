// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// A deliberately small, linear-time parser for the simplest STIX 2.1 indicator patterns:
//
//	[type:path = 'literal']            or several such comparisons joined by OR inside ONE pair of brackets.
//
// No regular expressions, no recursion, no evaluation. Anything else (AND, NOT, LIKE, MATCHES, IN,
// ISSUBSET, parentheses, FOLLOWEDBY, WITHIN/REPEATS/START/STOP qualifiers, other object types or
// paths, CIDR ranges) is rejected with a reason and never guessed.

const (
	patMaxLen    = 4096
	patMaxTokens = 512
	patMaxValue  = 2048
)

// IOCValue is one indicator extracted from a pattern or list. Type is one of
// sha256, sha1, md5, ipv4, ipv6, domain, url, email.
type IOCValue struct {
	Type  string
	Value string
}

type patTok struct {
	kind byte // 'i' ident, 's' string, or the punctuation byte itself
	text string
}

func patIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func patTokenize(p string) ([]patTok, error) {
	if len(p) > patMaxLen {
		return nil, fmt.Errorf("pattern longer than %d bytes", patMaxLen)
	}
	var toks []patTok
	for i := 0; i < len(p); {
		c := p[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'':
			var sb strings.Builder
			i++
			closed := false
			for i < len(p) {
				ch := p[i]
				if ch == '\\' {
					if i+1 < len(p) && (p[i+1] == '\\' || p[i+1] == '\'') {
						sb.WriteByte(p[i+1])
						i += 2
						continue
					}
					return nil, fmt.Errorf("unsupported escape in string literal")
				}
				i++
				if ch == '\'' {
					closed = true
					break
				}
				sb.WriteByte(ch)
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, patTok{'s', sb.String()})
		case c == '[' || c == ']' || c == '(' || c == ')' || c == '=' || c == ':' || c == '.' || c == ',' || c == '!' || c == '<' || c == '>':
			toks = append(toks, patTok{c, string(c)})
			i++
		case patIdentByte(c):
			j := i
			for j < len(p) && patIdentByte(p[j]) {
				j++
			}
			toks = append(toks, patTok{'i', p[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q", string(c))
		}
		if len(toks) > patMaxTokens {
			return nil, fmt.Errorf("pattern has more than %d tokens", patMaxTokens)
		}
	}
	return toks, nil
}

// ParseSTIXPattern extracts indicator values from a simple STIX pattern or returns the reason it is
// unsupported or invalid.
func ParseSTIXPattern(p string) ([]IOCValue, error) {
	toks, err := patTokenize(p)
	if err != nil {
		return nil, err
	}
	pos := 0
	next := func() (patTok, bool) {
		if pos >= len(toks) {
			return patTok{}, false
		}
		t := toks[pos]
		pos++
		return t, true
	}
	if t, ok := next(); !ok || t.kind != '[' {
		return nil, fmt.Errorf("pattern must start with '['")
	}
	var out []IOCValue
	for {
		obj, ok := next()
		if !ok {
			return nil, fmt.Errorf("pattern ends inside a comparison")
		}
		if obj.kind == '(' {
			return nil, fmt.Errorf("unsupported pattern form: parentheses")
		}
		if obj.kind != 'i' {
			return nil, fmt.Errorf("expected an object type, got %q", obj.text)
		}
		if strings.EqualFold(obj.text, "NOT") {
			return nil, fmt.Errorf("unsupported pattern form: NOT")
		}
		if t, ok := next(); !ok || t.kind != ':' {
			return nil, fmt.Errorf("expected ':' after object type %q", obj.text)
		}
		prop, ok := next()
		if !ok || prop.kind != 'i' {
			return nil, fmt.Errorf("expected an object property")
		}
		path := strings.ToLower(prop.text)
		algo := ""
		if path == "hashes" {
			if t, ok := next(); !ok || t.kind != '.' {
				return nil, fmt.Errorf("expected hashes.<algorithm>")
			}
			a, ok := next()
			if !ok || (a.kind != 's' && a.kind != 'i') {
				return nil, fmt.Errorf("expected a hash algorithm name")
			}
			algo = strings.ToUpper(strings.ReplaceAll(a.text, "-", ""))
		}
		op, ok := next()
		if !ok {
			return nil, fmt.Errorf("pattern ends before an operator")
		}
		if op.kind != '=' {
			return nil, fmt.Errorf("unsupported operator %q (only = is supported)", op.text)
		}
		lit, ok := next()
		if !ok || lit.kind != 's' {
			return nil, fmt.Errorf("expected a quoted string after =")
		}
		typ, err := patClassify(strings.ToLower(obj.text), path, algo)
		if err != nil {
			return nil, err
		}
		val, err := NormalizeIOCValue(typ, lit.text)
		if err != nil {
			return nil, err
		}
		out = append(out, IOCValue{typ, val})
		t, ok := next()
		if !ok {
			return nil, fmt.Errorf("unterminated pattern (missing ']')")
		}
		if t.kind == ']' {
			break
		}
		if t.kind == 'i' && strings.EqualFold(t.text, "OR") {
			continue
		}
		return nil, fmt.Errorf("unsupported pattern form: %q (only OR inside one bracket pair is supported)", t.text)
	}
	if pos < len(toks) {
		return nil, fmt.Errorf("unsupported pattern form: %q after the observation expression (no observation operators or qualifiers)", toks[pos].text)
	}
	return out, nil
}

func patClassify(obj, path, algo string) (string, error) {
	switch {
	case obj == "file" && path == "hashes":
		switch algo {
		case "SHA256":
			return "sha256", nil
		case "SHA1":
			return "sha1", nil
		case "MD5":
			return "md5", nil
		}
		return "", fmt.Errorf("unsupported hash algorithm %q (SHA-256, SHA-1, MD5 only)", algo)
	case obj == "ipv4-addr" && path == "value":
		return "ipv4", nil
	case obj == "ipv6-addr" && path == "value":
		return "ipv6", nil
	case obj == "domain-name" && path == "value":
		return "domain", nil
	case obj == "url" && path == "value":
		return "url", nil
	case obj == "email-addr" && path == "value":
		return "email", nil
	}
	return "", fmt.Errorf("unsupported object path %s:%s", obj, path)
}

func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// NormalizeIOCValue validates v for the given IOC type and returns its canonical form. It never
// repairs input (no defang handling, no CIDR expansion): a value that is not exactly valid is an error.
func NormalizeIOCValue(typ, v string) (string, error) {
	if v == "" || len(v) > patMaxValue {
		return "", fmt.Errorf("empty or over-long %s value", typ)
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] == 0x7f {
			return "", fmt.Errorf("%s value contains whitespace or control characters", typ)
		}
	}
	l := strings.ToLower(v)
	switch typ {
	case "sha256":
		if !isHexLen(l, 64) {
			return "", fmt.Errorf("not a SHA-256 (64 hex characters)")
		}
		return l, nil
	case "sha1":
		if !isHexLen(l, 40) {
			return "", fmt.Errorf("not a SHA-1 (40 hex characters)")
		}
		return l, nil
	case "md5":
		if !isHexLen(l, 32) {
			return "", fmt.Errorf("not an MD5 (32 hex characters)")
		}
		return l, nil
	case "ipv4", "ipv6":
		if strings.Contains(v, "/") {
			return "", fmt.Errorf("CIDR ranges are not supported")
		}
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("not a valid %s address", typ)
		}
		if typ == "ipv4" && !a.Is4() || typ == "ipv6" && (!a.Is6() || a.Is4In6()) {
			return "", fmt.Errorf("address is not %s", typ)
		}
		return a.String(), nil
	case "domain":
		l = strings.TrimSuffix(l, ".")
		if !validDomain(l) {
			return "", fmt.Errorf("not a valid domain name")
		}
		return l, nil
	case "url":
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || u.Hostname() == "" {
			return "", fmt.Errorf("not a valid absolute URL")
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "ftp":
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
		return v, nil
	case "email":
		at := strings.LastIndexByte(l, '@')
		if at < 1 || at > 64 || strings.Count(l, "@") != 1 || !validDomain(l[at+1:]) {
			return "", fmt.Errorf("not a valid email address")
		}
		return l, nil
	}
	return "", fmt.Errorf("unsupported indicator type %q", typ)
}

// DetectIOCType guesses the type of a bare list entry from its exact shape (used only for plain lists).
func DetectIOCType(v string) string {
	l := strings.ToLower(v)
	switch {
	case isHexLen(l, 64):
		return "sha256"
	case isHexLen(l, 40):
		return "sha1"
	case isHexLen(l, 32):
		return "md5"
	case strings.Contains(v, "://"):
		return "url"
	case strings.Contains(v, "@"):
		return "email"
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if a.Is4() {
			return "ipv4"
		}
		return "ipv6"
	}
	return "domain"
}
