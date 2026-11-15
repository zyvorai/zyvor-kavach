// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// URL inspector: tolerant parser. Parse only: nothing here resolves, fetches
// or connects. net/url is deliberately not used for the authority because it
// rejects or normalises exactly the tricks we want to see (userinfo lookalikes,
// decimal/hex/octal hosts, odd ports). See docs/url-email-inspection.md.

import (
	"net/netip"
	"strconv"
	"strings"
)

// URLParts is the tolerant parse of one URL.
type URLParts struct {
	Raw      string `json:"raw"`
	Cleaned  string `json:"cleaned"` // whitespace/control characters removed
	Scheme   string `json:"scheme"`
	HasAuth  bool   `json:"has_authority"`
	UserInfo string `json:"userinfo,omitempty"`
	Host     string `json:"host"`     // as written, lowercased, brackets removed
	HostDec  string `json:"host_dec"` // after one percent-decoding pass
	IPForm   string `json:"ip_form"`  // ""|dotted|decimal|hex|octal|mixed|ipv6
	IPCanon  string `json:"ip_canon"` // canonical dotted quad / ipv6 when IPForm != ""
	Port     string `json:"port,omitempty"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Fragment string `json:"fragment"`
	Stripped int    `json:"stripped_chars"`
}

const urlMaxLen = 8192

func urlIsScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// ParseURLTolerant splits a URL without rejecting odd forms. Never panics.
func ParseURLTolerant(in string) URLParts {
	p := URLParts{Raw: truncStr(in, urlMaxLen)}
	s := strings.TrimSpace(in)
	if len(s) > urlMaxLen {
		s = s[:urlMaxLen]
	}
	// Browsers drop tab/CR/LF anywhere in a URL; so do we, and count them.
	var sb strings.Builder
	for _, r := range s {
		if r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			p.Stripped++
			continue
		}
		sb.WriteRune(r)
	}
	s = sb.String()
	p.Cleaned = s
	rest := s
	if i := strings.IndexByte(s, ':'); i > 0 && urlIsScheme(s[:i]) {
		p.Scheme = strings.ToLower(s[:i])
		rest = s[i+1:]
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		p.Fragment = rest[i+1:]
		rest = rest[:i]
	}
	switch p.Scheme {
	case "javascript", "data", "vbscript", "mailto", "tel", "blob", "about":
		p.Path = rest
		return p
	}
	norm := strings.ReplaceAll(rest, "\\", "/")
	if strings.HasPrefix(norm, "//") {
		p.HasAuth = true
		norm = strings.TrimLeft(norm, "/")
		auth := norm
		tail := ""
		if i := strings.IndexAny(norm, "/?"); i >= 0 {
			auth, tail = norm[:i], norm[i:]
		}
		if i := strings.LastIndexByte(auth, '@'); i >= 0 {
			p.UserInfo = auth[:i]
			auth = auth[i+1:]
		}
		host := auth
		if strings.HasPrefix(auth, "[") {
			if j := strings.IndexByte(auth, ']'); j > 0 {
				host = auth[1:j]
				if strings.HasPrefix(auth[j+1:], ":") {
					p.Port = auth[j+2:]
				}
			}
		} else if i := strings.LastIndexByte(auth, ':'); i >= 0 {
			host, p.Port = auth[:i], auth[i+1:]
		}
		p.Host = strings.ToLower(strings.TrimSuffix(host, "."))
		p.HostDec = strings.ToLower(urlPctDecodeOnce(p.Host))
		p.IPForm, p.IPCanon = urlClassifyIPHost(p.HostDec)
		rest = tail
	} else if p.Scheme == "" {
		// scheme-less "host/path": treat the first segment as a host when it
		// looks like one (contains a dot, no spaces).
		seg := rest
		if i := strings.IndexAny(rest, "/?"); i >= 0 {
			seg = rest[:i]
		}
		if strings.Contains(seg, ".") && !strings.ContainsAny(seg, " ") {
			return ParseURLTolerant("http://" + s)
		}
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		p.Query = rest[i+1:]
		rest = rest[:i]
	}
	p.Path = rest
	return p
}

func urlPctDecodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// urlClassifyIPHost recognises every form a browser's IPv4 parser accepts:
// dotted decimal, a single 32-bit decimal or hex number, and dotted parts
// written in octal (leading 0) or hex (0x). Returns form and canonical text.
func urlClassifyIPHost(h string) (form, canon string) {
	if h == "" {
		return "", ""
	}
	if strings.Contains(h, ":") {
		if a, err := netip.ParseAddr(h); err == nil {
			return "ipv6", a.String()
		}
		return "", ""
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 || len(parts) == 0 {
		return "", ""
	}
	var vals []uint64
	kinds := map[string]bool{}
	for _, p := range parts {
		if p == "" {
			return "", ""
		}
		var v uint64
		var err error
		switch {
		case strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X"):
			v, err = strconv.ParseUint(p[2:], 16, 64)
			kinds["hex"] = true
		case len(p) > 1 && p[0] == '0' && !strings.ContainsAny(p, "89"):
			v, err = strconv.ParseUint(p[1:], 8, 64)
			kinds["octal"] = true
		default:
			v, err = strconv.ParseUint(p, 10, 64)
			kinds["dec"] = true
		}
		if err != nil {
			return "", ""
		}
		vals = append(vals, v)
	}
	// Compose per the WHATWG/inet_aton rule: last part fills the remaining bytes.
	var n uint64
	for i, v := range vals {
		if i < len(vals)-1 {
			if v > 255 {
				return "", ""
			}
			n |= v << (8 * uint(3-i))
		} else {
			max := uint64(1)<<(8*uint(4-i)) - 1
			if v > max {
				return "", ""
			}
			n |= v
		}
	}
	canon = netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}).String()
	switch {
	case len(parts) == 4 && len(kinds) == 1 && kinds["dec"]:
		return "dotted", canon
	case len(parts) < 4 && kinds["dec"] && len(kinds) == 1:
		return "decimal", canon
	case kinds["hex"] && len(kinds) == 1:
		return "hex", canon
	case kinds["octal"] && len(kinds) == 1:
		return "octal", canon
	}
	return "mixed", canon
}
