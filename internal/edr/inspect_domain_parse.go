// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Domain inspector: parsing and normalisation. Offline only: nothing here
// resolves, fetches or connects. See docs/domain-inspector.md.

import (
	"embed"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

//go:embed domaindata/*.txt
var domainDataFS embed.FS

// DomainParts is the parsed form of one host name.
type DomainParts struct {
	Input       string   `json:"input"`
	Normalized  string   `json:"normalized"`        // lowercase, no trailing dot, ASCII (punycode) form as supplied
	Unicode     string   `json:"unicode"`           // xn-- labels decoded
	Labels      []string `json:"labels"`            // normalized labels, left to right
	Suffix      string   `json:"suffix"`            // public suffix (partial list), e.g. co.uk
	SLD         string   `json:"sld"`               // registrable label (left of suffix), decoded
	Registrable string   `json:"registrable"`       // sld + "." + suffix
	Subdomains  []string `json:"subdomains"`        // labels left of the registrable name
	IPLike      string   `json:"ip_like,omitempty"` // ipv4|ipv6|decimal|hex|numeric-labels
	HasPunycode bool     `json:"has_punycode"`
	Err         string   `json:"error,omitempty"`
}

var errDomain = errors.New("invalid domain")

const (
	domainMaxLen   = 253
	domainMaxLabel = 63
)

// ParseDomain normalises and splits a host name. It never panics; invalid
// input yields Err set and best-effort fields.
func ParseDomain(in string) DomainParts {
	p := DomainParts{Input: in}
	s := strings.TrimSpace(in)
	// Tolerate a URL or host:port pasted by an analyst. Documented leniency.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") {
		if j := strings.Index(s, "]"); j > 0 {
			s = s[1:j]
		}
	} else if strings.Count(s, ":") == 1 {
		s = s[:strings.Index(s, ":")]
	}
	if !utf8.ValidString(s) {
		p.Err = "input is not valid UTF-8"
		return p
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	// Fullwidth/ideographic dots are treated as label separators (IDNA does the same).
	s = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(s)
	p.Normalized = s
	if s == "" {
		p.Err = "empty domain"
		return p
	}
	if len(s) > domainMaxLen {
		p.Err = "name longer than 253 bytes"
		p.Normalized = s[:64] + "..."
		return p
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Is4() {
			p.IPLike = "ipv4"
		} else {
			p.IPLike = "ipv6"
		}
		return p
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" {
			p.Err = "empty label (consecutive or leading dot)"
			return p
		}
		if len(l) > domainMaxLabel {
			p.Err = "label longer than 63 bytes"
			return p
		}
		for _, r := range l {
			if r < 0x20 || r == 0x7f || r == ' ' || strings.ContainsRune(`/\:@"'<>%&?#[]()!*,;=+|^~`+"`", r) {
				p.Err = "illegal character in label"
				return p
			}
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			p.Err = "label starts or ends with hyphen"
			return p
		}
	}
	p.Labels = labels
	// Numeric hosts (inet_aton style) are not names.
	if len(labels) == 1 {
		if isAllDigits(labels[0]) {
			p.IPLike = "decimal"
			return p
		}
		if strings.HasPrefix(labels[0], "0x") && isHexString(labels[0][2:]) && len(labels[0]) > 2 {
			p.IPLike = "hex"
			return p
		}
	}
	allNum := true
	for _, l := range labels {
		if !(isAllDigits(l) || (strings.HasPrefix(l, "0x") && len(l) > 2 && isHexString(l[2:]))) {
			allNum = false
		}
	}
	if allNum && len(labels) > 1 {
		p.IPLike = "numeric-labels"
		return p
	}

	// Decode punycode for display and script analysis.
	dec := make([]string, len(labels))
	for i, l := range labels {
		dec[i] = l
		if strings.HasPrefix(l, "xn--") {
			p.HasPunycode = true
			u, err := punycodeDecode(l[4:])
			if err != nil {
				p.Err = "invalid punycode in label " + truncDomain(l)
				return p
			}
			dec[i] = u
		}
	}
	p.Unicode = strings.Join(dec, ".")

	if len(labels) == 1 {
		p.Suffix = labels[0]
		p.Registrable = dec[0]
		p.SLD = ""
		return p
	}
	suf := domainSuffixLen(labels)
	if suf >= len(labels) { // whole name is a suffix, e.g. "co.uk" or "github.io"
		p.Suffix = strings.Join(labels, ".")
		p.Registrable = p.Suffix
		return p
	}
	p.Suffix = strings.Join(labels[len(labels)-suf:], ".")
	p.SLD = dec[len(labels)-suf-1]
	p.Registrable = p.SLD + "." + p.Suffix
	p.Subdomains = labels[:len(labels)-suf-1]
	return p
}

func truncDomain(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexString(s string) bool {
	if s == "" {
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

// ---- public suffix (partial) ----

var (
	domainDataOnce sync.Once
	domainSuffixes map[string]bool
	domainBadTLDs  map[string]bool
	domainBrands   []string
)

func loadDomainLines(name string) []string {
	b, err := domainDataFS.ReadFile("domaindata/" + name)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, strings.ToLower(ln))
	}
	return out
}

func initDomainData() {
	domainDataOnce.Do(func() {
		domainSuffixes = map[string]bool{}
		for _, s := range loadDomainLines("suffixes.txt") {
			domainSuffixes[s] = true
		}
		domainBadTLDs = map[string]bool{}
		for _, s := range loadDomainLines("tlds_suspicious.txt") {
			domainBadTLDs[s] = true
		}
		domainBrands = loadDomainLines("brands.txt")
	})
}

// domainSuffixLen returns how many trailing labels form the public suffix:
// the longest listed multi-label suffix, else 1.
func domainSuffixLen(labels []string) int {
	initDomainData()
	for n := min(len(labels), 3); n >= 2; n-- {
		if domainSuffixes[strings.Join(labels[len(labels)-n:], ".")] {
			return n
		}
	}
	return 1
}

// ---- punycode (RFC 3492 decoder; no external dependency) ----

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

// punycodeDecode decodes the part after "xn--". It bounds its work and
// returns an error on malformed or overflowing input.
func punycodeDecode(s string) (string, error) {
	var out []rune
	basic := strings.LastIndexByte(s, '-')
	if basic > 0 {
		for i := 0; i < basic; i++ {
			if s[i] >= 0x80 {
				return "", errDomain
			}
			out = append(out, rune(s[i]))
		}
		s = s[basic+1:]
	} else if basic == 0 {
		s = s[1:]
	}
	n, bias, i := pcInitialN, pcInitialBias, 0
	for pos := 0; pos < len(s); {
		oldi, w := i, 1
		for k := pcBase; ; k += pcBase {
			if pos >= len(s) {
				return "", errDomain
			}
			c := s[pos]
			pos++
			var d int
			switch {
			case c >= 'a' && c <= 'z':
				d = int(c - 'a')
			case c >= '0' && c <= '9':
				d = int(c-'0') + 26
			default:
				return "", errDomain
			}
			if d > (1<<30)/w {
				return "", errDomain
			}
			i += d * w
			t := k - bias
			if t < pcTMin {
				t = pcTMin
			} else if t > pcTMax {
				t = pcTMax
			}
			if d < t {
				break
			}
			if w > (1<<30)/(pcBase-t) {
				return "", errDomain
			}
			w *= pcBase - t
		}
		bias = pcAdapt(i-oldi, len(out)+1, oldi == 0)
		n += i / (len(out) + 1)
		i %= len(out) + 1
		if n > unicode.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return "", errDomain
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = rune(n)
		i++
		if len(out) > 256 {
			return "", errDomain
		}
	}
	return string(out), nil
}

// domainScript classifies a rune for mixed-script detection.
func domainScript(r rune) string {
	switch {
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r):
		return "Kana"
	case unicode.Is(unicode.Hangul, r):
		return "Hangul"
	}
	return ""
}
