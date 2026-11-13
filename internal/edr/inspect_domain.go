// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Domain inspector analyzer (kind "domain"). Offline and parse-only: it makes
// no DNS query and no connection. Every finding carries a modest weight and no
// single signal can reach the "suspicious" verdict level (40) on its own; the
// contract's verdict builder needs at least two independent signals.
// See docs/domain-inspector.md for the evaluation and its limits.

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

func init() {
	RegisterAnalyzer("domain", []string{InspectKindDomain}, analyzeDomain)
}

func analyzeDomain(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	b.Format("domain")
	text := strings.TrimSpace(in.Text)
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = strings.TrimSpace(text[:i]) // one domain per request
	}
	ds := ScoreDomain(text)
	p := ds.Parse
	b.Meta("parse", p)
	b.Meta("score", map[string]any{
		"dga_score": ds.Score, "applicable": ds.Applicable, "threshold": DomainDGAThreshold,
		"features": ds.Features, "factors": ds.Factors,
		"note": "heuristic; evaluated on synthetic data, see docs/domain-inspector.md",
	})
	if p.Err != "" {
		b.Finding(InspectFinding{ID: "dom-invalid", Title: "Not a valid domain name: " + p.Err,
			Severity: "low", Weight: 5, Evidence: truncDomain(text)})
		return nil
	}
	if p.IPLike != "" {
		if p.IPLike == "ipv4" || p.IPLike == "ipv6" {
			b.IOC(p.IPLike, p.Normalized)
		}
		b.Finding(InspectFinding{ID: "dom-ip-host", Title: "Host is a numeric/IP-form address, not a name (" + p.IPLike + ")",
			Severity: "low", Weight: 10, Evidence: p.Normalized})
		return nil
	}
	b.IOC("domain", p.Normalized)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if p.HasPunycode {
		b.Finding(InspectFinding{ID: "dom-punycode", Title: "Internationalised (punycode) label present",
			Severity: "info", Weight: 3, Evidence: p.Normalized + " = " + p.Unicode})
	}
	for _, l := range strings.Split(p.Unicode, ".") {
		if sc := mixedScripts(l); len(sc) > 1 && hasConfusableMix(sc) {
			b.Finding(InspectFinding{ID: "dom-mixed-script", Title: "Label mixes Latin with " + strings.Join(otherScripts(sc), "/") + " letters (homoglyph spoof shape)",
				Severity: "medium", Technique: "T1583.001", Weight: 30, Evidence: l})
			break
		}
	}

	// DGA likeness.
	switch {
	case ds.DGALike:
		w := 20 + (ds.Score-DomainDGAThreshold)*3/10
		if w > 35 {
			w = 35
		}
		b.Finding(InspectFinding{ID: "dom-dga-likeness", Title: fmt.Sprintf("Label looks algorithmically generated (score %d/100)", ds.Score),
			Severity: "medium", Technique: "T1568.002", Weight: w,
			Evidence: ds.Label + ": " + strings.Join(ds.Factors, ", ")})
	case ds.Applicable && ds.Score >= 30:
		b.Finding(InspectFinding{ID: "dom-dga-borderline", Title: fmt.Sprintf("Label is somewhat random-looking (score %d/100, below threshold %d)", ds.Score, DomainDGAThreshold),
			Severity: "info", Weight: 5, Evidence: ds.Label})
	}

	// DNS tunnelling / exfil shape on the subdomain chain.
	sub := strings.Join(p.Subdomains, ".")
	if len(p.Subdomains) >= 5 || len(sub) >= 100 {
		b.Finding(InspectFinding{ID: "dom-deep-subdomain", Title: fmt.Sprintf("Very long subdomain chain (%d labels, %d chars)", len(p.Subdomains), len(sub)),
			Severity: "low", Technique: "T1071.004", Weight: 12, Evidence: truncDomain(sub)})
	}
	for _, l := range p.Subdomains {
		if kind := encodedLabelKind(l); kind != "" {
			b.Finding(InspectFinding{ID: "dom-encoded-subdomain", Title: "Subdomain label looks like " + kind + " data (DNS tunnelling shape; CDNs also do this)",
				Severity: "low", Technique: "T1071.004", Weight: 14, Evidence: truncDomain(l)})
			break
		}
	}

	// Weak TLD signal.
	initDomainData()
	tld := p.Labels[len(p.Labels)-1]
	if domainBadTLDs[tld] {
		b.Finding(InspectFinding{ID: "dom-suspicious-tld", Title: "TLD ." + tld + " has a high abuse ratio (weak signal; many legitimate sites use it)",
			Severity: "info", Weight: 6, Evidence: p.Registrable})
	}

	// Brand impersonation.
	for _, f := range brandFindings(p) {
		b.Finding(f)
	}
	return nil
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func mixedScripts(label string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range label {
		if !unicode.IsLetter(r) {
			continue
		}
		if s := domainScript(r); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// hasConfusableMix is true when Latin is combined with Cyrillic or Greek.
// Latin+Han/Kana (normal in Japanese and Chinese names) is not flagged.
func hasConfusableMix(sc []string) bool {
	latin, conf := false, false
	for _, s := range sc {
		switch s {
		case "Latin":
			latin = true
		case "Cyrillic", "Greek":
			conf = true
		}
	}
	return latin && conf
}

func otherScripts(sc []string) []string {
	var o []string
	for _, s := range sc {
		if s != "Latin" {
			o = append(o, s)
		}
	}
	return o
}

// encodedLabelKind recognises hex and base32 shaped labels that are long
// enough to carry data.
func encodedLabelKind(l string) string {
	if len(l) >= 16 && isHexString(l) {
		return "hex"
	}
	if len(l) >= 26 {
		b32 := true
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
				b32 = false
				break
			}
		}
		if b32 && shannon(l) >= 3.5 {
			if cov, _ := domModel.segment(l); float64(cov)/float64(len(l)) < 0.6 {
				return "base32"
			}
		}
	}
	return ""
}

// editDistance is Levenshtein distance, with an adjacent swap counted as 1.
// It returns limit+1 as soon as the distance must exceed limit.
func editDistance(a, b string, limit int) int {
	if d := len(a) - len(b); d > limit || -d > limit {
		return limit + 1
	}
	if len(a) == len(b) && a != b {
		for i := 0; i+1 < len(a); i++ {
			if a[i] != b[i] {
				if a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] {
					return 1
				}
				break
			}
		}
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
			rowMin = min(rowMin, cur[j])
		}
		if rowMin > limit {
			return limit + 1
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func brandFindings(p DomainParts) []InspectFinding {
	initDomainData()
	var out []InspectFinding
	sld := p.SLD
	if sld == "" {
		return nil
	}
	flat := strings.ReplaceAll(sld, "-", "")
	for _, br := range domainBrands {
		if flat == br {
			return nil // the brand name itself (any TLD): not a squat of itself
		}
	}
	for _, br := range domainBrands {
		if len(br) < 5 {
			continue
		}
		lim := 1
		if len(br) >= 9 {
			lim = 2
		}
		if d := editDistance(flat, br, lim); d >= 1 && d <= lim {
			w := 20
			if d == 2 {
				w = 12
			}
			out = append(out, InspectFinding{ID: "dom-typosquat", Title: fmt.Sprintf("Within edit distance %d of well-known name %q", d, br),
				Severity: "medium", Technique: "T1583.001", Weight: w, Evidence: p.Registrable})
			return out
		}
	}
	for _, br := range domainBrands {
		if len(br) < 5 {
			continue
		}
		if strings.Contains(sld, br) {
			out = append(out, InspectFinding{ID: "dom-brand-embedded", Title: fmt.Sprintf("Registrable name embeds well-known name %q", br),
				Severity: "low", Technique: "T1583.001", Weight: 10, Evidence: p.Registrable})
			return out
		}
		for _, l := range p.Subdomains {
			if strings.Contains(l, br) {
				out = append(out, InspectFinding{ID: "dom-brand-subdomain", Title: fmt.Sprintf("Subdomain mentions well-known name %q on an unrelated registrable domain", br),
					Severity: "low", Technique: "T1583.001", Weight: 10, Evidence: truncStr(strings.Join(p.Subdomains, "."), 100) + "." + p.Registrable})
				return out
			}
		}
	}
	return out
}
