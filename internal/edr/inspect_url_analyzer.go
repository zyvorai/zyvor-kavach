// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// URL inspector analyzer (kind "url"). Parse only: no DNS, no fetch, no
// redirect following. Lexical findings carry modest weights; no single lexical
// signal reaches the "suspicious" level (40). javascript:/data:text/html with
// script are scheme-based and stronger. See docs/url-email-inspection.md.

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// URLPhishThreshold is the report score at or above which the evaluation counts
// a URL as "phishing-like". It is a documented evaluation threshold, not a
// verdict level.
const URLPhishThreshold = 20

func init() {
	RegisterAnalyzer("url", []string{InspectKindURL}, analyzeURL)
}

type urlResult struct {
	Findings []InspectFinding
	IOCs     []InspectIOC
	Parts    URLParts
}

func inspScratchBuilder(name string) *InspectBuilder {
	return &InspectBuilder{r: &InspectReport{}, analyzer: name, seenIOC: map[string]bool{}}
}

func analyzeURL(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	b.Format("url")
	text := strings.TrimSpace(in.Text)
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = strings.TrimSpace(text[:i]) // one URL per request
	}
	res := urlCollect(ctx, text, 0)
	b.Meta("parse", res.Parts)
	b.Meta("threshold", URLPhishThreshold)
	b.Meta("note", "lexical heuristics, parse only, never fetched; see docs/url-email-inspection.md")
	for _, f := range res.Findings {
		b.Finding(f)
	}
	for _, i := range res.IOCs {
		b.IOC(i.Type, i.Value)
	}
	return ctx.Err()
}

var (
	em_reDoublePct  = regexp.MustCompile(`(?i)%25[0-9a-f]{2}`)
	em_reUnreserved = regexp.MustCompile(`%(?:3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])`)
	em_reScriptish  = regexp.MustCompile(`(?i)<script|onerror\s*=|onload\s*=|<iframe|document\.(cookie|location|write)|eval\(|atob\(`)
)

var urlPathKeywords = []string{"login", "signin", "sign-in", "verify", "secure", "account", "update", "confirm", "password", "wallet", "banking", "webscr", "authenticate", "suspend", "recover", "unlock", "billing"}
var urlRedirectParams = map[string]bool{"url": true, "u": true, "redirect": true, "redirect_uri": true, "redirect_url": true, "next": true, "goto": true, "return": true, "returnurl": true, "return_to": true, "dest": true, "destination": true, "continue": true, "target": true, "link": true, "r": true, "to": true, "out": true, "q": true}
var urlShorteners = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy")

// urlCollect analyses one URL and returns findings (ids url-*) and IOCs.
func urlCollect(ctx context.Context, raw string, depth int) urlResult {
	res := urlResult{}
	p := ParseURLTolerant(raw)
	res.Parts = p
	add := func(id, title, sev string, w int, ev string) {
		res.Findings = append(res.Findings, InspectFinding{ID: id, Title: title, Severity: sev, Weight: w, Evidence: truncStr(ev, 200)})
	}
	if strings.TrimSpace(raw) == "" {
		return res
	}
	if depth == 0 {
		res.IOCs = append(res.IOCs, InspectIOC{Type: "url", Value: truncStr(p.Cleaned, 400)})
	}
	if p.Stripped > 0 {
		add("url-control-chars", fmt.Sprintf("%d tab/newline/control characters inside the URL (browsers drop them; filters may not)", p.Stripped), "low", 8, "")
	}
	if len(p.Cleaned) >= 250 {
		add("url-long", fmt.Sprintf("Very long URL (%d chars)", len(p.Cleaned)), "info", 4, truncStr(p.Cleaned, 80))
	}

	// Scheme-based risks.
	switch p.Scheme {
	case "javascript", "vbscript":
		add("url-scheme-script", p.Scheme+": URL runs script when opened", "high", 60, truncStr(p.Path, 150))
		if depth == 0 && ctx.Err() == nil {
			urlFoldScript(ctx, &res, "url-js", urlPctDecodeOnce(p.Path))
		}
		return res
	case "data":
		meta, body, _ := strings.Cut(p.Path, ",")
		lm := strings.ToLower(meta)
		decoded := body
		if strings.Contains(lm, ";base64") {
			if d, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.NewReplacer("%3D", "=", "%3d", "=").Replace(body), "=")); err == nil {
				decoded = string(d)
			}
		} else {
			decoded = urlPctDecodeOnce(body)
		}
		switch {
		case strings.HasPrefix(lm, "text/html") || strings.HasPrefix(lm, "application/xhtml") || strings.HasPrefix(lm, "image/svg"):
			if em_reScriptish.MatchString(decoded) {
				add("url-data-html-script", "data: URL carries HTML/SVG with script", "high", 55, truncStr(decoded, 120))
				if depth == 0 && ctx.Err() == nil {
					urlFoldScript(ctx, &res, "url-data", decoded)
				}
			} else {
				add("url-data-html", "data: URL carries an HTML document (used to host phishing pages without a server)", "medium", 25, truncStr(decoded, 120))
			}
		default:
			add("url-data", "data: URL", "low", 10, truncStr(meta, 80))
		}
		return res
	case "file":
		add("url-scheme-file", "file: URL (local file reference)", "low", 20, truncStr(p.Cleaned, 120))
		return res
	case "mailto", "tel", "about", "blob":
		return res
	}
	if !p.HasAuth {
		return res
	}

	// Authority tricks.
	if p.UserInfo != "" {
		ui := strings.ToLower(urlPctDecodeOnce(p.UserInfo))
		if i := strings.IndexByte(ui, ':'); i >= 0 && !strings.Contains(ui[:i], ".") {
			// user:password form; the password part may hold the lookalike
			ui = ui[i+1:] + " " + ui[:i]
		}
		if strings.Contains(ui, ".") || strings.Contains(ui, "://") || strings.Contains(ui, "www") {
			add("url-userinfo-lookalike", "Userinfo before '@' looks like a domain; the real host is after the '@'", "medium", 28, p.UserInfo+" @ "+p.Host)
		} else {
			add("url-userinfo", "URL contains userinfo before '@' (rare in legitimate links)", "low", 10, p.UserInfo+" @ "+p.Host)
		}
	}
	if p.Port != "" {
		port := 0
		okNum := true
		for _, c := range p.Port {
			if c < '0' || c > '9' {
				okNum = false
				break
			}
			port = port*10 + int(c-'0')
			if port > 1<<20 {
				break
			}
		}
		switch {
		case !okNum || port > 65535 || port == 0:
			add("url-port-invalid", "Invalid port", "low", 12, p.Port)
		default:
			if !((p.Scheme == "http" && port == 80) || (p.Scheme == "https" && port == 443)) {
				add("url-port-odd", fmt.Sprintf("Non-standard port %d", port), "info", 6, p.Port)
			}
		}
	}
	host := p.HostDec
	for _, dot := range []string{"。", "．", "｡"} {
		if strings.Contains(host, dot) {
			add("url-unicode-dots", "Host uses Unicode full-stop lookalikes as label separators", "medium", 15, p.Host)
			host = strings.ReplaceAll(host, dot, ".")
		}
	}
	if strings.Contains(p.Host, "%") {
		add("url-host-percent-encoded", "Host name contains percent-encoding (never needed in a real host)", "medium", 22, p.Host)
	}
	switch p.IPForm {
	case "dotted", "ipv6":
		add("url-ip-host", "Host is a raw IP address", "low", 12, p.IPCanon)
	case "":
	default:
		add("url-ip-obfuscated", "Host is an IP written as "+p.IPForm+" number(s); canonical form "+p.IPCanon, "medium", 25, p.Host)
	}
	if p.IPCanon != "" {
		t := "ipv4"
		if p.IPForm == "ipv6" {
			t = "ipv6"
		}
		res.IOCs = append(res.IOCs, InspectIOC{Type: t, Value: p.IPCanon})
	} else if host != "" {
		// Reuse the domain analyzer on the host (punycode, mixed script,
		// typosquat, DGA shape, suspicious TLD, brand). Offline.
		sb := inspScratchBuilder("domain")
		_ = analyzeDomain(ctx, InspectInput{Kind: InspectKindDomain, Text: host}, sb)
		for _, f := range sb.r.Findings {
			f.ID = "url-host-" + strings.TrimPrefix(f.ID, "dom-")
			f.Title = "Host: " + f.Title
			res.Findings = append(res.Findings, f)
		}
		res.IOCs = append(res.IOCs, sb.r.IOCs...)
		pd := ParseDomain(host)
		if len(pd.Labels) >= 6 {
			add("url-many-subdomains", fmt.Sprintf("Host has %d labels", len(pd.Labels)), "info", 5, host)
		}
		if len(host) > 60 {
			add("url-long-host", fmt.Sprintf("Very long host name (%d chars)", len(host)), "info", 5, host)
		}
		if strings.Count(host, "-") >= 3 {
			add("url-host-hyphens", "Host has many hyphens", "info", 4, host)
		}
		if urlShorteners[pd.Registrable] {
			add("url-shortener", "Link shortener: the real destination is hidden (not resolved here)", "low", 6, host)
		}
	}

	// Path / query lexical features.
	full := p.Path + "?" + p.Query
	if em_reDoublePct.MatchString(full) {
		add("url-double-encoding", "Percent-encoding applied twice (%25xx)", "low", 10, truncStr(full, 100))
	}
	if n := len(em_reUnreserved.FindAllString(full, -1)); n >= 3 {
		add("url-encoded-plain-chars", fmt.Sprintf("%d letters/digits percent-encoded needlessly", n), "low", 8, truncStr(full, 100))
	}
	dp := strings.ToLower(urlPctDecodeOnce(urlPctDecodeOnce(p.Path)))
	if strings.Contains(dp, "../") || strings.Contains(dp, "..\\") || strings.HasSuffix(dp, "/..") {
		add("url-path-traversal", "Path contains ../ traversal", "low", 8, truncStr(p.Path, 100))
	}
	kw := map[string]bool{}
	for _, k := range urlPathKeywords {
		if strings.Contains(dp, k) || strings.Contains(strings.ToLower(p.Query), k) {
			kw[k] = true
		}
	}
	if len(kw) >= 2 {
		add("url-path-keywords", fmt.Sprintf("%d credential/account keywords in path or query", len(kw)), "info", 8, truncStr(p.Path+"?"+p.Query, 100))
	}
	if p.Scheme == "http" && len(kw) >= 1 && p.IPForm == "" {
		add("url-plain-http-login", "Account-style URL over plain http", "info", 4, truncStr(p.Cleaned, 80))
	}

	// Query parameters: blobs and nested redirect targets.
	blob := false
	for _, kv := range strings.FieldsFunc(p.Query, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(kv, "=")
		dv := urlPctDecodeOnce(urlPctDecodeOnce(v))
		if !blob && len(dv) >= 64 && shannon(dv) >= 4.2 && !strings.Contains(dv, "://") {
			blob = true
			add("url-query-blob", fmt.Sprintf("Query parameter %q holds a %d-char high-entropy blob", truncStr(k, 20), len(dv)), "info", 6, truncStr(dv, 60))
		}
		if depth < 2 && (strings.HasPrefix(strings.ToLower(dv), "http://") || strings.HasPrefix(strings.ToLower(dv), "https://") || strings.HasPrefix(dv, "//")) {
			in := ParseURLTolerant(dv)
			if in.Host == "" {
				continue
			}
			outer, inner := ParseDomain(host).Registrable, ParseDomain(in.HostDec).Registrable
			if in.IPCanon != "" {
				inner = in.IPCanon
			}
			if outer != inner {
				w := 8
				if urlRedirectParams[strings.ToLower(k)] {
					w = 12
				}
				add("url-nested-redirect", fmt.Sprintf("Parameter %q carries a URL to a different site (%s); possible open-redirect abuse", truncStr(k, 20), inner), "low", w, truncStr(dv, 120))
				sub := urlCollect(ctx, dv, depth+1)
				for _, f := range sub.Findings {
					f.ID = "url-nested-" + strings.TrimPrefix(f.ID, "url-")
					f.Title = "Redirect target: " + f.Title
					f.Weight = (f.Weight + 1) / 2
					res.Findings = append(res.Findings, f)
				}
				res.IOCs = append(res.IOCs, sub.IOCs...)
			}
		}
	}
	return res
}

// urlFoldScript runs the registered script analyzers on extracted code and folds
// the findings in (ids prefixed). It reuses the deobfuscation engine and byte
// rules through RunAnalyzers; nothing is executed.
func urlFoldScript(ctx context.Context, res *urlResult, prefix, code string) {
	if len(code) > 256<<10 {
		code = code[:256<<10]
	}
	if strings.TrimSpace(code) == "" {
		return
	}
	rep := RunAnalyzers(ctx, InspectInput{Kind: InspectKindScript, Text: code})
	for _, f := range rep.Findings {
		f.ID = prefix + "-" + f.ID
		f.Title = "Embedded script: " + f.Title
		res.Findings = append(res.Findings, f)
	}
	res.IOCs = append(res.IOCs, rep.IOCs...)
}
