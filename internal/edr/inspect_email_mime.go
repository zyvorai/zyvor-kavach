// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Email inspector: MIME walking, HTML body checks and attachment analysis.
// Uses only net/mail, mime, mime/multipart and mime/quotedprintable.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path"
	"regexp"
	"strings"
)

var (
	em_reURLText   = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"'\x60\\^{}|]+`)
	em_reAnchor    = regexp.MustCompile(`(?is)<a\b([^>]*)>(.*?)</a\s*>`)
	em_reHref      = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	em_reTag       = regexp.MustCompile(`(?s)<[^>]*>`)
	em_reForm      = regexp.MustCompile(`(?is)<form\b([^>]*)>`)
	em_reAction    = regexp.MustCompile(`(?is)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	em_rePassword  = regexp.MustCompile(`(?is)<input\b[^>]*type\s*=\s*["']?password`)
	em_reHidden    = regexp.MustCompile(`(?is)<[a-z0-9]+\b[^>]*style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|max-height\s*:\s*0)[^"]*"[^>]*>(.{0,1000}?)</`)
	em_reZeroFont  = regexp.MustCompile(`(?is)font-size\s*:\s*0(?:px|pt|em|rem|%)?\s*(?:;|"|'|!)`)
	em_reDataSrc   = regexp.MustCompile(`(?is)\bsrc\s*=\s*["']?data:`)
	em_reScriptTag = regexp.MustCompile(`(?is)<script\b`)
	em_reIframe    = regexp.MustCompile(`(?is)<(?:iframe|object|embed)\b`)
	em_reMetaRef   = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?refresh`)
	em_reBaseTag   = regexp.MustCompile(`(?is)<base\b[^>]*href`)
	em_reVisDomain = regexp.MustCompile(`(?i)^\s*(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:\s?#]|$)`)
)

func emailFirstGroup(m []string) string {
	for _, s := range m[1:] {
		if s != "" {
			return s
		}
	}
	return ""
}

func (st *emailState) addURL(u string) {
	u = strings.TrimRight(strings.TrimSpace(u), ".,;:!?)]'\"")
	if u == "" || st.urlSeen[u] {
		return
	}
	st.urlSeen[u] = true
	if len(st.urls) >= emailMaxURLs {
		st.urlsCapped = true
		return
	}
	st.urls = append(st.urls, u)
}

func (st *emailState) scanText(text, where string) {
	if len(text) > 1<<20 {
		text = text[:1<<20]
	}
	for _, m := range em_reURLText.FindAllString(text, 200) {
		st.addURL(m)
	}
	st.textBlobs = append(st.textBlobs, text)
}

func emReadCapped(r io.Reader, n int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(r, n+1))
	if int64(len(data)) > n {
		return data[:n], true, err
	}
	return data, false, err
}

// emDecodeBody applies Content-Transfer-Encoding with caps. Malformed input is
// decoded as far as possible.
func emDecodeBody(r io.Reader, cte string, limit int64) ([]byte, bool, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		raw, over, err := emReadCapped(r, limit*4/3+16)
		clean := make([]byte, 0, len(raw))
		for _, c := range raw {
			if c == '=' || c == '+' || c == '/' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				clean = append(clean, c)
			}
		}
		clean = []byte(strings.TrimRight(string(clean), "="))
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
		n, _ := base64.RawStdEncoding.Decode(out, clean)
		return out[:n], over, err
	case "quoted-printable":
		return emReadCapped(quotedprintable.NewReader(r), limit)
	default:
		return emReadCapped(r, limit)
	}
}

func (st *emailState) walk(body io.Reader, h map[string][]string, depth int) {
	if st.ctx.Err() != nil {
		return
	}
	st.parts++
	if st.parts > emailMaxParts {
		st.b.LimitHit("mime-parts")
		return
	}
	if depth > emailMaxDepth {
		st.addOnce("email-mime-too-deep", "MIME nesting deeper than the cap; deeper parts were not analysed", "low", 8, fmt.Sprintf("depth>%d", emailMaxDepth))
		st.b.LimitHit("mime-depth")
		return
	}
	ctHdr := emHget(h, "Content-Type")
	ct, params, err := mime.ParseMediaType(ctHdr)
	if err != nil && ctHdr != "" && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		st.addOnce("email-mime-bad-content-type", "Malformed Content-Type header", "info", 3, truncStr(ctHdr, 80))
	}
	if ct == "" {
		ct = "text/plain"
	}
	ct = strings.ToLower(ct)
	cte := emHget(h, "Content-Transfer-Encoding")
	switch {
	case strings.HasPrefix(ct, "multipart/"):
		bd := params["boundary"]
		switch {
		case bd == "":
			st.addOnce("email-mime-no-boundary", "multipart without a boundary", "low", 5, ct)
			return
		case len(bd) > 200:
			st.addOnce("email-mime-boundary-huge", fmt.Sprintf("MIME boundary is %d chars (RFC 2046 allows 70); parsing skipped", len(bd)), "low", 10, "")
			return
		case len(bd) > 70:
			st.addOnce("email-mime-boundary-long", fmt.Sprintf("MIME boundary is %d chars (RFC 2046 allows 70)", len(bd)), "info", 4, "")
		}
		mr := multipart.NewReader(body, bd)
		for i := 0; i < emailMaxParts; i++ {
			p, err := mr.NextRawPart()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					st.addOnce("email-mime-truncated", "MIME structure truncated or malformed: "+truncStr(err.Error(), 80), "info", 3, "")
				}
				return
			}
			st.walk(p, p.Header, depth+1)
			if st.ctx.Err() != nil {
				return
			}
		}
		st.b.LimitHit("mime-parts")
		return
	case ct == "message/rfc822" || ct == "message/global":
		data, over, _ := emDecodeBody(body, cte, emailMaxPartBytes)
		st.account(len(data), over)
		if m, err := mail.ReadMessage(strings.NewReader(string(data))); err == nil {
			st.addOnce("email-embedded-message", "Attached/forwarded message analysed as nested mail", "info", 0, "")
			st.walk(m.Body, m.Header, depth+1)
		}
		return
	}
	room := int64(emailMaxTotalBytes - st.totalBytes)
	if room <= 0 {
		st.b.LimitHit("decoded-bytes")
		return
	}
	lim := int64(emailMaxPartBytes)
	if room < lim {
		lim = room
	}
	data, over, _ := emDecodeBody(body, cte, lim)
	st.account(len(data), over)

	name := emPartFilename(h, params)
	disp, _, _ := mime.ParseMediaType(emHget(h, "Content-Disposition"))
	isAtt := strings.EqualFold(disp, "attachment") || name != "" ||
		(!strings.HasPrefix(ct, "text/") && !strings.HasPrefix(ct, "image/") && !strings.HasPrefix(ct, "multipart/"))
	if !isAtt {
		switch ct {
		case "text/html", "application/xhtml+xml":
			st.analyzeHTML(string(data))
		case "text/plain":
			st.scanText(string(data), "text")
		}
		return
	}
	st.attachment(name, ct, data)
}

func (st *emailState) account(n int, over bool) {
	st.totalBytes += n
	if over || st.totalBytes >= emailMaxTotalBytes {
		st.b.LimitHit("decoded-bytes")
	}
}

func emPartFilename(h map[string][]string, ctParams map[string]string) string {
	_, dp, _ := mime.ParseMediaType(emHget(h, "Content-Disposition"))
	n := dp["filename"]
	if n == "" {
		n = ctParams["name"]
	}
	if n == "" {
		return ""
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(n); err == nil {
		n = dec
	}
	return n
}

func (st *emailState) analyzeHTML(src string) {
	if len(src) > 2<<20 {
		src = src[:2<<20]
	}
	// Anchors: href targets and text-vs-href mismatch.
	mism := 0
	for i, m := range em_reAnchor.FindAllStringSubmatch(src, 500) {
		_ = i
		hm := em_reHref.FindStringSubmatch(m[1])
		if hm == nil {
			continue
		}
		href := strings.TrimSpace(html.UnescapeString(emailFirstGroup(hm)))
		if href == "" || strings.HasPrefix(href, "#") {
			continue
		}
		low := strings.ToLower(href)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "vbscript:") {
			st.addURL(href)
		}
		text := strings.TrimSpace(html.UnescapeString(em_reTag.ReplaceAllString(m[2], " ")))
		if v := em_reVisDomain.FindStringSubmatch(text); v != nil {
			hp := ParseURLTolerant(href)
			if hp.HostDec != "" && emailReg(v[1]) != emailReg(hp.HostDec) {
				mism++
				if mism == 1 {
					st.add("email-link-text-mismatch", "Link text shows one site but the href goes to another", "medium", 30, truncStr(text, 60)+" -> "+truncStr(href, 100))
				}
			}
		}
	}
	for _, m := range em_reURLText.FindAllString(em_reTag.ReplaceAllString(src, " "), 100) {
		st.addURL(html.UnescapeString(m))
	}
	// Forms.
	for _, m := range em_reForm.FindAllStringSubmatch(src, 20) {
		act := ""
		if am := em_reAction.FindStringSubmatch(m[1]); am != nil {
			act = html.UnescapeString(emailFirstGroup(am))
		}
		ap := ParseURLTolerant(act)
		if (ap.Scheme == "http" || ap.Scheme == "https") && ap.HostDec != "" && emailReg(ap.HostDec) != st.fromReg {
			st.addOnce("email-form-external-action", "HTML form posts to a host other than the sender's domain", "medium", 22, act)
		} else {
			st.addOnce("email-form", "HTML form inside the message (many clients block these; phishing uses them)", "low", 6, act)
		}
	}
	if em_rePassword.MatchString(src) {
		st.add("email-form-password", "Password input field inside the message", "medium", 20, "")
	}
	if m := em_reHidden.FindStringSubmatch(src); m != nil && len(strings.TrimSpace(em_reTag.ReplaceAllString(m[1], ""))) >= 40 {
		st.add("email-html-hidden-text", "Visible-to-parser but hidden text block (also how legitimate preheaders are made)", "info", 4, truncStr(strings.TrimSpace(em_reTag.ReplaceAllString(m[1], "")), 80))
	}
	if em_reZeroFont.MatchString(src) {
		st.add("email-html-zero-font", "font-size:0 text (hides content from readers; filter-evasion shape)", "info", 3, "")
	}
	if em_reDataSrc.MatchString(src) {
		st.add("email-html-data-uri", "data: URI used as a resource source", "info", 3, "")
	}
	if em_reScriptTag.MatchString(src) {
		st.add("email-html-script", "<script> in an HTML mail body", "medium", 20, "")
	}
	if em_reIframe.MatchString(src) {
		st.add("email-html-embed", "iframe/object/embed in an HTML mail body", "low", 12, "")
	}
	if em_reMetaRef.MatchString(src) {
		st.add("email-html-meta-refresh", "meta refresh redirect in an HTML mail body", "low", 15, "")
	}
	if em_reBaseTag.MatchString(src) {
		st.add("email-html-base-href", "<base href> rewrites all relative links", "low", 8, "")
	}
	st.textBlobs = append(st.textBlobs, html.UnescapeString(em_reTag.ReplaceAllString(src, " ")))
}

var (
	emailDocExts   = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "rtf", "csv", "zip", "htm", "html")
	emailExecExts  = setOf("exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "ps1", "msi", "dll", "cpl", "reg", "msc", "sh")
	emailBoxExts   = setOf("iso", "img", "vhd", "vhdx", "rar", "7z", "ace", "cab", "gz")
	emailMacroExts = setOf("docm", "xlsm", "pptm", "dotm", "xlsb", "xlam", "xla")
	emailScriptExt = setOf("js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "hta", "wsf", "sh", "py")
	emailNativeFmt = setOf("PE", "DOS/MZ", "ELF", "Mach-O", "Mach-O fat", "LNK", "script (shebang)")
)

func (st *emailState) attachment(name, ct string, data []byte) {
	b := st.b
	st.attCount++
	if st.attCount > emailMaxAttachments {
		b.LimitHit("attachments")
		return
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	b.IOC("sha256", hash)
	label := name
	if label == "" {
		label = "(unnamed " + ct + ")"
	}
	label = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, label)
	format := detectFileFormat(data)
	st.attMeta = append(st.attMeta, map[string]any{"name": truncStr(label, 120), "content_type": ct, "size": len(data), "sha256": hash, "format": format})
	fs := func(id, title, sev string, w int, ev string) {
		st.add("email-att-"+id, fmt.Sprintf("Attachment %q: %s", truncStr(label, 60), title), sev, w, ev)
	}
	lower := strings.ToLower(path.Base(strings.ReplaceAll(label, "\\", "/")))
	exts := strings.Split(lower, ".")
	ext, prev := "", ""
	if len(exts) > 1 {
		ext = strings.TrimSpace(exts[len(exts)-1])
		if len(exts) > 2 {
			prev = strings.TrimSpace(exts[len(exts)-2])
		}
	}
	if strings.ContainsAny(label, "‮‭‫‪⁦⁧⁨") {
		fs("bidi-name", "file name contains a right-to-left override/bidi control character (extension spoofing)", "high", 35, label)
	}
	switch {
	case prev != "" && emailDocExts[prev] && (emailExecExts[ext] || emailMacroExts[ext]):
		fs("double-extension", fmt.Sprintf("double extension .%s.%s (document name hiding an executable type)", prev, ext), "high", 35, label)
	case emailExecExts[ext]:
		fs("risky-type", "executable/script file type ."+ext, "medium", 20, label)
	case emailBoxExts[ext]:
		fs("container-type", "archive/disk-image type ."+ext+" (often used to carry payloads past filters)", "low", 8, label)
	case emailMacroExts[ext]:
		fs("macro-type", "macro-enabled Office type ."+ext, "low", 8, label)
	case ext == "html" || ext == "htm":
		fs("html-attachment", "HTML attachment (credential-harvesting pages are delivered this way)", "low", 10, label)
	case ext == "chm" || ext == "one":
		fs("risky-type", "type ."+ext+" can run content when opened", "medium", 15, label)
	}
	if len(label) > 20 && strings.Contains(label, strings.Repeat(" ", 10)) {
		fs("padded-name", "long run of spaces in the file name (hides the real extension)", "low", 15, truncStr(label, 80))
	}
	if emailNativeFmt[format] && (emailDocExts[ext] || ext == "") && ext != "" {
		fs("type-mismatch", "content is "+format+" but the name says ."+ext, "high", 40, label)
	}
	if ext == "html" || ext == "htm" {
		st.analyzeHTML(string(data))
	}
	if st.analyzed >= emailMaxAnalyzed || st.ctx.Err() != nil {
		b.LimitHit("attachments-analyzed")
		return
	}
	if strings.HasPrefix(ct, "image/") && format == "" {
		return // plain image, nothing for the file analyzers to add
	}
	st.analyzed++
	rep := RunAnalyzers(st.ctx, InspectInput{Kind: InspectKindFile, Name: label, Data: data})
	emFoldReport(st, rep, "email-att-", fmt.Sprintf("Attachment %q: ", truncStr(label, 60)))
	if emailScriptExt[ext] {
		txt := string(data)
		if len(txt) > 1<<20 {
			txt = txt[:1<<20]
		}
		emFoldReport(st, RunAnalyzers(st.ctx, InspectInput{Kind: InspectKindScript, Name: label, Text: txt}), "email-att-script-", fmt.Sprintf("Attachment %q (script): ", truncStr(label, 60)))
	}
}

func emFoldReport(st *emailState, rep *InspectReport, idPrefix, titlePrefix string) {
	for _, f := range rep.Findings {
		f.ID = idPrefix + f.ID
		f.Title = titlePrefix + f.Title
		st.b.Finding(f)
	}
	for _, i := range rep.IOCs {
		st.b.IOC(i.Type, i.Value)
	}
	for _, e := range rep.Errors {
		st.b.LimitHit("attachment-analyzer-error:" + truncStr(e, 40))
	}
}
