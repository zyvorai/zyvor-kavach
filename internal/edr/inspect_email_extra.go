// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// email-extra: complements the "email" analyzer with phishing-focused checks
// that carry ATT&CK technique ids (T1566.001 attachment, T1566.002 link), a
// basic Outlook .msg (OLE2) detector, hidden-link / tracking-pixel / QR-image
// hints in HTML bodies and refanging of defanged URLs (hxxp, [.], (dot)).
// Parse only: nothing is executed, fetched or stored.

import (
	"context"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"path"
	"regexp"
	"strings"
)

const (
	emxMaxDepth  = 6
	emxMaxParts  = 200
	emxMaxBody   = 4 << 20
	emxMaxMsgURL = 100
)

var (
	emxImg       = regexp.MustCompile(`(?is)<img\b([^>]*)>`)
	emxSrc       = regexp.MustCompile(`(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	emxDim       = regexp.MustCompile(`(?is)\b(?:width|height)\s*[=:]\s*["']?\s*[01](?:px)?\s*(?:["'>;\s]|$)`)
	emxAlt       = regexp.MustCompile(`(?is)\b(?:alt|title|name|id|class)\s*=\s*["'][^"']*\bqr\b[^"']*["']`)
	emxScanText  = regexp.MustCompile(`(?i)\bscan\b[^.]{0,60}\b(?:qr|code|camera|phone)\b|\bqr\s*code\b`)
	emxHiddenSty = regexp.MustCompile(`(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|")|(?:width|height)\s*:\s*[01]px|text-indent\s*:\s*-\d{3,}`)
	emxDefanged  = regexp.MustCompile(`(?i)\bh(?:xx|\*\*|xt)ps?(?::|\[:\]|\[://\])//[^\s<>"']{3,200}|\bh(?:xx|\*\*|xt)ps?\[:\]//[^\s<>"']{3,200}`)
	emxDefProto  = regexp.MustCompile(`(?i)^h(?:xx|\*\*|xt)p(s?)(?::|\[:\]|\[://\])(?://)?`)
	emxQRName    = regexp.MustCompile(`(?i)\bqr|qr[-_.]|[-_.]qr`)
	emxMsgName   = regexp.MustCompile(`(?i)[A-Za-z0-9_\-. ()]{1,80}\.(?:exe|scr|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|jar|lnk|ps1|msi|dll|iso|img|chm|one|docm|xlsm|pptm)\b`)
	emxBracket   = strings.NewReplacer("[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", "[at]", "@")
)

var emxExecExt = setOf("exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "ps1", "msi", "dll", "cpl", "iso", "img", "vhd", "vhdx", "chm", "one", "docm", "xlsm", "pptm", "xlsb", "html", "htm", "svg")
var emxDocExt = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "rtf", "csv", "zip")

func init() {
	RegisterAnalyzer("email-extra", []string{InspectKindEmail}, analyzeEmailExtra)
}

type emxState struct {
	ctx   context.Context
	b     *InspectBuilder
	once  map[string]bool
	parts int
	names []string
	html  []string
	text  []string
}

func (s *emxState) add(id, title, sev string, w int, tech, ev string) {
	if s.once[id] {
		return
	}
	s.once[id] = true
	s.b.Finding(InspectFinding{ID: id, Title: title, Severity: sev, Weight: w, Technique: tech, Evidence: truncStr(ev, 160)})
}

func analyzeEmailExtra(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	raw := in.Text
	if len(raw) >= 8 && raw[:8] == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" {
		return analyzeMsg(ctx, []byte(raw), b)
	}
	if len(raw) > InspectMaxTextBytes {
		raw = raw[:InspectMaxTextBytes]
	}
	if strings.HasPrefix(raw, "From ") {
		if i := strings.IndexByte(raw, '\n'); i >= 0 {
			raw = raw[i+1:]
		}
	}
	s := &emxState{ctx: ctx, b: b, once: map[string]bool{}}
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		s.text = append(s.text, raw)
	} else {
		s.walk(msg.Body, msg.Header, 0)
	}
	for _, h := range s.html {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.analyzeHTML(h)
	}
	s.refang()
	if len(s.names) > 0 {
		b.Meta("email-extra.attachment_names", s.names)
	}
	return ctx.Err()
}

func (s *emxState) walk(body io.Reader, h map[string][]string, depth int) {
	s.parts++
	if s.ctx.Err() != nil {
		return
	}
	if s.parts > emxMaxParts || depth > emxMaxDepth {
		s.b.LimitHit("email-extra-parts")
		return
	}
	ct, params, _ := mime.ParseMediaType(emHget(h, "Content-Type"))
	ct = strings.ToLower(ct)
	if ct == "" {
		ct = "text/plain"
	}
	if strings.HasPrefix(ct, "multipart/") {
		bd := params["boundary"]
		if bd == "" || len(bd) > 200 {
			return
		}
		mr := multipart.NewReader(body, bd)
		for i := 0; i < emxMaxParts; i++ {
			p, err := mr.NextPart()
			if err != nil {
				return
			}
			s.walk(p, p.Header, depth+1)
		}
		return
	}
	if ct == "message/rfc822" {
		data, _, _ := emReadCapped(body, emxMaxBody)
		if m, err := mail.ReadMessage(strings.NewReader(string(data))); err == nil {
			s.walk(m.Body, m.Header, depth+1)
		}
		return
	}
	name := emPartFilename(h, params)
	data, _, _ := emDecodeBody(body, emHget(h, "Content-Transfer-Encoding"), emxMaxBody)
	if name != "" {
		s.attachment(name)
	}
	switch {
	case ct == "text/html" && name == "":
		s.html = append(s.html, string(data))
	case ct == "text/plain" && name == "":
		s.text = append(s.text, string(data))
	case strings.HasPrefix(ct, "image/"):
		if emxQRName.MatchString(strings.ToLower(name + " " + emHget(h, "Content-ID"))) {
			s.add("email-x-qr-image-name", "Image named like a QR code (quishing: the link is in the picture, invisible to URL scanning)", "medium", 18, "T1566.002", name)
		}
	}
}

func (s *emxState) attachment(name string) {
	if len(s.names) < 50 {
		s.names = append(s.names, truncStr(name, 80))
	}
	low := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	parts := strings.Split(low, ".")
	if len(parts) < 2 {
		return
	}
	ext, prev := strings.TrimSpace(parts[len(parts)-1]), ""
	if len(parts) > 2 {
		prev = strings.TrimSpace(parts[len(parts)-2])
	}
	switch {
	case prev != "" && emxDocExt[prev] && emxExecExt[ext]:
		s.add("email-x-att-double-ext", fmt.Sprintf("Attachment %q looks like a .%s document but ends in .%s", truncStr(name, 60), prev, ext), "high", 12, "T1566.001", name)
	case emxExecExt[ext]:
		s.add("email-x-att-dangerous-ext", fmt.Sprintf("Attachment with dangerous extension .%s", ext), "medium", 8, "T1566.001", name)
	}
}

func (s *emxState) analyzeHTML(src string) {
	if len(src) > 2<<20 {
		src = src[:2<<20]
	}
	for _, m := range em_reAnchor.FindAllStringSubmatch(src, 500) {
		hm := em_reHref.FindStringSubmatch(m[1])
		if hm == nil {
			continue
		}
		href := strings.TrimSpace(html.UnescapeString(emailFirstGroup(hm)))
		if !strings.HasPrefix(strings.ToLower(href), "http") {
			continue
		}
		inner := strings.TrimSpace(em_reTag.ReplaceAllString(m[2], ""))
		if emxHiddenSty.MatchString(m[1]) {
			s.add("email-x-hidden-link", "Link hidden with CSS (display:none, zero size or font)", "medium", 16, "T1566.002", href)
		} else if inner == "" && !strings.Contains(strings.ToLower(m[2]), "<img") {
			s.add("email-x-empty-link", "Link with no visible text or image", "low", 6, "T1566.002", href)
		}
	}
	for _, m := range emxImg.FindAllStringSubmatch(src, 300) {
		attrs := m[1]
		sm := emxSrc.FindStringSubmatch(attrs)
		if sm == nil {
			continue
		}
		u := strings.ToLower(strings.TrimSpace(emailFirstGroup(sm)))
		if (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) && emxDim.MatchString(attrs) {
			s.add("email-x-tracking-pixel", "1x1 or 0-size remote image (tracking pixel; loading it tells the sender the mail was opened)", "info", 0, "", u)
		}
		if emxAlt.MatchString(attrs) {
			s.add("email-x-qr-image-hint", "Image tagged as a QR code", "low", 10, "T1566.002", "")
		}
	}
	text := html.UnescapeString(em_reTag.ReplaceAllString(src, " "))
	if emxScanText.MatchString(text) && strings.Contains(strings.ToLower(src), "<img") {
		s.add("email-x-qr-lure-text", "Body asks the reader to scan a QR code and contains an image (quishing shape; the image is not decoded here)", "low", 10, "T1566.002", "")
	}
	s.text = append(s.text, text)
}

// refang finds defanged URLs (hxxps://evil[.]com) in text and records the
// restored form as an IOC. They are never fetched.
func (s *emxState) refang() {
	n := 0
	for _, t := range s.text {
		if len(t) > 1<<20 {
			t = t[:1<<20]
		}
		t = emxBracket.Replace(t)
		for _, m := range emxDefanged.FindAllString(t, 50) {
			u := emxDefProto.ReplaceAllString(m, "http$1://")
			if !strings.HasPrefix(u, "http") || u == m {
				continue
			}
			if n++; n > 50 {
				return
			}
			s.b.IOC("url", truncStr(u, 300))
			s.add("email-x-defanged-url", "Defanged URL (hxxp / [.]) in the message, refanged as an indicator; normal in reports, unusual in a delivered mail", "low", 6, "T1566.002", m)
		}
	}
}

// analyzeMsg is a basic Outlook .msg detector: it does not walk the CFB
// directory. It scans the bytes for stream-name markers, attachment names and
// URLs (ASCII and UTF-16LE) and hands the whole file to the file analyzers.
func analyzeMsg(ctx context.Context, data []byte, b *InspectBuilder) error {
	str := string(data)
	u16 := func(s string) string {
		o := make([]byte, 0, len(s)*2)
		for i := 0; i < len(s); i++ {
			o = append(o, s[i], 0)
		}
		return string(o)
	}
	count := func(s string) int { return strings.Count(str, s) + strings.Count(str, u16(s)) }
	if count("__substg1.0_") == 0 && count("__properties_version1.0") == 0 {
		return nil
	}
	b.Format("msg")
	s := &emxState{ctx: ctx, b: b, once: map[string]bool{}}
	b.Finding(InspectFinding{ID: "email-x-msg-detected", Title: "Outlook .msg message (OLE2 compound file); header-level scan only, the CFB streams are not walked", Severity: "info"})
	att := count("__attach_version1.0_#")
	b.Meta("email-extra.msg", map[string]any{"attachments": att, "size": len(data)})
	if att > 0 {
		s.add("email-x-msg-attachments", fmt.Sprintf("%d attachment storage(s) in the .msg", att), "info", 2, "T1566.001", "")
	}
	txt := msgText(data)
	for _, m := range emxMsgName.FindAllString(txt, 20) {
		s.attachment(strings.TrimSpace(m))
	}
	seen := map[string]bool{}
	for _, m := range em_reURLText.FindAllString(txt, emxMaxMsgURL) {
		if !seen[m] {
			seen[m] = true
			b.IOC("url", truncStr(m, 300))
		}
	}
	if ctx.Err() == nil {
		rep := RunAnalyzers(ctx, InspectInput{Kind: InspectKindFile, Name: "message.msg", Data: data})
		for _, f := range rep.Findings {
			f.ID = "email-msg-" + f.ID
			b.Finding(f)
		}
		for _, i := range rep.IOCs {
			b.IOC(i.Type, i.Value)
		}
	}
	if len(s.names) > 0 {
		b.Meta("email-extra.attachment_names", s.names)
	}
	return ctx.Err()
}

// msgText drops single NULs so UTF-16LE ASCII reads as text, turns NUL pairs
// (string terminators) into a space and blanks other control bytes.
func msgText(data []byte) string {
	if len(data) > 8<<20 {
		data = data[:8<<20]
	}
	out := make([]byte, 0, len(data))
	prev := byte(1)
	for _, c := range data {
		was := prev
		prev = c
		if c == 0 {
			if was == 0 && len(out) > 0 && out[len(out)-1] != ' ' {
				out = append(out, ' ') // a NUL pair ends a UTF-16 string
			}
			continue
		}
		if c < 0x20 || c > 0x7e {
			c = ' '
		}
		out = append(out, c)
	}
	return string(out)
}
