// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func runKind(kind, text string) *InspectReport {
	return RunAnalyzers(context.Background(), InspectInput{Kind: kind, Text: text})
}

func idSet(r *InspectReport) map[string]InspectFinding {
	m := map[string]InspectFinding{}
	for _, f := range r.Findings {
		m[f.ID] = f
	}
	return m
}

func TestInspectKindsURLEmail(t *testing.T) {
	has := func(k string) bool {
		for _, x := range inspectKinds {
			if x == k {
				return true
			}
		}
		return false
	}
	if !has(InspectKindURL) || !has(InspectKindEmail) || InspectKindURL != "url" || InspectKindEmail != "email" {
		t.Fatalf("kinds not registered: %v", inspectKinds)
	}
	names := InspectAnalyzerNames()
	if len(names["url"]) == 0 || len(names["email"]) == 0 {
		t.Fatalf("no analyzers for url/email: %v", names)
	}
}

func TestURLTricks(t *testing.T) {
	cases := []struct{ name, url, want string }{
		{"userinfo", "http://paypal.com@evil.example/signin", "url-userinfo-lookalike"},
		{"userinfo-plain", "http://admin@files.example/x", "url-userinfo"},
		{"decimal-ip", "http://3232235777/login", "url-ip-obfuscated"},
		{"hex-ip", "http://0xC0A80101/a", "url-ip-obfuscated"},
		{"octal-ip", "http://0300.0250.0.01/a", "url-ip-obfuscated"},
		{"dotted-ip", "http://203.0.113.9/a", "url-ip-host"},
		{"port-invalid", "http://example.com:99999/", "url-port-invalid"},
		{"port-odd", "http://example.com:8081/", "url-port-odd"},
		{"punycode", "http://xn--pple-43d.com/", "url-host-punycode"},
		{"pct-host", "http://exa%6dple.com/", "url-host-percent-encoded"},
		{"double-enc", "http://example.com/a%252e%252e/b", "url-double-encoding"},
		{"traversal", "http://example.com/a/../../etc/passwd", "url-path-traversal"},
		{"js", "javascript:alert(document.cookie)", "url-scheme-script"},
		{"data-html", "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>")), "url-data-html-script"},
		{"file", "file:///C:/Windows/System32/calc.exe", "url-scheme-file"},
		{"nested", "https://good.example/r?url=https%3A%2F%2Fevil.example%2Flogin", "url-nested-redirect"},
		{"blob", "https://good.example/p?d=" + "aZ3kQ9xLm2Pq7Rt5Wy8Uv1Ns4Hd6Jb0Fc3Gx9Ke2Mo5Li8Ty1Ar7Zu4Wq6Ep3Dv0Sb9Nh2Cj5Xk8Ol1", "url-query-blob"},
		{"ctrl", "http://exam\tple.com/a", "url-control-chars"},
		{"unicode-dots", "http://example\u3002com/a", "url-unicode-dots"},
		{"shortener", "https://bit.ly/3abcDEF", "url-shortener"},
		{"typosquat", "https://paypa1.com/login", "url-host-typosquat"},
	}
	for _, c := range cases {
		r := runKind(InspectKindURL, c.url)
		if _, ok := idSet(r)[c.want]; !ok {
			t.Errorf("%s: want %s, got %v (%s)", c.name, c.want, keys(idSet(r)), c.url)
		}
	}
}

func keys(m map[string]InspectFinding) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func TestURLParseNumericHosts(t *testing.T) {
	for in, want := range map[string]string{"3232235777": "192.168.1.1", "0xc0a80101": "192.168.1.1", "0300.0250.0.01": "192.168.0.1", "192.168.1.1": "192.168.1.1", "127.1": "127.0.0.1"} {
		form, canon := urlClassifyIPHost(in)
		if form == "" || canon != want {
			t.Errorf("%s: form=%q canon=%q want %s", in, form, canon, want)
		}
	}
	if f, _ := urlClassifyIPHost("example.com"); f != "" {
		t.Error("name misclassified as ip")
	}
}

func TestURLScoring(t *testing.T) {
	// One lexical signal never reaches a verdict.
	for _, u := range []string{"http://paypal.com@evil.example/", "http://3232235777/", "http://example.com:99999/", "https://good.example/r?url=https%3A%2F%2Fevil.example%2F"} {
		if r := runKind(InspectKindURL, u); r.Score >= 40 {
			t.Errorf("%s alone reached %d (%s)", u, r.Score, r.Level)
		}
	}
	// Script scheme is stronger.
	if r := runKind(InspectKindURL, "javascript:eval(atob('YWxlcnQoMSk='))"); r.Score < 40 {
		t.Errorf("javascript: scored only %d", r.Score)
	}
	for _, u := range []string{"https://www.example.com/docs/index.html?page=2", "https://github.com/golang/go/issues/12345", "https://en.wikipedia.org/wiki/Phishing"} {
		if r := runKind(InspectKindURL, u); r.Level != "clean" {
			t.Errorf("benign %s -> %s %v", u, r.Level, r.Factors)
		}
	}
}

func TestURLNeverFetches(t *testing.T) {
	for _, f := range []string{"inspect_url_analyzer.go", "inspect_url_parse.go", "inspect_email_analyzer.go", "inspect_email_mime.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"net/http", "\"net\"", "net.Dial", "net.Lookup", "http.Get", "exec.Command", "os/exec", "net.Resolver"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s references %s", f, bad)
			}
		}
	}
}

func FuzzURLParse(f *testing.F) {
	for _, s := range []string{"http://a@b:1/c?d#e", "javascript:x", "//x", "http://[::1]:80/", "data:,", "%", "http://%zz/", "\x00\x01"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = ParseURLTolerant(s)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = urlCollect(ctx, s, 0)
	})
}

// ---- email ----

func mkMail(headers []string, body string) string {
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}

func baseHeaders(from string) []string {
	return []string{
		"From: " + from, "To: bob@corp.example", "Subject: hello",
		"Date: Tue, 10 Nov 2026 10:00:00 +0000", "Message-ID: <abc123@sender.example>",
		"MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
	}
}

func TestEmailBenignPlain(t *testing.T) {
	h := append(baseHeaders("Alice Example <alice@sender.example>"),
		"Return-Path: <alice@sender.example>",
		"Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example",
		"Received: from mail.sender.example ([198.51.100.7]) by mx.corp.example; Tue, 10 Nov 2026 10:00:05 +0000",
		"Received: from laptop ([10.0.0.5]) by mail.sender.example; Tue, 10 Nov 2026 10:00:01 +0000")
	r := runKind(InspectKindEmail, mkMail(h, "Hi Bob,\r\nlunch tomorrow? Notes: https://www.example.com/notes/lunch\r\n"))
	if r.Level != "clean" {
		t.Fatalf("benign plain mail: %s %d %v", r.Level, r.Score, r.Factors)
	}
}

func TestEmailBenignNewsletter(t *testing.T) {
	html := `<html><body><div style="display:none;font-size:0;max-height:0">Your weekly digest of product news and tips from the team, read it now</div>
<p>Hello! <a href="https://click.esp.example/track?u=` + strings.Repeat("abc123XYZ", 12) + `&redirect=https%3A%2F%2Fblog.sender.example%2Fpost">Read the post</a></p>
<p><a href="https://www.sender.example/unsubscribe?id=77">Unsubscribe</a> | <a href="https://www.sender.example/prefs">Preferences</a></p>
<img src="https://img.sender.example/p.gif" width="1" height="1"></body></html>`
	h := []string{"From: Sender News <news@sender.example>", "To: bob@corp.example", "Subject: Weekly digest",
		"Date: Tue, 10 Nov 2026 10:00:00 +0000", "Message-ID: <20261110.1@bounce.esp.example>", "Return-Path: <b-1@bounce.esp.example>",
		"MIME-Version: 1.0", "Content-Type: multipart/alternative; boundary=\"BND\"",
		"Authentication-Results: mx.corp.example; spf=pass; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example"}
	body := "--BND\r\nContent-Type: text/plain\r\n\r\nWeekly digest: https://www.sender.example/digest\r\n--BND\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + qpEnc(html) + "\r\n--BND--\r\n"
	r := runKind(InspectKindEmail, mkMail(h, body))
	if r.Level != "clean" {
		t.Fatalf("newsletter: %s %d %v", r.Level, r.Score, r.Factors)
	}
}

func qpEnc(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c == '=' {
			b.WriteString("=3D")
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func TestEmailHeaderTricks(t *testing.T) {
	cases := []struct {
		name string
		h    []string
		want string
	}{
		{"display-addr", baseHeaders(`"ceo@bigbank.example" <x@evil.example>`), "email-displayname-address"},
		{"display-brand", baseHeaders(`"PayPal Support" <help@mailer.evil.example>`), "email-displayname-brand"},
		{"reply-to", append(baseHeaders("A <a@sender.example>"), "Reply-To: a.sender@gmail.com"), "email-replyto-mismatch"},
		{"return-path", append(baseHeaders("A <a@sender.example>"), "Return-Path: <bounce@other.example>"), "email-returnpath-mismatch"},
		{"sender", append(baseHeaders("A <a@sender.example>"), "Sender: z@third.example"), "email-sender-mismatch"},
		{"msgid", append(baseHeaders("A <a@other.example>")), "email-messageid-mismatch"},
		{"dmarc", append(baseHeaders("A <a@sender.example>"), "Authentication-Results: mx.corp.example; spf=fail; dkim=none; dmarc=fail header.from=sender.example"), "email-dmarc-fail"},
		{"spf", append(baseHeaders("A <a@sender.example>"), "Authentication-Results: mx.corp.example; spf=softfail"), "email-spf-softfail"},
		{"dkim", append(baseHeaders("A <a@sender.example>"), "Authentication-Results: mx.corp.example; dkim=fail"), "email-dkim-fail"},
		{"auth-from", append(baseHeaders("A <a@sender.example>"), "Authentication-Results: mx.corp.example; dmarc=pass header.from=other.example"), "email-auth-from-mismatch"},
		{"backwards", append(baseHeaders("A <a@sender.example>"),
			"Received: from b by c; Tue, 10 Nov 2026 08:00:00 +0000",
			"Received: from a by b; Tue, 10 Nov 2026 09:30:00 +0000"), "email-received-time-backwards"},
		{"private-hop", append(baseHeaders("A <a@sender.example>"),
			"Received: from x ([8.8.8.8]) by c; Tue, 10 Nov 2026 10:00:00 +0000",
			"Received: from y ([192.168.4.4]) by x; Tue, 10 Nov 2026 09:59:00 +0000"), "email-received-private-first-hop"},
		{"typosquat-from", baseHeaders("A <a@paypa1.com>"), "email-from-typosquat"},
		{"no-auth", baseHeaders("A <a@sender.example>"), "email-auth-absent"},
		{"dkim-note", append(baseHeaders("A <a@sender.example>"), "DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=x; bh=aa; b=bb"), "email-dkim-not-recomputed"},
	}
	for _, c := range cases {
		r := runKind(InspectKindEmail, mkMail(c.h, "body\r\n"))
		if _, ok := idSet(r)[c.want]; !ok {
			t.Errorf("%s: want %s got %v", c.name, c.want, keys(idSet(r)))
		}
	}
}

func TestEmailAuthIsReportedNotRecomputed(t *testing.T) {
	h := append(baseHeaders("A <a@sender.example>"), "DKIM-Signature: v=1; d=sender.example; s=x; bh=aa; b=bb",
		"Authentication-Results: mx.corp.example; dkim=pass header.d=sender.example")
	r := runKind(InspectKindEmail, mkMail(h, "x"))
	if _, ok := idSet(r)["email-dkim-fail"]; ok {
		t.Fatal("must not compute a DKIM verdict itself")
	}
	if f := idSet(r)["email-dkim-not-recomputed"]; f.Weight != 0 {
		t.Fatal("not-recomputed note must be weightless")
	}
}

func TestEmailHTMLTricks(t *testing.T) {
	cases := map[string]string{
		"email-link-text-mismatch":     `<a href="https://evil.example/x">https://www.paypal.com/login</a>`,
		"email-form-external-action":   `<form action="https://evil.example/post"><input name=u></form>`,
		"email-form-password":          `<form action="/p"><input type="password" name="p"></form>`,
		"email-html-zero-font":         `<span style="font-size:0px;">invisible</span>`,
		"email-html-data-uri":          `<img src="data:image/png;base64,AAAA">`,
		"email-html-script":            `<script>alert(1)</script>`,
		"email-html-meta-refresh":      `<meta http-equiv="refresh" content="0;url=https://evil.example">`,
		"email-html-hidden-text":       `<div style="display:none">` + strings.Repeat("secret words ", 6) + `</div>`,
		"email-url-userinfo-lookalike": `<a href="http://paypal.com@evil.example/">Sign in</a>`,
		"email-url-scheme-script":      `<a href="javascript:alert(1)">Click</a>`,
	}
	for want, frag := range cases {
		h := []string{"From: A <a@sender.example>", "Subject: x", "Date: Tue, 10 Nov 2026 10:00:00 +0000", "Message-ID: <1@sender.example>", "MIME-Version: 1.0", "Content-Type: text/html"}
		r := runKind(InspectKindEmail, mkMail(h, "<html><body>"+frag+"</body></html>"))
		if _, ok := idSet(r)[want]; !ok {
			t.Errorf("want %s got %v", want, keys(idSet(r)))
		}
	}
}

func mimeWithAttachment(name, ctype string, data []byte) string {
	h := baseHeaders("A <a@sender.example>")
	h = h[:len(h)-1]
	h = append(h, "Content-Type: multipart/mixed; boundary=\"B\"")
	enc := base64.StdEncoding.EncodeToString(data)
	var wrapped strings.Builder
	for len(enc) > 76 {
		wrapped.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	wrapped.WriteString(enc)
	body := "--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\nContent-Type: " + ctype + "; name=\"" + name + "\"\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapped.String() + "\r\n--B--\r\n"
	return mkMail(h, body)
}

func TestEmailAttachments(t *testing.T) {
	pe := benignPEStub()
	r := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindEmail, Text: mimeWithAttachment("invoice.pdf.exe", "application/octet-stream", pe)})
	ids := idSet(r)
	if _, ok := ids["email-att-double-extension"]; !ok {
		t.Errorf("double ext missing: %v", keys(ids))
	}
	hasHash := false
	for _, i := range r.IOCs {
		if i.Type == "sha256" && len(i.Value) == 64 {
			hasHash = true
		}
	}
	if !hasHash {
		t.Error("attachment sha256 IOC missing")
	}
	folded := false
	for id := range ids {
		if strings.HasPrefix(id, "email-att-file-") || strings.HasPrefix(id, "email-att-pe") {
			folded = true
		}
	}
	_ = folded // file analyzers may stay silent on a benign stub; checked with the zip below.

	r = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindEmail, Text: mimeWithAttachment("report.pdf", "application/pdf", pe)})
	if _, ok := idSet(r)["email-att-type-mismatch"]; !ok {
		t.Errorf("type mismatch missing: %v", keys(idSet(r)))
	}
	r = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindEmail, Text: mimeWithAttachment("bill\u202egpj.exe", "application/octet-stream", pe)})
	if _, ok := idSet(r)["email-att-bidi-name"]; !ok {
		t.Errorf("bidi missing: %v", keys(idSet(r)))
	}

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("../../startup/run.exe")
	w.Write([]byte("MZ"))
	zw.Close()
	r = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindEmail, Text: mimeWithAttachment("docs.zip", "application/zip", zb.Bytes())})
	if _, ok := idSet(r)["email-att-file-arch-traversal"]; !ok {
		t.Errorf("archive analyzer findings not folded: %v", keys(idSet(r)))
	}
}

func TestEmailQuotedPrintableAndURLs(t *testing.T) {
	h := baseHeaders("A <a@sender.example>")
	h[len(h)-1] = "Content-Type: text/plain"
	h = append(h, "Content-Transfer-Encoding: quoted-printable")
	r := runKind(InspectKindEmail, mkMail(h, "go to http://paypal.com=40evil.example/x now"))
	found := false
	for _, i := range r.IOCs {
		if i.Type == "url" && strings.Contains(i.Value, "paypal.com@evil.example") {
			found = true
		}
	}
	if !found {
		t.Errorf("QP-decoded URL not extracted: %v", r.IOCs)
	}
	if _, ok := idSet(r)["email-url-userinfo-lookalike"]; !ok {
		t.Errorf("url analyzer not applied to body links: %v", keys(idSet(r)))
	}
}

func TestEmailHostileMIME(t *testing.T) {
	base := baseHeaders("A <a@sender.example>")
	base = base[:len(base)-1]
	// deep nesting
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("--b" + string(rune('a'+i%20)) + "\r\nContent-Type: multipart/mixed; boundary=\"b" + string(rune('a'+(i+1)%20)) + "\"\r\n\r\n")
	}
	h := append(append([]string{}, base...), "Content-Type: multipart/mixed; boundary=\"ba\"")
	r := runKind(InspectKindEmail, mkMail(h, sb.String()))
	_ = r // must simply terminate without panic
	// huge boundary
	h = append(append([]string{}, base...), "Content-Type: multipart/mixed; boundary=\""+strings.Repeat("x", 5000)+"\"")
	r = runKind(InspectKindEmail, mkMail(h, "--"+strings.Repeat("x", 5000)+"\r\n\r\nhi"))
	if _, ok := idSet(r)["email-mime-boundary-huge"]; !ok {
		t.Errorf("huge boundary not flagged: %v", keys(idSet(r)))
	}
	// truncated
	h = append(append([]string{}, base...), "Content-Type: multipart/mixed; boundary=\"B\"")
	r = runKind(InspectKindEmail, mkMail(h, "--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Ty"))
	if len(r.Errors) != 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	// many parts
	var many strings.Builder
	for i := 0; i < 500; i++ {
		many.WriteString("--B\r\nContent-Type: text/plain\r\n\r\nx\r\n")
	}
	many.WriteString("--B--\r\n")
	r = runKind(InspectKindEmail, mkMail(h, many.String()))
	if len(r.Errors) != 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	// garbage and empty headers
	for _, s := range []string{"not an email at all", "\r\n\r\nbody only", "From: \x00\xff\r\n\r\nx", "Content-Type: multipart/mixed\r\n\r\n--"} {
		r = runKind(InspectKindEmail, s)
		if len(r.Errors) != 0 {
			t.Errorf("%q errors: %v", s, r.Errors)
		}
	}
}

func FuzzEmail(f *testing.F) {
	f.Add("From: a@b.example\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nx\r\n--B--\r\n")
	f.Add("Received: from a ([1.2.3.4]) by b; garbage\r\n\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		r := runKind(InspectKindEmail, s)
		if len(r.Errors) != 0 {
			t.Fatalf("errors: %v", r.Errors)
		}
	})
}
