// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"strings"
	"testing"
)

func emxMail(parts ...string) string {
	h := strings.Join(baseHeaders("A <a@sender.example>")[:6], "\r\n")
	return h + "\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n" + strings.Join(parts, "") + "--B--\r\n"
}

func emxPart(hdr, body string) string {
	return "--B\r\n" + hdr + "\r\n\r\n" + body + "\r\n"
}

func TestEmailExtraPhishing(t *testing.T) {
	html := `<html><body><a href="https://evil.example/x" style="display:none">x</a>
<a href="https://evil.example/y"></a><img src="https://track.example/p.gif" width="1" height="1">
<img src="cid:q" alt="qr code"><p>Scan the QR code with your phone</p></body></html>`
	m := emxMail(
		emxPart("Content-Type: text/html", html),
		emxPart("Content-Type: text/plain", "see hxxps://bad[.]example/login now"),
		emxPart("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"", "MZ"),
		emxPart("Content-Type: image/png\r\nContent-Disposition: inline; filename=\"qr-code.png\"", "x"),
	)
	r := runKind(InspectKindEmail, m)
	ids := idSet(r)
	for _, id := range []string{"email-x-hidden-link", "email-x-empty-link", "email-x-tracking-pixel", "email-x-qr-image-hint",
		"email-x-qr-lure-text", "email-x-defanged-url", "email-x-att-double-ext", "email-x-qr-image-name"} {
		if _, ok := ids[id]; !ok {
			t.Errorf("missing %s: %v", id, keys(ids))
		}
	}
	if ids["email-x-att-double-ext"].Technique != "T1566.001" || ids["email-x-hidden-link"].Technique != "T1566.002" {
		t.Errorf("technique tags wrong: %+v %+v", ids["email-x-att-double-ext"], ids["email-x-hidden-link"])
	}
	found := false
	for _, i := range r.IOCs {
		if i.Type == "url" && i.Value == "https://bad.example/login" {
			found = true
		}
	}
	if !found {
		t.Errorf("refanged URL not an IOC: %v", r.IOCs)
	}
}

func TestEmailExtraBenign(t *testing.T) {
	m := emxMail(emxPart("Content-Type: text/html", `<p>Hello <a href="https://sender.example/a">our site</a></p>`),
		emxPart("Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"", "%PDF-1.4"))
	for id := range idSet(runKind(InspectKindEmail, m)) {
		if strings.HasPrefix(id, "email-x-") {
			t.Errorf("benign mail produced %s", id)
		}
	}
}

func TestEmailExtraMsg(t *testing.T) {
	u16 := func(s string) string {
		var sb strings.Builder
		for i := 0; i < len(s); i++ {
			sb.WriteByte(s[i])
			sb.WriteByte(0)
		}
		return sb.String()
	}
	data := "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + strings.Repeat("\x00", 64) + u16("__substg1.0_0037001F") + u16("__attach_version1.0_#00000000") +
		u16("payload.js") + "\x00\x00https://evil.example/m"
	r := runKind(InspectKindEmail, data)
	ids := idSet(r)
	if _, ok := ids["email-x-msg-detected"]; !ok {
		t.Fatalf("msg not detected: %v", keys(ids))
	}
	if _, ok := ids["email-x-att-dangerous-ext"]; !ok {
		t.Errorf("dangerous name not found: %v", keys(ids))
	}
	if r.Format != "msg" && r.Format != "email" {
		t.Logf("format %q", r.Format)
	}
	// Plain OLE without .msg markers is not reported.
	r2 := runKind(InspectKindEmail, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"+strings.Repeat("\x00", 64))
	if _, ok := idSet(r2)["email-x-msg-detected"]; ok {
		t.Error("bare OLE flagged as msg")
	}
}

func TestEmailExtraEndpoint(t *testing.T) {
	withCleanRing(t, func() {
		mux := http.NewServeMux()
		RegisterInspect(mux, "tok")
		if !containsStr(InspectAnalyzerNames()[InspectKindEmail], "email-extra") {
			t.Fatal("email-extra not registered")
		}
		m := emxMail(emxPart("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.doc.js\"", "x"))
		r := inspectPost(t, mux, "/v1/inspect/email", "message/rfc822", []byte(m))
		found := false
		for _, f := range r.Findings {
			if f.ID == "email-x-att-double-ext" && f.Technique == "T1566.001" {
				found = true
			}
		}
		if !found || len(r.Errors) != 0 {
			t.Fatalf("endpoint report: %+v", r.Findings)
		}
	})
}

func FuzzEmailExtra(f *testing.F) {
	f.Add(emxMail(emxPart("Content-Type: text/html", `<a href="http://x" style="display:none">`)))
	f.Add("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1__substg1.0_ hxxp[:]//a[.]b")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		if r := runKind(InspectKindEmail, s); len(r.Errors) != 0 {
			t.Fatalf("errors: %v", r.Errors)
		}
	})
}
