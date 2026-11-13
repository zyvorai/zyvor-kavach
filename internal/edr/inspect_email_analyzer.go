// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Email inspector analyzer (kind "email"): raw RFC 5322 / MIME text. Parse only.
// It never fetches a link, resolves a name or contacts a server. Authentication
// results are REPORTED from the Authentication-Results header the receiving
// server wrote; DKIM signatures are NOT re-verified here (that needs DNS).
// See docs/url-email-inspection.md.

import (
	"context"
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Caps for hostile input.
const (
	emailMaxParts       = 64
	emailMaxDepth       = 6
	emailMaxAttachments = 50 // hashed
	emailMaxAnalyzed    = 8  // run through the file analyzers
	emailMaxPartBytes   = 8 << 20
	emailMaxTotalBytes  = 24 << 20
	emailMaxURLs        = 25
)

func init() {
	RegisterAnalyzer("email", []string{InspectKindEmail}, analyzeEmail)
}

type emailState struct {
	ctx        context.Context
	b          *InspectBuilder
	fromReg    string
	parts      int
	totalBytes int
	attCount   int
	analyzed   int
	urls       []string
	urlSeen    map[string]bool
	urlsCapped bool
	link       map[string]InspectFinding // folded link findings, best weight per id
	once       map[string]bool
	textBlobs  []string
	attMeta    []map[string]any
}

func (st *emailState) add(id, title, sev string, w int, ev string) {
	st.b.Finding(InspectFinding{ID: id, Title: title, Severity: sev, Weight: w, Evidence: truncStr(ev, 200)})
}

func (st *emailState) addOnce(id, title, sev string, w int, ev string) {
	if st.once[id] {
		return
	}
	st.once[id] = true
	st.add(id, title, sev, w, ev)
}

func emailReg(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	if r := ParseDomain(domain).Registrable; r != "" {
		return r
	}
	return domain
}

func emAddrDomain(a string) string {
	if i := strings.LastIndexByte(a, '@'); i >= 0 {
		return strings.ToLower(strings.TrimRight(a[i+1:], ".> "))
	}
	return ""
}

var emFreeMailRegs = setOf("gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "aol.com", "proton.me", "protonmail.com", "icloud.com", "gmx.com", "mail.com", "yandex.com", "zoho.com")

var (
	em_reEmbeddedAddr = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	em_reRecvIP4      = regexp.MustCompile(`[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]`)
	em_reRecvIP6      = regexp.MustCompile(`(?i)\[IPv6:([0-9a-f:.]+)\]`)
	em_reParen        = regexp.MustCompile(`\([^)]*\)`)
	em_reAuthRes      = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)`)
	em_reAuthProp     = regexp.MustCompile(`(?i)\b(header\.from|smtp\.mailfrom|header\.d|header\.i)\s*=\s*"?([^\s;"]+)`)
	em_reDKIMd        = regexp.MustCompile(`(?i)(?:^|;|\s)d\s*=\s*([A-Za-z0-9.-]+)`)
)

func emIsPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func analyzeEmail(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	b.Format("email")
	raw := in.Text
	if len(raw) > InspectMaxTextBytes {
		raw = raw[:InspectMaxTextBytes]
		b.LimitHit("input-truncated")
	}
	if strings.HasPrefix(raw, "From ") { // mbox separator line
		if i := strings.IndexByte(raw, '\n'); i >= 0 {
			raw = raw[i+1:]
		}
	}
	st := &emailState{ctx: ctx, b: b, urlSeen: map[string]bool{}, link: map[string]InspectFinding{}, once: map[string]bool{}}
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		st.add("email-parse-error", "Could not parse as an RFC 5322 message: "+err.Error(), "low", 5, "")
		// Fall back: scan the whole text for URLs so something is still reported.
		st.scanText(raw, "unparsed")
		st.finish()
		return nil
	}
	st.analyzeHeaders(msg.Header)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	st.walk(msg.Body, msg.Header, 0)
	st.finish()
	return ctx.Err()
}

func emHget(h map[string][]string, k string) string {
	for key, v := range h {
		if strings.EqualFold(key, k) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func emHall(h map[string][]string, k string) []string {
	var out []string
	for key, v := range h {
		if strings.EqualFold(key, k) {
			out = append(out, v...)
		}
	}
	return out
}

func (st *emailState) analyzeHeaders(h mail.Header) {
	b := st.b
	hm := map[string][]string(h)
	fromRaw := emHget(hm, "From")
	var fromAddr, fromName string
	if fromRaw == "" {
		st.add("email-no-from", "No From header", "low", 8, "")
	} else if addrs, err := mail.ParseAddressList(fromRaw); err == nil && len(addrs) > 0 {
		fromAddr, fromName = addrs[0].Address, addrs[0].Name
		if len(addrs) > 1 {
			st.add("email-multiple-from", fmt.Sprintf("%d addresses in From", len(addrs)), "low", 5, fromRaw)
		}
	} else {
		st.add("email-from-unparsable", "From header is not a valid address list", "low", 8, fromRaw)
		if m := em_reEmbeddedAddr.FindString(fromRaw); m != "" {
			fromAddr = m
		}
	}
	fromDom := emAddrDomain(fromAddr)
	st.fromReg = emailReg(fromDom)
	b.IOC("email", fromAddr)
	b.Meta("headers", map[string]any{
		"from": truncStr(fromRaw, 200), "reply_to": truncStr(emHget(hm, "Reply-To"), 200),
		"return_path": truncStr(emHget(hm, "Return-Path"), 200), "sender": truncStr(emHget(hm, "Sender"), 200),
		"message_id": truncStr(emHget(hm, "Message-Id"), 200), "subject": truncStr(emHget(hm, "Subject"), 200), "date": emHget(hm, "Date"),
	})
	st.textBlobs = append(st.textBlobs, emHget(hm, "Subject"))

	// Display-name spoofing.
	if fromName != "" {
		if m := em_reEmbeddedAddr.FindString(fromName); m != "" && emailReg(emAddrDomain(m)) != st.fromReg {
			st.add("email-displayname-address", "Display name contains a different e-mail address than the real sender", "medium", 30, fromName+" <"+fromAddr+">")
		}
		flat := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			if r >= 'A' && r <= 'Z' {
				return r + 32
			}
			return -1
		}, fromName)
		initDomainData()
		sld := ParseDomain(fromDom).SLD
		for _, br := range domainBrands {
			if len(br) >= 5 && strings.Contains(flat, br) && !strings.Contains(strings.ReplaceAll(sld, "-", ""), br) {
				st.add("email-displayname-brand", fmt.Sprintf("Display name mentions well-known name %q but the sender domain is %s", br, st.fromReg), "medium", 22, fromName+" <"+fromAddr+">")
				break
			}
		}
	}
	// Lookalike sender domain through the domain analyzer.
	if fromDom != "" {
		sb := inspScratchBuilder("domain")
		_ = analyzeDomain(st.ctx, InspectInput{Kind: InspectKindDomain, Text: fromDom}, sb)
		for _, f := range sb.r.Findings {
			if strings.HasPrefix(f.ID, "dom-dga-borderline") {
				continue
			}
			f.ID = "email-from-" + strings.TrimPrefix(f.ID, "dom-")
			f.Title = "Sender domain: " + f.Title
			b.Finding(f)
		}
	}

	// Address mismatches.
	cmp := func(hdr, id string, w int, label string) string {
		v := emHget(hm, hdr)
		if v == "" {
			return ""
		}
		a := ""
		if p, err := mail.ParseAddress(v); err == nil {
			a = p.Address
		} else if m := em_reEmbeddedAddr.FindString(v); m != "" {
			a = m
		}
		d := emAddrDomain(a)
		if d != "" && st.fromReg != "" && emailReg(d) != st.fromReg {
			ww := w
			if id == "email-replyto-mismatch" && emFreeMailRegs[emailReg(d)] && !emFreeMailRegs[st.fromReg] {
				ww += 5
			}
			st.add(id, label+" domain "+emailReg(d)+" differs from From domain "+st.fromReg, "low", ww, v)
			b.IOC("email", a)
		}
		return d
	}
	cmp("Reply-To", "email-replyto-mismatch", 15, "Reply-To")
	cmp("Return-Path", "email-returnpath-mismatch", 4, "Return-Path (bounce address; ESPs and lists differ legitimately)")
	cmp("Sender", "email-sender-mismatch", 4, "Sender")
	mid := strings.Trim(strings.TrimSpace(emHget(hm, "Message-Id")), "<>")
	if mid == "" {
		st.add("email-no-message-id", "No Message-ID header", "info", 3, "")
	} else if d := emAddrDomain(mid); d != "" && st.fromReg != "" && emailReg(d) != st.fromReg {
		st.add("email-messageid-mismatch", "Message-ID domain "+emailReg(d)+" differs from From domain "+st.fromReg, "info", 3, mid)
	}
	if emHget(hm, "Date") == "" {
		st.add("email-no-date", "No Date header", "info", 3, "")
	}

	st.analyzeReceived(hm)
	st.analyzeAuth(hm)
}

func (st *emailState) analyzeReceived(hm map[string][]string) {
	recv := emHall(hm, "Received")
	if len(recv) == 0 {
		return
	}
	type hop struct {
		t   time.Time
		ok  bool
		ips []string
	}
	hops := make([]hop, len(recv)) // index 0 = most recent (top)
	for i, r := range recv {
		if j := strings.LastIndexByte(r, ';'); j >= 0 {
			ds := strings.TrimSpace(em_reParen.ReplaceAllString(r[j+1:], ""))
			ds = strings.Join(strings.Fields(ds), " ")
			if t, err := mail.ParseDate(ds); err == nil {
				hops[i].t, hops[i].ok = t, true
			}
		}
		for _, m := range em_reRecvIP4.FindAllStringSubmatch(r, 4) {
			hops[i].ips = append(hops[i].ips, m[1])
		}
		for _, m := range em_reRecvIP6.FindAllStringSubmatch(r, 2) {
			hops[i].ips = append(hops[i].ips, m[1])
		}
	}
	st.b.Meta("received_hops", len(recv))
	if len(recv) > 25 {
		st.add("email-received-many-hops", fmt.Sprintf("%d Received headers", len(recv)), "info", 4, "")
	}
	// Oldest hop is last. Times should not decrease going toward the top.
	for i := len(hops) - 1; i >= 1; i-- {
		if hops[i].ok && hops[i-1].ok && hops[i-1].t.Before(hops[i].t.Add(-5*time.Minute)) {
			st.add("email-received-time-backwards", "Received timestamps go backwards along the chain (beyond 5 minutes of skew)", "low", 12,
				hops[i].t.Format(time.RFC3339)+" then "+hops[i-1].t.Format(time.RFC3339))
			break
		}
	}
	last := hops[len(hops)-1]
	for _, ip := range last.ips {
		if emIsPrivate(ip) {
			st.add("email-received-private-first-hop", "Earliest Received hop is a private/loopback address (normal for internal relays, odd for external mail)", "info", 4, ip)
			break
		}
	}
	// Date far from the top Received time.
	if d, err := mail.ParseDate(emHget(hm, "Date")); err == nil && hops[0].ok {
		diff := hops[0].t.Sub(d)
		if diff < 0 {
			diff = -diff
		}
		if diff > 72*time.Hour {
			st.add("email-date-skew", "Date header differs from the newest Received time by more than 72 hours", "info", 5, emHget(hm, "Date"))
		}
	}
}

type emAuthVerdict struct{ method, result, authserv string }

func (st *emailState) analyzeAuth(hm map[string][]string) {
	var verdicts []emAuthVerdict
	props := map[string]string{}
	for _, h := range emHall(hm, "Authentication-Results") {
		id := strings.TrimSpace(h)
		if i := strings.IndexAny(id, "; \t"); i >= 0 {
			id = id[:i]
		}
		for _, m := range em_reAuthRes.FindAllStringSubmatch(h, -1) {
			verdicts = append(verdicts, emAuthVerdict{strings.ToLower(m[1]), strings.ToLower(m[2]), id})
		}
		for _, m := range em_reAuthProp.FindAllStringSubmatch(h, -1) {
			props[strings.ToLower(m[1])] = strings.ToLower(m[2])
		}
	}
	for _, h := range emHall(hm, "Received-SPF") {
		f := strings.Fields(strings.ToLower(h))
		if len(f) > 0 {
			verdicts = append(verdicts, emAuthVerdict{"spf", f[0], "Received-SPF"})
		}
	}
	dkimSigs := emHall(hm, "Dkim-Signature")
	st.b.Meta("auth", map[string]any{"verdicts": verdicts, "properties": props, "dkim_signatures": len(dkimSigs),
		"note": "reported from the receiving server's Authentication-Results; NOT recomputed. A header added by the sender cannot be told apart without knowing your own authserv-id."})
	if len(dkimSigs) > 0 {
		st.add("email-dkim-not-recomputed", "DKIM-Signature present; signature not re-verified here (needs DNS and exact body bytes), only the recorded Authentication-Results are reported", "info", 0, "")
		for _, s := range dkimSigs {
			if m := em_reDKIMd.FindStringSubmatch(s); m != nil && st.fromReg != "" && emailReg(m[1]) != st.fromReg {
				st.add("email-dkim-domain-unaligned", "DKIM signing domain "+emailReg(m[1])+" differs from From domain "+st.fromReg, "info", 3, m[1])
				break
			}
		}
	}
	if len(verdicts) == 0 {
		st.add("email-auth-absent", "No Authentication-Results or Received-SPF header recorded", "info", 2, "")
		return
	}
	worst := map[string]string{}
	rank := map[string]int{"pass": 0, "none": 1, "neutral": 1, "policy": 1, "temperror": 2, "permerror": 2, "softfail": 3, "fail": 4}
	for _, v := range verdicts {
		if cur, ok := worst[v.method]; !ok || rank[v.result] > rank[cur] {
			worst[v.method] = v.result
		}
	}
	sorted := make([]string, 0)
	for m := range worst {
		sorted = append(sorted, m)
	}
	sort.Strings(sorted)
	for _, m := range sorted {
		r := worst[m]
		ev := m + "=" + r
		switch {
		case m == "dmarc" && r == "fail":
			st.add("email-dmarc-fail", "Receiving server recorded dmarc=fail", "medium", 25, ev)
		case m == "spf" && r == "fail":
			st.add("email-spf-fail", "Receiving server recorded spf=fail", "medium", 15, ev)
		case m == "spf" && r == "softfail":
			st.add("email-spf-softfail", "Receiving server recorded spf=softfail", "low", 8, ev)
		case m == "dkim" && r == "fail":
			st.add("email-dkim-fail", "Receiving server recorded dkim=fail", "low", 12, ev)
		case m == "compauth" && r == "fail":
			st.add("email-compauth-fail", "Receiving server recorded compauth=fail (composite authentication)", "medium", 15, ev)
		case (m == "spf" || m == "dkim" || m == "dmarc") && (r == "temperror" || r == "permerror"):
			st.add("email-auth-error", "Receiving server recorded "+ev, "info", 3, ev)
		}
	}
	if hf := props["header.from"]; hf != "" && st.fromReg != "" && emailReg(hf) != st.fromReg {
		st.add("email-auth-from-mismatch", "Authentication-Results header.from ("+hf+") differs from the From domain", "low", 12, hf)
	}
}

func (st *emailState) finish() {
	b := st.b
	// Link findings are folded once per id so a mail with 25 links does not
	// repeat itself.
	for _, u := range st.urls {
		if st.ctx.Err() != nil {
			break
		}
		res := urlCollect(st.ctx, u, 0)
		for _, i := range res.IOCs {
			b.IOC(i.Type, i.Value)
		}
		for _, f := range res.Findings {
			id := "email-" + f.ID
			if f.ID == "url-nested-redirect" && st.fromReg != "" && strings.Contains(strings.ToLower(f.Evidence), st.fromReg) {
				continue // click-tracking redirect back to the sender's own site
			}
			w := f.Weight
			if w < 30 {
				w = (w + 1) / 2 // weak lexical signal, halved in mail context (tracking links are long and redirecting)
			}
			if cur, ok := st.link[id]; !ok || w > cur.Weight {
				f.ID, f.Weight = id, w
				f.Title = "Link: " + f.Title
				if f.Evidence == "" {
					f.Evidence = u
				}
				st.link[id] = f
			}
		}
	}
	ids := make([]string, 0, len(st.link))
	for id := range st.link {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b.Finding(st.link[id])
	}
	if st.urlsCapped {
		b.LimitHit("urls")
	}
	b.Meta("urls", len(st.urls))
	b.Meta("parts", st.parts)
	b.Meta("attachments", st.attMeta)
	b.Meta("decoded_bytes", st.totalBytes)
	// Weak wording signal.
	lower := strings.ToLower(strings.Join(st.textBlobs, "\n"))
	n := 0
	var hit []string
	for _, w := range emailUrgency {
		if strings.Contains(lower, w) {
			n++
			hit = append(hit, w)
		}
	}
	if n >= 3 {
		st.add("email-urgency-wording", fmt.Sprintf("%d pressure/urgency phrases (weak signal: legitimate mail also uses them)", n), "info", 4, strings.Join(hit, ", "))
	}
}

var emailUrgency = []string{"urgent", "immediately", "within 24 hours", "account suspended", "account will be", "verify your account", "verify your identity", "password expires", "final notice", "unusual activity", "confirm your", "gift card", "wire transfer", "act now", "security alert", "limited time", "click here"}
