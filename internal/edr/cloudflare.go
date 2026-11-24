// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Cloudflare log analytics (observation only, offline): Logpush exports of the HTTP requests and
// firewall events zone datasets and the Gateway DNS and Gateway HTTP account datasets. Field names
// come from Cloudflare's developer documentation (see docs/sase-log-analytics.md for which were read).
const (
	cfAttackMax     = 20 // WAF attack score 1..20 is Cloudflare's "attack" class
	cfBlockBurst    = 20
	cfBotMax        = 10
	cfBotRequests   = 20
	cfClassRequests = 3
	cfErrBurst      = 25
	cfNXBurst       = 30
)

var cfRules = []SvRule{
	{"cf-an-attack-score-allowed", "Initial Access", "Exploit Public-Facing Application", "T1190", "high", "Request with an attack-class WAF score was served",
		"A WAF attack score of 20 or less is Cloudflare's own 'attack' band; the request was not blocked or challenged and the edge returned a success or redirect.",
		"The zone has no rule acting on the score, the path is a known false-positive source, or the origin rejected the request on its own."},
	{"cf-an-injection-score-allowed", "Initial Access", "Exploit Public-Facing Application", "T1190", "high", "Request with a low SQLi, XSS or RCE attack score was served",
		"The per-class score for SQL injection, cross-site scripting or remote code execution was 20 or less and the request still got a non-error answer.",
		"A security scanner you run, or a field that legitimately carries code or SQL such as a query editor."},
	{"cf-an-waf-block-burst", "Reconnaissance", "Active Scanning", "T1595", "medium", "One client IP was blocked or challenged many times",
		"Twenty or more blocked or challenged requests from one address in the log is the shape of scanning or a brute-force attempt that the edge is absorbing.",
		"A monitoring probe, a misconfigured integration retrying, or a shared NAT address with many users."},
	{"cf-an-leaked-credential-login", "Credential Access", "Valid Accounts", "T1078", "high", "Login-style request used credentials Cloudflare flagged as leaked",
		"The leaked-credentials check matched the submitted password (or user and password) against a known-leak corpus and the POST succeeded or redirected.",
		"A user who reuses an old password but whose account is otherwise safe; the check is about the credential, not the person."},
	{"cf-an-automated-bot-allowed", "Collection", "Automated Collection", "T1119", "medium", "High-volume client scored as automated was served",
		"A bot score of 10 or less means Cloudflare judged the client very likely automated; twenty or more served requests from it is scraping, stuffing or probing that the zone is not mitigating.",
		"An uptime monitor, an allowed integration or a partner crawler that is not on the verified-bot list."},
	{"cf-an-bad-client-class-allowed", "Command and Control", "Proxy: Multi-hop Proxy", "T1090.003", "low", "Traffic from a Tor, scanner or bad-host client class was served",
		"Cloudflare's client IP class marked the source as Tor, a known scanner or a bad host, and the zone served it repeatedly.",
		"Privacy-minded users on Tor, or a security vendor's scanner you contract."},
	{"cf-an-origin-error-burst", "Impact", "Endpoint Denial of Service", "T1499", "low", "Burst of 5xx answers from the edge for one host",
		"Twenty-five or more 5xx responses for one host in the log suggest an origin outage or an attack that is overloading it.",
		"A deploy, an origin restart or a dependency outage."},
	{"cf-an-gateway-dns-threat-allowed", "Command and Control", "Application Layer Protocol: DNS", "T1071.004", "high", "Gateway DNS query matched a threat category or feed and was not blocked",
		"The query matched a malware, phishing, botnet, command-and-control or similar category or an indicator feed, and the resolver decision is not a block.",
		"A security team resolving samples on purpose, or a Gateway policy in log-only mode (resolver-decision vocabulary is unverified; see the doc)."},
	{"cf-an-gateway-untrusted-cert-passthrough", "Defense Evasion", "Subvert Trust Controls", "T1553", "medium", "Gateway HTTP let an untrusted upstream certificate through",
		"The untrusted-certificate action was passThrough, so the user reached a server whose certificate Gateway did not trust.",
		"A lab or internal service with a private CA that Gateway has not been told about."},
	{"cf-an-gateway-dlp-allowed", "Exfiltration", "Exfiltration Over Web Service", "T1567", "high", "Gateway HTTP upload or download matched a DLP profile and was not blocked",
		"A DLP profile match with an action that does not block means the data was logged but still moved.",
		"A DLP profile in log-only mode by design, or a profile that over-matches."},
	{"cf-an-gateway-dns-tunnel-like", "Command and Control", "Application Layer Protocol: DNS", "T1071.004", "high", "Many very long DNS names under one parent in Gateway DNS",
		"Data hidden in long DNS labels is how DNS tunnelling moves data past web controls.",
		"Some CDNs, anti-virus lookups and mail-security services use long labels."},
	{"cf-an-gateway-nxdomain-burst", "Command and Control", "Dynamic Resolution: Domain Generation Algorithms", "T1568.002", "medium", "One user or device got many NXDOMAIN answers",
		"Thirty or more NXDOMAIN responses to one identity is the shape of a domain-generation algorithm looking for a live server.",
		"A mistyped search-domain list, a retired internal service or a misconfigured agent."},
}

var cfRiskyCats = []string{"malware", "phishing", "botnet", "command and control", "command & control", "spyware", "cryptomin", "ransomware", "newly seen", "dga", "dns tunnel", "suspicious"}

func cfAction(s string) string {
	l := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	switch {
	case l == "":
		return "allow"
	case strings.Contains(l, "solved"), strings.Contains(l, "bypass"):
		return "allow"
	case strings.Contains(l, "block"), strings.Contains(l, "connectionclose"), strings.Contains(l, "deny"), strings.Contains(l, "drop"), strings.Contains(l, "sinkhole"):
		return "block"
	case strings.Contains(l, "challenge"):
		return "challenge"
	case l == "log":
		return "log"
	case strings.Contains(l, "allow"), l == "skip", l == "rewrite", l == "unknown":
		return "allow"
	}
	return "other"
}

func cfScore(r map[string]string, k string) int {
	n := int(zsInt(zsGet(r, k)))
	if n < 1 || n > 99 {
		return 0
	}
	return n
}

func cfKind(r map[string]string) string {
	switch {
	case zsHas(r, "queryname", "resolverdecision", "querytypename", "matchedcategorynames", "querycategorynames"):
		return "cf-gwdns"
	case zsHas(r, "httphost", "untrustedcertificateaction", "uploadmatcheddlpprofiles", "downloadmatcheddlpprofiles", "httpmethod") && !zsHas(r, "clientrequesthost"):
		return "cf-gwhttp"
	case zsHas(r, "matchindex", "originatorrayid", "kind") && zsHas(r, "action", "ruleid"):
		return "cf-fw"
	case zsHas(r, "securityaction", "securityactions", "edgestarttimestamp", "edgeresponsestatus", "clientrequesthost", "wafattackscore", "botscore", "clientrequestpath"):
		return "cf-http"
	}
	return ""
}

func cfBuild(r map[string]string, line int) (SvEvent, bool) {
	kind := cfKind(r)
	if kind == "" {
		return SvEvent{}, false
	}
	e := SvEvent{Vendor: "cloudflare", Kind: kind, Line: line}
	e.T = zsTime(zsGet(r, "datetime", "edgestarttimestamp", "timestamp", "time"))
	switch kind {
	case "cf-http", "cf-fw":
		e.Src = zsGet(r, "clientip")
		e.Host = strings.ToLower(zsGet(r, "clientrequesthost", "edgerequesthost"))
		e.Path = zsSafeURL(zsGet(r, "clientrequestpath", "clientrequesturi"))
		e.Method = strings.ToUpper(zsGet(r, "clientrequestmethod"))
		e.UA = webTruncate(webSanitise(zsGet(r, "clientrequestuseragent")), 120)
		e.Raw = zsGet(r, "securityaction", "action")
		e.Action = cfAction(e.Raw)
		e.Status = int(zsInt(zsGet(r, "edgeresponsestatus")))
		e.Country = strings.ToUpper(zsGet(r, "clientcountry"))
		e.Score, e.RCE, e.SQLi, e.XSS = cfScore(r, "wafattackscore"), cfScore(r, "wafrceattackscore"), cfScore(r, "wafsqliattackscore"), cfScore(r, "wafxssattackscore")
		e.Bot = cfScore(r, "botscore")
		e.BotSrc = zsGet(r, "botscoresrc")
		e.IPClass = zsGet(r, "clientipclass")
		e.Leaked = zsGet(r, "leakedcredentialcheckresult")
	case "cf-gwdns":
		e.User = strings.ToLower(zsGet(r, "email", "userid", "devicename", "deviceid"))
		e.Src = zsGet(r, "srcip")
		e.Query = strings.ToLower(strings.TrimSuffix(zsGet(r, "queryname"), "."))
		e.Host = e.Query
		e.Raw = zsGet(r, "resolverdecision")
		e.Action = cfAction(e.Raw)
		if e.Raw == "" {
			e.Action = "other"
		}
		for _, k := range []string{"matchedcategorynames", "querycategorynames", "resolvedipcategorynames", "cnamecategorynames", "matchedindicatorfeednames", "queryindicatorfeednames"} {
			e.Cats = append(e.Cats, zsList(zsGet(r, k))...)
		}
		switch strings.ToUpper(zsGet(r, "rcode")) {
		case "3", "NXDOMAIN":
			e.RCode = "NXDOMAIN"
		}
		e.Country = strings.ToUpper(zsGet(r, "srcipcountrycode"))
	case "cf-gwhttp":
		e.User = strings.ToLower(zsGet(r, "email", "userid", "devicename", "deviceid"))
		e.Src = zsGet(r, "sourceip")
		e.Host = strings.ToLower(zsGet(r, "httphost"))
		e.Path = zsSafeURL(zsGet(r, "url"))
		e.Method = strings.ToUpper(zsGet(r, "httpmethod"))
		e.UA = webTruncate(webSanitise(zsGet(r, "useragent")), 120)
		e.Raw = zsGet(r, "action")
		e.Action = cfAction(e.Raw)
		if e.Raw == "" {
			e.Action = "other"
		}
		e.Status = int(zsInt(zsGet(r, "httpstatuscode")))
		e.CertAct = zsGet(r, "untrustedcertificateaction")
		e.DLP = append(zsList(zsGet(r, "uploadmatcheddlpprofiles")), zsList(zsGet(r, "downloadmatcheddlpprofiles"))...)
		e.Cats = zsList(zsGet(r, "categorynames"))
		e.Country = strings.ToUpper(zsGet(r, "sourceipcountrycode"))
	}
	e.User = webTruncate(webSanitise(e.User), 120)
	e.Host = webTruncate(webSanitise(e.Host), 200)
	e.Raw = webTruncate(webSanitise(e.Raw), 40)
	return e, true
}

// CloudflareRun parses and analyses one exported Cloudflare log; used by the routes, the harness and tests.
func CloudflareRun(raw []byte, format string, opt SvOptions) (*SvReport, []Finding, error) {
	p, err := svParseLog(raw, format, false, cfBuild)
	if err != nil {
		return nil, nil, err
	}
	p.Vendor = "cloudflare"
	rep, fs := AnalyzeCloudflare(p, opt)
	return rep, fs, nil
}

func cfServed(e *SvEvent) bool {
	return (e.Action == "allow" || e.Action == "log") && (e.Status == 0 || e.Status < 400)
}

// AnalyzeCloudflare runs every cf-an rule over the parsed events.
func AnalyzeCloudflare(p *svParsed, opt SvOptions) (*SvReport, []Finding) {
	ev := p.Events
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].T.IsZero() || ev[j].T.IsZero() {
			return false
		}
		return ev[i].T.Before(ev[j].T)
	})
	var out []svFinding
	counts := map[string]int{}
	truncated := false
	emit := func(rule, sev string, t time.Time, who, key, desc, sample string) {
		if counts[rule] >= svCapPerRule*4 {
			truncated = true
			return
		}
		counts[rule]++
		out = append(out, svFinding{Rule: rule, Sev: sev, User: who, Key: key, Desc: desc, Sample: sample, T: t})
	}
	users := map[string]bool{}
	var first, last time.Time
	blocked := map[string]int{}
	blockedEv := map[string]SvEvent{}
	botN := map[string]int{}
	botEv := map[string]SvEvent{}
	classN := map[string]int{}
	classEv := map[string]SvEvent{}
	errN := map[string]int{}
	errEv := map[string]SvEvent{}
	dnsLong := map[[2]string]int{}
	dnsEx := map[[2]string]string{}
	nx := map[string]int{}
	nxEx := map[string]SvEvent{}
	seen := map[string]bool{}
	once := func(k string) bool {
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}
	for i := range ev {
		e := &ev[i]
		svTimeRange(&first, &last, e.T)
		who := svWho(e)
		if who != "" {
			users[who] = true
		}
		sample := fmt.Sprintf("%s %s%s status=%d action=%s", e.Method, e.Host, e.Path, e.Status, orUnknown(e.Raw))
		switch e.Kind {
		case "cf-http", "cf-fw":
			if e.Score >= 1 && e.Score <= cfAttackMax && cfServed(e) && once("a|"+e.Src+e.Host+e.Path) {
				emit("cf-an-attack-score-allowed", "high", e.T, e.Src, e.Src+e.Host+e.Path, fmt.Sprintf("client %s sent %s %s%s with WAF attack score %d and got %d", orUnknown(e.Src), orUnknown(e.Method), e.Host, e.Path, e.Score, e.Status), sample)
			}
			for _, c := range []struct {
				n string
				v int
			}{{"RCE", e.RCE}, {"SQLi", e.SQLi}, {"XSS", e.XSS}} {
				if c.v >= 1 && c.v <= cfAttackMax && cfServed(e) && once("i|"+c.n+e.Src+e.Host+e.Path) {
					emit("cf-an-injection-score-allowed", "high", e.T, e.Src, c.n+e.Src+e.Host+e.Path, fmt.Sprintf("client %s sent %s %s%s with %s attack score %d and got %d", orUnknown(e.Src), orUnknown(e.Method), e.Host, e.Path, c.n, c.v, e.Status), sample)
					break
				}
			}
			if e.Action == "block" || e.Action == "challenge" {
				blocked[e.Src]++
				if _, ok := blockedEv[e.Src]; !ok {
					blockedEv[e.Src] = *e
				}
			}
			l := strings.ToLower(e.Leaked)
			if (l == "password_leaked" || l == "username_and_password_leaked") && (e.Method == "" || e.Method == "POST") && cfServed(e) && once("l|"+e.Src+e.Host+e.Path) {
				emit("cf-an-leaked-credential-login", "high", e.T, e.Src, e.Src+e.Host+e.Path, fmt.Sprintf("client %s submitted a %s credential to %s%s and got %d", orUnknown(e.Src), strings.ReplaceAll(l, "_", " "), e.Host, e.Path, e.Status), sample)
			}
			if e.Bot >= 1 && e.Bot <= cfBotMax && cfServed(e) && !strings.Contains(strings.ToLower(e.BotSrc), "verified") {
				k := e.Src + "|" + e.Host
				botN[k]++
				if _, ok := botEv[k]; !ok {
					botEv[k] = *e
				}
			}
			switch strings.ToLower(e.IPClass) {
			case "tor", "scan", "badhost":
				if cfServed(e) {
					k := e.Src + "|" + strings.ToLower(e.IPClass)
					classN[k]++
					if _, ok := classEv[k]; !ok {
						classEv[k] = *e
					}
				}
			}
			if e.Status >= 500 && e.Status < 600 && e.Host != "" {
				errN[e.Host]++
				if _, ok := errEv[e.Host]; !ok {
					errEv[e.Host] = *e
				}
			}
		case "cf-gwdns":
			if c := zsContains(strings.Join(e.Cats, " "), cfRiskyCats); c != "" && e.Action != "block" && once("d|"+who+e.Query) {
				emit("cf-an-gateway-dns-threat-allowed", "high", e.T, who, who+e.Query, fmt.Sprintf("%s resolved %s, which matched %q, and the decision was %s", orUnknown(who), e.Query, webTruncate(webSanitise(strings.Join(e.Cats, ",")), 80), orUnknown(e.Raw)), "dns "+e.Query+" decision="+orUnknown(e.Raw))
			}
			if svDNSLong(e.Query) && e.Action != "block" {
				k := [2]string{who, zsParent(e.Query)}
				dnsLong[k]++
				if _, ok := dnsEx[k]; !ok {
					dnsEx[k] = e.Query
				}
			}
			if e.RCode == "NXDOMAIN" && who != "" {
				nx[who]++
				if _, ok := nxEx[who]; !ok {
					nxEx[who] = *e
				}
			}
		case "cf-gwhttp":
			if strings.EqualFold(e.CertAct, "passThrough") && once("c|"+who+e.Host) {
				emit("cf-an-gateway-untrusted-cert-passthrough", "medium", e.T, who, who+e.Host, fmt.Sprintf("%s reached %s although its certificate was untrusted (action passThrough)", orUnknown(who), e.Host), sample)
			}
			if len(e.DLP) > 0 && e.Action != "block" && once("p|"+who+e.Host+strings.Join(e.DLP, ",")) {
				emit("cf-an-gateway-dlp-allowed", "high", e.T, who, who+e.Host+strings.Join(e.DLP, ","), fmt.Sprintf("%s: %s matched DLP profile %s and was not blocked", orUnknown(who), e.Host, webTruncate(webSanitise(strings.Join(e.DLP, ",")), 80)), sample)
			}
		}
	}
	for _, ip := range svSortedKeys(blocked) {
		if blocked[ip] >= cfBlockBurst {
			emit("cf-an-waf-block-burst", "medium", blockedEv[ip].T, ip, ip, fmt.Sprintf("client %s was blocked or challenged %d times", orUnknown(ip), blocked[ip]), fmt.Sprintf("%s %s%s action=%s", blockedEv[ip].Method, blockedEv[ip].Host, blockedEv[ip].Path, blockedEv[ip].Raw))
		}
	}
	for _, k := range svSortedKeys(botN) {
		if botN[k] >= cfBotRequests {
			e := botEv[k]
			emit("cf-an-automated-bot-allowed", "medium", e.T, e.Src, k, fmt.Sprintf("client %s sent %d requests to %s scored as automated (bot score %d or less) and was served", orUnknown(e.Src), botN[k], e.Host, cfBotMax), fmt.Sprintf("%s %s%s bot=%d", e.Method, e.Host, e.Path, e.Bot))
		}
	}
	for _, k := range svSortedKeys(classN) {
		if classN[k] >= cfClassRequests {
			e := classEv[k]
			emit("cf-an-bad-client-class-allowed", "low", e.T, e.Src, k, fmt.Sprintf("client %s (class %s) was served %d requests", orUnknown(e.Src), e.IPClass, classN[k]), fmt.Sprintf("%s %s%s class=%s", e.Method, e.Host, e.Path, e.IPClass))
		}
	}
	for _, h := range svSortedKeys(errN) {
		if errN[h] >= cfErrBurst {
			e := errEv[h]
			emit("cf-an-origin-error-burst", "low", e.T, "", h, fmt.Sprintf("host %s returned %d 5xx responses", h, errN[h]), fmt.Sprintf("%s %s%s status=%d", e.Method, e.Host, e.Path, e.Status))
		}
	}
	for _, k := range zsSortedKeys2(dnsLong) {
		if dnsLong[k] >= zsTunnelQueries {
			emit("cf-an-gateway-dns-tunnel-like", "high", last, k[0], k[0]+"|"+k[1], fmt.Sprintf("%s sent %d very long DNS names under %s", orUnknown(k[0]), dnsLong[k], k[1]), "dns "+dnsEx[k])
		}
	}
	for _, u := range svSortedKeys(nx) {
		if nx[u] >= cfNXBurst {
			emit("cf-an-gateway-nxdomain-burst", "medium", nxEx[u].T, u, u, fmt.Sprintf("%s received %d NXDOMAIN answers", u, nx[u]), "dns "+nxEx[u].Query+" rcode=NXDOMAIN")
		}
	}
	return svFinish("cloudflare", cfRules, p, out, opt, users, first, last, truncated)
}

func svSortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func cloudflareGuidance() []GuidanceEntry { return svGuidance(cfRules, "Cloudflare") }
