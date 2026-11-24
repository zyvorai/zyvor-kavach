// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Cisco Umbrella log analytics (observation only, offline): the DNS and proxy CSV logs Umbrella writes
// to a log bucket, which have no header row. Column positions for the headerless form come from sample
// rows in a public third-party parser page, not from Cisco's field table, which could not be fetched;
// see docs/sase-log-analytics.md. Files with a header row, JSON lines, or camelCase proxy keys are
// read by name.
const (
	umbBlockBurst = 25
	umbNXBurst    = 30
)

var umbRules = []SvRule{
	{"umb-an-threat-category-allowed", "Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001", "high", "Request to a malware, phishing or command-and-control category was allowed",
		"The log labels the destination with a threat category and the action is Allowed, so the policy did not stop it.",
		"A security team visiting samples on purpose, a category that the policy leaves on monitor, or a mis-categorised site."},
	{"umb-an-anonymizer-allowed", "Command and Control", "Proxy: External Proxy", "T1090.002", "medium", "Allowed traffic to a proxy, anonymiser or newly seen domain category",
		"Proxy and anonymiser services, newly seen domains and dynamic DNS are over-represented in attack infrastructure and policy evasion.",
		"Privacy tools approved for some staff or a brand-new vendor domain."},
	{"umb-an-dns-tunnel-like", "Command and Control", "Application Layer Protocol: DNS", "T1071.004", "high", "Many very long DNS names under one parent domain",
		"Data hidden in long DNS labels is how DNS tunnelling moves data past web controls.",
		"Some CDNs, anti-virus lookups and mail-security services use long labels."},
	{"umb-an-nxdomain-burst", "Command and Control", "Dynamic Resolution: Domain Generation Algorithms", "T1568.002", "medium", "One identity got many NXDOMAIN answers",
		"Thirty or more NXDOMAIN responses to one identity is the shape of a domain-generation algorithm looking for a live server.",
		"A mistyped search-domain list, a retired internal service or a misconfigured agent."},
	{"umb-an-block-burst", "Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001", "medium", "One identity was blocked many times",
		"Twenty-five or more blocked requests from one identity can be an infected host retrying a blocked command-and-control name, or a user hitting a blocked category repeatedly.",
		"A browser extension or application that retries a blocked ad or tracking domain."},
	{"umb-an-proxy-malware-allowed", "Execution", "User Execution: Malicious File", "T1204.002", "high", "Proxy record carries an antivirus or AMP malware verdict yet was allowed",
		"An antivirus detection or a malicious AMP disposition on a response that the proxy still allowed means the file may have reached the user.",
		"A retrospective verdict that arrived after delivery, or a detection that the policy intentionally only logs."},
}

var umbThreatCats = []string{"malware", "phishing", "command and control", "botnet", "cryptomining", "ransomware", "potentially harmful", "dga", "exploit"}
var umbEvasionCats = []string{"proxy", "anonymizer", "newly seen", "dynamic dns", "tunnel", "vpn"}

func umbAction(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "":
		return "other"
	case strings.Contains(l, "block"), strings.Contains(l, "deny"):
		return "block"
	case strings.Contains(l, "allow"):
		return "allow"
	}
	return "other"
}

func umbCol(r map[string]string, i int) string { return strings.TrimSpace(r[fmt.Sprintf("c%d", i)]) }

func umbBuild(r map[string]string, line int) (SvEvent, bool) {
	e := SvEvent{Vendor: "umbrella", Line: line}
	if _, ok := r["c0"]; ok { // headerless CSV
		a5, a6 := umbAction(umbCol(r, 5)), umbAction(umbCol(r, 6))
		switch {
		case a5 != "other" && umbCol(r, 8) != "" && !strings.Contains(umbCol(r, 7), "://"):
			e.Kind = "umb-dns"
			e.T = zsTime(umbCol(r, 0))
			e.User, e.Src = umbCol(r, 1), umbCol(r, 3)
			e.Raw, e.Action = umbCol(r, 5), a5
			e.Query = strings.ToLower(strings.TrimSuffix(umbCol(r, 8), "."))
			e.RCode = strings.ToUpper(umbCol(r, 7))
			e.Cats = zsList(umbCol(r, 9))
		case a6 != "other" && (strings.Contains(umbCol(r, 7), "://") || strings.Contains(umbCol(r, 7), ".")):
			e.Kind = "umb-proxy"
			e.T = zsTime(umbCol(r, 0))
			e.User, e.Src = umbCol(r, 1), umbCol(r, 2)
			e.Raw, e.Action = umbCol(r, 6), a6
			e.Path = zsSafeURL(umbCol(r, 7))
			e.Host = zsHostOf(umbCol(r, 7))
			e.UA = webTruncate(webSanitise(umbCol(r, 9)), 120)
			e.Status = int(zsInt(umbCol(r, 10)))
			if len(r) > 20 {
				e.Cats = zsList(umbCol(r, 20))
			}
		default:
			return SvEvent{}, false
		}
	} else {
		e.T = zsTime(zsGet(r, "timestamp", "ts", "datetime", "time"))
		switch {
		case zsHas(r, "verdict", "url", "avdetections", "ampdisposition", "statuscode", "destinationip", "requestmethod", "contenttype"):
			e.Kind = "umb-proxy"
			e.User = zsGet(r, "identity", "identities", "identitiesv8", "policyidentity", "granularidentity")
			e.Src = zsGet(r, "internalip", "externalip")
			e.Raw = zsGet(r, "verdict", "action")
			e.Action = umbAction(e.Raw)
			e.Path = zsSafeURL(zsGet(r, "url"))
			e.Host = zsHostOf(zsGet(r, "url"))
			e.UA = webTruncate(webSanitise(zsGet(r, "useragent")), 120)
			e.Status = int(zsInt(zsGet(r, "statuscode")))
			e.Method = strings.ToUpper(zsGet(r, "requestmethod"))
			e.Cats = append(zsList(zsGet(r, "categories")), zsList(zsGet(r, "blockedcategories"))...)
			av := zsGet(r, "avdetections")
			if d := strings.ToLower(zsGet(r, "ampdisposition")); strings.Contains(d, "malicious") {
				av += " amp:malicious"
			}
			if m := zsGet(r, "ampmalware"); m != "" {
				av += " amp:" + m
			}
			e.AV = strings.TrimSpace(av)
		case zsHas(r, "domain", "querytype", "responsecode", "queryname"):
			e.Kind = "umb-dns"
			e.User = zsGet(r, "identity", "identities", "policyidentity", "mostgranularidentity", "granularidentity")
			e.Src = zsGet(r, "internalip", "externalip")
			e.Raw = zsGet(r, "action", "verdict")
			e.Action = umbAction(e.Raw)
			e.Query = strings.ToLower(strings.TrimSuffix(zsGet(r, "domain", "queryname"), "."))
			e.RCode = strings.ToUpper(zsGet(r, "responsecode", "rcode"))
			e.Cats = append(zsList(zsGet(r, "categories")), zsList(zsGet(r, "blockedcategories"))...)
		default:
			return SvEvent{}, false
		}
	}
	e.Host = webTruncate(webSanitise(strings.ToLower(e.Host)), 200)
	if e.Kind == "umb-dns" {
		e.Host = e.Query
	}
	e.User = webTruncate(webSanitise(strings.ToLower(e.User)), 120)
	e.Raw = webTruncate(webSanitise(e.Raw), 40)
	return e, true
}

// UmbrellaRun parses and analyses one exported Umbrella log.
func UmbrellaRun(raw []byte, format string, opt SvOptions) (*SvReport, []Finding, error) {
	p, err := svParseLog(raw, format, true, umbBuild)
	if err != nil {
		return nil, nil, err
	}
	p.Vendor = "umbrella"
	rep, fs := AnalyzeUmbrella(p, opt)
	return rep, fs, nil
}

// AnalyzeUmbrella runs every umb-an rule over the parsed events.
func AnalyzeUmbrella(p *svParsed, opt SvOptions) (*SvReport, []Finding) {
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
	seen := map[string]bool{}
	once := func(k string) bool {
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}
	blocked := map[string]int{}
	blockedEv := map[string]SvEvent{}
	nx := map[string]int{}
	nxEv := map[string]SvEvent{}
	dnsLong := map[[2]string]int{}
	dnsEx := map[[2]string]string{}
	for i := range ev {
		e := &ev[i]
		svTimeRange(&first, &last, e.T)
		who := svWho(e)
		if who != "" {
			users[who] = true
		}
		dest := e.Host
		sample := fmt.Sprintf("%s %s action=%s", strings.TrimPrefix(e.Kind, "umb-"), dest+e.Path, orUnknown(e.Raw))
		cats := strings.Join(e.Cats, " ")
		if e.Action == "allow" {
			if c := zsContains(cats, umbThreatCats); c != "" && once("t|"+who+dest) {
				emit("umb-an-threat-category-allowed", "high", e.T, who, who+dest, fmt.Sprintf("%s reached %s, categorised %q, and it was allowed", orUnknown(who), dest, webTruncate(webSanitise(cats), 80)), sample)
			} else if c := zsContains(cats, umbEvasionCats); c != "" && once("e|"+who+dest) {
				emit("umb-an-anonymizer-allowed", "medium", e.T, who, who+dest, fmt.Sprintf("%s reached %s, categorised %q, and it was allowed", orUnknown(who), dest, webTruncate(webSanitise(cats), 80)), sample)
			}
		}
		if e.Action == "block" && who != "" {
			blocked[who]++
			if _, ok := blockedEv[who]; !ok {
				blockedEv[who] = *e
			}
		}
		if e.Kind == "umb-dns" {
			if e.RCode == "NXDOMAIN" && who != "" {
				nx[who]++
				if _, ok := nxEv[who]; !ok {
					nxEv[who] = *e
				}
			}
			if svDNSLong(e.Query) && e.Action != "block" {
				k := [2]string{who, zsParent(e.Query)}
				dnsLong[k]++
				if _, ok := dnsEx[k]; !ok {
					dnsEx[k] = e.Query
				}
			}
		}
		if e.Kind == "umb-proxy" && e.AV != "" && e.Action == "allow" && once("v|"+who+dest+e.AV) {
			emit("umb-an-proxy-malware-allowed", "high", e.T, who, who+dest+e.AV, fmt.Sprintf("%s: response from %s carried %q and was allowed", orUnknown(who), dest, webTruncate(webSanitise(e.AV), 80)), sample)
		}
	}
	for _, u := range svSortedKeys(blocked) {
		if blocked[u] >= umbBlockBurst {
			e := blockedEv[u]
			emit("umb-an-block-burst", "medium", e.T, u, u, fmt.Sprintf("%s was blocked %d times", u, blocked[u]), fmt.Sprintf("%s %s", strings.TrimPrefix(e.Kind, "umb-"), e.Host+e.Path))
		}
	}
	for _, u := range svSortedKeys(nx) {
		if nx[u] >= umbNXBurst {
			emit("umb-an-nxdomain-burst", "medium", nxEv[u].T, u, u, fmt.Sprintf("%s received %d NXDOMAIN answers", u, nx[u]), "dns "+nxEv[u].Query+" rcode=NXDOMAIN")
		}
	}
	for _, k := range zsSortedKeys2(dnsLong) {
		if dnsLong[k] >= zsTunnelQueries {
			emit("umb-an-dns-tunnel-like", "high", last, k[0], k[0]+"|"+k[1], fmt.Sprintf("%s sent %d very long DNS names under %s", orUnknown(k[0]), dnsLong[k], k[1]), "dns "+dnsEx[k])
		}
	}
	return svFinish("umbrella", umbRules, p, out, opt, users, first, last, truncated)
}

func umbrellaGuidance() []GuidanceEntry { return svGuidance(umbRules, "Umbrella") }
