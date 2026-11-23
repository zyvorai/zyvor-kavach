// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

// DNS query-log heuristics. Everything is computed from the supplied window only: Kavach has no
// registration data, no passive DNS and no reputation feed, so "newly seen domain" in the sense of
// a young registration cannot be determined and is deliberately not claimed.
const (
	dnsDGAMinLen        = 10
	dnsDGAMinScore      = 4
	dnsDGAMinDomains    = 3
	dnsTunnelSubs       = 100
	dnsTunnelAvgLen     = 30.0
	dnsTunnelMaxLabel   = 52
	dnsTunnelLongSubs   = 20
	dnsTunnelTXT        = 50
	dnsNXPerMinute      = 50
	dnsNXDistinct       = 30
	dnsFluxIPs          = 8
	dnsFluxNets         = 4
	dnsFluxTTL          = 300
	dnsDomainsCap       = 50000
	dnsClientsCap       = 20000
	dnsSubsCap          = 2000
	dnsPerClientDomains = 64
)

var dnsSLDTwoPart = map[string]bool{"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "com.au": true, "net.au": true, "org.au": true, "co.jp": true, "or.jp": true, "ne.jp": true,
	"com.br": true, "com.cn": true, "net.cn": true, "org.cn": true, "co.in": true, "co.za": true, "co.nz": true, "com.mx": true, "com.tr": true, "com.sg": true, "com.hk": true, "co.kr": true, "com.ar": true, "com.ua": true}

// netRegDomain returns the last two labels (three for a small built-in list of two-part suffixes).
// It is an approximation: there is no public-suffix list in the standard library.
func netRegDomain(q string) (reg, sub string) {
	labels := strings.Split(strings.Trim(q, "."), ".")
	if len(labels) < 2 {
		return "", ""
	}
	n := 2
	if len(labels) >= 3 && dnsSLDTwoPart[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if n > len(labels) {
		n = len(labels)
	}
	reg = strings.Join(labels[len(labels)-n:], ".")
	sub = strings.Join(labels[:len(labels)-n], ".")
	return reg, sub
}

func dnsSkipName(q string) bool {
	if q == "" || strings.HasSuffix(q, ".arpa") || strings.HasSuffix(q, ".local") || strings.HasSuffix(q, ".localhost") || strings.HasSuffix(q, ".internal") || !strings.Contains(q, ".") {
		return true
	}
	if _, err := netip.ParseAddr(q); err == nil {
		return true
	}
	return false
}

var dnsCommonBigrams = func() map[string]bool {
	m := map[string]bool{}
	for _, b := range strings.Fields(dnsBigramList) {
		m[b] = true
	}
	return m
}()

const dnsBigramList = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi ga ib yi ub da"

// dnsDGAScore returns a 0-5 score and whether the label is long enough to judge. Five weak signals
// each add one point: Shannon entropy, low vowel share, a long consonant run, many digits and few
// common English bigrams. Hash-like CDN names, base32/base64 identifiers, hex ids and some
// non-English brand names also score high: this is a ranking aid, not a classifier.
func dnsDGAScore(label string) (int, bool) {
	if len(label) < dnsDGAMinLen || len(label) > 63 {
		return 0, false
	}
	var cnt [256]int
	letters, vowels, digits, run, maxRun, bi, biCommon := 0, 0, 0, 0, 0, 0, 0
	for i := 0; i < len(label); i++ {
		c := label[i]
		cnt[c]++
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case c >= 'a' && c <= 'z':
			letters++
			if strings.IndexByte("aeiou", c) >= 0 {
				vowels++
				run = 0
			} else {
				run++
				if run > maxRun {
					maxRun = run
				}
			}
		default:
			run = 0
		}
		if i > 0 && label[i-1] >= 'a' && label[i-1] <= 'z' && c >= 'a' && c <= 'z' {
			bi++
			if dnsCommonBigrams[label[i-1:i+1]] {
				biCommon++
			}
		}
	}
	n := float64(len(label))
	h := 0.0
	for _, k := range cnt {
		if k > 0 {
			p := float64(k) / n
			h -= p * math.Log2(p)
		}
	}
	score := 0
	if h >= 3.2 {
		score++
	}
	if letters > 0 && float64(vowels)/float64(letters) < 0.2 {
		score++
	}
	if maxRun >= 5 {
		score++
	}
	if float64(digits)/n >= 0.3 {
		score++
	}
	if bi > 0 && float64(biCommon)/float64(bi) < 0.45 {
		score++
	}
	return score, true
}

func dnsIsNX(rc string) bool { return rc == "NXDOMAIN" || rc == "3" }

func dnsTXTLike(qt string) bool {
	switch qt {
	case "TXT", "NULL", "ANY", "16", "10", "255":
		return true
	}
	return false
}

type dnsDomainStat struct {
	subs               map[string]struct{}
	queries, txt, long int
	subLenSum          int
	maxLabel           int
	clients            map[string]struct{}
	ips                map[string]struct{}
	nets               map[string]struct{}
	minTTL             int
	first              netEventRef
}

type netEventRef struct {
	t   int64
	set bool
}

type dnsClientStat struct {
	dga     map[string]struct{}
	dgaQ    int
	dgaNX   int
	allQ    int
	nxTotal int
}

// netDNSAnalyze runs the DNS heuristics. emit(rule, time, entity IP, key, description, severity).
func netDNSAnalyze(evs []NetEvent, rep *NetReport, emit func(rule string, t int64, ip, key, desc, sev string), over func() bool) {
	domains := map[string]*dnsDomainStat{}
	clients := map[string]*dnsClientStat{}
	type minKey struct {
		c string
		m int64
	}
	type nxB struct {
		n     int
		names map[string]struct{}
	}
	nx := map[minKey]*nxB{}
	nxFlag := map[string]bool{}
	for i := range evs {
		e := &evs[i]
		if e.Kind != "dns" || dnsSkipName(e.Query) {
			continue
		}
		if i%4096 == 0 && over() {
			return
		}
		rep.DNSQueries++
		reg, sub := netRegDomain(e.Query)
		if reg == "" {
			continue
		}
		client := e.Src
		d := domains[reg]
		if d == nil && len(domains) < dnsDomainsCap {
			d = &dnsDomainStat{subs: map[string]struct{}{}, clients: map[string]struct{}{}, ips: map[string]struct{}{}, nets: map[string]struct{}{}, minTTL: -1}
			domains[reg] = d
		}
		if d != nil {
			d.queries++
			if sub != "" {
				if len(d.subs) < dnsSubsCap {
					d.subs[sub] = struct{}{}
				}
				d.subLenSum += len(sub)
				for _, l := range strings.Split(sub, ".") {
					if len(l) > d.maxLabel {
						d.maxLabel = len(l)
					}
				}
			}
			if dnsTXTLike(e.QType) {
				d.txt++
			}
			if client != "" && len(d.clients) < 64 {
				d.clients[client] = struct{}{}
			}
			if !d.first.set {
				d.first = netEventRef{e.T.Unix(), true}
			}
			if e.QType == "" || e.QType == "A" || e.QType == "AAAA" || e.QType == "1" || e.QType == "28" {
				for _, a := range e.Answers {
					if ad, err := netip.ParseAddr(a); err == nil && !netPrivate(ad) && len(d.ips) < 256 {
						d.ips[ad.String()] = struct{}{}
						if p, err := ad.Prefix(map[bool]int{true: 16, false: 32}[ad.Is4()]); err == nil {
							d.nets[p.String()] = struct{}{}
						}
					}
				}
				if e.TTL >= 0 && (d.minTTL < 0 || e.TTL < d.minTTL) {
					d.minTTL = e.TTL
				}
			}
		}
		if client == "" {
			continue
		}
		cs := clients[client]
		if cs == nil && len(clients) < dnsClientsCap {
			cs = &dnsClientStat{dga: map[string]struct{}{}}
			clients[client] = cs
		}
		isNX := dnsIsNX(e.RCode)
		if cs != nil {
			cs.allQ++
			if isNX {
				cs.nxTotal++
			}
			// the second-level label (leftmost label of the registered domain)
			sld := strings.SplitN(reg, ".", 2)[0]
			if sc, ok := dnsDGAScore(sld); ok && sc >= dnsDGAMinScore {
				cs.dgaQ++
				if isNX {
					cs.dgaNX++
				}
				if _, seen := cs.dga[reg]; !seen && len(cs.dga) < dnsPerClientDomains {
					cs.dga[reg] = struct{}{}
				}
			}
		}
		if isNX {
			k := minKey{client, e.T.Unix() / 60}
			b := nx[k]
			if b == nil && len(nx) < 100000 {
				b = &nxB{names: map[string]struct{}{}}
				nx[k] = b
			}
			if b != nil {
				b.n++
				if len(b.names) < 256 {
					b.names[e.Query] = struct{}{}
				}
				if b.n >= dnsNXPerMinute && len(b.names) >= dnsNXDistinct && !nxFlag[client] {
					nxFlag[client] = true
					emit("net-an-dns-nxdomain-storm", e.T.Unix(), client, client, fmt.Sprintf("%s received %d NXDOMAIN answers for %d distinct names within one minute", client, b.n, len(b.names)), "")
				}
			}
		}
	}
	names := make([]string, 0, len(domains))
	for k := range domains {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, reg := range names {
		d := domains[reg]
		subs := len(d.subs)
		avg := 0.0
		if d.queries > 0 && subs > 0 {
			avg = float64(d.subLenSum) / float64(d.queries)
		}
		t := d.first.t
		tunnel := (subs >= dnsTunnelSubs && avg >= dnsTunnelAvgLen) ||
			(subs >= dnsTunnelLongSubs && d.maxLabel >= dnsTunnelMaxLabel) ||
			(d.txt >= dnsTunnelTXT && subs >= dnsTunnelLongSubs)
		if tunnel {
			emit("net-an-dns-tunnel", t, firstKey(d.clients), reg, fmt.Sprintf("domain %s received %d queries with %d distinct subdomains (average subdomain length %.0f, longest label %d, %d TXT/NULL/ANY queries) from %d client(s); a DNS tunnelling shape (confidence: medium, CDN, antivirus cloud lookups and DNS blocklists look similar)", reg, d.queries, subs, avg, d.maxLabel, d.txt, len(d.clients)), "")
		}
		if len(d.ips) >= dnsFluxIPs && len(d.nets) >= dnsFluxNets && d.minTTL >= 0 && d.minTTL <= dnsFluxTTL {
			emit("net-an-dns-fast-flux", t, firstKey(d.clients), reg, fmt.Sprintf("domain %s resolved to %d distinct public addresses in %d networks with a minimum TTL of %ds in this log (confidence: low, content-delivery networks behave the same way)", reg, len(d.ips), len(d.nets), d.minTTL), "")
		}
	}
	cn := make([]string, 0, len(clients))
	for k := range clients {
		cn = append(cn, k)
	}
	sort.Strings(cn)
	for _, c := range cn {
		cs := clients[c]
		if len(cs.dga) >= dnsDGAMinDomains {
			conf := "low"
			if cs.dgaQ > 0 && float64(cs.dgaNX)/float64(cs.dgaQ) >= 0.5 {
				conf = "medium"
			}
			ex := make([]string, 0, 3)
			for k := range cs.dga {
				ex = append(ex, k)
			}
			sort.Strings(ex)
			if len(ex) > 3 {
				ex = ex[:3]
			}
			emit("net-an-dns-dga", 0, c, c, fmt.Sprintf("%s queried %d distinct algorithmic-looking domains (%d queries, %d NXDOMAIN), for example %s (confidence: %s; hash-like CDN and cloud names also score high)", c, len(cs.dga), cs.dgaQ, cs.dgaNX, strings.Join(ex, ", "), conf), "")
		}
	}
}

func firstKey(m map[string]struct{}) string {
	best := ""
	for k := range m {
		if best == "" || k < best {
			best = k
		}
	}
	return best
}
