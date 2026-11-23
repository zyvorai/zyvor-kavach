// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bufio"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Offline network-log analytics (observation only). Thresholds are fixed constants tuned for
// summarising a log you send, not for production alerting; every finding carries a confidence word
// and the reason a benign cause is plausible. Nothing is blocked, scanned or looked up.
const (
	netBudget          = 3 * time.Second
	netFindCapPerRule  = 25
	netBeaconMin       = 12
	netBeaconMaxRel    = 0.15 // median absolute deviation / median interval
	netBeaconWithin    = 0.85 // share of intervals within +-20% of the median
	netBeaconMinIntSec = 5.0
	netBeaconMaxIntSec = 6 * 3600.0
	netSeriesCap       = 2000
	netPairsCap        = 50000
	netLongConnSec     = 4 * 3600.0
	netScanBucket      = 300
	netScanPorts       = 20
	netScanHosts       = 25
	netScanPairsCap    = 4096
	netScanKeysCap     = 20000
	netBruteWindow     = 600
	netBruteConns      = 30
	netSSHFails        = 10
	netFanoutWindow    = 600
	netSMBHosts        = 8
	netAdminHosts      = 10
	netExfilMinBytes   = 50 << 20
	netExfilMinPairs   = 10
	netExfilZ          = 6.0
	netRarePortConns   = 5
	netAlertStorm      = 200
	netDenyStorm       = 100
	netAllowAfterDeny  = 20
	netAdminFails      = 5
	netListMax         = 5000
)

var netRules = []struct{ ID, Tactic, Technique, TechID, Sev string }{
	{"net-an-beaconing", "Command and Control", "Application Layer Protocol", "T1071", "medium"},
	{"net-an-long-connection", "Command and Control", "Application Layer Protocol", "T1071", "low"},
	{"net-an-port-scan-vertical", "Discovery", "Network Service Discovery", "T1046", "medium"},
	{"net-an-port-scan-horizontal", "Discovery", "Network Service Discovery", "T1046", "medium"},
	{"net-an-login-bruteforce", "Credential Access", "Brute Force", "T1110", "medium"},
	{"net-an-ssh-guesser-success", "Credential Access", "Brute Force", "T1110", "high"},
	{"net-an-smb-fanout", "Lateral Movement", "SMB/Windows Admin Shares", "T1021.002", "high"},
	{"net-an-smb-admin-share", "Lateral Movement", "SMB/Windows Admin Shares", "T1021.002", "medium"},
	{"net-an-eastwest-fanout", "Lateral Movement", "Remote Services", "T1021", "medium"},
	{"net-an-tls-selfsigned", "Command and Control", "Encrypted Channel", "T1573", "low"},
	{"net-an-tls-expired", "Command and Control", "Encrypted Channel", "T1573", "low"},
	{"net-an-tls-fingerprint-match", "Command and Control", "Encrypted Channel", "T1573", "medium"},
	{"net-an-zeek-notice", "Command and Control", "Application Layer Protocol", "T1071", "low"},
	{"net-an-dns-dga", "Command and Control", "Dynamic Resolution: Domain Generation Algorithms", "T1568.002", "medium"},
	{"net-an-dns-nxdomain-storm", "Command and Control", "Dynamic Resolution: Domain Generation Algorithms", "T1568.002", "medium"},
	{"net-an-dns-fast-flux", "Command and Control", "Dynamic Resolution: Fast Flux DNS", "T1568.001", "low"},
	{"net-an-dns-tunnel", "Command and Control", "Application Layer Protocol: DNS", "T1071.004", "high"},
	{"net-an-exfil-volume", "Exfiltration", "Exfiltration Over Alternative Protocol", "T1048", "medium"},
	{"net-an-rare-port", "Command and Control", "Non-Standard Port", "T1571", "low"},
	{"net-an-badlist-contact", "Command and Control", "Application Layer Protocol", "T1071", "high"},
	{"net-an-alert-storm", "Reconnaissance", "Active Scanning", "T1595", "medium"},
	{"net-eve-c2", "Command and Control", "Application Layer Protocol", "T1071", "high"},
	{"net-eve-exploit", "Initial Access", "Exploit Public-Facing Application", "T1190", "high"},
	{"net-eve-recon", "Reconnaissance", "Active Scanning", "T1595", "low"},
	{"net-eve-dos", "Impact", "Endpoint Denial of Service", "T1499", "medium"},
	{"net-eve-credential", "Credential Access", "Brute Force", "T1110", "medium"},
	{"net-eve-policy", "Command and Control", "Application Layer Protocol", "T1071", "low"},
	{"net-an-fw-deny-storm", "Reconnaissance", "Active Scanning", "T1595", "medium"},
	{"net-an-fw-allow-after-deny", "Initial Access", "Exploit Public-Facing Application", "T1190", "medium"},
	{"net-an-fw-threat-allowed", "Initial Access", "Exploit Public-Facing Application", "T1190", "medium"},
	{"net-an-fw-config-change", "Defense Evasion", "Disable or Modify System Firewall", "T1562.004", "low"},
	{"net-an-fw-admin-login-failed", "Credential Access", "Brute Force", "T1110", "medium"},
}

func init() {
	for _, r := range netRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func netRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(netRules))
	for _, a := range netRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// NetOptions carries the lists the operator supplies. Kavach never downloads either.
type NetOptions struct {
	Host    string
	BadNets []netip.Prefix
	FPs     map[string]string // JA3 / JA3S / JA4 fingerprint (lower case) -> label
}

type NetTalker struct {
	IP    string `json:"ip"`
	Bytes int64  `json:"bytes"`
	Conns int    `json:"connections"`
}

type NetSigCount struct {
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Count     int    `json:"count"`
}

type NetReport struct {
	Mode          string         `json:"mode"`
	Format        string         `json:"format"`
	Received      int            `json:"received"`
	Parsed        int            `json:"parsed"`
	Rejected      int            `json:"rejected"`
	ByKind        map[string]int `json:"by_kind"`
	ByRule        map[string]int `json:"by_rule"`
	From          *time.Time     `json:"from,omitempty"`
	To            *time.Time     `json:"to,omitempty"`
	TopTalkers    []NetTalker    `json:"top_talkers"`
	TopSignatures []NetSigCount  `json:"top_signatures,omitempty"`
	DNSQueries    int            `json:"dns_queries,omitempty"`
	ListEntries   int            `json:"list_entries,omitempty"`
	Findings      int            `json:"findings"`
	Truncated     bool           `json:"truncated,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
	Note          string         `json:"note"`
}

// netParseLists reads the optional bad-IP/CIDR list and the fingerprint list (one entry per line,
// '#' comments, blank lines ignored; fingerprint lines may carry a label after whitespace).
func netParseBadNets(text string) ([]netip.Prefix, int) {
	var out []netip.Prefix
	bad := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	for sc.Scan() && len(out) < netListMax {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if p, err := netip.ParsePrefix(l); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(l); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		} else {
			bad++
		}
	}
	return out, bad
}

func netParseFPs(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	for sc.Scan() && len(out) < netListMax {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		fp := strings.ToLower(webTruncate(webSanitise(f[0]), 64))
		label := ""
		if len(f) > 1 {
			label = netRedact(strings.Join(f[1:], " "))
		}
		out[fp] = label
	}
	return out
}

func netMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	if len(c)%2 == 1 {
		return c[len(c)/2]
	}
	return (c[len(c)/2-1] + c[len(c)/2]) / 2
}

func netMAD(xs []float64, med float64) float64 {
	d := make([]float64, len(xs))
	for i, x := range xs {
		d[i] = math.Abs(x - med)
	}
	return netMedian(d)
}

// netBeacon reports whether a sorted series of connection times (unix seconds) is regular.
func netBeacon(ts []float64) (ok bool, med, rel, within float64) {
	if len(ts) < netBeaconMin {
		return false, 0, 0, 0
	}
	iv := make([]float64, 0, len(ts))
	prev := ts[0]
	for _, t := range ts[1:] {
		if t-prev < 1 { // collapse bursts inside one second
			continue
		}
		iv = append(iv, t-prev)
		prev = t
	}
	if len(iv) < netBeaconMin-1 {
		return false, 0, 0, 0
	}
	med = netMedian(iv)
	if med < netBeaconMinIntSec || med > netBeaconMaxIntSec {
		return false, med, 0, 0
	}
	rel = netMAD(iv, med) / med
	n := 0
	for _, x := range iv {
		if math.Abs(x-med) <= 0.2*med {
			n++
		}
	}
	within = float64(n) / float64(len(iv))
	return rel <= netBeaconMaxRel && within >= netBeaconWithin, med, rel, within
}

var netFailStates = map[string]bool{"S0": true, "REJ": true, "RSTOS0": true, "RSTRH": true, "SH": true, "SHR": true}
var netNoBeaconPorts = map[int]bool{53: true, 67: true, 68: true, 123: true, 137: true, 138: true, 514: true, 1900: true, 5353: true}
var netCommonPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true, 22: true, 25: true, 53: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true, 123: true, 3306: true, 5432: true, 1433: true, 3389: true, 445: true, 21: true, 8000: true, 8888: true, 5228: true, 853: true, 1194: true, 51820: true, 500: true, 4500: true}
var netAdminPorts = map[int]bool{135: true, 22: true, 23: true, 3389: true, 5985: true, 5986: true, 5900: true}

type netSeries struct {
	ts    []float64
	n     int
	pub   bool
	first time.Time
}

func netIsProbe(e *NetEvent) bool {
	switch e.Kind {
	case "conn":
		return netFailStates[e.State]
	case "flow", "fw":
		return e.Action == "deny" || (e.Kind == "flow" && e.Action != "deny" && e.OrigBytes+e.RespBytes > 0 && e.OrigBytes+e.RespBytes <= 200)
	}
	return false
}

func netSuccessful(e *NetEvent) bool {
	return (e.Kind == "conn" || e.Kind == "flow" || e.Kind == "fw") && e.Start && e.Action != "deny" && !(e.Kind == "conn" && netFailStates[e.State])
}

func netEveRule(category, sig string) string {
	c, s := strings.ReplaceAll(strings.ToLower(category), " ", "-"), strings.ToLower(sig)
	has := func(x string, subs ...string) bool {
		for _, k := range subs {
			if strings.Contains(x, k) {
				return true
			}
		}
		return false
	}
	switch {
	case has(c, "trojan", "malware", "command-and-control", "c2", "coin") || has(s, "cnc", "c2 ", " c&c", "botnet"):
		return "net-eve-c2"
	case has(c, "default-username", "default-login", "unsuccessful-user", "suspicious-login", "credential"):
		return "net-eve-credential"
	case has(c, "web-application-attack", "attempted-admin", "attempted-user", "shellcode", "exploit", "successful-admin", "successful-user", "rpc-portmap-decode") || has(s, "exploit", "injection", "overflow"):
		return "net-eve-exploit"
	case has(c, "denial-of-service", "attempted-dos"):
		return "net-eve-dos"
	case has(c, "recon", "scan", "information-leak"):
		return "net-eve-recon"
	}
	return "net-eve-policy"
}

// AnalyzeNetwork runs the detections over parsed events.
func AnalyzeNetwork(p *netParsed, opt NetOptions) (*NetReport, []Finding) {
	rep := &NetReport{Mode: "observe-only", Format: p.Format, Received: p.Received, Parsed: len(p.Events), Rejected: p.Rejected,
		ByKind: p.ByKind, ByRule: map[string]int{}, TopTalkers: []NetTalker{}, Errors: p.Errors,
		ListEntries: len(opt.BadNets) + len(opt.FPs),
		Note:        "offline analysis of logs you sent; no capture, lookup or blocking. Thresholds are fixed heuristics tuned for summarising a supplied log, not for production alerting; every finding states its confidence and a benign explanation."}
	host := opt.Host
	if host == "" {
		host = "net:logs"
	}
	deadline := time.Now().Add(netBudget)
	over := func() bool {
		if time.Now().After(deadline) {
			rep.Truncated = true
			return true
		}
		return false
	}
	evs := p.Events
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].T.Before(evs[j].T) })
	var last time.Time
	if len(evs) > 0 {
		f := evs[0].T
		last = evs[len(evs)-1].T
		rep.From, rep.To = &f, &last
	}
	var out []Finding
	perRule := map[string]int{}
	seen := map[string]bool{}
	sevOf := map[string]string{}
	for _, r := range netRules {
		sevOf[r.ID] = r.Sev
	}
	emit := func(rule string, t int64, ip, key, desc, sev string) {
		k := rule + "|" + key
		if seen[k] || perRule[rule] >= netFindCapPerRule {
			return
		}
		seen[k] = true
		perRule[rule]++
		rep.ByRule[rule]++
		if sev == "" {
			sev = sevOf[rule]
		}
		tm := last
		if t > 0 {
			tm = time.Unix(t, 0).UTC()
		}
		m := ruleMITRE[rule]
		out = append(out, Finding{ID: fmt.Sprintf("%s:%s:%s:%s:%d", host, rule, ip, key, tm.UnixNano()), Time: tm, Host: host, Rule: rule, Severity: sev,
			Description: webTruncate(desc, 600) + " (heuristic over the logs you sent; investigate, not proof of compromise)", Destination: ip,
			Tags:     []string{m.ID, "network", "analytics", "observe-only"},
			Evidence: Event{Time: tm, Host: host, Executable: "net:log", Command: webTruncate(desc, 300)}})
	}
	emitT := func(rule string, t time.Time, ip, key, desc, sev string) { emit(rule, t.Unix(), ip, key, desc, sev) }

	// --- single pass: talkers, series, scans, brute force, fan-out, volume, TLS, notices, lists
	type pairKey struct {
		src, dst string
		port     int
		proto    string
	}
	series := map[pairKey]*netSeries{}
	type scanKey struct {
		src string
		b   int64
	}
	type scanB struct {
		pairs map[[2]string]struct{} // dst, port
		ports map[string]map[int]struct{}
		hosts map[int]map[string]struct{}
		n     int
	}
	scans := map[scanKey]*scanB{}
	type bfKey struct {
		src, dst string
		port     int
		b        int64
	}
	brute := map[bfKey]int{}
	type fanKey struct {
		src string
		b   int64
	}
	smb, adm := map[fanKey]map[string]struct{}{}, map[fanKey]map[string]struct{}{}
	talk := map[string]*NetTalker{}
	volume := map[[2]string]int64{}
	portConns := map[pairKey]int{}
	portSrcs, portDsts := map[int]map[string]struct{}{}, map[int]map[string]struct{}{}
	sshFail := map[[2]string]int{}
	sshFailFlag := map[[2]string]bool{}
	type badKey struct{ internal, bad string }
	type badVal struct {
		n           int
		first, last time.Time
		ports       map[int]struct{}
		via         string
	}
	bad := map[badKey]*badVal{}
	type alertKey struct{ rule, src string }
	type alertVal struct {
		n, minSev, blocked int
		sigs               map[string]int
		first              time.Time
		cats               map[string]struct{}
	}
	alerts := map[alertKey]*alertVal{}
	sigCount := map[[2]string]int{}
	alertMin := map[[2]interface{}]int{}
	fwDeny := map[scanKey]int{}
	denyHist := map[[2]string][]int64{}
	allowAfterFlag := map[[2]string]bool{}
	adminFail := map[string]int{}
	selfSeen := map[string]bool{}

	inBad := func(a netip.Addr) bool {
		if !a.IsValid() {
			return false
		}
		for _, pf := range opt.BadNets {
			if pf.Contains(a) {
				return true
			}
		}
		return false
	}

	for i := range evs {
		e := &evs[i]
		if i%4096 == 0 && over() {
			break
		}
		// talkers
		if e.Src != "" && (e.Kind == "conn" || e.Kind == "flow") {
			t := talk[e.Src]
			if t == nil && len(talk) < 50000 {
				t = &NetTalker{IP: e.Src}
				talk[e.Src] = t
			}
			if t != nil {
				t.Bytes += e.OrigBytes + e.RespBytes
				if e.Start {
					t.Conns++
				}
			}
		}
		// operator list contact
		if len(opt.BadNets) > 0 && (e.Kind == "conn" || e.Kind == "flow" || e.Kind == "fw" || e.Kind == "tls" || e.Kind == "http" || e.Kind == "dns" || e.Kind == "alert") {
			check := func(internal string, other netip.Addr, via string) {
				if inBad(other) && len(bad) < 5000 {
					k := badKey{internal, other.String()}
					v := bad[k]
					if v == nil {
						v = &badVal{first: e.T, ports: map[int]struct{}{}, via: via}
						bad[k] = v
					}
					v.n++
					v.last = e.T
					if e.DPort > 0 && len(v.ports) < 8 {
						v.ports[e.DPort] = struct{}{}
					}
				}
			}
			if e.DstA.IsValid() {
				check(e.Src, e.DstA, e.Kind)
			}
			if e.SrcA.IsValid() && e.Kind != "dns" {
				check(e.Dst, e.SrcA, e.Kind)
			}
			if e.Kind == "dns" {
				for _, a := range e.Answers {
					if ad, ok := netParseAddr(a); ok {
						check(e.Src, ad, "dns answer")
					}
				}
			}
		}
		switch e.Kind {
		case "conn", "flow", "fw":
			if e.Kind == "fw" && e.Category != "traffic" && e.Category != "threat" {
				break
			}
			if e.Kind == "fw" && e.Category == "threat" {
				break
			}
			srcPriv, dstPriv := netPrivate(e.SrcA), netPrivate(e.DstA)
			// beacon series
			if netSuccessful(e) && e.DstA.IsValid() && !dstPriv && e.DPort > 0 && !netNoBeaconPorts[e.DPort] && (e.Proto == "tcp" || e.Proto == "udp") {
				k := pairKey{e.Src, e.Dst, e.DPort, e.Proto}
				s := series[k]
				if s == nil && len(series) < netPairsCap {
					s = &netSeries{first: e.T}
					series[k] = s
				}
				if s != nil {
					s.n++
					if len(s.ts) < netSeriesCap {
						s.ts = append(s.ts, float64(e.T.UnixNano())/1e9)
					}
				}
			}
			// long connection (public destination, established)
			if e.Kind == "conn" && e.Dur >= netLongConnSec && e.DstA.IsValid() && !dstPriv && !netFailStates[e.State] {
				emitT("net-an-long-connection", e.T, e.Src, e.Src+">"+e.Dst+fmt.Sprint(e.DPort), fmt.Sprintf("%s held a connection to %s:%d open for %.1f hours (confidence: low; remote-admin sessions, VPN tunnels and streaming do this)", e.Src, e.Dst, e.DPort, e.Dur/3600), "")
			}
			// scans
			if e.Start && netIsProbe(e) && e.SrcA.IsValid() && e.DstA.IsValid() && e.DPort > 0 {
				k := scanKey{e.Src, e.T.Unix() / netScanBucket}
				b := scans[k]
				if b == nil && len(scans) < netScanKeysCap {
					b = &scanB{pairs: map[[2]string]struct{}{}, ports: map[string]map[int]struct{}{}, hosts: map[int]map[string]struct{}{}}
					scans[k] = b
				}
				if b != nil && b.n < netScanPairsCap {
					b.n++
					b.pairs[[2]string{e.Dst, fmt.Sprint(e.DPort)}] = struct{}{}
					if b.ports[e.Dst] == nil {
						b.ports[e.Dst] = map[int]struct{}{}
					}
					b.ports[e.Dst][e.DPort] = struct{}{}
					if b.hosts[e.DPort] == nil {
						b.hosts[e.DPort] = map[string]struct{}{}
					}
					b.hosts[e.DPort][e.Dst] = struct{}{}
				}
			}
			// login brute force by connection volume
			if e.Start && e.DstA.IsValid() && (e.DPort == 22 || e.DPort == 23 || e.DPort == 3389 || e.DPort == 21 || e.DPort == 5900) && e.Action != "deny" {
				k := bfKey{e.Src, e.Dst, e.DPort, e.T.Unix() / netBruteWindow}
				if brute[k] < 1<<30 && (len(brute) < 100000 || brute[k] > 0) {
					brute[k]++
					if brute[k] == netBruteConns {
						emitT("net-an-login-bruteforce", e.T, e.Src, fmt.Sprintf("%s>%s:%d", e.Src, e.Dst, e.DPort), fmt.Sprintf("%s opened %d or more connections to %s:%d within %ds (confidence: low to medium; a connection count cannot tell failed from successful logins, automation and health checks look the same)", e.Src, netBruteConns, e.Dst, e.DPort, netBruteWindow), "")
					}
				}
			}
			// east-west fan-out
			if srcPriv && dstPriv && netSuccessful(e) && e.DPort > 0 {
				k := fanKey{e.Src, e.T.Unix() / netFanoutWindow}
				switch {
				case e.DPort == 445 || e.DPort == 139:
					if smb[k] == nil && len(smb) < 20000 {
						smb[k] = map[string]struct{}{}
					}
					if m := smb[k]; m != nil && len(m) < 256 {
						m[e.Dst] = struct{}{}
					}
				case netAdminPorts[e.DPort]:
					if adm[k] == nil && len(adm) < 20000 {
						adm[k] = map[string]struct{}{}
					}
					if m := adm[k]; m != nil && len(m) < 256 {
						m[e.Dst] = struct{}{}
					}
				}
			}
			// outbound volume and rare ports (private -> public only)
			if srcPriv && e.DstA.IsValid() && !dstPriv && e.Action != "deny" {
				if len(volume) < netPairsCap || volume[[2]string{e.Src, e.Dst}] > 0 {
					volume[[2]string{e.Src, e.Dst}] += e.OrigBytes
				}
				if e.Start && e.DPort >= 1024 && !netCommonPorts[e.DPort] && (e.Proto == "tcp" || e.Proto == "udp") {
					k := pairKey{e.Src, e.Dst, e.DPort, e.Proto}
					if len(portConns) < netPairsCap || portConns[k] > 0 {
						portConns[k]++
					}
					if portSrcs[e.DPort] == nil && len(portSrcs) < 20000 {
						portSrcs[e.DPort], portDsts[e.DPort] = map[string]struct{}{}, map[string]struct{}{}
					}
					if m := portSrcs[e.DPort]; m != nil && len(m) < 64 {
						m[e.Src] = struct{}{}
						portDsts[e.DPort][e.Dst] = struct{}{}
					}
				}
			}
			// firewall deny history
			if e.Action == "deny" && e.SrcA.IsValid() && e.DstA.IsValid() && (e.Kind == "fw" || e.Kind == "flow") {
				k := scanKey{e.Src, e.T.Unix() / netScanBucket}
				if fwDeny[k] < 1<<30 && (len(fwDeny) < netScanKeysCap || fwDeny[k] > 0) {
					fwDeny[k]++
					if fwDeny[k] == netDenyStorm {
						emitT("net-an-fw-deny-storm", e.T, e.Src, e.Src, fmt.Sprintf("%s was denied %d or more times within %ds (confidence: medium; a misconfigured client retrying also does this)", e.Src, netDenyStorm, netScanBucket), "")
					}
				}
				pk := [2]string{e.Src, e.Dst}
				h := denyHist[pk]
				if len(denyHist) < 50000 || h != nil {
					cut := e.T.Unix() - netBruteWindow
					kept := h[:0]
					for _, x := range h {
						if x >= cut {
							kept = append(kept, x)
						}
					}
					if len(kept) < 512 {
						kept = append(kept, e.T.Unix())
					}
					denyHist[pk] = kept
				}
			} else if e.Action == "allow" && e.Start && (e.Kind == "fw" || e.Kind == "flow") && e.SrcA.IsValid() && !srcPriv {
				pk := [2]string{e.Src, e.Dst}
				if h := denyHist[pk]; len(h) >= netAllowAfterDeny && !allowAfterFlag[pk] && e.T.Unix()-h[len(h)-1] <= netBruteWindow {
					allowAfterFlag[pk] = true
					emitT("net-an-fw-allow-after-deny", e.T, e.Src, e.Src+">"+e.Dst, fmt.Sprintf("external %s was denied %d times toward %s and then allowed (port %d) within %ds; the first allowed connection after a denial run may point at a rule gap (confidence: low to medium, a legitimate retry after a rule change looks the same)", e.Src, len(h), e.Dst, e.DPort, netBruteWindow), "")
				}
			}
		case "ssh":
			if e.AuthOK == 0 && e.SrcA.IsValid() {
				k := [2]string{e.Src, e.Dst}
				sshFail[k]++
				if sshFail[k] == netSSHFails && !sshFailFlag[k] {
					sshFailFlag[k] = true
					emitT("net-an-login-bruteforce", e.T, e.Src, e.Src+">"+e.Dst+":ssh", fmt.Sprintf("%s failed SSH authentication %d times against %s (Zeek ssh.log; confidence: medium)", e.Src, netSSHFails, e.Dst), "")
				}
			} else if e.AuthOK == 1 && sshFailFlag[[2]string{e.Src, e.Dst}] {
				emitT("net-an-ssh-guesser-success", e.T, e.Src, e.Src+">"+e.Dst, fmt.Sprintf("%s authenticated to %s over SSH after %d earlier failures (confidence: medium to high; a user who mistyped a password many times is the usual benign cause)", e.Src, e.Dst, sshFail[[2]string{e.Src, e.Dst}]), "")
			}
		case "tls":
			if len(opt.FPs) > 0 {
				for _, fp := range []string{e.JA3, e.JA3S, e.JA4} {
					if fp == "" {
						continue
					}
					if lab, ok := opt.FPs[strings.ToLower(fp)]; ok {
						emitT("net-an-tls-fingerprint-match", e.T, e.Src, e.Src+">"+e.Dst+fp, fmt.Sprintf("%s presented TLS fingerprint %s to %s (%s) which is on your supplied list%s (confidence: low to medium; fingerprints are shared by many programs)", e.Src, webTruncate(fp, 40), e.Dst, e.SNI, netLabel(lab)), "")
					}
				}
			}
			if e.State == "established" && e.DstA.IsValid() && !netPrivate(e.DstA) {
				if e.SelfSigned && !selfSeen[e.Dst+"|"+e.Subject] {
					selfSeen[e.Dst+"|"+e.Subject] = true
					emitT("net-an-tls-selfsigned", e.T, e.Src, e.Dst+"|"+e.Subject, fmt.Sprintf("%s completed TLS to %s (%s) with a self-signed certificate (%s) (confidence: low; internal tools and appliances use them, malware often does too)", e.Src, e.Dst, e.SNI, e.Subject), "")
				}
				if !e.NotAfter.IsZero() && e.NotAfter.Before(e.T) {
					emitT("net-an-tls-expired", e.T, e.Src, e.Dst+"|"+e.Subject, fmt.Sprintf("%s completed TLS to %s (%s) with a certificate that expired %s (confidence: low; neglected services are the common benign cause)", e.Src, e.Dst, e.SNI, e.NotAfter.Format("2006-01-02")), "")
				}
			}
		case "x509":
			if e.SelfSigned && !selfSeen["x|"+e.Subject] {
				selfSeen["x|"+e.Subject] = true
				emitT("net-an-tls-selfsigned", e.T, "", "x509|"+e.Subject, fmt.Sprintf("a self-signed certificate (%s) appears in x509.log (confidence: low)", e.Subject), "")
			}
			if !e.NotAfter.IsZero() && e.NotAfter.Before(e.T) {
				emitT("net-an-tls-expired", e.T, "", "x509|"+e.Subject, fmt.Sprintf("an expired certificate (%s, not valid after %s) appears in x509.log (confidence: low)", e.Subject, e.NotAfter.Format("2006-01-02")), "")
			}
		case "notice":
			emitT("net-an-zeek-notice", e.T, e.Src, e.Note+"|"+e.Src+"|"+e.Dst, fmt.Sprintf("Zeek raised notice %s%s: %s (relayed from your Zeek policy; Kavach did not re-evaluate it)", e.Note, netEndpoints(e), e.Msg), "")
		case "smb":
			low := strings.ToLower(e.Msg)
			if strings.Contains(low, "admin$") || strings.Contains(low, "c$") || strings.Contains(low, "ipc$") && strings.Contains(low, "svcctl") || strings.Contains(low, "svcctl") || strings.Contains(low, "atsvc") || strings.Contains(low, "psexe") {
				emitT("net-an-smb-admin-share", e.T, e.Src, e.Src+">"+e.Dst+"|"+e.Msg, fmt.Sprintf("%s used an SMB administrative share or remote service endpoint on %s (%s) (confidence: medium; IT administration and software deployment do the same)", e.Src, e.Dst, e.Msg), "")
			}
		case "alert":
			rule := netEveRule(e.Category, e.Sig)
			k := alertKey{rule, e.Src}
			v := alerts[k]
			if v == nil && len(alerts) < 20000 {
				v = &alertVal{minSev: 99, sigs: map[string]int{}, first: e.T, cats: map[string]struct{}{}}
				alerts[k] = v
			}
			if v != nil {
				v.n++
				if e.Sev > 0 && e.Sev < v.minSev {
					v.minSev = e.Sev
				}
				if e.Action == "deny" {
					v.blocked++
				}
				if len(v.sigs) < 64 || v.sigs[e.Sig] > 0 {
					v.sigs[e.Sig]++
				}
				if len(v.cats) < 8 {
					v.cats[e.Category] = struct{}{}
				}
			}
			sk := [2]string{e.Sig, e.Category}
			if len(sigCount) < 20000 || sigCount[sk] > 0 {
				sigCount[sk]++
			}
			ak := [2]interface{}{e.Src, e.T.Unix() / 60}
			if len(alertMin) < 100000 || alertMin[ak] > 0 {
				alertMin[ak]++
				if alertMin[ak] == netAlertStorm {
					emitT("net-an-alert-storm", e.T, e.Src, e.Src, fmt.Sprintf("%s triggered %d IDS alerts within one minute (confidence: medium; scanners, load tests and a noisy signature all do this)", e.Src, netAlertStorm), "")
				}
			}
		}
		if e.Kind == "fw" {
			switch e.Category {
			case "config-change":
				emitT("net-an-fw-config-change", e.T, e.Src, e.Src+"|"+e.User+"|"+e.Msg+fmt.Sprint(e.T.Unix()), fmt.Sprintf("firewall configuration change by %s%s: %s (confidence: low; verify against your change records)", orUnknown(e.User), netFrom(e), e.Msg), "")
			case "admin-login-failed":
				key := e.Src
				if key == "" {
					key = "user:" + e.User
				}
				adminFail[key]++
				if adminFail[key] == netAdminFails {
					emitT("net-an-fw-admin-login-failed", e.T, e.Src, key, fmt.Sprintf("%d failed firewall administrator logins from %s (user %s) in this log (confidence: medium)", netAdminFails, orUnknown(key), orUnknown(e.User)), "")
				}
			case "threat":
				if e.Action == "allow" {
					emitT("net-an-fw-threat-allowed", e.T, e.Src, e.Src+"|"+e.Msg, fmt.Sprintf("firewall threat log recorded %q from %s to %s with an allow/alert action (confidence: medium; the device did not block it)", e.Msg, e.Src, e.Dst), "")
				}
			}
		}
	}

	// --- post-processing of aggregates
	if !over() {
		keys := make([]pairKey, 0, len(series))
		for k := range series {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			if a.src != b.src {
				return a.src < b.src
			}
			if a.dst != b.dst {
				return a.dst < b.dst
			}
			return a.port < b.port
		})
		for _, k := range keys {
			s := series[k]
			if ok, med, rel, within := netBeacon(s.ts); ok {
				conf := "low"
				if s.n >= 30 && rel <= 0.08 {
					conf = "medium"
				}
				emitT("net-an-beaconing", s.first, k.src, fmt.Sprintf("%s>%s:%d", k.src, k.dst, k.port), fmt.Sprintf("%s contacted %s:%d/%s %d times at a median interval of %.0fs (relative deviation %.2f, %.0f%% of intervals within 20%% of the median) (confidence: %s; update checks, monitoring agents and chat or sync clients are regular too)", k.src, k.dst, k.port, k.proto, s.n, med, rel, within*100, conf), "")
			}
		}
	}
	scanKeys := make([]scanKey, 0, len(scans))
	for k := range scans {
		scanKeys = append(scanKeys, k)
	}
	sort.Slice(scanKeys, func(i, j int) bool {
		if scanKeys[i].b != scanKeys[j].b {
			return scanKeys[i].b < scanKeys[j].b
		}
		return scanKeys[i].src < scanKeys[j].src
	})
	for _, k := range scanKeys {
		b := scans[k]
		t := k.b * netScanBucket
		dsts := make([]string, 0, len(b.ports))
		for d := range b.ports {
			dsts = append(dsts, d)
		}
		sort.Strings(dsts)
		for _, d := range dsts {
			if n := len(b.ports[d]); n >= netScanPorts {
				emit("net-an-port-scan-vertical", t, k.src, k.src+">"+d, fmt.Sprintf("%s probed %d distinct ports on %s within %ds, mostly refused or empty (confidence: medium; authorised scanners and inventory tools look the same)", k.src, n, d, netScanBucket), "")
			}
		}
		ports := make([]int, 0, len(b.hosts))
		for p := range b.hosts {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		for _, p := range ports {
			if n := len(b.hosts[p]); n >= netScanHosts {
				emit("net-an-port-scan-horizontal", t, k.src, fmt.Sprintf("%s>*:%d", k.src, p), fmt.Sprintf("%s probed port %d on %d distinct hosts within %ds, mostly refused or empty (confidence: medium; authorised scanners and discovery tools look the same)", k.src, p, n, netScanBucket), "")
			}
		}
	}
	for k, m := range smb {
		if len(m) >= netSMBHosts {
			emit("net-an-smb-fanout", k.b*netFanoutWindow, k.src, k.src, fmt.Sprintf("%s connected to SMB on %d distinct internal hosts within %ds (confidence: medium; file servers, backup and software-deployment hosts do this routinely)", k.src, len(m), netFanoutWindow), "")
		}
	}
	for k, m := range adm {
		if len(m) >= netAdminHosts {
			emit("net-an-eastwest-fanout", k.b*netFanoutWindow, k.src, k.src, fmt.Sprintf("%s connected to remote-administration ports (RPC, SSH, RDP, WinRM, VNC) on %d distinct internal hosts within %ds (confidence: medium; jump hosts, patching and monitoring servers do this routinely)", k.src, len(m), netFanoutWindow), "")
		}
	}
	netExfil(volume, emit)
	pk := make([]pairKey, 0)
	for k, n := range portConns {
		if n >= netRarePortConns && len(portSrcs[k.port]) == 1 && len(portDsts[k.port]) == 1 {
			pk = append(pk, k)
		}
	}
	sort.Slice(pk, func(i, j int) bool {
		return portConns[pk[i]] > portConns[pk[j]] || (portConns[pk[i]] == portConns[pk[j]] && pk[i].src+pk[i].dst < pk[j].src+pk[j].dst)
	})
	for i, k := range pk {
		if i >= 10 {
			break
		}
		emit("net-an-rare-port", 0, k.src, fmt.Sprintf("%s>%s:%d", k.src, k.dst, k.port), fmt.Sprintf("%s made %d connections to %s on uncommon port %d/%s, a port no other host in this log used (confidence: low; custom applications and games use odd ports)", k.src, portConns[k], k.dst, k.port, k.proto), "")
	}
	bk := make([]badKey, 0, len(bad))
	for k := range bad {
		bk = append(bk, k)
	}
	sort.Slice(bk, func(i, j int) bool { return bk[i].internal+bk[i].bad < bk[j].internal+bk[j].bad })
	for _, k := range bk {
		v := bad[k]
		emitT("net-an-badlist-contact", v.first, k.internal, k.internal+">"+k.bad, fmt.Sprintf("%s had %d %s record(s) with %s, an address on your supplied list, between %s and %s (confidence: depends on your list; Kavach did not look the address up)", orUnknown(k.internal), v.n, v.via, k.bad, v.first.Format(time.RFC3339), v.last.Format(time.RFC3339)), "")
	}
	ak := make([]alertKey, 0, len(alerts))
	for k := range alerts {
		ak = append(ak, k)
	}
	sort.Slice(ak, func(i, j int) bool { return ak[i].rule+ak[i].src < ak[j].rule+ak[j].src })
	for _, k := range ak {
		v := alerts[k]
		sev := ""
		switch {
		case v.minSev == 1:
			sev = "high"
		case v.minSev == 2 && sevOf[k.rule] != "high":
			sev = "medium"
		case v.minSev >= 3 && v.minSev != 99:
			sev = "low"
		}
		top := netTopKeys(v.sigs, 3)
		cats := make([]string, 0, len(v.cats))
		for c := range v.cats {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		emitT(k.rule, v.first, k.src, k.src, fmt.Sprintf("%s raised %d Suricata alert(s) in %d signature(s), categories [%s], top: %s; %d blocked by the sensor (confidence: medium; the category-to-technique mapping is coarse and an alert is a signature match, not proof)", k.src, v.n, len(v.sigs), strings.Join(cats, ", "), strings.Join(top, " | "), v.blocked), sev)
	}
	netDNSAnalyze(evs, rep, emit, over)
	// report extras
	for _, t := range talk {
		rep.TopTalkers = append(rep.TopTalkers, *t)
	}
	sort.Slice(rep.TopTalkers, func(i, j int) bool {
		if rep.TopTalkers[i].Bytes != rep.TopTalkers[j].Bytes {
			return rep.TopTalkers[i].Bytes > rep.TopTalkers[j].Bytes
		}
		return rep.TopTalkers[i].IP < rep.TopTalkers[j].IP
	})
	if len(rep.TopTalkers) > 10 {
		rep.TopTalkers = rep.TopTalkers[:10]
	}
	for k, n := range sigCount {
		rep.TopSignatures = append(rep.TopSignatures, NetSigCount{Signature: k[0], Category: k[1], Count: n})
	}
	sort.Slice(rep.TopSignatures, func(i, j int) bool {
		if rep.TopSignatures[i].Count != rep.TopSignatures[j].Count {
			return rep.TopSignatures[i].Count > rep.TopSignatures[j].Count
		}
		return rep.TopSignatures[i].Signature < rep.TopSignatures[j].Signature
	})
	if len(rep.TopSignatures) > 10 {
		rep.TopSignatures = rep.TopSignatures[:10]
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	rep.Findings = len(out)
	return rep, out
}

func netExfil(volume map[[2]string]int64, emit func(rule string, t int64, ip, key, desc, sev string)) {
	if len(volume) < netExfilMinPairs {
		return
	}
	xs := make([]float64, 0, len(volume))
	for _, v := range volume {
		xs = append(xs, float64(v))
	}
	med := netMedian(xs)
	mad := netMAD(xs, med)
	type kv struct {
		k [2]string
		v int64
	}
	var hits []kv
	for k, v := range volume {
		if v < netExfilMinBytes {
			continue
		}
		x := float64(v)
		z := 0.0
		if mad > 0 {
			z = 0.6745 * (x - med) / mad
		}
		if (mad > 0 && z >= netExfilZ) || (mad == 0 && x >= 10*math.Max(med, 1)) {
			hits = append(hits, kv{k, v})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].v > hits[j].v })
	for i, h := range hits {
		if i >= 10 {
			break
		}
		emit("net-an-exfil-volume", 0, h.k[0], h.k[0]+">"+h.k[1], fmt.Sprintf("%s sent %.1f MiB to %s, far above the median of %.2f MiB across %d internal-to-external pairs in this log (robust z-score over median and MAD; confidence: low to medium; backups, software uploads and video calls are large too)", h.k[0], float64(h.v)/(1<<20), h.k[1], med/(1<<20), len(xs)), "")
	}
}

func netTopKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	l := make([]kv, 0, len(m))
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || (l[i].v == l[j].v && l[i].k < l[j].k) })
	var out []string
	for i, x := range l {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s x%d", webTruncate(x.k, 80), x.v))
	}
	return out
}

func netLabel(l string) string {
	if l == "" {
		return ""
	}
	return " labelled \"" + l + "\""
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func netEndpoints(e *NetEvent) string {
	if e.Src == "" && e.Dst == "" {
		return ""
	}
	return fmt.Sprintf(" (%s -> %s)", orUnknown(e.Src), orUnknown(e.Dst))
}

func netFrom(e *NetEvent) string {
	if e.Src == "" {
		return ""
	}
	return " from " + e.Src
}
