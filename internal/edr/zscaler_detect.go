// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"
)

// Offline analytics over exported Zscaler logs (observation only). Thresholds are fixed constants
// tuned for summarising a log you send, not for production alerting. Every finding says why a benign
// cause is plausible. Nothing is blocked, looked up or sent anywhere; URL query strings are dropped.
const (
	zsCapPerRule      = 25
	zsBlockedAllowWin = 30 * time.Minute
	zsDLPRepeat       = 5
	zsLargeUpload     = 100 << 20
	zsSaaSUpload      = 5 << 20
	zsSaaSUsers       = 3
	zsUnscanMin       = 3
	zsZPADenied       = 10
	zsZPAWindow       = 10 * time.Minute
	zsZPASweep        = 8
	zsTravelKmh       = 900.0
	zsTravelMinKm     = 500.0
	zsTravelCountry   = time.Hour
	zsTravelMaxGap    = 12 * time.Hour
	zsOffHoursMin     = 5
	zsTunnelQueries   = 20
	zsListMax         = 5000
)

var zsRules = []struct{ ID, Tactic, Technique, TechID, Sev, Title, Why, Benign string }{
	{"zs-an-threat-allowed", "Initial Access", "Drive-by Compromise", "T1189", "high", "Threat-flagged web transaction was allowed",
		"The log carries a threat name or category yet the action is allow, so the gateway let the transaction through (policy, a monitor-only mode or an exception).",
		"A monitor-only or caution policy, a tenant exception, or a threat label on a low-risk object such as an adware cookie."},
	{"zs-an-sandbox-allowed", "Execution", "User Execution: Malicious File", "T1204.002", "high", "Sandbox-flagged file was allowed through",
		"A sandbox or advanced-threat verdict on a file with an allow action means the file may have reached the user before or without a block.",
		"Patient-zero allow while the sandbox was still scanning, or a later-reclassified file."},
	{"zs-an-blocked-then-allowed", "Defense Evasion", "Impair Defenses", "T1562", "medium", "Same user and host blocked, then allowed within 30 minutes",
		"A block followed quickly by an allow for the same user and host suggests the user found a way around the control: another URL, a policy exception, a different forwarding path or a recategorisation.",
		"A help-desk exception, a category update, or a block on a sub-resource followed by an allow for the page."},
	{"zs-an-dlp-allowed", "Exfiltration", "Exfiltration Over Web Service", "T1567", "high", "Request that matched a DLP dictionary or engine was allowed",
		"Sensitive-data matches that are only logged do not stop the data leaving.",
		"A DLP rule in monitor mode by design, or a dictionary that is known to over-match."},
	{"zs-an-dlp-repeat", "Exfiltration", "Exfiltration Over Web Service", "T1567", "medium", "One user repeatedly hit DLP rules",
		"Repeated DLP matches from one user can be a bulk copy or repeated attempts at different destinations.",
		"A finance or HR user working with sensitive documents as part of the job."},
	{"zs-an-risky-category-allowed", "Command and Control", "Application Layer Protocol: Web Protocols", "T1071.001", "medium", "Allowed traffic to a risky URL category",
		"Newly registered, anonymiser, phishing, botnet and similar categories are over-represented in attacks; an allow means the policy does not stop them.",
		"Security research, a newly registered vendor domain, or a category that has not yet been tuned."},
	{"zs-an-unsanctioned-saas", "Exfiltration", "Exfiltration Over Web Service", "T1567", "medium", "Unsanctioned file-sharing, mail or messaging app in use",
		"Applications outside the operator's sanctioned list in data-moving classes are a shadow-IT and data-leak route.",
		"A new tool a team is evaluating or one the sanctioned list does not yet name."},
	{"zs-an-large-upload", "Exfiltration", "Exfiltration Over Web Service", "T1567", "medium", "Very large upload from one user to one host",
		"A large volume sent to a single web host is the classic shape of bulk exfiltration.",
		"A backup, a video upload or a software release by an engineer."},
	{"zs-an-unscannable-allowed", "Defense Evasion", "Obfuscated Files or Information", "T1027", "low", "Repeated allowed content the gateway could not scan",
		"Encrypted or oversized content the gateway cannot scan passes without inspection of its content.",
		"Password-protected archives exchanged with partners, large installers."},
	{"zs-an-zpa-denied-burst", "Discovery", "Network Service Discovery", "T1046", "medium", "Burst of denied private-application access attempts",
		"Many denied attempts to private applications in minutes looks like a user or stolen session probing what is reachable.",
		"A misconfigured client retrying, or an application whose access policy just changed."},
	{"zs-an-zpa-app-sweep", "Lateral Movement", "Remote Services", "T1021", "medium", "One user reached many private applications in minutes",
		"Touching many application segments in a short window is atypical for a user and resembles internal reconnaissance.",
		"An administrator, an auditor or a monitoring script."},
	{"zs-an-impossible-travel", "Initial Access", "Valid Accounts", "T1078", "high", "Sign-in locations too far apart for the elapsed time",
		"The same account appears in two places faster than travel allows, which indicates a shared or stolen credential or session.",
		"A VPN or egress change, or a mobile carrier whose IP geolocates elsewhere."},
	{"zs-an-off-hours", "Initial Access", "Valid Accounts", "T1078", "low", "Repeated activity outside working hours",
		"A user who is normally active in the day showing a lot of activity at night can mean a compromised account.",
		"Shift work, travel in another time zone, or on-call staff."},
	{"zs-an-bypass-tool", "Defense Evasion", "Proxy", "T1090", "medium", "Anonymiser, VPN, proxy-avoidance or DNS-over-HTTPS use",
		"Tools that hide the real destination or move DNS outside the gateway weaken inspection and logging.",
		"Browsers that enable DNS-over-HTTPS by default, or approved privacy tooling."},
	{"zs-an-dns-tunnel-like", "Command and Control", "Application Layer Protocol: DNS", "T1071.004", "high", "Many long, high-entropy DNS names under one parent domain",
		"Data hidden in long DNS labels is how DNS tunnelling moves data past web controls.",
		"Some CDNs, anti-virus cloud lookups and mail-security services use long labels."},
	{"zs-an-fw-risky-port-allowed", "Initial Access", "External Remote Services", "T1133", "medium", "Cloud firewall allowed a remote-admin or file-sharing port to the internet",
		"Telnet, SMB, RDP, VNC or WinRM leaving the network to a public address is rarely intended.",
		"A sanctioned remote-support session or a business partner that requires the protocol."},
}

func init() {
	for _, r := range zsRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func zsRuleMeta(id string) int {
	for i := range zsRules {
		if zsRules[i].ID == id {
			return i
		}
	}
	return -1
}

func zsRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(zsRules))
	for _, a := range zsRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// ZsOptions carries what the operator supplies.
type ZsOptions struct {
	Host       string
	Sanctioned map[string]bool // lower-case sanctioned application names; empty disables the unsanctioned-app rule
	WorkStart  int             // first working hour, UTC, default 6
	WorkEnd    int             // first non-working hour, UTC, default 22
}

type ZsUserRisk struct {
	User     string   `json:"user"`
	Score    int      `json:"risk_score"`
	Level    string   `json:"risk_level"`
	Findings int      `json:"findings"`
	Rules    []string `json:"rules"`
}

type ZsAppRisk struct {
	App        string `json:"app"`
	Class      string `json:"class,omitempty"`
	Users      int    `json:"users"`
	Events     int    `json:"events"`
	BytesUp    int64  `json:"bytes_up"`
	Sanctioned string `json:"sanctioned"` // yes, no or unknown
	Score      int    `json:"risk_score"`
	Level      string `json:"risk_level"`
}

type ZsReport struct {
	Mode      string         `json:"mode"`
	Format    string         `json:"format"`
	Received  int            `json:"received"`
	Parsed    int            `json:"parsed"`
	Rejected  int            `json:"rejected"`
	ByKind    map[string]int `json:"by_kind"`
	ByRule    map[string]int `json:"by_rule"`
	From      *time.Time     `json:"from,omitempty"`
	To        *time.Time     `json:"to,omitempty"`
	Users     int            `json:"users"`
	TopUsers  []ZsUserRisk   `json:"top_users"`
	TopApps   []ZsAppRisk    `json:"top_apps,omitempty"`
	Findings  int            `json:"findings"`
	Errors    []string       `json:"errors,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
	Note      string         `json:"note"`
}

const zsNote = "heuristics over an exported log, not proof of compromise or of a policy failure: the export may omit fields, categories and actions are as the gateway labelled them, and geography is whatever the log carries. Nothing was sent to or fetched from Zscaler."

var zsRiskyCats = []string{"anonymizer", "proxy avoidance", "newly registered", "newly revived", "phishing", "malicious", "botnet", "cryptomin", "dynamic dns", "command and control", "spyware", "peer-to-peer"}
var zsBypassCats = []string{"anonymizer", "proxy avoidance", "vpn", "tor "}
var zsDoHHosts = []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net", "dns.nextdns.io", "doh.opendns.com", "dns.adguard.com", "mozilla.cloudflare-dns.com", "doh.dns.sb"}
var zsShadowClasses = []string{"file sharing", "file host", "online storage", "cloud storage", "webmail", "instant messag", "generative ai", "ai/ml", "ai ml", "remote access"}
var zsRiskyPorts = map[int]string{23: "telnet", 135: "msrpc", 139: "netbios", 445: "smb", 3389: "rdp", 5900: "vnc", 5985: "winrm", 5986: "winrm"}

func zsContains(s string, list []string) string {
	l := strings.ToLower(s)
	if l == "" {
		return ""
	}
	for _, c := range list {
		if strings.Contains(l, c) {
			return c
		}
	}
	return ""
}

func zsHaversine(a, b *ZsEvent) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dlat, dlon := (b.Lat-a.Lat)*rad, (b.Lon-a.Lon)*rad
	h := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(a.Lat*rad)*math.Cos(b.Lat*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(h)))
}

type zsFinding struct {
	Rule, Sev, User, Key, Desc, Sample string
	T                                  time.Time
}

func zsPublic(ip string) bool {
	a, ok := netParseAddr(ip)
	return ok && !netPrivate(a)
}

func zsLevel(score int) string {
	switch {
	case score >= 30:
		return "high"
	case score >= 10:
		return "medium"
	}
	return "low"
}

func zsParent(q string) string {
	l := strings.Split(strings.TrimSuffix(q, "."), ".")
	if len(l) <= 2 {
		return strings.Join(l, ".")
	}
	return strings.Join(l[len(l)-2:], ".")
}

// AnalyzeZscaler runs every zs-an rule over the parsed events and scores users and apps.
func AnalyzeZscaler(p *zsParsed, opt ZsOptions) (*ZsReport, []Finding) {
	if opt.WorkStart == 0 && opt.WorkEnd == 0 {
		opt.WorkStart, opt.WorkEnd = 6, 22
	}
	ev := p.Events
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].T.IsZero() || ev[j].T.IsZero() {
			return false
		}
		return ev[i].T.Before(ev[j].T)
	})
	rep := &ZsReport{Mode: "observe-only", Format: p.Format, Received: p.Received, Parsed: len(p.Events), Rejected: p.Rejected, ByKind: p.ByKind,
		ByRule: map[string]int{}, Errors: p.Errors, Note: zsNote, TopUsers: []ZsUserRisk{}}
	if p.Received > zsRecordsMax {
		rep.Truncated = true
	}
	var out []zsFinding
	counts := map[string]int{}
	emit := func(rule, sev string, t time.Time, user, key, desc, sample string) {
		if counts[rule] >= zsCapPerRule*4 {
			rep.Truncated = true
			return
		}
		counts[rule]++
		out = append(out, zsFinding{Rule: rule, Sev: sev, User: user, Key: key, Desc: desc, Sample: sample, T: t})
	}
	users := map[string]bool{}
	var first, last time.Time
	type uh struct{ u, h string }
	lastBlock := map[uh]time.Time{}
	blockedFlag := map[uh]bool{}
	dlpBlocks := map[string]int{}
	dlpFlag := map[string]bool{}
	catKey := map[[2]string]int{}
	catEv := map[[2]string]ZsEvent{}
	upBy := map[uh]int64{}
	unscan := map[string]int{}
	bypass := map[string]int{}
	bypassEv := map[string]ZsEvent{}
	type appAgg struct {
		class  string
		users  map[string]bool
		events int
		up     int64
		risky  bool
	}
	apps := map[string]*appAgg{}
	zpaDenied := map[string][]time.Time{}
	zpaSeen := map[string][]struct {
		t   time.Time
		app string
	}{}
	zpaFlag := map[string]bool{}
	sweepFlag := map[string]bool{}
	geoPrev := map[string]*ZsEvent{}
	travelFlag := map[string]int{}
	offHours := map[string]int{}
	userEvents := map[string]int{}
	dnsLong := map[[2]string]int{}
	dnsEx := map[[2]string]string{}
	fwRisk := map[[3]string]int{}
	for i := range ev {
		e := &ev[i]
		if !e.T.IsZero() {
			if first.IsZero() || e.T.Before(first) {
				first = e.T
			}
			if e.T.After(last) {
				last = e.T
			}
		}
		u := e.User
		if u == "" {
			u = e.ClientIP
		}
		if u != "" {
			users[u] = true
			userEvents[u]++
		}
		subject := "user " + orUnknown(u)
		switch e.Kind {
		case "web":
			sampleURL := e.URL
			if sampleURL == "" {
				sampleURL = e.Host
			}
			sample := fmt.Sprintf("%s %s %s action=%s", e.Method, sampleURL, e.URLCat, e.RawAction)
			sandbox := strings.Contains(strings.ToLower(e.ThreatClass+" "+e.ThreatCat+" "+e.Threat), "sandbox")
			switch {
			case sandbox && e.Action == "allow":
				emit("zs-an-sandbox-allowed", "high", e.T, u, e.Host, fmt.Sprintf("%s: file (%s) with sandbox verdict %q was allowed from %s", subject, orUnknown(e.FileType), webTruncate(webSanitise(e.ThreatCat+" "+e.Threat), 80), e.Host), sample)
			case (e.Threat != "" || e.ThreatCat != "") && e.Action == "allow":
				emit("zs-an-threat-allowed", "high", e.T, u, e.Host+"|"+e.Threat, fmt.Sprintf("%s: threat %q (%s) on %s was allowed", subject, webTruncate(webSanitise(e.Threat), 60), webTruncate(webSanitise(e.ThreatCat), 40), e.Host), sample)
			}
			k := uh{u, e.Host}
			if e.Host != "" && !e.T.IsZero() {
				switch e.Action {
				case "block":
					lastBlock[k] = e.T
				case "allow":
					if bt, ok := lastBlock[k]; ok && e.T.Sub(bt) <= zsBlockedAllowWin && e.T.After(bt) && !blockedFlag[k] {
						blockedFlag[k] = true
						emit("zs-an-blocked-then-allowed", "medium", e.T, u, e.Host, fmt.Sprintf("%s: %s was blocked at %s and allowed %s later", subject, e.Host, bt.Format("15:04:05"), e.T.Sub(bt).Round(time.Second)), sample)
					}
				}
			}
			if len(e.DLP) > 0 {
				switch e.Action {
				case "allow":
					emit("zs-an-dlp-allowed", "high", e.T, u, e.Host+"|"+strings.Join(e.DLP, ","), fmt.Sprintf("%s: %s upload matched DLP %s and was allowed", subject, e.Host, webTruncate(strings.Join(e.DLP, ","), 80)), sample)
				case "block":
					dlpBlocks[u]++
					if dlpBlocks[u] >= zsDLPRepeat && !dlpFlag[u] {
						dlpFlag[u] = true
						emit("zs-an-dlp-repeat", "medium", e.T, u, u, fmt.Sprintf("%s: %d or more requests blocked by DLP", subject, dlpBlocks[u]), sample)
					}
				}
			}
			if c := zsContains(e.URLCat+" "+e.URLSuper, zsRiskyCats); c != "" && e.Action == "allow" {
				ck := [2]string{u, c}
				catKey[ck]++
				if _, ok := catEv[ck]; !ok {
					catEv[ck] = *e
				}
			}
			if e.Action == "allow" {
				upBy[k] += e.Up
			}
			if e.Unscannable != "" && e.Action == "allow" {
				unscan[u]++
			}
			if b := zsContains(e.URLCat+" "+e.URLSuper, zsBypassCats); b != "" && e.Action == "allow" {
				bypass[u+"|"+e.Host]++
				if _, ok := bypassEv[u+"|"+e.Host]; !ok {
					bypassEv[u+"|"+e.Host] = *e
				}
			} else if zsContains(e.Host, zsDoHHosts) != "" && e.Action != "block" {
				bypass[u+"|"+e.Host]++
				if _, ok := bypassEv[u+"|"+e.Host]; !ok {
					bypassEv[u+"|"+e.Host] = *e
				}
			}
			if e.App != "" {
				a := apps[e.App]
				if a == nil {
					a = &appAgg{users: map[string]bool{}}
					apps[e.App] = a
				}
				a.class = e.AppClass
				a.events++
				a.up += e.Up
				if u != "" {
					a.users[u] = true
				}
				if zsContains(e.AppClass, zsShadowClasses) != "" && e.Action == "allow" {
					a.risky = true
				}
			}
		case "dns":
			if zsContains(e.Query, zsDoHHosts) != "" && e.Action != "block" {
				bypass[u+"|"+e.Query]++
				if _, ok := bypassEv[u+"|"+e.Query]; !ok {
					bypassEv[u+"|"+e.Query] = *e
				}
			}
			long := len(e.Query) >= 80
			for _, l := range strings.Split(e.Query, ".") {
				if len(l) >= 40 {
					long = true
				}
			}
			if long && e.Action != "block" {
				dk := [2]string{u, zsParent(e.Query)}
				dnsLong[dk]++
				if _, ok := dnsEx[dk]; !ok {
					dnsEx[dk] = e.Query
				}
			}
		case "fw":
			if name, ok := zsRiskyPorts[e.DPort]; ok && e.Action == "allow" && zsPublic(e.Host) {
				fwRisk[[3]string{u, name, e.Host}]++
			}
			if e.DPort == 853 && e.Action == "allow" && zsPublic(e.Host) {
				bypass[u+"|dot "+e.Host]++
				if _, ok := bypassEv[u+"|dot "+e.Host]; !ok {
					bypassEv[u+"|dot "+e.Host] = *e
				}
			}
		case "zpa":
			if u != "" && !e.T.IsZero() {
				if e.Action == "block" {
					w := append(zpaDenied[u], e.T)
					for len(w) > 0 && e.T.Sub(w[0]) > zsZPAWindow {
						w = w[1:]
					}
					zpaDenied[u] = w
					if len(w) >= zsZPADenied && !zpaFlag[u] {
						zpaFlag[u] = true
						emit("zs-an-zpa-denied-burst", "medium", e.T, u, u, fmt.Sprintf("%s: %d denied private-application attempts within %s", subject, len(w), zsZPAWindow), fmt.Sprintf("zpa %s app=%s status=%s", e.Host, e.Segment, e.RawAction))
					}
				} else {
					key := e.Segment
					if key == "" {
						key = e.Host
					}
					w := append(zpaSeen[u], struct {
						t   time.Time
						app string
					}{e.T, key})
					for len(w) > 0 && e.T.Sub(w[0].t) > zsZPAWindow {
						w = w[1:]
					}
					zpaSeen[u] = w
					set := map[string]bool{}
					for _, x := range w {
						set[x.app] = true
					}
					if len(set) >= zsZPASweep && !sweepFlag[u] {
						sweepFlag[u] = true
						emit("zs-an-zpa-app-sweep", "medium", e.T, u, u, fmt.Sprintf("%s: %d distinct private applications within %s", subject, len(set), zsZPAWindow), fmt.Sprintf("zpa %s app=%s", e.Host, e.Segment))
					}
				}
			}
		}
		// geography: any record kind that carries a country or coordinates
		if u != "" && !e.T.IsZero() && (e.HasGeo || (e.Kind == "zpa" && e.Country != "")) {
			if pv := geoPrev[u]; pv != nil {
				gap := e.T.Sub(pv.T)
				if gap > 0 && gap <= zsTravelMaxGap && travelFlag[u] < 3 {
					switch {
					case e.HasGeo && pv.HasGeo:
						km := zsHaversine(pv, e)
						if km >= zsTravelMinKm && km/gap.Hours() > zsTravelKmh {
							travelFlag[u]++
							emit("zs-an-impossible-travel", "high", e.T, u, u, fmt.Sprintf("%s: %.0f km in %s (%s to %s, about %.0f km/h)", subject, km, gap.Round(time.Second), orUnknown(pv.Country), orUnknown(e.Country), km/gap.Hours()), fmt.Sprintf("zpa %s", e.Host))
						}
					case e.Country != "" && pv.Country != "" && e.Country != pv.Country && gap <= zsTravelCountry:
						travelFlag[u]++
						emit("zs-an-impossible-travel", "medium", e.T, u, u, fmt.Sprintf("%s: country changed %s to %s within %s (country only, no coordinates)", subject, pv.Country, e.Country, gap.Round(time.Second)), fmt.Sprintf("zpa %s", e.Host))
					}
				}
			}
			geoPrev[u] = e
		}
		if u != "" && !e.T.IsZero() && (e.Kind == "zpa" || e.Kind == "web") {
			if h := e.T.UTC().Hour(); h < opt.WorkStart || h >= opt.WorkEnd {
				offHours[u]++
			}
		}
	}
	// aggregated rules, in a stable order
	for _, k := range zsSortedKeys2(catKey) {
		e := catEv[k]
		sev := "medium"
		if strings.Contains(k[1], "phishing") || strings.Contains(k[1], "malicious") || strings.Contains(k[1], "botnet") || strings.Contains(k[1], "command") {
			sev = "high"
		}
		emit("zs-an-risky-category-allowed", sev, e.T, k[0], k[0]+"|"+k[1], fmt.Sprintf("user %s: %d allowed request(s) in a %q category, first to %s", orUnknown(k[0]), catKey[k], k[1], e.Host), fmt.Sprintf("%s %s %s", e.Method, orUnknown(e.URL), e.URLCat))
	}
	for k, n := range upBy {
		if n >= zsLargeUpload {
			emit("zs-an-large-upload", "medium", last, k.u, k.u+"|"+k.h, fmt.Sprintf("user %s: %d MiB sent to %s", orUnknown(k.u), n>>20, k.h), "upload total")
		}
	}
	for u, n := range unscan {
		if n >= zsUnscanMin {
			emit("zs-an-unscannable-allowed", "low", last, u, u, fmt.Sprintf("user %s: %d allowed transactions the gateway could not scan", orUnknown(u), n), "unscannable content")
		}
	}
	for k, n := range bypass {
		e := bypassEv[k]
		u, _, _ := strings.Cut(k, "|")
		emit("zs-an-bypass-tool", "medium", e.T, u, k, fmt.Sprintf("user %s: %d request(s) to %s (%s)", orUnknown(u), n, orUnknown(e.Host), orUnknown(zsContains(e.URLCat+" "+e.URLSuper+" "+e.Host+" "+e.Query, append(append([]string{}, zsBypassCats...), zsDoHHosts...)))), fmt.Sprintf("%s %s", e.Kind, orUnknown(e.Host)))
	}
	for dk, n := range dnsLong {
		if n >= zsTunnelQueries {
			emit("zs-an-dns-tunnel-like", "high", last, dk[0], dk[0]+"|"+dk[1], fmt.Sprintf("user %s: %d long DNS names under %s", orUnknown(dk[0]), n, dk[1]), "dns "+webTruncate(dnsEx[dk], 100))
		}
	}
	for k, n := range fwRisk {
		emit("zs-an-fw-risky-port-allowed", "medium", last, k[0], strings.Join(k[:], "|"), fmt.Sprintf("user %s: %d allowed %s connection(s) to public address %s", orUnknown(k[0]), n, k[1], k[2]), "fw "+k[1])
	}
	for u, n := range offHours {
		if n >= zsOffHoursMin && n*100/userEvents[u] >= 30 {
			emit("zs-an-off-hours", "low", last, u, u, fmt.Sprintf("user %s: %d of %d events outside %02d:00-%02d:00 UTC", orUnknown(u), n, userEvents[u], opt.WorkStart, opt.WorkEnd), "off-hours")
		}
	}
	// unsanctioned apps and app risk
	var appRisk []ZsAppRisk
	for name, a := range apps {
		sanc := "unknown"
		if len(opt.Sanctioned) > 0 {
			sanc = "yes"
			if !opt.Sanctioned[strings.ToLower(name)] {
				sanc = "no"
			}
		}
		ar := ZsAppRisk{App: webTruncate(webSanitise(name), 80), Class: webTruncate(webSanitise(a.class), 60), Users: len(a.users), Events: a.events, BytesUp: a.up, Sanctioned: sanc}
		if a.risky {
			ar.Score += 10
		}
		if sanc == "no" {
			ar.Score += 15
			if a.risky && (len(a.users) >= zsSaaSUsers || a.up >= zsSaaSUpload) {
				emit("zs-an-unsanctioned-saas", "medium", last, "", name, fmt.Sprintf("%s (%s) is not on the sanctioned list: %d user(s), %d KiB uploaded", name, orUnknown(a.class), len(a.users), a.up>>10), "app "+name)
			}
		}
		if a.up >= zsSaaSUpload {
			ar.Score += 5
		}
		appRisk = append(appRisk, ar)
	}
	// findings and per-user risk
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Sev] != rank[out[j].Sev] {
			return rank[out[i].Sev] < rank[out[j].Sev]
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Key < out[j].Key
	})
	w := map[string]int{"high": 8, "medium": 3, "low": 1}
	userScore := map[string]int{}
	userRules := map[string]map[string]int{}
	userFind := map[string]int{}
	appHit := map[string]int{}
	var fs []Finding
	host := opt.Host
	if host == "" {
		host = "zscaler"
	}
	per := map[string]int{}
	for _, f := range out {
		if f.User != "" {
			if userRules[f.User] == nil {
				userRules[f.User] = map[string]int{}
			}
			userRules[f.User][f.Rule]++
			if userRules[f.User][f.Rule] <= 5 {
				userScore[f.User] += w[f.Sev]
			}
			userFind[f.User]++
		}
		if f.Rule == "zs-an-unsanctioned-saas" {
			appHit[f.Key] += w[f.Sev]
		}
		if per[f.Rule] >= zsCapPerRule {
			rep.Truncated = true
			continue
		}
		per[f.Rule]++
		rep.ByRule[f.Rule]++
		mi := zsRuleMeta(f.Rule)
		m := zsRules[mi]
		t := f.T
		if t.IsZero() {
			t = time.Now().UTC()
		}
		h := fnv.New64a()
		h.Write([]byte(f.Key + "|" + f.Desc))
		desc := fmt.Sprintf("%s: %s. %s (heuristic over an exported Zscaler log. Possible benign cause: %s)", m.Title, f.Desc, m.Why, m.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, f.Rule, h.Sum64(), t.UnixNano()), Time: t, Host: host, Rule: f.Rule, Severity: f.Sev,
			Description: webTruncate(desc, 900), Tags: []string{m.TechID, "zscaler", "observe-only"},
			Evidence: Event{Time: t, Host: host, Executable: "zscaler:log", Command: webTruncate(webSanitise(f.Sample), 300)}})
	}
	rep.Findings = len(fs)
	for u, s := range userScore {
		if s > 100 {
			s = 100
		}
		var rs []string
		for r := range userRules[u] {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		rep.TopUsers = append(rep.TopUsers, ZsUserRisk{User: u, Score: s, Level: zsLevel(s), Findings: userFind[u], Rules: rs})
	}
	sort.Slice(rep.TopUsers, func(i, j int) bool {
		if rep.TopUsers[i].Score != rep.TopUsers[j].Score {
			return rep.TopUsers[i].Score > rep.TopUsers[j].Score
		}
		return rep.TopUsers[i].User < rep.TopUsers[j].User
	})
	if len(rep.TopUsers) > 20 {
		rep.TopUsers = rep.TopUsers[:20]
	}
	for i := range appRisk {
		appRisk[i].Score += appHit[appRisk[i].App]
		if appRisk[i].Score > 100 {
			appRisk[i].Score = 100
		}
		appRisk[i].Level = zsLevel(appRisk[i].Score)
	}
	sort.Slice(appRisk, func(i, j int) bool {
		if appRisk[i].Score != appRisk[j].Score {
			return appRisk[i].Score > appRisk[j].Score
		}
		return appRisk[i].App < appRisk[j].App
	})
	if len(appRisk) > 20 {
		appRisk = appRisk[:20]
	}
	rep.TopApps = appRisk
	rep.Users = len(users)
	if !first.IsZero() {
		rep.From, rep.To = &first, &last
	}
	return rep, fs
}

func zsSortedKeys2[V any](m map[[2]string]V) [][2]string {
	ks := make([][2]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i][0] != ks[j][0] {
			return ks[i][0] < ks[j][0]
		}
		return ks[i][1] < ks[j][1]
	})
	return ks
}

// ZscalerRun parses and analyses one exported Zscaler log; used by the HTTP routes, the harness and tests.
func ZscalerRun(raw []byte, format string, opt ZsOptions) (*ZsReport, []Finding, error) {
	p, err := zsParseLog(raw, format)
	if err != nil {
		return nil, nil, err
	}
	rep, fs := AnalyzeZscaler(p, opt)
	return rep, fs, nil
}

func zscalerGuidance() []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range zsRules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". A heuristic over an exported Zscaler log, not proof of compromise.", r.Why, r.Benign, r.TechID,
			[]string{"Open the user's other records in the same export around the time of the finding.", "Check whether the policy action in the log matches what the policy is meant to do."},
			[]string{"Consider tightening the matching policy or moving it out of monitor-only mode (advisory; Kavach changes nothing)."}))
	}
	return out
}
