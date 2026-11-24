// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"time"
)

// A ZDX-style digital-experience score computed offline from probe metrics the operator exports
// (CSV, TSV, JSON or JSON lines: page fetch time, DNS time, server response, availability, latency,
// packet loss, CPU, memory, Wi-Fi signal). The formula below is Kavach's own and is NOT Zscaler's
// proprietary ZDX Score; only the 0-100 range and the Poor/Okay/Good band edges (0-33, 34-65,
// 66-100) follow Zscaler's public description, as remembered and unverified. Nothing contacts ZDX.
const (
	zdxRowsMax    = 100000
	zdxMinSamples = 3
)

var zdxRules = []struct{ ID, Tactic, Technique, TechID, Sev, Title, Why, Benign string }{
	{"zdx-an-poor-experience", "Impact", "Service Stop", "T1489", "low", "User and application pair scores Poor on the experience score",
		"A sustained Poor score means the user effectively cannot use the application; it can be an outage, an attack on availability or a network fault.",
		"A local Wi-Fi problem or a planned maintenance window."},
	{"zdx-an-packet-loss", "Impact", "Network Denial of Service", "T1498", "low", "High packet loss on probes",
		"Loss above two percent across several probes degrades real-time and interactive traffic.",
		"A congested home network or a mobile link."},
	{"zdx-an-dns-slow", "Impact", "Network Denial of Service", "T1498", "low", "Slow DNS resolution on probes",
		"A DNS time above 200 ms on average inflates every first connection and can point to a resolver problem or DNS interference.",
		"A distant resolver, a roaming user or a cold cache."},
	{"zdx-an-device-pressure", "Impact", "Resource Hijacking", "T1496", "low", "Device CPU or memory is saturated during probes",
		"Sustained 90 percent CPU or memory use makes the experience poor for reasons unrelated to the network and can be a sign of cryptomining or runaway software.",
		"A large build, video call or scheduled scan."},
}

func init() {
	for _, r := range zdxRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func zdxRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(zdxRules))
	for _, a := range zdxRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

func zdxGuidance() []GuidanceEntry {
	var out []GuidanceEntry
	for _, r := range zdxRules {
		out = append(out, ruleEntry(r.ID, r.Title, r.Title+". Computed from exported probe metrics with Kavach's own formula, not the Zscaler ZDX Score.", r.Why, r.Benign, r.TechID,
			[]string{"Compare the user with others on the same application and site.", "Check the lowest sub-score named in the finding."}, []string{"Consider the fix that matches the weak sub-score, such as the network, DNS or the device (advisory)."}))
	}
	return out
}

type zdxMetric struct {
	Key     string
	Aliases []string
	Group   string
	Weight  float64
	Good    float64 // at or better than this scores 100
	Bad     float64 // at or worse than this scores 0
}

var zdxMetrics = []zdxMetric{
	{"page_fetch_ms", []string{"pagefetchtime", "pagefetchtimems", "pft", "pftms", "pagefetch"}, "application", 30, 1000, 8000},
	{"server_response_ms", []string{"serverresponsetime", "serverresponsetimems", "ttfb", "serverresponse", "responsetimems"}, "application", 10, 200, 2000},
	{"availability_pct", []string{"availability", "availabilitypct", "uptime"}, "application", 15, 100, 90},
	{"dns_ms", []string{"dnstime", "dnstimems", "dns", "dnsms"}, "dns", 10, 30, 400},
	{"latency_ms", []string{"latency", "latencyms", "rtt", "rttms", "pinglatency"}, "network", 10, 40, 400},
	{"packet_loss_pct", []string{"packetloss", "packetlosspct", "loss", "lossp"}, "network", 10, 0, 10},
	{"cpu_pct", []string{"cpu", "cpupct", "cpuutilization", "cpuusage"}, "device", 5, 50, 100},
	{"memory_pct", []string{"memory", "memorypct", "mem", "memutilization", "memoryusage"}, "device", 5, 60, 100},
	{"wifi_dbm", []string{"wifisignal", "wifidbm", "rssi", "signalstrength", "wifisignaldbm"}, "device", 5, -50, -85},
}

func zdxSub(m zdxMetric, v float64) float64 {
	var s float64
	if m.Good > m.Bad { // higher is better
		s = (v - m.Bad) / (m.Good - m.Bad)
	} else {
		s = (m.Bad - v) / (m.Bad - m.Good)
	}
	if s < 0 {
		s = 0
	}
	if s > 1 {
		s = 1
	}
	return s * 100
}

// ZdxBand names a score the way Zscaler's public bands do.
func ZdxBand(score int) string {
	switch {
	case score >= 66:
		return "good"
	case score >= 34:
		return "okay"
	}
	return "poor"
}

type ZdxRow struct {
	User, App string
	T         time.Time
	V         map[string]float64
}

type ZdxEntry struct {
	User     string             `json:"user,omitempty"`
	App      string             `json:"app,omitempty"`
	Samples  int                `json:"samples"`
	Score    int                `json:"score"`
	Band     string             `json:"band"`
	Weakest  string             `json:"weakest_group"`
	Metrics  map[string]float64 `json:"average_metrics"`
	SubScore map[string]int     `json:"sub_scores"`
}

type ZdxReport struct {
	Mode     string         `json:"mode"`
	Rows     int            `json:"rows"`
	Rejected int            `json:"rejected"`
	Score    int            `json:"score"`
	Band     string         `json:"band"`
	ByUser   []ZdxEntry     `json:"by_user"`
	ByApp    []ZdxEntry     `json:"by_app"`
	ByPair   []ZdxEntry     `json:"by_user_app,omitempty"`
	ByRule   map[string]int `json:"by_rule"`
	Findings int            `json:"findings"`
	Errors   []string       `json:"errors,omitempty"`
	Note     string         `json:"note"`
}

const zdxNote = "an offline experience score from exported probe metrics using Kavach's own weights (application 55, DNS 10, network 20, device 15); it is not the Zscaler ZDX Score and uses no ZDX data beyond what you exported. Missing metrics are left out and the weights renormalised."

func zdxParse(raw []byte) ([]ZdxRow, int, []string, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil, 0, nil, fmt.Errorf("empty probe export")
	}
	var recs []map[string]string
	rejected := 0
	var errs []string
	if trim[0] == '{' || trim[0] == '[' {
		dec := json.NewDecoder(bytes.NewReader(trim))
		dec.UseNumber()
		for {
			var v any
			if err := dec.Decode(&v); err != nil {
				break
			}
			var items []any
			if a, ok := v.([]any); ok {
				items = a
			} else {
				items = []any{v}
			}
			for _, x := range items {
				if m, ok := x.(map[string]any); ok {
					r := map[string]string{}
					zsFlatten(m, r, 0)
					recs = append(recs, r)
				} else {
					rejected++
				}
			}
		}
	} else {
		head := string(trim[:min(len(trim), 4096)])
		if i := strings.IndexByte(head, '\n'); i >= 0 {
			head = head[:i]
		}
		rd := csv.NewReader(bytes.NewReader(trim))
		rd.LazyQuotes, rd.FieldsPerRecord, rd.Comma = true, -1, zsDelim(head)
		hdr, err := rd.Read()
		if err != nil {
			return nil, 0, nil, fmt.Errorf("could not read a header row")
		}
		keys := make([]string, len(hdr))
		for i, h := range hdr {
			keys[i] = zsKey(h)
		}
		for {
			row, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				rejected++
				continue
			}
			r := map[string]string{}
			for j, v := range row {
				if j < len(keys) && keys[j] != "" {
					r[keys[j]] = v
				}
			}
			recs = append(recs, r)
		}
	}
	if len(recs) > zdxRowsMax {
		return nil, 0, nil, errNetTooMany
	}
	var rows []ZdxRow
	for i, r := range recs {
		row := ZdxRow{V: map[string]float64{}}
		row.User = strings.ToLower(webTruncate(webSanitise(zsGet(r, "user", "username", "login", "device", "devicename")), 100))
		row.App = webTruncate(webSanitise(zsGet(r, "app", "application", "appname", "applicationname")), 80)
		row.T = zsTime(zsGet(r, "time", "timestamp", "datetime", "date"))
		for _, m := range zdxMetrics {
			if v, ok := zsFloat(zsGet(r, append([]string{zsKey(m.Key)}, m.Aliases...)...)); ok {
				row.V[m.Key] = v
			}
		}
		if len(row.V) == 0 {
			rejected++
			if len(errs) < zsErrorsMax {
				errs = append(errs, fmt.Sprintf("row %d: no recognised metric columns", i+1))
			}
			continue
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, rejected, errs, fmt.Errorf("no row had a recognised metric column (page_fetch_ms, dns_ms, latency_ms, packet_loss_pct, cpu_pct, ...)")
	}
	return rows, rejected, errs, nil
}

func zdxScore(avg map[string]float64) (int, map[string]int, string) {
	var num, den float64
	grp := map[string][2]float64{}
	for _, m := range zdxMetrics {
		v, ok := avg[m.Key]
		if !ok {
			continue
		}
		s := zdxSub(m, v)
		num += s * m.Weight
		den += m.Weight
		g := grp[m.Group]
		g[0] += s * m.Weight
		g[1] += m.Weight
		grp[m.Group] = g
	}
	if den == 0 {
		return 0, nil, ""
	}
	sub := map[string]int{}
	weakest, low := "", 101.0
	var names []string
	for k := range grp {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		g := grp[k]
		s := g[0] / g[1]
		sub[k] = int(s + 0.5)
		if s < low {
			low, weakest = s, k
		}
	}
	return int(num/den + 0.5), sub, weakest
}

func zdxAverage(rows []ZdxRow) map[string]float64 {
	sum, n := map[string]float64{}, map[string]int{}
	for _, r := range rows {
		for k, v := range r.V {
			sum[k] += v
			n[k]++
		}
	}
	avg := map[string]float64{}
	for k, s := range sum {
		avg[k] = float64(int(s/float64(n[k])*10+0.5)) / 10
	}
	return avg
}

func zdxEntry(user, app string, rows []ZdxRow) ZdxEntry {
	avg := zdxAverage(rows)
	sc, sub, weak := zdxScore(avg)
	return ZdxEntry{User: user, App: app, Samples: len(rows), Score: sc, Band: ZdxBand(sc), Weakest: weak, Metrics: avg, SubScore: sub}
}

// ZdxRun scores exported probe metrics per user, per application and per user-application pair.
func ZdxRun(raw []byte, host string) (*ZdxReport, []Finding, error) {
	rows, rej, errs, err := zdxParse(raw)
	if err != nil {
		return nil, nil, err
	}
	rep := &ZdxReport{Mode: "observe-only", Rows: len(rows), Rejected: rej, Errors: errs, Note: zdxNote, ByRule: map[string]int{}, ByUser: []ZdxEntry{}, ByApp: []ZdxEntry{}}
	all := zdxEntry("", "", rows)
	rep.Score, rep.Band = all.Score, all.Band
	byU, byA, byP := map[string][]ZdxRow{}, map[string][]ZdxRow{}, map[[2]string][]ZdxRow{}
	for _, r := range rows {
		if r.User != "" {
			byU[r.User] = append(byU[r.User], r)
		}
		if r.App != "" {
			byA[r.App] = append(byA[r.App], r)
		}
		if r.User != "" && r.App != "" {
			byP[[2]string{r.User, r.App}] = append(byP[[2]string{r.User, r.App}], r)
		}
	}
	for u, rs := range byU {
		rep.ByUser = append(rep.ByUser, zdxEntry(u, "", rs))
	}
	for a, rs := range byA {
		rep.ByApp = append(rep.ByApp, zdxEntry("", a, rs))
	}
	var pairs []ZdxEntry
	for k, rs := range byP {
		pairs = append(pairs, zdxEntry(k[0], k[1], rs))
	}
	for _, l := range []*[]ZdxEntry{&rep.ByUser, &rep.ByApp, &pairs} {
		s := *l
		sort.Slice(s, func(i, j int) bool {
			if s[i].Score != s[j].Score {
				return s[i].Score < s[j].Score
			}
			return s[i].User+s[i].App < s[j].User+s[j].App
		})
		if len(s) > 20 {
			*l = s[:20]
		}
	}
	rep.ByPair = pairs
	if host == "" {
		host = "zscaler:zdx"
	}
	now := time.Now().UTC()
	var fs []Finding
	emit := func(rule, who, detail string) {
		if rep.ByRule[rule] >= zsCapPerRule {
			return
		}
		rep.ByRule[rule]++
		var m int
		for i := range zdxRules {
			if zdxRules[i].ID == rule {
				m = i
			}
		}
		r := zdxRules[m]
		h := fnv.New64a()
		h.Write([]byte(who + "|" + detail))
		desc := fmt.Sprintf("%s: %s. %s (computed from exported probe metrics with Kavach's own formula, not the Zscaler ZDX Score. Possible benign cause: %s)", r.Title, detail, r.Why, r.Benign)
		fs = append(fs, Finding{ID: fmt.Sprintf("%s:%s:%x:%d", host, rule, h.Sum64(), now.UnixNano()), Time: now, Host: host, Rule: rule, Severity: r.Sev,
			Description: webTruncate(desc, 900), Tags: []string{r.TechID, "zscaler", "zdx", "observe-only"},
			Evidence: Event{Time: now, Host: host, Executable: "zscaler:zdx", Command: webTruncate(webSanitise(who+" | "+detail), 300)}})
	}
	for _, p := range pairs {
		if p.Samples >= zdxMinSamples && p.Band == "poor" {
			emit("zdx-an-poor-experience", p.User+"|"+p.App, fmt.Sprintf("user %s on %s scores %d (%s) over %d probes, weakest area %s", p.User, p.App, p.Score, p.Band, p.Samples, orUnknown(p.Weakest)))
		}
	}
	for _, g := range []struct {
		by  map[string][]ZdxRow
		who string
	}{{byU, "user"}} {
		keys := make([]string, 0, len(g.by))
		for k := range g.by {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rs := g.by[k]
			if len(rs) < zdxMinSamples {
				continue
			}
			avg := zdxAverage(rs)
			if v, ok := avg["packet_loss_pct"]; ok && v >= 2 {
				emit("zdx-an-packet-loss", k, fmt.Sprintf("%s %s averages %.1f%% packet loss over %d probes", g.who, k, v, len(rs)))
			}
			if v, ok := avg["dns_ms"]; ok && v >= 200 {
				emit("zdx-an-dns-slow", k, fmt.Sprintf("%s %s averages %.0f ms DNS time over %d probes", g.who, k, v, len(rs)))
			}
			if c, ok := avg["cpu_pct"]; ok && c >= 90 {
				emit("zdx-an-device-pressure", k, fmt.Sprintf("%s %s averages %.0f%% CPU over %d probes", g.who, k, c, len(rs)))
			} else if mm, ok := avg["memory_pct"]; ok && mm >= 90 {
				emit("zdx-an-device-pressure", k, fmt.Sprintf("%s %s averages %.0f%% memory over %d probes", g.who, k, mm, len(rs)))
			}
		}
	}
	rep.Findings = len(fs)
	return rep, fs, nil
}
