// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

var netFormats = []string{"auto", "zeek", "eve", "zeek-json", "dns", "dnscsv", "vpc", "nsg", "flowcsv", "panos", "fortigate", "asa"}

// NetRun parses and analyses one network log; used by the HTTP routes and tests.
func NetRun(raw []byte, format string, opt NetOptions) (*NetReport, []Finding, error) {
	p, err := netParseLog(raw, format)
	if err != nil {
		return nil, nil, err
	}
	rep, fs := AnalyzeNetwork(p, opt)
	return rep, fs, nil
}

type netEnvelope struct {
	Log          string `json:"log"`
	Format       string `json:"format"`
	Host         string `json:"host"`
	BadNets      any    `json:"bad_nets"`
	Fingerprints any    `json:"fingerprints"`
}

func netListText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var b strings.Builder
		for i, s := range x {
			if str, ok := s.(string); ok && i < netListMax {
				b.WriteString(str)
				b.WriteByte('\n')
			}
		}
		return b.String()
	}
	return ""
}

func netHostLabel(h string) string {
	if h == "" {
		return ""
	}
	return "net:" + strings.ToLower(webTruncate(webSanitise(h), 120))
}

func netRespond(w http.ResponseWriter, store *Store, rep *NetReport, findings []Finding) {
	if rep.Parsed == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "no record could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
		return
	}
	if len(findings) > webFindingsMx {
		findings = findings[:webFindingsMx]
	}
	stored, err := webStoreFindings(store, findings)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	rep.Findings = stored
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

func netFail(w http.ResponseWriter, err error) {
	if err == errNetTooMany {
		http.Error(w, fmt.Sprintf("too many records (max %d)", netLinesMax), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "invalid network log: "+webTruncate(webSanitise(err.Error()), 160), http.StatusBadRequest)
}

// RegisterNetLogs mounts the network-log routes. POST routes need the admin token.
func RegisterNetLogs(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/net/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "formats": netFormats, "rules": netRuleList(), "max_records": netLinesMax,
			"thresholds": map[string]any{"beacon_min_connections": netBeaconMin, "beacon_max_relative_deviation": netBeaconMaxRel, "scan_ports": netScanPorts, "scan_hosts": netScanHosts, "dns_tunnel_subdomains": dnsTunnelSubs, "exfil_min_bytes": netExfilMinBytes, "exfil_robust_z": netExfilZ},
			"note":       "thresholds are fixed constants tuned for summarising a supplied log, not for production alerting"})
	})
	mux.HandleFunc("POST /v1/net/logs", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		rep, findings, err := NetRun(raw, q.Get("format"), NetOptions{Host: netHostLabel(q.Get("host"))})
		if err != nil {
			netFail(w, err)
			return
		}
		netRespond(w, store, rep, findings)
	})
	mux.HandleFunc("POST /v1/net/analyze", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		var env netEnvelope
		if json.Unmarshal(raw, &env) != nil || env.Log == "" {
			http.Error(w, "body must be a JSON envelope with a log string", http.StatusBadRequest)
			return
		}
		opt := NetOptions{Host: netHostLabel(env.Host)}
		nets, badLines := netParseBadNets(netListText(env.BadNets))
		opt.BadNets = nets
		opt.FPs = netParseFPs(netListText(env.Fingerprints))
		rep, findings, err := NetRun([]byte(env.Log), env.Format, opt)
		if err != nil {
			netFail(w, err)
			return
		}
		if badLines > 0 {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%d bad_nets entries were not an address or CIDR and were ignored", badLines))
		}
		netRespond(w, store, rep, findings)
	})
	mux.HandleFunc("GET /v1/net/timeline", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		win := 30
		if v := q.Get("window_minutes"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1440 {
				http.Error(w, "window_minutes must be 1..1440", http.StatusBadRequest)
				return
			}
			win = n
		}
		ip := strings.TrimSpace(q.Get("ip"))
		if ip != "" {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				http.Error(w, "ip is not an address", http.StatusBadRequest)
				return
			}
			ip = a.Unmap().String()
		}
		tl := BuildNetTimeline(store.List(), ip, strings.TrimSpace(q.Get("host")), time.Duration(win)*time.Minute)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tl)
	})
}

// ---- evidence correlation (f) ----

type NetTimelineItem struct {
	Time        time.Time `json:"time"`
	Rule        string    `json:"rule"`
	Family      string    `json:"family"`
	Severity    string    `json:"severity"`
	Host        string    `json:"host"`
	Entity      string    `json:"entity,omitempty"`
	Relation    string    `json:"relation"`
	Score       int       `json:"score"`
	Description string    `json:"description"`
}

type NetEntitySummary struct {
	Entity   string   `json:"entity"`
	Findings int      `json:"findings"`
	Families []string `json:"families"`
	Score    int      `json:"score"`
}

type NetTimeline struct {
	Mode          string             `json:"mode"`
	Entity        string             `json:"entity,omitempty"`
	Host          string             `json:"host,omitempty"`
	WindowMinutes int                `json:"window_minutes"`
	Anchors       int                `json:"anchors"`
	Families      []string           `json:"families"`
	Items         []NetTimelineItem  `json:"items"`
	Entities      []NetEntitySummary `json:"entities,omitempty"`
	Note          string             `json:"note"`
}

func netFamily(rule string) string {
	switch {
	case strings.HasPrefix(rule, "net-") || strings.HasPrefix(rule, "netcfg-"):
		return "network"
	case strings.HasPrefix(rule, "web-"):
		return "web"
	case strings.HasPrefix(rule, "auth-"):
		return "auth"
	case strings.HasPrefix(rule, "idp-") || strings.HasPrefix(rule, "identity-"):
		return "identity"
	case strings.HasPrefix(rule, "cld-") || strings.HasPrefix(rule, "cloud-"):
		return "cloud"
	case strings.HasPrefix(rule, "ransom"):
		return "ransomware"
	case strings.HasPrefix(rule, "ioc-"):
		return "ioc"
	}
	return "host"
}

func netSevWeight(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

// BuildNetTimeline joins existing findings that mention the same address or share a host label
// within a time window into one ranked list. It reads findings only; it adds none. With neither ip
// nor host it returns the addresses seen in two or more finding families.
func BuildNetTimeline(findings []Finding, ip, host string, window time.Duration) *NetTimeline {
	tl := &NetTimeline{Mode: "observe-only", Entity: ip, Host: host, WindowMinutes: int(window / time.Minute), Items: []NetTimelineItem{}, Families: []string{},
		Note: "a join of findings Kavach already holds by exact address, host label and time; correlation is not causation, and a finding that merely mentions an address is not proof the address was involved"}
	if ip == "" && host == "" {
		type agg struct {
			n   int
			fam map[string]struct{}
			sc  int
		}
		m := map[string]*agg{}
		for _, f := range findings {
			a, err := netip.ParseAddr(strings.TrimSpace(f.Destination))
			if err != nil {
				continue
			}
			k := a.Unmap().String()
			g := m[k]
			if g == nil {
				if len(m) >= 50000 {
					continue
				}
				g = &agg{fam: map[string]struct{}{}}
				m[k] = g
			}
			g.n++
			g.fam[netFamily(f.Rule)] = struct{}{}
			g.sc += netSevWeight(f.Severity)
		}
		for k, g := range m {
			if len(g.fam) < 2 {
				continue
			}
			fams := make([]string, 0, len(g.fam))
			for f := range g.fam {
				fams = append(fams, f)
			}
			sort.Strings(fams)
			tl.Entities = append(tl.Entities, NetEntitySummary{Entity: k, Findings: g.n, Families: fams, Score: g.sc * len(fams)})
		}
		sort.Slice(tl.Entities, func(i, j int) bool {
			if tl.Entities[i].Score != tl.Entities[j].Score {
				return tl.Entities[i].Score > tl.Entities[j].Score
			}
			return tl.Entities[i].Entity < tl.Entities[j].Entity
		})
		if len(tl.Entities) > 20 {
			tl.Entities = tl.Entities[:20]
		}
		return tl
	}
	mentions := func(f *Finding) bool {
		if ip == "" {
			return false
		}
		return f.Destination == ip || strings.Contains(f.Description, ip) || strings.Contains(f.Evidence.Command, ip)
	}
	sameHost := func(f *Finding) bool { return host != "" && strings.EqualFold(f.Host, host) }
	var anchors []Finding
	for i := range findings {
		if mentions(&findings[i]) || sameHost(&findings[i]) {
			anchors = append(anchors, findings[i])
		}
	}
	tl.Anchors = len(anchors)
	hostSet := map[string]bool{}
	for _, a := range anchors {
		if !strings.Contains(a.Host, ":") && a.Host != "" {
			hostSet[strings.ToLower(a.Host)] = true
		}
	}
	nearAnchor := func(t time.Time) bool {
		for _, a := range anchors {
			d := t.Sub(a.Time)
			if d < 0 {
				d = -d
			}
			if d <= window {
				return true
			}
		}
		return false
	}
	fams := map[string]struct{}{}
	for i := range findings {
		f := &findings[i]
		rel := ""
		switch {
		case mentions(f) || sameHost(f):
			rel = "direct"
		case hostSet[strings.ToLower(f.Host)] && nearAnchor(f.Time):
			rel = "same host, within window"
		default:
			continue
		}
		fam := netFamily(f.Rule)
		fams[fam] = struct{}{}
		sc := netSevWeight(f.Severity) * 10
		if rel == "direct" {
			sc += 5
		}
		tl.Items = append(tl.Items, NetTimelineItem{Time: f.Time, Rule: f.Rule, Family: fam, Severity: f.Severity, Host: f.Host, Entity: f.Destination, Relation: rel, Score: sc, Description: webTruncate(f.Description, 300)})
		if len(tl.Items) >= 5000 {
			break
		}
	}
	for f := range fams {
		tl.Families = append(tl.Families, f)
	}
	sort.Strings(tl.Families)
	bonus := 5 * (len(tl.Families) - 1)
	for i := range tl.Items {
		if bonus > 0 {
			tl.Items[i].Score += bonus
		}
	}
	sort.SliceStable(tl.Items, func(i, j int) bool {
		if tl.Items[i].Score != tl.Items[j].Score {
			return tl.Items[i].Score > tl.Items[j].Score
		}
		return tl.Items[i].Time.Before(tl.Items[j].Time)
	})
	if len(tl.Items) > 200 {
		tl.Items = tl.Items[:200]
	}
	return tl
}
