// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"sort"
	"strings"
	"time"
)

// Model 1: DNS / domain-event tunneling and DGA-burst detector.
//
// Input: dns telemetry (Query) and network events whose destination is a host name. Time is bucketed
// into fixed 5 minute windows of EVENT time per host. Per window and registrable domain we keep only
// a capped set of hashed subdomain strings plus length/entropy sums. When a window closes it is
// scored; flagged windows are kept (capped). The DGA part reuses ScoreDomain (inspect_domain_score.go).

const (
	mlDNSWindowSec    = 300
	mlDNSMinLookups   = 50  // host cold-start guard: lookups seen before any flag is raised
	mlDNSMaxRegs      = 64  // registrable domains tracked per open window
	mlDNSMaxNames     = 128 // distinct subdomain hashes kept per registrable per window
	mlDNSMaxFlags     = 20  // flagged windows kept per host
	mlDNSTunnelNames  = 20  // distinct subdomains of one registrable domain for a tunnel candidate
	mlDNSTunnelScore  = 60.0
	mlDNSDGAMinDoms   = 5 // distinct DGA-like registrable domains in one window
	mlDNSDGAScore     = 50.0
	mlDNSFactorWindow = time.Hour
)

type mlDNSReg struct {
	Names  []uint64 `json:"n"` // distinct subdomain hashes (capped)
	LenSum float64  `json:"l"` // sum of subdomain length over distinct names
	EntSum float64  `json:"e"` // sum of subdomain Shannon entropy over distinct names
	N      int      `json:"c"` // lookups
	DGA    bool     `json:"dga,omitempty"`
	DScore int      `json:"ds,omitempty"`
}

type mlDNSWin struct {
	Start   int64                `json:"start"`
	Lookups int                  `json:"lookups"`
	Regs    map[string]*mlDNSReg `json:"regs"`
	Dropped int                  `json:"dropped,omitempty"`
}

type mlDNSFlag struct {
	Start    int64    `json:"window_start_unix"`
	Kind     string   `json:"kind"` // tunneling | dga_burst
	Domain   string   `json:"domain"`
	Score    float64  `json:"score"`
	Distinct int      `json:"distinct"`
	Lookups  int      `json:"lookups"`
	Reasons  []string `json:"reasons"`
}

type mlDNSHost struct {
	Lookups int         `json:"lookups"`
	Windows int         `json:"windows"`
	Late    int         `json:"late,omitempty"`
	Skipped int         `json:"skipped,omitempty"` // names with no scorable registrable (IP-like, invalid)
	Open    *mlDNSWin   `json:"open,omitempty"`
	Flags   []mlDNSFlag `json:"flags"`
}

func (e *mlExtEngine) learnDNS(host, name string, t time.Time) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if host == "" || name == "" || len(name) > 255 {
		return
	}
	h := e.st.DNS[host]
	if h == nil {
		if len(e.st.DNS) >= mlExtMaxHosts {
			e.st.Dropped["dns_hosts"]++
			return
		}
		h = &mlDNSHost{Flags: []mlDNSFlag{}}
		e.st.DNS[host] = h
	}
	ds := ScoreDomain(name)
	if ds.Registrable == "" || ds.Parse.IPLike != "" || ds.Parse.Err != "" {
		h.Skipped++
		return
	}
	start := t.Unix() / mlDNSWindowSec * mlDNSWindowSec
	if h.Open != nil && start < h.Open.Start {
		h.Late++ // out-of-order older than the open window: not folded in (keeps closed windows immutable)
		return
	}
	if h.Open != nil && start > h.Open.Start {
		h.closeWindow()
	}
	if h.Open == nil {
		h.Open = &mlDNSWin{Start: start, Regs: map[string]*mlDNSReg{}}
	}
	h.Lookups++
	h.Open.Lookups++
	r := h.Open.Regs[ds.Registrable]
	if r == nil {
		if len(h.Open.Regs) >= mlDNSMaxRegs {
			h.Open.Dropped++
			return
		}
		r = &mlDNSReg{DGA: ds.DGALike && ds.Applicable, DScore: ds.Score}
		h.Open.Regs[ds.Registrable] = r
	}
	r.N++
	sub := strings.Join(ds.Parse.Subdomains, ".")
	if sub == "" {
		return
	}
	hh := mlHash(sub)
	for _, x := range r.Names {
		if x == hh {
			return
		}
	}
	if len(r.Names) >= mlDNSMaxNames {
		return
	}
	r.Names = append(r.Names, hh)
	r.LenSum += float64(len(sub))
	r.EntSum += shannon(sub)
}

func (h *mlDNSHost) closeWindow() {
	w := h.Open
	h.Open = nil
	if w == nil {
		return
	}
	h.Windows++
	if h.Lookups < mlDNSMinLookups {
		return // cold start: never flag below the guard
	}
	h.Flags = append(h.Flags, evalDNSWindow(w)...)
	if len(h.Flags) > mlDNSMaxFlags {
		h.Flags = append([]mlDNSFlag(nil), h.Flags[len(h.Flags)-mlDNSMaxFlags:]...)
	}
}

// evalDNSWindow scores one window; deterministic (sorted iteration).
func evalDNSWindow(w *mlDNSWin) []mlDNSFlag {
	var out []mlDNSFlag
	dga, dgaSum := 0, 0
	bestDGA, bestDGAScore := "", -1
	for _, reg := range mlSortedKeys(w.Regs) {
		r := w.Regs[reg]
		d := len(r.Names)
		if d >= mlDNSTunnelNames {
			meanLen, meanEnt := r.LenSum/float64(d), r.EntSum/float64(d)
			vol := clamp01(float64(d-10) / 90)
			ln := clamp01((meanLen - 12) / 28)
			en := clamp01((meanEnt - 2.5) / 1.5)
			sc := 100 * (0.5*vol + 0.3*ln + 0.2*en)
			if sc >= mlDNSTunnelScore {
				out = append(out, mlDNSFlag{Start: w.Start, Kind: "tunneling", Domain: reg, Score: mlRound(sc, 1), Distinct: d, Lookups: r.N,
					Reasons: []string{
						"distinct_subdomains " + f2(float64(d)) + " (volume factor " + f2(vol) + ")",
						"mean_subdomain_length " + f2(meanLen) + " (length factor " + f2(ln) + ")",
						"mean_subdomain_entropy " + f2(meanEnt) + " bits (entropy factor " + f2(en) + ")"}})
			}
		}
		if r.DGA {
			dga++
			dgaSum += r.DScore
			if r.DScore > bestDGAScore {
				bestDGA, bestDGAScore = reg, r.DScore
			}
		}
	}
	if dga >= mlDNSDGAMinDoms {
		mean := float64(dgaSum) / float64(dga)
		sc := 100 * (0.6*clamp01(float64(dga)/12) + 0.4*clamp01(mean/80))
		if sc >= mlDNSDGAScore {
			out = append(out, mlDNSFlag{Start: w.Start, Kind: "dga_burst", Domain: bestDGA, Score: mlRound(sc, 1), Distinct: dga, Lookups: w.Lookups,
				Reasons: []string{
					f2(float64(dga)) + " distinct DGA-like registrable domains in one " + f2(mlDNSWindowSec/60) + " minute window",
					"mean ScoreDomain " + f2(mean) + "/100 (threshold " + f2(DomainDGAThreshold) + ")"}})
		}
	}
	return out
}

type mlDNSHostRow struct {
	Host        string     `json:"host"`
	Lookups     int        `json:"sample_count"`
	Windows     int        `json:"windows"`
	Status      string     `json:"status"`
	Flagged     int        `json:"flagged_windows"`
	TopScore    float64    `json:"top_score"`
	LastFlagged *time.Time `json:"last_flagged,omitempty"`
}

func dnsStatus(h *mlDNSHost) string {
	if h.Lookups < mlDNSMinLookups {
		return "not_enough_data"
	}
	return "ok"
}

func (e *mlExtEngine) dnsView(host string, limit int) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := map[string]any{"method": mlMethod, "model": "dns-tunnel-dga-v1", "window_seconds": mlDNSWindowSec, "min_lookups": mlDNSMinLookups,
		"tunnel_min_distinct_subdomains": mlDNSTunnelNames, "tunnel_score_threshold": mlDNSTunnelScore,
		"dga_min_domains": mlDNSDGAMinDoms, "dga_score_threshold": mlDNSDGAScore, "dga_domain_threshold": DomainDGAThreshold,
		"hosts_tracked": len(e.st.DNS), "dropped_hosts": e.st.Dropped["dns_hosts"]}
	if host != "" {
		h := e.st.DNS[host]
		res["host"] = host
		if h == nil {
			res["status"], res["sample_count"], res["flags"] = "not_enough_data", 0, []mlDNSFlag{}
			return res
		}
		res["status"], res["sample_count"], res["windows"] = dnsStatus(h), h.Lookups, h.Windows
		res["late_events_ignored"], res["unscorable_names"] = h.Late, h.Skipped
		res["flags"] = h.Flags
		if h.Open != nil {
			open := map[string]any{"window_start_unix": h.Open.Start, "lookups": h.Open.Lookups, "partial": true, "domains_tracked": len(h.Open.Regs)}
			if h.Lookups >= mlDNSMinLookups {
				open["would_flag"] = evalDNSWindow(h.Open)
			} else {
				open["status"] = "not_enough_data"
			}
			res["open_window"] = open
		}
		return res
	}
	rows := []mlDNSHostRow{}
	for _, k := range mlSortedKeys(e.st.DNS) {
		h := e.st.DNS[k]
		row := mlDNSHostRow{Host: k, Lookups: h.Lookups, Windows: h.Windows, Status: dnsStatus(h), Flagged: len(h.Flags)}
		for _, f := range h.Flags {
			if f.Score > row.TopScore {
				row.TopScore = f.Score
			}
			t := time.Unix(f.Start, 0).UTC()
			row.LastFlagged = &t
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Flagged != rows[j].Flagged {
			return rows[i].Flagged > rows[j].Flagged
		}
		return rows[i].TopScore > rows[j].TopScore
	})
	res["total"] = len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	res["hosts"] = rows
	return res
}

// dnsFactor: highest flagged-window score within the hour before the finding (and 10 minutes after).
func (e *mlExtEngine) dnsFactor(host string, ft time.Time) (float64, string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.st.DNS[host]
	if h == nil || h.Lookups < mlDNSMinLookups {
		n := 0
		if h != nil {
			n = h.Lookups
		}
		return 0, "not enough DNS/domain lookups for this host (" + f2(float64(n)) + " of " + f2(mlDNSMinLookups) + ")", false
	}
	best, kind := 0.0, ""
	for _, f := range h.Flags {
		ws := time.Unix(f.Start, 0)
		if ws.After(ft.Add(-mlDNSFactorWindow)) && ws.Before(ft.Add(10*time.Minute)) && f.Score > best {
			best, kind = f.Score, f.Kind+" "+f.Domain
		}
	}
	if best == 0 {
		return 0, "no tunneling or DGA-burst window near the finding (" + f2(float64(h.Lookups)) + " lookups seen)", true
	}
	return best / 100, "flagged " + kind + " window score " + f2(best), true
}
