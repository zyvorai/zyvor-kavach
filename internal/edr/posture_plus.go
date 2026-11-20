// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Exposure / posture management (Spotlight/Exposure class). Observation only:
// nothing here patches, blocks or remediates; it ranks and reports.

const (
	maxPostureAssets   = 1000
	maxPostureTags     = 10
	maxPostureHosts    = 200  // baselined hosts
	maxBaselineItems   = 2000 // items per domain per host
	maxDriftItems      = 200  // reported per change class
	maxPriorityResults = 500
)

var postureDomains = []string{"sbom", "fim", "persistence"}

// PostureAsset carries analyst-supplied business context for a host.
type PostureAsset struct {
	Host        string    `json:"host"`
	Criticality int       `json:"criticality"` // 1 (low) .. 5 (crown jewel)
	Owner       string    `json:"owner,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Updated     time.Time `json:"updated"`
}

// PostureBaseline is a point-in-time inventory snapshot of one host.
type PostureBaseline struct {
	Host      string                       `json:"host"`
	Taken     time.Time                    `json:"taken"`
	Items     map[string]map[string]string `json:"items"` // domain -> key -> value
	Truncated bool                         `json:"truncated,omitempty"`
}

type postureState struct {
	Assets    map[string]PostureAsset    `json:"assets"`
	Baselines map[string]PostureBaseline `json:"baselines"`
}

type postureSvc struct {
	mu    sync.Mutex
	path  string
	st    postureState
	store *Store
	rows  func(domain string) []map[string]any
	vulns func() []Vulnerability
}

type ScoreComponent struct {
	Factor string  `json:"factor"`
	Points float64 `json:"points"`
	Max    float64 `json:"max"`
	Detail string  `json:"detail"`
}

type PrioritizedVuln struct {
	ID          string           `json:"id"`
	CVE         string           `json:"cve"`
	Host        string           `json:"host"`
	Product     string           `json:"product"`
	Severity    string           `json:"severity"`
	Score       float64          `json:"score"` // 0..100
	Rank        int              `json:"rank"`
	Breakdown   []ScoreComponent `json:"breakdown"`
	Description string           `json:"description,omitempty"`
}

type DriftItem struct {
	Domain   string `json:"domain"`
	Key      string `json:"key"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Severity string `json:"severity_hint"`
	Reason   string `json:"reason"`
}

type DriftReport struct {
	Host        string      `json:"host"`
	HasBaseline bool        `json:"has_baseline"`
	BaselineAt  *time.Time  `json:"baseline_at,omitempty"`
	Added       []DriftItem `json:"added"`
	Removed     []DriftItem `json:"removed"`
	Changed     []DriftItem `json:"changed"`
	Highest     string      `json:"highest_severity"`
	Total       int         `json:"total"`
}

func pClean(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return html.EscapeString(s)
}

func newPostureSvc(store *Store) *postureSvc {
	p := &postureSvc{
		store: store,
		st:    postureState{Assets: map[string]PostureAsset{}, Baselines: map[string]PostureBaseline{}},
		rows:  Live.List,
		vulns: func() []Vulnerability {
			vulnMu.Lock()
			defer vulnMu.Unlock()
			return append([]Vulnerability(nil), vulns...)
		},
	}
	if store != nil && store.path != "" {
		p.path = store.path + ".posture.json"
		if b, err := os.ReadFile(p.path); err == nil {
			_ = json.Unmarshal(b, &p.st)
		}
		if p.st.Assets == nil {
			p.st.Assets = map[string]PostureAsset{}
		}
		if p.st.Baselines == nil {
			p.st.Baselines = map[string]PostureBaseline{}
		}
	}
	return p
}

func (p *postureSvc) saveLocked() error {
	if p.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(p.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// ---- scoring ----

func sevToCVSS(s string) float64 {
	switch strings.ToLower(s) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5
	case "low":
		return 2.5
	}
	return 0
}

func hasExposureTag(tags []string) bool {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "internet", "internet-facing", "internet_exposed", "public", "exposed", "dmz":
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scoreVuln: CVSS (0-40) + criticality (0-30) + co-located high/critical
// findings (0-10) + internet exposure (0-10) + known exploited (0-10).
func scoreVuln(v Vulnerability, assets map[string]PostureAsset, hiFindings map[string]int) PrioritizedVuln {
	cvss, src := v.ExPRTScore, "exprt_score"
	if cvss <= 0 {
		cvss, src = sevToCVSS(v.Severity), "severity "+strings.ToLower(v.Severity)
	}
	if cvss > 10 {
		cvss = 10
	}
	comps := []ScoreComponent{{"cvss", round1(cvss * 4), 40, fmt.Sprintf("%.1f/10 from %s x4", cvss, src)}}
	a, known := assets[v.Host]
	crit, detail := 3, "host not registered, default 3 x6"
	if known {
		crit, detail = a.Criticality, fmt.Sprintf("criticality %d/5 x6", a.Criticality)
	}
	comps = append(comps, ScoreComponent{"asset_criticality", float64(crit * 6), 30, detail})
	fp, fd := 0.0, "no high/critical findings on host"
	if n := hiFindings[v.Host]; n > 0 {
		fp, fd = float64(5+minInt(n, 5)), fmt.Sprintf("%d high/critical findings on host (5 + min(n,5))", n)
	}
	comps = append(comps, ScoreComponent{"host_findings", fp, 10, fd})
	ep, ed := 0.0, "no internet exposure tag"
	if known && hasExposureTag(a.Tags) {
		ep, ed = 10, "asset tagged internet-exposed"
	}
	comps = append(comps, ScoreComponent{"internet_exposure", ep, 10, ed})
	kp, kd := 0.0, "not known exploited"
	if v.Exploited {
		kp, kd = 10, "exploited in the wild"
	}
	comps = append(comps, ScoreComponent{"known_exploited", kp, 10, kd})
	total := 0.0
	for _, c := range comps {
		total += c.Points
	}
	return PrioritizedVuln{ID: pClean(v.ID, 128), CVE: pClean(v.CVE, 64), Host: pClean(v.Host, 128),
		Product: pClean(v.Product, 200), Severity: pClean(v.Severity, 16), Score: round1(total),
		Breakdown: comps, Description: pClean(v.Description, 300)}
}

func (p *postureSvc) priority(limit int) []PrioritizedVuln {
	p.mu.Lock()
	assets := make(map[string]PostureAsset, len(p.st.Assets))
	for k, v := range p.st.Assets {
		assets[k] = v
	}
	p.mu.Unlock()
	hi := map[string]int{}
	if p.store != nil {
		for _, f := range p.store.List() {
			if severityRank(f.Severity) >= 3 {
				hi[f.Host]++
			}
		}
	}
	out := []PrioritizedVuln{}
	for _, v := range p.vulns() {
		out = append(out, scoreVuln(v, assets, hi))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	if limit <= 0 || limit > maxPriorityResults {
		limit = maxPriorityResults
	}
	if len(out) > limit {
		out = out[:limit]
	}
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// ---- baselines / drift ----

func rowStr(r map[string]any, k string) string {
	if v, ok := r[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// itemKV reduces a row to a stable identity key and a comparable value.
func itemKV(domain string, r map[string]any) (string, string) {
	switch domain {
	case "sbom":
		return rowStr(r, "component"), rowStr(r, "version")
	case "persistence":
		return rowStr(r, "type") + "|" + rowStr(r, "name"), rowStr(r, "risk")
	default: // fim
		val := strings.Join([]string{rowStr(r, "size"), rowStr(r, "mtime"), rowStr(r, "mode"),
			rowStr(r, "sha256"), rowStr(r, "hash")}, "|")
		return rowStr(r, "path"), val
	}
}

func isSetuidRow(r map[string]any) bool {
	if b, ok := r["setuid"].(bool); ok && b {
		return true
	}
	if s := rowStr(r, "setuid"); s == "true" || s == "1" {
		return true
	}
	if strings.Contains(strings.ToLower(rowStr(r, "change")), "setuid") {
		return true
	}
	m := rowStr(r, "mode")
	if strings.Contains(m, "s") {
		return true
	}
	if len(m) == 4 && m[0] >= '4' && m[0] <= '7' {
		if _, err := strconv.ParseUint(m, 8, 32); err == nil {
			return true
		}
	}
	return false
}

func (p *postureSvc) snapshot(host string) PostureBaseline {
	b := PostureBaseline{Host: host, Taken: time.Now().UTC(), Items: map[string]map[string]string{}}
	for _, d := range postureDomains {
		m := map[string]string{}
		for _, r := range p.rows(d) {
			if rowStr(r, "host") != host {
				continue
			}
			k, v := itemKV(d, r)
			if k == "" || k == "|" {
				continue
			}
			if d == "fim" && isSetuidRow(r) {
				v += "|setuid"
			}
			if _, exists := m[k]; !exists && len(m) >= maxBaselineItems {
				b.Truncated = true
				break
			}
			m[truncate(k, 300)] = truncate(v, 300)
		}
		b.Items[d] = m
	}
	return b
}

func (p *postureSvc) hosts() []string {
	set := map[string]struct{}{}
	for _, d := range postureDomains {
		for _, r := range p.rows(d) {
			if h := rowStr(r, "host"); h != "" {
				set[h] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

var errBaselineCap = fmt.Errorf("baseline host limit reached")

func (p *postureSvc) takeBaseline(host string) error {
	b := p.snapshot(host)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.st.Baselines[host]; !ok && len(p.st.Baselines) >= maxPostureHosts {
		return errBaselineCap
	}
	p.st.Baselines[host] = b
	return p.saveLocked()
}

func driftSev(domain, kind, before, after string) (string, string) {
	switch domain {
	case "persistence":
		switch kind {
		case "added":
			if after == "high" || after == "critical" {
				return "critical", "new persistence entry with elevated risk"
			}
			return "high", "new persistence entry"
		case "changed":
			return "medium", "persistence entry risk changed"
		}
		return "low", "persistence entry removed"
	case "fim":
		setuid := strings.HasSuffix(after, "|setuid") || strings.HasSuffix(before, "|setuid")
		if setuid && kind != "removed" {
			return "critical", "setuid file added or changed"
		}
		switch kind {
		case "added":
			return "high", "new monitored file"
		case "changed":
			return "high", "monitored file changed"
		}
		return "medium", "monitored file removed"
	}
	switch kind { // sbom
	case "added":
		return "medium", "new package"
	case "changed":
		return "medium", "package version changed"
	}
	return "low", "package removed"
}

func (p *postureSvc) drift(host string) DriftReport {
	rep := DriftReport{Host: pClean(host, 128), Added: []DriftItem{}, Removed: []DriftItem{}, Changed: []DriftItem{}, Highest: "none"}
	p.mu.Lock()
	base, ok := p.st.Baselines[host]
	p.mu.Unlock()
	if !ok {
		return rep
	}
	rep.HasBaseline = true
	t := base.Taken
	rep.BaselineAt = &t
	cur := p.snapshot(host)
	hi := 0
	add := func(dst *[]DriftItem, domain, kind, key, before, after string) {
		sev, why := driftSev(domain, kind, before, after)
		rep.Total++
		if r := severityRank(sev); r > hi {
			hi, rep.Highest = r, sev
		}
		if len(*dst) < maxDriftItems {
			*dst = append(*dst, DriftItem{Domain: domain, Key: pClean(key, 300), Before: pClean(before, 300),
				After: pClean(after, 300), Severity: sev, Reason: why})
		}
	}
	for _, d := range postureDomains {
		bm, cm := base.Items[d], cur.Items[d]
		for _, k := range sortedKeys(cm) {
			if bv, found := bm[k]; !found {
				add(&rep.Added, d, "added", k, "", cm[k])
			} else if bv != cm[k] {
				add(&rep.Changed, d, "changed", k, bv, cm[k])
			}
		}
		for _, k := range sortedKeys(bm) {
			if _, found := cm[k]; !found {
				add(&rep.Removed, d, "removed", k, bm[k], "")
			}
		}
	}
	for _, s := range [][]DriftItem{rep.Added, rep.Removed, rep.Changed} {
		s := s
		sort.SliceStable(s, func(i, j int) bool { return severityRank(s[i].Severity) > severityRank(s[j].Severity) })
	}
	return rep
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- HTTP ----

func writePostureJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// RegisterPosturePlus mounts /v1/posture/* (asset criticality, vulnerability
// priority, configuration drift, summary). Observe only.
func RegisterPosturePlus(mux *http.ServeMux, token string, store *Store) {
	registerPosturePlus(mux, token, newPostureSvc(store))
}

func registerPosturePlus(mux *http.ServeMux, token string, p *postureSvc) {
	mux.HandleFunc("GET /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		p.mu.Lock()
		out := make([]PostureAsset, 0, len(p.st.Assets))
		for _, a := range p.st.Assets {
			out = append(out, a)
		}
		p.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
		writePostureJSON(w, 200, out)
	})
	mux.HandleFunc("POST /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var in PostureAsset
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		host := strings.TrimSpace(in.Host)
		if host == "" || len(host) > 128 || in.Criticality < 1 || in.Criticality > 5 {
			http.Error(w, "host required and criticality must be 1-5", 400)
			return
		}
		// Host is stored raw as the join key (it is escaped on output of derived reports).
		a := PostureAsset{Host: host, Criticality: in.Criticality, Owner: pClean(in.Owner, 64), Updated: time.Now().UTC()}
		for _, t := range in.Tags {
			if t = pClean(t, 32); t != "" && len(a.Tags) < maxPostureTags {
				a.Tags = append(a.Tags, t)
			}
		}
		p.mu.Lock()
		if _, exists := p.st.Assets[host]; !exists && len(p.st.Assets) >= maxPostureAssets {
			p.mu.Unlock()
			http.Error(w, "asset limit reached", 400)
			return
		}
		p.st.Assets[host] = a
		err := p.saveLocked()
		p.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		a.Host = html.EscapeString(a.Host)
		writePostureJSON(w, 201, a)
	})
	mux.HandleFunc("DELETE /v1/posture/assets", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		host := r.URL.Query().Get("host")
		p.mu.Lock()
		_, ok := p.st.Assets[host]
		delete(p.st.Assets, host)
		if ok {
			_ = p.saveLocked()
		}
		p.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/posture/vuln-priority", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writePostureJSON(w, 200, map[string]any{
			"model": "cvss*4 (40) + criticality*6 (30) + host_findings (10) + internet_exposure (10) + known_exploited (10)",
			"items": p.priority(limit),
		})
	})
	mux.HandleFunc("POST /v1/posture/baseline", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		hosts := []string{r.URL.Query().Get("host")}
		if hosts[0] == "" {
			hosts = p.hosts()
		}
		done := 0
		for _, h := range hosts {
			if err := p.takeBaseline(h); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			done++
		}
		writePostureJSON(w, 200, map[string]any{"baselined": done})
	})
	mux.HandleFunc("GET /v1/posture/drift", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "host required", 400)
			return
		}
		writePostureJSON(w, 200, p.drift(host))
	})
	mux.HandleFunc("GET /v1/posture/summary", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		p.mu.Lock()
		dist := map[string]int{"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
		for _, a := range p.st.Assets {
			dist[strconv.Itoa(a.Criticality)]++
		}
		nAssets := len(p.st.Assets)
		baselined := make([]string, 0, len(p.st.Baselines))
		for h := range p.st.Baselines {
			baselined = append(baselined, h)
		}
		p.mu.Unlock()
		sort.Strings(baselined)
		type hostDrift struct {
			Host    string `json:"host"`
			Total   int    `json:"total"`
			Highest string `json:"highest_severity"`
		}
		drifting := []hostDrift{}
		for _, h := range baselined {
			if d := p.drift(h); d.Total > 0 {
				drifting = append(drifting, hostDrift{d.Host, d.Total, d.Highest})
			}
		}
		sort.SliceStable(drifting, func(i, j int) bool {
			if ri, rj := severityRank(drifting[i].Highest), severityRank(drifting[j].Highest); ri != rj {
				return ri > rj
			}
			return drifting[i].Total > drifting[j].Total
		})
		if len(drifting) > 10 {
			drifting = drifting[:10]
		}
		all := p.priority(0)
		top := all
		if len(top) > 5 {
			top = top[:5]
		}
		high := 0
		for _, v := range all {
			if v.Score >= 70 {
				high++
			}
		}
		writePostureJSON(w, 200, map[string]any{
			"assets":          map[string]any{"registered": nAssets, "by_criticality": dist},
			"vulnerabilities": map[string]any{"total": len(all), "score_70_plus": high, "top": top},
			"drift":           map[string]any{"baselined_hosts": len(baselined), "hosts_with_drift": drifting},
			"observed_hosts":  len(p.hosts()),
			"observe_only":    true,
		})
	})
}
