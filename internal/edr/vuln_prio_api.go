package edr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Evidence-based vulnerability prioritisation (observation only).
//
//	GET  /v1/vulns/priority?host=&limit=   ranked matched CVEs with SSVC factors
//	GET  /v1/vulns/priority/{cve}          full explanation for one CVE
//	GET  /v1/vulns/priority/status         feed status, tree version, thresholds, limits
//	POST /v1/vulns/priority/refresh        refresh EPSS now; 409 when feed is off
//
// Existing /v1/vulns/* endpoints are untouched. See docs/vuln-priority.md.

var vpCVERe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// vpFactor is one SSVC decision point with provenance.
type vpFactor struct {
	Name     string `json:"decision_point"`
	Value    string `json:"value"` // observed value, may be "unknown"
	Source   string `json:"source"`
	Known    bool   `json:"known"`
	Assumed  string `json:"assumed_value,omitempty"`
	Evidence string `json:"evidence"`
}

// VPItem is one (host, package, CVE) finding with its SSVC evaluation.
type VPItem struct {
	Rank        int        `json:"rank"`
	Host        string     `json:"host"`
	Package     string     `json:"package"`
	Version     string     `json:"version"`
	CVE         string     `json:"cve"`
	Outcome     string     `json:"ssvc_outcome"`
	EPSS        *float64   `json:"epss"`
	EPSSPctile  *float64   `json:"epss_percentile"`
	CVSS        float64    `json:"cvss"`
	KEV         bool       `json:"known_exploited"`
	Factors     []vpFactor `json:"factors"`
	SSVC        SSVCResult `json:"ssvc"`
	Explanation []string   `json:"explanation"`
}

type vpVector struct {
	Vector string `json:"cvss_vector"`
}

// vpVectors reads optional per-CVE CVSS vectors from KAVACH_CVE_FILE
// (extra "cvss_vector" key next to the existing advisory fields).
func vpVectors() map[string]string {
	out := map[string]string{}
	p := os.Getenv("KAVACH_CVE_FILE")
	if p == "" {
		return out
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	var rows []struct {
		CVE string `json:"cve"`
		vpVector
	}
	if json.Unmarshal(b, &rows) != nil {
		return out
	}
	for _, r := range rows {
		if r.Vector != "" {
			out[strings.ToUpper(r.CVE)] = r.Vector
		}
	}
	return out
}

// vpParseVector reads a CVSS v3.x or v4.0 vector. Automatable and technical
// impact are "unknown" when the vector is missing or malformed. These are
// documented approximations of the SSVC decision points, not CISA's analyst
// judgement:
//
//	automatable = yes when AV:N, AC:L, PR:N, UI:N (v4: also AT:N); a v4
//	              supplemental AU:Y/N is used verbatim when present.
//	technical   = total when C:H and I:H (v4: VC:H and VI:H); else partial.
func vpParseVector(v string) (auto, tech, why string) {
	parts := strings.Split(v, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:") {
		return vpUnknown, vpUnknown, "no valid CVSS vector"
	}
	ver := strings.TrimPrefix(parts[0], "CVSS:")
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			return vpUnknown, vpUnknown, "malformed CVSS vector"
		}
		m[k] = val
	}
	switch {
	case strings.HasPrefix(ver, "3."):
		for _, k := range []string{"AV", "AC", "PR", "UI", "C", "I", "A"} {
			if m[k] == "" {
				return vpUnknown, vpUnknown, "incomplete CVSS v3 vector"
			}
		}
		auto = "no"
		if m["AV"] == "N" && m["AC"] == "L" && m["PR"] == "N" && m["UI"] == "N" {
			auto = "yes"
		}
		tech = "partial"
		if m["C"] == "H" && m["I"] == "H" {
			tech = "total"
		}
		return auto, tech, "CVSS v" + ver + " vector " + v
	case ver == "4.0":
		for _, k := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA"} {
			if m[k] == "" {
				return vpUnknown, vpUnknown, "incomplete CVSS v4.0 vector"
			}
		}
		switch m["AU"] {
		case "Y":
			auto = "yes"
		case "N":
			auto = "no"
		default:
			auto = "no"
			if m["AV"] == "N" && m["AC"] == "L" && m["AT"] == "N" && m["PR"] == "N" && m["UI"] == "N" {
				auto = "yes"
			}
		}
		tech = "partial"
		if m["VC"] == "H" && m["VI"] == "H" {
			tech = "total"
		}
		return auto, tech, "CVSS v4.0 vector " + v
	}
	return vpUnknown, vpUnknown, "unsupported CVSS version " + ver
}

// vpAssetCrit reads the posture asset store (<store>.posture.json), cached by
// mtime/size. 0 = host not registered.
type vpAssetCache struct {
	mu    sync.Mutex
	mtime time.Time
	size  int64
	crit  map[string]int
}

func (c *vpAssetCache) load(path string) map[string]int {
	if path == "" {
		return map[string]int{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return map[string]int{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.crit != nil && fi.ModTime().Equal(c.mtime) && fi.Size() == c.size {
		return c.crit
	}
	out := map[string]int{}
	if b, err := os.ReadFile(path); err == nil {
		var st struct {
			Assets map[string]PostureAsset `json:"assets"`
		}
		if json.Unmarshal(b, &st) == nil {
			for h, a := range st.Assets {
				out[h] = a.Criticality
			}
		}
	}
	c.crit, c.mtime, c.size = out, fi.ModTime(), fi.Size()
	return out
}

// vpBuildFactors maps evidence to SSVC decision points.
func vpBuildFactors(f VMFinding, vec string, crit int) (SSVCInput, []vpFactor, *vpEPSSScore) {
	var in SSVCInput
	var fs []vpFactor
	add := func(name, val, src, ev string, def string) string {
		known := val != vpUnknown
		x := vpFactor{Name: name, Value: val, Source: src, Known: known, Evidence: ev}
		if !known {
			x.Assumed = def
		}
		fs = append(fs, x)
		return val
	}

	// Exploitation: KEV precedence, then EPSS threshold, else unknown.
	sc, haveEPSS := vpEPSS.Lookup(f.CVE)
	switch {
	case f.KnownExploited:
		ev := "CVE is in the CISA KEV catalogue"
		if f.KEVDateAdded != "" {
			ev += " (added " + f.KEVDateAdded + ")"
		}
		in.Exploitation = add("exploitation", "active", "cisa-kev", ev+"; KEV takes precedence over EPSS", "")
	case haveEPSS && sc.EPSS >= vpEPSSPoCThreshold:
		in.Exploitation = add("exploitation", "poc", "first-epss",
			fmt.Sprintf("EPSS %.5f >= threshold %.2f: treated as public-PoC-level evidence (Kavach policy, not proof of a PoC); not in KEV", sc.EPSS, vpEPSSPoCThreshold), "")
	case haveEPSS:
		in.Exploitation = add("exploitation", vpUnknown, "first-epss",
			fmt.Sprintf("EPSS %.5f is below threshold %.2f and the CVE is not in KEV: a low EPSS does not show that no PoC exists", sc.EPSS, vpEPSSPoCThreshold), ssvcDefaults.Exploitation)
	default:
		in.Exploitation = add("exploitation", vpUnknown, "none",
			"not in KEV (or KEV feed off) and no EPSS score cached (EPSS feed off or CVE not in cache)", ssvcDefaults.Exploitation)
	}

	auto, tech, why := vpParseVector(vec)
	asrc := "cvss-vector"
	if auto == vpUnknown {
		asrc = "none"
	}
	in.Automatable = add("automatable", auto, asrc, why+" (approximation from CVSS metrics, not an analyst kill-chain assessment)", ssvcDefaults.Automatable)
	in.TechnicalImpact = add("technical_impact", tech, asrc, why+" (approximation from CVSS C/I metrics)", ssvcDefaults.TechnicalImpact)

	switch {
	case crit >= 4:
		in.MissionPrevalence = add("mission_prevalence", "essential", "posture-asset-criticality", fmt.Sprintf("host criticality %d/5 mapped to essential (>=4)", crit), "")
	case crit == 3:
		in.MissionPrevalence = add("mission_prevalence", "support", "posture-asset-criticality", "host criticality 3/5 mapped to support", "")
	case crit >= 1:
		in.MissionPrevalence = add("mission_prevalence", "minimal", "posture-asset-criticality", fmt.Sprintf("host criticality %d/5 mapped to minimal (<=2)", crit), "")
	default:
		in.MissionPrevalence = add("mission_prevalence", vpUnknown, "none", "host is not registered in /v1/posture/assets", ssvcDefaults.MissionPrevalence)
	}
	in.WellBeing = add("public_wellbeing", vpUnknown, "none", "Kavach holds no data on safety or public-well-being harm", ssvcDefaults.WellBeing)

	var sp *vpEPSSScore
	if haveEPSS {
		sp = &sc
	}
	return in, fs, sp
}

func vpExplain(it *VPItem) []string {
	e := []string{fmt.Sprintf("SSVC outcome %s = row %d of CISA SSVC Table 9 (%s) with mission-and-well-being %q.",
		it.SSVC.Outcome, it.SSVC.Row, ssvcTreeVersion, it.SSVC.MissionWB)}
	for _, f := range it.Factors {
		if f.Known {
			e = append(e, fmt.Sprintf("%s = %s [%s]: %s", f.Name, f.Value, f.Source, f.Evidence))
		} else {
			e = append(e, fmt.Sprintf("%s = unknown, assumed %s per documented default [%s]: %s", f.Name, f.Assumed, f.Source, f.Evidence))
		}
	}
	if it.SSVC.Sensitive {
		e = append(e, fmt.Sprintf("Outcome depends on unknown inputs (%s): between %s and %s depending on their true values.",
			strings.Join(it.SSVC.Unknown, ", "), it.SSVC.BestCase, it.SSVC.WorstCase))
	}
	if it.EPSS != nil {
		e = append(e, fmt.Sprintf("EPSS %.5f (percentile %.5f) is a modelled probability of exploitation activity in the next 30 days; it says nothing about impact.", *it.EPSS, *it.EPSSPctile))
	}
	return e
}

func vpEvaluate(host string, vectors map[string]string, crit map[string]int) []VPItem {
	finds, _ := vmFindings(vmPackages(host))
	items := make([]VPItem, 0, len(finds))
	for _, f := range finds {
		f.CVE = strings.ToUpper(f.CVE)
		in, fs, sp := vpBuildFactors(f, vectors[f.CVE], crit[f.Host])
		res := ssvcEvaluate(in)
		it := VPItem{Host: f.Host, Package: f.Package, Version: f.Version, CVE: f.CVE, Outcome: res.Outcome,
			CVSS: f.CVSS, KEV: f.KnownExploited, Factors: fs, SSVC: res}
		if sp != nil {
			e, p := sp.EPSS, sp.Percentile
			it.EPSS, it.EPSSPctile = &e, &p
		}
		it.Explanation = vpExplain(&it)
		items = append(items, it)
	}
	vpSort(items)
	return items
}

func fval(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

// vpSort orders by SSVC outcome, then EPSS (unknown last), then CVSS, then a
// total order on (CVE, host, package, version) for determinism.
func vpSort(items []VPItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ra, rb := ssvcRank(a.Outcome), ssvcRank(b.Outcome); ra != rb {
			return ra > rb
		}
		if ea, eb := fval(a.EPSS), fval(b.EPSS); ea != eb {
			return ea > eb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Version < b.Version
	})
	for i := range items {
		items[i].Rank = i + 1
	}
}

func vpLimitations() []string {
	return []string{
		"EPSS is a probability of exploitation activity in the next 30 days, not a measure of impact, and it is global, not specific to this organisation.",
		"SSVC needs organisational context (mission prevalence, public well-being impact). Kavach only has the optional asset criticality (1-5) from /v1/posture/assets; well-being is always unknown.",
		"Unknown decision points use the documented defaults (exploitation none, automatable no, technical impact partial, mission support, well-being minimal); see outcome_if_unknowns_* for the range.",
		"Automatable and technical impact are approximated from CVSS vectors, and only when KAVACH_CVE_FILE advisories carry a cvss_vector; otherwise unknown.",
		"A low EPSS or a missing KEV entry is not evidence that no exploit exists; exploitation then stays unknown rather than none.",
		"The EPSS cache holds only CVEs matched on this install at the last refresh (max 50000); new matches show unknown EPSS until the next refresh.",
		"The embedded advisory set is a small SAMPLE unless KAVACH_CVE_FILE or KAVACH_VULN_FEED is set.",
		"Observation only: results are advice and never trigger patching or any change.",
	}
}

// RegisterVulnPriority mounts the /v1/vulns/priority endpoints.
func RegisterVulnPriority(mux *http.ServeMux, token string, store *Store) {
	posturePath := ""
	if store != nil && store.path != "" {
		posturePath = store.path + ".posture.json"
		SetEPSSCachePath(store.path + ".epss.json")
	}
	assets := &vpAssetCache{}
	vpEPSS.wanted = func() map[string]bool {
		w := map[string]bool{}
		finds, _ := vmFindings(vmPackages(""))
		for _, f := range finds {
			w[strings.ToUpper(f.CVE)] = true
		}
		vmFeeds.mu.Lock()
		for k := range vmFeeds.cache.KEV {
			w[k] = true
		}
		vmFeeds.mu.Unlock()
		return w
	}
	jsonOut := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	eval := func(host string) []VPItem {
		return vpEvaluate(host, vpVectors(), assets.load(posturePath))
	}

	mux.HandleFunc("GET /v1/vulns/priority", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		limit := 50
		if s := r.URL.Query().Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 500 {
				http.Error(w, "limit must be 1-500", 400)
				return
			}
			limit = n
		}
		items := eval(r.URL.Query().Get("host"))
		total := len(items)
		if len(items) > limit {
			items = items[:limit]
		}
		writeJSON(w, map[string]any{"tree_version": ssvcTreeVersion, "total": total, "count": len(items),
			"ranking": "ssvc outcome, then epss (unknown last), then cvss, then cve/host/package",
			"epss":    vpEPSS.Status(), "items": items, "limitations": vpLimitations()})
	})
	mux.HandleFunc("GET /v1/vulns/priority/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, map[string]any{
			"tree_version": ssvcTreeVersion,
			"epss_feed":    vpEPSS.Status(),
			"thresholds": map[string]any{"epss_poc": vpEPSSPoCThreshold,
				"mission_prevalence": "criticality >=4 essential, 3 support, 1-2 minimal, unregistered unknown"},
			"defaults_for_unknown": ssvcDefaults,
			"limitations":          vpLimitations(),
		})
	})
	mux.HandleFunc("POST /v1/vulns/priority/refresh", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if !vpEPSSEnabled() {
			jsonOut(w, http.StatusConflict, map[string]any{"error": "EPSS feed disabled; set KAVACH_EPSS_FEED=on", "status": vpEPSS.Status()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		writeJSON(w, vpEPSS.Refresh(ctx))
	})
	mux.HandleFunc("GET /v1/vulns/priority/{cve}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		cve := strings.ToUpper(r.PathValue("cve"))
		if !vpCVERe.MatchString(cve) {
			http.Error(w, "invalid CVE id", 400)
			return
		}
		var hits []VPItem
		for _, it := range eval("") {
			if it.CVE == cve {
				hits = append(hits, it)
			}
		}
		if len(hits) == 0 {
			http.Error(w, "CVE not matched on any host", 404)
			return
		}
		writeJSON(w, map[string]any{"cve": cve, "tree_version": ssvcTreeVersion, "hosts": len(hits),
			"top_outcome": hits[0].Outcome, "items": hits, "epss": vpEPSS.Status(), "limitations": vpLimitations()})
	})
	vpEPSS.Start()
}
