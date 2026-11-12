package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Software inventory and vulnerability management (observation only:
// remediation text is advice, nothing is patched or changed by Kavach).
// Complements posture_plus.go (which prioritises Spotlight rows) by matching
// the per-host package inventory against an advisory dataset.

// VMAdvisory is one CVE/advisory entry; versions below FixedIn are affected.
type VMAdvisory struct {
	CVE       string  `json:"cve"`
	Package   string  `json:"package"`
	FixedIn   string  `json:"fixed_in"`
	CVSS      float64 `json:"cvss"`
	Summary   string  `json:"summary"`
	Remediate string  `json:"remediation,omitempty"`
}

// vmSampleAdvisories is a SAMPLE dataset for demonstration only; it is not a
// complete or authoritative feed. Load a real one via KAVACH_CVE_FILE.
var vmSampleAdvisories = []VMAdvisory{
	{CVE: "CVE-2022-0778", Package: "openssl", FixedIn: "1.1.1n", CVSS: 7.5, Summary: "BN_mod_sqrt infinite loop (SAMPLE entry)"},
	{CVE: "CVE-2023-38545", Package: "curl", FixedIn: "8.4.0", CVSS: 9.8, Summary: "SOCKS5 heap buffer overflow (SAMPLE entry)"},
	{CVE: "CVE-2024-6387", Package: "openssh", FixedIn: "9.8", CVSS: 8.1, Summary: "regreSSHion signal handler race (SAMPLE entry)"},
	{CVE: "CVE-2021-3156", Package: "sudo", FixedIn: "1.9.5", CVSS: 7.8, Summary: "Baron Samedit heap overflow (SAMPLE entry)"},
	{CVE: "CVE-2022-37434", Package: "zlib", FixedIn: "1.2.12", CVSS: 9.8, Summary: "inflate heap overflow (SAMPLE entry)"},
}

// vmLoadAdvisories returns advisories from KAVACH_CVE_FILE or the sample set.
func vmLoadAdvisories() ([]VMAdvisory, string) {
	if p := os.Getenv("KAVACH_CVE_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			var a []VMAdvisory
			if json.Unmarshal(b, &a) == nil && len(a) > 0 {
				return a, "file:" + p
			}
		}
	}
	return vmSampleAdvisories, "embedded-sample"
}

// vmCmpVersion compares versions part by part; numeric parts numerically,
// letter parts lexically (1.1.1n); epoch and -release suffixes are ignored.
func vmCmpVersion(a, b string) int {
	pa, pb := vmSplitVersion(a), vmSplitVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		xn, xe := strconv.Atoi(x)
		yn, ye := strconv.Atoi(y)
		switch {
		case xe == nil && ye == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x != y:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func vmSplitVersion(v string) []string {
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	var out []string
	var cur strings.Builder
	kind := 0
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		if r == '.' {
			flush()
			kind = 0
			continue
		}
		k := 2
		if r >= '0' && r <= '9' {
			k = 1
		}
		if k != kind {
			flush()
		}
		kind = k
		cur.WriteRune(r)
	}
	flush()
	return out
}

// VMFinding is one matched vulnerable package on a host.
type VMFinding struct {
	Host     string  `json:"host"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	CVE      string  `json:"cve"`
	CVSS     float64 `json:"cvss"`
	FixedIn  string  `json:"fixed_in"`
	Summary  string  `json:"summary"`
	Guidance string  `json:"remediation_guidance"`
}

func vmPackages(host string) []map[string]any {
	var out []map[string]any
	for _, r := range Live.List("sbom") {
		if host == "" || rowStr(r, "host") == host {
			out = append(out, r)
		}
	}
	return out
}

func vmMatch(pkgs []map[string]any, adv []VMAdvisory) []VMFinding {
	out := []VMFinding{}
	for _, p := range pkgs {
		name := strings.ToLower(rowStr(p, "component"))
		ver := rowStr(p, "version")
		for _, a := range adv {
			if name != strings.ToLower(a.Package) || ver == "" || vmCmpVersion(ver, a.FixedIn) >= 0 {
				continue
			}
			g := a.Remediate
			if g == "" {
				g = "Advice only: upgrade " + a.Package + " to " + a.FixedIn + " or later via your package manager, then re-run inventory. Kavach does not apply patches."
			}
			out = append(out, VMFinding{Host: rowStr(p, "host"), Package: a.Package, Version: ver, CVE: a.CVE,
				CVSS: a.CVSS, FixedIn: a.FixedIn, Summary: a.Summary, Guidance: g})
		}
	}
	return out
}

// vmExposure scores 0-100 from the worst CVSS plus a count-based bump.
func vmExposure(f []VMFinding) int {
	if len(f) == 0 {
		return 0
	}
	mx := 0.0
	for _, x := range f {
		if x.CVSS > mx {
			mx = x.CVSS
		}
	}
	return minInt(int(mx*8)+len(f)*2, 100)
}

func vmHosts() []string {
	seen := map[string]bool{}
	var hs []string
	for _, r := range Live.List("sbom") {
		if h := rowStr(r, "host"); h != "" && !seen[h] {
			seen[h] = true
			hs = append(hs, h)
		}
	}
	sort.Strings(hs)
	return hs
}

type vmTop struct {
	Package string   `json:"package"`
	Hosts   int      `json:"affected_hosts"`
	CVEs    []string `json:"cves"`
	MaxCVSS float64  `json:"max_cvss"`
	Fix     string   `json:"remediation_guidance"`
}

// RegisterVulnMgmt registers /v1/vulns/* and /v1/sbom/{host}.
func RegisterVulnMgmt(mux *http.ServeMux, token string) {
	get := func(path string, fn func(r *http.Request) any) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			writeJSON(w, fn(r))
		})
	}
	get("/v1/vulns/software", func(r *http.Request) any {
		p := vmPackages(r.URL.Query().Get("host"))
		return map[string]any{"count": len(p), "software": p}
	})
	get("/v1/vulns/advisories", func(r *http.Request) any {
		a, src := vmLoadAdvisories()
		return map[string]any{"source": src, "note": "sample dataset unless KAVACH_CVE_FILE is set", "count": len(a), "advisories": a}
	})
	get("/v1/vulns/findings", func(r *http.Request) any {
		a, src := vmLoadAdvisories()
		f := vmMatch(vmPackages(r.URL.Query().Get("host")), a)
		return map[string]any{"advisory_source": src, "count": len(f), "findings": f}
	})
	get("/v1/vulns/exposure", func(r *http.Request) any {
		a, src := vmLoadAdvisories()
		rows := []map[string]any{}
		for _, h := range vmHosts() {
			f := vmMatch(vmPackages(h), a)
			rows = append(rows, map[string]any{"host": h, "exposure_score": vmExposure(f), "vulnerabilities": len(f)})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["exposure_score"].(int) > rows[j]["exposure_score"].(int) })
		return map[string]any{"advisory_source": src, "hosts": rows}
	})
	get("/v1/vulns/top", func(r *http.Request) any {
		a, src := vmLoadAdvisories()
		hosts := map[string]map[string]bool{}
		m := map[string]*vmTop{}
		for _, f := range vmMatch(vmPackages(""), a) {
			g := m[f.Package]
			if g == nil {
				g = &vmTop{Package: f.Package, Fix: f.Guidance}
				m[f.Package] = g
				hosts[f.Package] = map[string]bool{}
			}
			hosts[f.Package][f.Host] = true
			g.CVEs = append(g.CVEs, f.CVE)
			if f.CVSS > g.MaxCVSS {
				g.MaxCVSS = f.CVSS
			}
		}
		out := []*vmTop{}
		for k, g := range m {
			g.Hosts = len(hosts[k])
			out = append(out, g)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Hosts != out[j].Hosts {
				return out[i].Hosts > out[j].Hosts
			}
			return out[i].MaxCVSS > out[j].MaxCVSS
		})
		return map[string]any{"advisory_source": src, "top": out}
	})
	mux.HandleFunc("GET /v1/sbom/{host}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, vmCycloneDX(r.PathValue("host")))
	})
}

// vmCycloneDX builds a CycloneDX 1.5-style BOM with matched vulnerabilities.
func vmCycloneDX(host string) map[string]any {
	a, _ := vmLoadAdvisories()
	pkgs := vmPackages(host)
	comps := []map[string]any{}
	for _, p := range pkgs {
		n, v := rowStr(p, "component"), rowStr(p, "version")
		comps = append(comps, map[string]any{"type": "library", "name": n, "version": v,
			"bom-ref": n + "@" + v, "purl": "pkg:generic/" + n + "@" + v})
	}
	vulns := []map[string]any{}
	for _, f := range vmMatch(pkgs, a) {
		vulns = append(vulns, map[string]any{"id": f.CVE, "description": f.Summary,
			"ratings":        []map[string]any{{"score": f.CVSS, "method": "CVSSv3"}},
			"recommendation": f.Guidance,
			"affects":        []map[string]any{{"ref": f.Package + "@" + f.Version}}})
	}
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata":   map[string]any{"component": map[string]any{"type": "device", "name": host}, "tools": []map[string]any{{"name": "kavach"}}},
		"components": comps, "vulnerabilities": vulns}
}
