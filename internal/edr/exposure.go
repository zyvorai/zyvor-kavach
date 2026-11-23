// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Software exposure reporting (observation only). Operators ingest CycloneDX
// or SPDX JSON SBOMs per host; Kavach keeps counts and component metadata
// (name, version, purl, type) only, matches them against a local advisory
// dataset and reports which assets are exposed. Everything is local and
// offline: no network access, no scanning, nothing is patched. The embedded
// dataset is a small labelled SAMPLE and is not a complete vulnerability feed.

const (
	expMaxSBOMBytes     = 8 << 20
	expMaxAdvisoryBytes = 8 << 20
	expMaxComponents    = 20000
	expMaxHosts         = 2000
	expMaxAdvisories    = 50000
	expAdvisoryFormat   = "kavach-advisories/1"
	expSampleNote       = "SAMPLE dataset of a few well-known advisories for demonstration. It is NOT a complete or current vulnerability feed; import your own KEV/OSV data via POST /v1/exposure/advisories/import. A host reported as not exposed is only not exposed to the loaded dataset."
)

// ExpComponent is the only per-component data retained from an SBOM.
type ExpComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Type    string `json:"type,omitempty"`
}

type expSBOM struct {
	Format     string         `json:"format"` // cyclonedx | spdx
	Spec       string         `json:"spec,omitempty"`
	Updated    time.Time      `json:"updated"`
	Components []ExpComponent `json:"components"`
}

// ExpRange is one affected interval. Empty Introduced means "from the start".
// At most one of Fixed (exclusive upper bound) or LastAffected (inclusive).
type ExpRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// ExpAdvisory is one advisory affecting one package (identified by purl
// without version) in the listed ranges and/or exact versions.
type ExpAdvisory struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases,omitempty"`
	PURL     string     `json:"purl"`
	Ranges   []ExpRange `json:"ranges,omitempty"`
	Versions []string   `json:"versions,omitempty"`
	Severity string     `json:"severity,omitempty"` // low|medium|high|critical
	CVSS     float64    `json:"cvss,omitempty"`
	KEV      bool       `json:"kev,omitempty"`
	Summary  string     `json:"summary,omitempty"`
}

type expAdvisorySet struct {
	Format     string        `json:"format"`
	Source     string        `json:"source"`
	Imported   time.Time     `json:"imported"`
	Advisories []ExpAdvisory `json:"advisories"`
}

type expState struct {
	SBOMs map[string]*expSBOM `json:"sboms"`
	Set   *expAdvisorySet     `json:"advisory_set,omitempty"`
}

type expSvc struct {
	mu    sync.Mutex
	path  string
	st    expState
	store *Store
}

// expSample is the embedded SAMPLE dataset (see expSampleNote).
var expSample = []ExpAdvisory{
	{ID: "CVE-2021-44228", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core", Ranges: []ExpRange{{Introduced: "2.0-beta9", Fixed: "2.15.0"}}, Severity: "critical", CVSS: 10, KEV: true, Summary: "Log4Shell JNDI lookup remote code execution (SAMPLE entry)"},
	{ID: "CVE-2021-23337", PURL: "pkg:npm/lodash", Ranges: []ExpRange{{Introduced: "0", Fixed: "4.17.21"}}, Severity: "high", CVSS: 7.2, Summary: "template command injection (SAMPLE entry)"},
	{ID: "CVE-2023-32681", PURL: "pkg:pypi/requests", Ranges: []ExpRange{{Introduced: "2.3.0", Fixed: "2.31.0"}}, Severity: "medium", CVSS: 6.1, Summary: "Proxy-Authorization header leak on redirect (SAMPLE entry)"},
	{ID: "CVE-2022-42889", PURL: "pkg:maven/org.apache.commons/commons-text", Ranges: []ExpRange{{Introduced: "1.5", Fixed: "1.10.0"}}, Severity: "critical", CVSS: 9.8, Summary: "Text4Shell interpolation code execution (SAMPLE entry)"},
	{ID: "CVE-2023-44487", PURL: "pkg:golang/golang.org/x/net", Ranges: []ExpRange{{Introduced: "0", Fixed: "0.17.0"}}, Severity: "high", CVSS: 7.5, KEV: true, Summary: "HTTP/2 rapid reset denial of service (SAMPLE entry)"},
}

// ---------- purl ----------

// expParsePURL returns the version-less package key ("type/namespace/name",
// lower-cased, pypi names normalised), the version and the purl type.
func expParsePURL(p string) (key, version, typ string, ok bool) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(strings.ToLower(p), "pkg:") || len(p) > 1024 {
		return
	}
	p = p[4:]
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimLeft(p, "/")
	slash := strings.IndexByte(p, '/')
	if slash <= 0 {
		return
	}
	typ = strings.ToLower(p[:slash])
	rest := p[slash+1:]
	if at := strings.LastIndexByte(rest, '@'); at >= 0 && at > strings.LastIndexByte(rest, '/') {
		version, _ = url.PathUnescape(rest[at+1:])
		rest = rest[:at]
	}
	segs := strings.Split(rest, "/")
	for i, s := range segs {
		if u, err := url.PathUnescape(s); err == nil {
			s = u
		}
		segs[i] = strings.ToLower(s)
	}
	if typ == "pypi" {
		segs[len(segs)-1] = strings.NewReplacer("_", "-", ".", "-").Replace(segs[len(segs)-1])
	}
	name := strings.Join(segs, "/")
	if name == "" || strings.HasSuffix(name, "/") {
		return
	}
	return typ + "/" + name, version, typ, true
}

// expEcosystem maps a purl type to the lfCompare ecosystem name.
func expEcosystem(typ string) string {
	if typ == "golang" {
		return "go"
	}
	return typ
}

// ---------- SBOM parsing ----------

type cdxComp struct {
	Type       string    `json:"type"`
	Group      string    `json:"group"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	PURL       string    `json:"purl"`
	Components []cdxComp `json:"components"`
}

type spdxPkg struct {
	Name         string `json:"name"`
	VersionInfo  string `json:"versionInfo"`
	ExternalRefs []struct {
		Type    string `json:"referenceType"`
		Locator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

func expClip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ExpParseSBOM parses CycloneDX or SPDX 2.x JSON into component metadata.
func ExpParseSBOM(b []byte) (*expSBOM, error) {
	var probe struct {
		BomFormat   string    `json:"bomFormat"`
		SpecVersion string    `json:"specVersion"`
		SPDXVersion string    `json:"spdxVersion"`
		Components  []cdxComp `json:"components"`
		Packages    []spdxPkg `json:"packages"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	out := &expSBOM{Components: []ExpComponent{}}
	add := func(c ExpComponent) error {
		if c.Name == "" && c.PURL == "" {
			return nil
		}
		if len(out.Components) >= expMaxComponents {
			return fmt.Errorf("more than %d components", expMaxComponents)
		}
		c.Name, c.Version, c.PURL, c.Type = expClip(c.Name, 256), expClip(c.Version, 128), expClip(c.PURL, 512), expClip(c.Type, 64)
		out.Components = append(out.Components, c)
		return nil
	}
	switch {
	case strings.EqualFold(probe.BomFormat, "CycloneDX"):
		out.Format, out.Spec = "cyclonedx", expClip(probe.SpecVersion, 16)
		var walk func(cs []cdxComp, depth int) error
		walk = func(cs []cdxComp, depth int) error {
			for _, c := range cs {
				name := c.Name
				if c.Group != "" {
					name = c.Group + "/" + c.Name
				}
				if err := add(ExpComponent{Name: name, Version: c.Version, PURL: c.PURL, Type: c.Type}); err != nil {
					return err
				}
				if depth < 16 {
					if err := walk(c.Components, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(probe.Components, 0); err != nil {
			return nil, err
		}
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		out.Format, out.Spec = "spdx", expClip(strings.TrimPrefix(probe.SPDXVersion, "SPDX-"), 16)
		for _, p := range probe.Packages {
			purl := ""
			for _, r := range p.ExternalRefs {
				if strings.EqualFold(r.Type, "purl") {
					purl = r.Locator
					break
				}
			}
			if err := add(ExpComponent{Name: p.Name, Version: p.VersionInfo, PURL: purl, Type: "package"}); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("unrecognised SBOM: expected CycloneDX JSON (bomFormat) or SPDX 2.x JSON (spdxVersion)")
	}
	return out, nil
}

// ---------- advisory import ----------

type osvRec struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// ExpParseAdvisories accepts, in one body: the kavach-advisories/1 format, OSV
// records (a single object, an array, or {"vulns":[...]}), or a CISA KEV
// catalogue ({"vulnerabilities":[{"cveID":...}]}) which only returns KEV ids.
func ExpParseAdvisories(b []byte) (advs []ExpAdvisory, kevIDs []string, err error) {
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		var osvs []osvRec
		if err = json.Unmarshal(b, &osvs); err != nil {
			return nil, nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return expFromOSV(osvs), nil, nil
	}
	var top struct {
		Format          string        `json:"format"`
		Advisories      []ExpAdvisory `json:"advisories"`
		Vulns           []osvRec      `json:"vulns"`
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err = json.Unmarshal(b, &top); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	switch {
	case top.Format != "" || top.Advisories != nil:
		if top.Format != expAdvisoryFormat {
			return nil, nil, fmt.Errorf("format must be %q", expAdvisoryFormat)
		}
		advs = top.Advisories
	case top.Vulnerabilities != nil:
		for _, v := range top.Vulnerabilities {
			if v.CVE != "" {
				kevIDs = append(kevIDs, strings.ToUpper(v.CVE))
			}
		}
	case top.Vulns != nil:
		advs = expFromOSV(top.Vulns)
	default:
		var one osvRec
		if json.Unmarshal(b, &one) == nil && one.ID != "" {
			return expFromOSV([]osvRec{one}), nil, nil
		}
		return nil, nil, errors.New("unrecognised advisory file: expected kavach-advisories/1, OSV records or a CISA KEV catalogue")
	}
	return advs, kevIDs, nil
}

func expOSVPurlType(eco string) string {
	switch strings.ToLower(strings.SplitN(eco, ":", 2)[0]) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "go":
		return "golang"
	case "maven":
		return "maven"
	case "rubygems":
		return "gem"
	case "crates.io":
		return "cargo"
	case "nuget":
		return "nuget"
	}
	return ""
}

func expFromOSV(recs []osvRec) []ExpAdvisory {
	var out []ExpAdvisory
	for _, r := range recs {
		for _, a := range r.Affected {
			purl := a.Package.PURL
			if purl == "" {
				t := expOSVPurlType(a.Package.Ecosystem)
				if t == "" || a.Package.Name == "" {
					continue // ecosystem not mappable to a purl; skipped, not guessed
				}
				name := a.Package.Name
				if t == "maven" {
					name = strings.Replace(name, ":", "/", 1)
				}
				purl = "pkg:" + t + "/" + name
			}
			adv := ExpAdvisory{ID: r.ID, Aliases: r.Aliases, PURL: purl, Versions: a.Versions, Summary: expClip(r.Summary, 300), Severity: strings.ToLower(r.DatabaseSpecific.Severity)}
			for _, rg := range a.Ranges {
				if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
					continue // GIT ranges cannot be matched against package versions
				}
				cur := ExpRange{}
				open := false
				for _, e := range rg.Events {
					switch {
					case e.Introduced != "":
						if open {
							adv.Ranges = append(adv.Ranges, cur)
						}
						cur, open = ExpRange{Introduced: e.Introduced}, true
					case e.Fixed != "":
						cur.Fixed = e.Fixed
						adv.Ranges = append(adv.Ranges, cur)
						cur, open = ExpRange{}, false
					case e.LastAffected != "":
						cur.LastAffected = e.LastAffected
						adv.Ranges = append(adv.Ranges, cur)
						cur, open = ExpRange{}, false
					}
				}
				if open {
					adv.Ranges = append(adv.Ranges, cur)
				}
			}
			out = append(out, adv)
		}
	}
	return out
}

func expValidAdvisory(a *ExpAdvisory) error {
	a.ID = strings.TrimSpace(a.ID)
	if a.ID == "" || len(a.ID) > 128 {
		return errors.New("advisory id missing or too long")
	}
	if _, _, _, ok := expParsePURL(a.PURL); !ok {
		return fmt.Errorf("advisory %s: invalid purl %q", a.ID, a.PURL)
	}
	if len(a.Ranges) == 0 && len(a.Versions) == 0 {
		return fmt.Errorf("advisory %s: needs ranges or versions", a.ID)
	}
	if len(a.Ranges) > 64 || len(a.Versions) > 1000 || len(a.Aliases) > 32 {
		return fmt.Errorf("advisory %s: too many ranges, versions or aliases", a.ID)
	}
	a.Summary = expClip(a.Summary, 300)
	switch a.Severity {
	case "", "low", "medium", "high", "critical":
	case "moderate":
		a.Severity = "medium"
	default:
		a.Severity = ""
	}
	if a.CVSS < 0 || a.CVSS > 10 {
		a.CVSS = 0
	}
	return nil
}

// ---------- matching ----------

// expAffected reports whether version is affected. determinate=false when the
// version cannot be compared under the ecosystem's scheme (never guessed).
func expAffected(typ string, a ExpAdvisory, version string) (affected, determinate bool) {
	eco := expEcosystem(typ)
	for _, v := range a.Versions {
		if v == version {
			return true, true
		}
	}
	if len(a.Ranges) == 0 {
		return false, true
	}
	det := true
	for _, r := range a.Ranges {
		in := true
		if r.Introduced != "" && r.Introduced != "0" {
			c, ok := lfCompare(eco, version, r.Introduced)
			if !ok {
				det = false
				continue
			}
			in = c >= 0
		}
		if in && r.Fixed != "" {
			c, ok := lfCompare(eco, version, r.Fixed)
			if !ok {
				det = false
				continue
			}
			in = c < 0
		} else if in && r.LastAffected != "" {
			c, ok := lfCompare(eco, version, r.LastAffected)
			if !ok {
				det = false
				continue
			}
			in = c <= 0
		}
		if in {
			return true, true
		}
	}
	return false, det
}

type ExpMatch struct {
	ID       string  `json:"id"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	Severity string  `json:"severity,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	KEV      bool    `json:"kev"`
	Summary  string  `json:"summary,omitempty"`
}

type ExpFactor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"` // 0..1
	Weight float64 `json:"weight"`
	Note   string  `json:"note"`
}

type ExpAsset struct {
	Host            string      `json:"host"`
	Format          string      `json:"sbom_format"`
	SBOMUpdated     time.Time   `json:"sbom_updated"`
	Components      int         `json:"components"`
	WithPURL        int         `json:"components_with_purl"`
	Indeterminate   int         `json:"indeterminate_version_checks"`
	ExposedPackages int         `json:"exposed_packages"`
	Score           float64     `json:"score"` // 0..100
	Level           string      `json:"level"`
	Factors         []ExpFactor `json:"factors"`
	Matches         []ExpMatch  `json:"matches"`
}

var expSevRank = map[string]float64{"low": 2, "medium": 5, "high": 7.5, "critical": 9.5}

func (s *expSvc) advisories() ([]ExpAdvisory, string, bool) {
	if s.st.Set != nil && len(s.st.Set.Advisories) > 0 {
		return s.st.Set.Advisories, "imported:" + s.st.Set.Source, false
	}
	return expSample, "embedded-sample", true
}

func expAnalyse(host string, sb *expSBOM, advs []ExpAdvisory, crit int) ExpAsset {
	idx := map[string][]int{}
	for i, a := range advs {
		if k, _, _, ok := expParsePURL(a.PURL); ok {
			idx[k] = append(idx[k], i)
		}
	}
	as := ExpAsset{Host: host, Format: sb.Format, SBOMUpdated: sb.Updated, Components: len(sb.Components), Matches: []ExpMatch{}, Factors: []ExpFactor{}}
	exposed := map[string]bool{}
	for _, c := range sb.Components {
		key, pver, typ, ok := expParsePURL(c.PURL)
		if !ok {
			continue
		}
		as.WithPURL++
		ver := c.Version
		if ver == "" {
			ver = pver
		}
		if ver == "" {
			continue
		}
		for _, i := range idx[key] {
			a := advs[i]
			aff, det := expAffected(typ, a, ver)
			if !det {
				as.Indeterminate++
			}
			if !aff {
				continue
			}
			fixed := ""
			for _, r := range a.Ranges {
				if r.Fixed != "" {
					fixed = r.Fixed
				}
			}
			as.Matches = append(as.Matches, ExpMatch{ID: a.ID, Package: key, Version: ver, FixedIn: fixed, Severity: a.Severity, CVSS: a.CVSS, KEV: a.KEV, Summary: a.Summary})
			exposed[key+"@"+ver] = true
		}
	}
	as.ExposedPackages = len(exposed)
	sort.Slice(as.Matches, func(i, j int) bool {
		if as.Matches[i].KEV != as.Matches[j].KEV {
			return as.Matches[i].KEV
		}
		if as.Matches[i].CVSS != as.Matches[j].CVSS {
			return as.Matches[i].CVSS > as.Matches[j].CVSS
		}
		return as.Matches[i].ID < as.Matches[j].ID
	})
	var kev int
	var maxCVSS float64
	for _, m := range as.Matches {
		if m.KEV {
			kev++
		}
		c := m.CVSS
		if c == 0 {
			c = expSevRank[m.Severity]
		}
		if c > maxCVSS {
			maxCVSS = c
		}
	}
	if len(as.Matches) > 0 {
		kv := 0.0
		if kev > 0 {
			kv = 1
		}
		as.Factors = []ExpFactor{
			{"known_exploited", kv, 0.45, fmt.Sprintf("%d matched advisories flagged known-exploited in the loaded dataset", kev)},
			{"max_severity", clamp01(maxCVSS / 10), 0.35, "highest CVSS (or severity-derived score) among matches: " + f2(maxCVSS)},
			{"breadth", clamp01(float64(len(exposed)) / 10), 0.20, fmt.Sprintf("%d exposed package versions (saturates at 10)", len(exposed))},
		}
		for _, f := range as.Factors {
			as.Score += f.Value * f.Weight
		}
		as.Score = float64(int(as.Score*1000+0.5)) / 10
	}
	if crit >= 1 {
		as.Factors = append(as.Factors, ExpFactor{"asset_criticality", float64(crit-1) / 4, 0, fmt.Sprintf("asset criticality %d/5 shown for context; not part of the exposure score (see /v1/ml/priority)", crit)})
	}
	as.Level = priorityLevel(as.Score)
	if len(as.Matches) == 0 {
		as.Level = "none"
	}
	return as
}

// ---------- persistence ----------

func (s *expSvc) load() {
	s.st = expState{SBOMs: map[string]*expSBOM{}}
	if s.path == "" {
		return
	}
	if b, err := os.ReadFile(s.path); err == nil {
		var st expState
		if json.Unmarshal(b, &st) == nil && st.SBOMs != nil {
			s.st = st
		}
	}
}

func (s *expSvc) saveLocked() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(s.st)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// ---------- priority hook ----------

type expPriorityFn func(host string) (float64, string, bool)

var expPriorityHook atomic.Pointer[expPriorityFn]

func init() {
	// Small on purpose; the factor is present only when KAVACH_EXPOSURE_PRIORITY=1 and the host has an SBOM.
	mlPriorityWeights = append(mlPriorityWeights, struct {
		Name   string
		Weight float64
	}{"exposure", 0.10})
}

// expAssetsFn lists the analysed assets that carry at least one match. It is
// read by the attack-path scorer (attack_paths.go) and is nil until
// RegisterExposure has run.
type expAssetsFn func() []ExpAsset

var expAssetsHook atomic.Pointer[expAssetsFn]

func (s *expSvc) exposedAssets() []ExpAsset {
	s.mu.Lock()
	advs, _, _ := s.advisories()
	hosts := make([]string, 0, len(s.st.SBOMs))
	for h := range s.st.SBOMs {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var out []ExpAsset
	for _, h := range hosts {
		if as := expAnalyse(h, s.st.SBOMs[h], advs, 0); len(as.Matches) > 0 {
			out = append(out, as)
		}
	}
	s.mu.Unlock()
	return out
}

func (s *expSvc) hostScore(host string) (float64, string, bool) {
	s.mu.Lock()
	sb := s.st.SBOMs[host]
	advs, src, _ := s.advisories()
	s.mu.Unlock()
	if sb == nil {
		return 0, "no SBOM ingested for this host", false
	}
	as := expAnalyse(host, sb, advs, 0)
	return as.Score / 100, fmt.Sprintf("%d exposed package versions, score %s/100 against %s (advisory; not a complete feed)", as.ExposedPackages, f2(as.Score), src), true
}

// ---------- HTTP ----------

// RegisterExposure wires software exposure reporting. No goroutine is started;
// the only lifecycle item is the optional priority hook, cleared on stop.
func RegisterExposure(mux *http.ServeMux, token string, store *Store) {
	s := &expSvc{store: store}
	if store.path != "" {
		s.path = store.path + ".exposure.json"
	}
	s.load()
	{
		fn := expAssetsFn(s.exposedAssets)
		expAssetsHook.Store(&fn)
	}
	if os.Getenv("KAVACH_EXPOSURE_PRIORITY") == "1" {
		fn := expPriorityFn(s.hostScore)
		expPriorityHook.Store(&fn)
		RegisterStopper("exposure-hook", func(context.Context) error { expPriorityHook.CompareAndSwap(&fn, nil); return nil })
	}
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	auth := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if requireAuth(w, r, token) {
				f(w, r)
			}
		}
	}
	admin := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			isAdmin, ok := requireAdminOrSession(w, r, token)
			if !ok {
				return
			}
			if !isAdmin {
				http.Error(w, "admin token required", http.StatusForbidden)
				return
			}
			f(w, r)
		}
	}
	body := func(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
		if err != nil {
			var mb *http.MaxBytesError
			if errors.As(err, &mb) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "read error", http.StatusBadRequest)
			}
			return nil, false
		}
		return b, true
	}
	validHost := func(h string) bool {
		if h == "" || len(h) > 253 {
			return false
		}
		for _, c := range h {
			if c < 0x21 || c == 0x7f {
				return false
			}
		}
		return true
	}
	ingest := func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		if !validHost(host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		b, ok := body(w, r, expMaxSBOMBytes)
		if !ok {
			return
		}
		sb, err := ExpParseSBOM(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sb.Updated = time.Now().UTC()
		s.mu.Lock()
		if _, exists := s.st.SBOMs[host]; !exists && len(s.st.SBOMs) >= expMaxHosts {
			s.mu.Unlock()
			http.Error(w, "host limit reached", http.StatusConflict)
			return
		}
		s.st.SBOMs[host] = sb
		s.saveLocked()
		s.mu.Unlock()
		out(w, 200, map[string]any{"host": host, "format": sb.Format, "spec": sb.Spec, "components": len(sb.Components), "stored": "component metadata only (name, version, purl, type)"})
	}
	mux.HandleFunc("PUT /v1/exposure/sboms/{host}", admin(ingest))
	mux.HandleFunc("POST /v1/exposure/sboms/{host}", admin(ingest))
	mux.HandleFunc("DELETE /v1/exposure/sboms/{host}", admin(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		_, ok := s.st.SBOMs[r.PathValue("host")]
		delete(s.st.SBOMs, r.PathValue("host"))
		s.saveLocked()
		s.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		out(w, 200, map[string]any{"deleted": r.PathValue("host")})
	}))
	mux.HandleFunc("GET /v1/exposure/sboms", auth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		rows := []map[string]any{}
		for h, sb := range s.st.SBOMs {
			rows = append(rows, map[string]any{"host": h, "format": sb.Format, "spec": sb.Spec, "components": len(sb.Components), "updated": sb.Updated})
		}
		s.mu.Unlock()
		sort.Slice(rows, func(i, j int) bool { return rows[i]["host"].(string) < rows[j]["host"].(string) })
		out(w, 200, map[string]any{"count": len(rows), "sboms": rows})
	}))
	mux.HandleFunc("GET /v1/exposure/sboms/{host}", auth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		sb := s.st.SBOMs[r.PathValue("host")]
		s.mu.Unlock()
		if sb == nil {
			http.Error(w, "not found", 404)
			return
		}
		out(w, 200, map[string]any{"host": r.PathValue("host"), "format": sb.Format, "spec": sb.Spec, "updated": sb.Updated, "count": len(sb.Components), "components": sb.Components})
	}))
	mux.HandleFunc("GET /v1/exposure/advisories", auth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		advs, src, sample := s.advisories()
		n := len(advs)
		list := advs
		if len(list) > 500 {
			list = list[:500]
		}
		s.mu.Unlock()
		note := "Operator-imported dataset; coverage is whatever you loaded."
		if sample {
			note = expSampleNote
		}
		out(w, 200, map[string]any{"source": src, "sample": sample, "count": n, "advisories": list, "format": expAdvisoryFormat, "note": note, "offline": true})
	}))
	mux.HandleFunc("POST /v1/exposure/advisories/import", admin(func(w http.ResponseWriter, r *http.Request) {
		b, ok := body(w, r, expMaxAdvisoryBytes)
		if !ok {
			return
		}
		advs, kevIDs, err := ExpParseAdvisories(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for i := range advs {
			if err := expValidAdvisory(&advs[i]); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		replace := r.URL.Query().Get("mode") == "replace"
		source := expClip(strings.TrimSpace(r.URL.Query().Get("source")), 120)
		explicitSource := source != ""
		if !explicitSource {
			source = "operator-import"
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		set := s.st.Set
		if set == nil || replace {
			set = &expAdvisorySet{Format: expAdvisoryFormat}
		} else {
			cp := *set
			cp.Advisories = append([]ExpAdvisory(nil), set.Advisories...)
			set = &cp
		}
		if len(advs) == 0 && len(kevIDs) > 0 && len(set.Advisories) == 0 {
			http.Error(w, "a KEV catalogue lists CVE ids only; import advisories first, then the KEV file to flag them", http.StatusBadRequest)
			return
		}
		byKey := map[string]int{}
		for i, a := range set.Advisories {
			byKey[a.ID+"|"+a.PURL] = i
		}
		for _, a := range advs {
			k := a.ID + "|" + a.PURL
			if i, ok := byKey[k]; ok {
				set.Advisories[i] = a
				continue
			}
			byKey[k] = len(set.Advisories)
			set.Advisories = append(set.Advisories, a)
		}
		flagged := 0
		if len(kevIDs) > 0 {
			ids := map[string]bool{}
			for _, id := range kevIDs {
				ids[id] = true
			}
			for i := range set.Advisories {
				a := &set.Advisories[i]
				hit := ids[strings.ToUpper(a.ID)]
				for _, al := range a.Aliases {
					hit = hit || ids[strings.ToUpper(al)]
				}
				if hit && !a.KEV {
					a.KEV = true
					flagged++
				}
			}
		}
		if len(set.Advisories) > expMaxAdvisories {
			http.Error(w, fmt.Sprintf("more than %d advisories", expMaxAdvisories), http.StatusRequestEntityTooLarge)
			return
		}
		if explicitSource || set.Source == "" {
			set.Source = source
		}
		set.Imported = time.Now().UTC()
		source = set.Source
		s.st.Set = set
		s.saveLocked()
		mode := "merge"
		if replace {
			mode = "replace"
		}
		out(w, 200, map[string]any{"imported": len(advs), "kev_flagged": flagged, "total": len(set.Advisories), "source": source, "mode": mode})
	}))
	mux.HandleFunc("DELETE /v1/exposure/advisories", admin(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.st.Set = nil
		s.saveLocked()
		s.mu.Unlock()
		out(w, 200, map[string]any{"source": "embedded-sample", "note": "operator dataset removed; the embedded SAMPLE is active"})
	}))
	mux.HandleFunc("GET /v1/exposure/report", auth(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		host, minScore := q.Get("host"), 0.0
		if v := q.Get("min_score"); v != "" {
			_, _ = fmt.Sscanf(v, "%g", &minScore)
		}
		crit := map[string]int{}
		if p := newPostureSvc(store); p != nil {
			p.mu.Lock()
			for k, v := range p.st.Assets {
				crit[k] = v.Criticality
			}
			p.mu.Unlock()
		}
		s.mu.Lock()
		advs, src, sample := s.advisories()
		assets := []ExpAsset{}
		scanned := 0
		for h, sb := range s.st.SBOMs {
			if host != "" && h != host {
				continue
			}
			scanned++
			as := expAnalyse(h, sb, advs, crit[h])
			if len(as.Matches) > 0 && as.Score >= minScore {
				assets = append(assets, as)
			}
		}
		s.mu.Unlock()
		sort.Slice(assets, func(i, j int) bool {
			if assets[i].Score != assets[j].Score {
				return assets[i].Score > assets[j].Score
			}
			return assets[i].Host < assets[j].Host
		})
		note := "Local, offline matching of ingested SBOMs against the operator-imported advisory dataset. Not a complete vulnerability feed; absence from this report is not proof of safety. Kavach reports exposure only; it never patches."
		if sample {
			note = expSampleNote + " Local and offline; Kavach reports exposure only and never patches."
		}
		out(w, 200, map[string]any{"generated_at": time.Now().UTC(), "advisory_source": src, "advisory_sample": sample, "advisory_count": len(advs),
			"hosts_with_sbom": scanned, "exposed_hosts": len(assets), "assets": assets, "offline": true, "note": note})
	}))
}
