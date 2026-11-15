package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Real vulnerability feeds (observation only). Network feeds are OPT-IN via
// KAVACH_VULN_FEED=kev,osv. Default (unset) keeps the embedded SAMPLE set.
//
// Privacy: to api.osv.dev Kavach sends ONLY {package name, ecosystem,
// version} tuples and OSV ids. No hostnames, IPs or tenant data. To cisa.gov
// it sends a plain GET with no inventory data. Only the fixed hosts below are
// contacted, over https, with limited redirects.

var (
	vfKEVURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	vfOSVBase  = "https://api.osv.dev"
	vfInsecure = false // tests only: allow http to httptest servers
	vfHosts    = map[string]bool{"www.cisa.gov": true, "cisa.gov": true, "api.osv.dev": true}
)

const (
	vfBatchSize   = 500
	vfMaxDetails  = 200
	vfMaxKEVBytes = 16 << 20
	vfMaxOSVBytes = 8 << 20
	vfCacheTTL    = 24 * time.Hour
	vfInterval    = 6 * time.Hour
)

type vfOSVEntry struct {
	IDs     []string  `json:"ids"`
	Fetched time.Time `json:"fetched"`
}

type vfCache struct {
	KEV        map[string]string     `json:"kev"` // CVE -> dateAdded
	KEVFetched time.Time             `json:"kev_fetched"`
	OSV        map[string]vfOSVEntry `json:"osv"` // eco|name|version
	Vulns      map[string]VMAdvisory `json:"vulns"`
}

// VulnFeedStatus is exposed on /v1/vulns/feeds/status.
type VulnFeedStatus struct {
	Enabled     []string  `json:"enabled"`
	Source      string    `json:"source"`
	LastRefresh time.Time `json:"last_refresh"`
	KEVCount    int       `json:"kev_count"`
	OSVPackages int       `json:"osv_cached_packages"`
	OSVVulns    int       `json:"osv_cached_vulns"`
	FeedErrors  []string  `json:"feed_errors"`
	OfflineFile string    `json:"offline_file,omitempty"`
	Note        string    `json:"note"`
}

type vulnFeeds struct {
	mu        sync.Mutex
	cache     vfCache
	cachePath string
	last      time.Time
	errs      []string
	started   bool
	client    *http.Client
}

var vmFeeds = &vulnFeeds{cache: vfNewCache()}

func vfNewCache() vfCache {
	return vfCache{KEV: map[string]string{}, OSV: map[string]vfOSVEntry{}, Vulns: map[string]VMAdvisory{}}
}

// SetVulnCachePath sets the on-disk cache location and loads it.
func SetVulnCachePath(p string) {
	f := vmFeeds
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cachePath = p
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	c := vfNewCache()
	if err := json.Unmarshal(b, &c); err != nil {
		f.errs = append(f.errs, "cache parse: "+err.Error())
		log.Printf("kavach vuln feeds: cache parse error: %v", err)
		return
	}
	if c.KEV == nil {
		c.KEV = map[string]string{}
	}
	if c.OSV == nil {
		c.OSV = map[string]vfOSVEntry{}
	}
	if c.Vulns == nil {
		c.Vulns = map[string]VMAdvisory{}
	}
	f.cache = c
}

// vfEnabled parses KAVACH_VULN_FEED.
func vfEnabled() (kev, osv bool, names []string) {
	for _, s := range strings.Split(os.Getenv("KAVACH_VULN_FEED"), ",") {
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "kev":
			kev = true
			names = append(names, "kev")
		case "osv":
			osv = true
			names = append(names, "osv")
		}
	}
	return
}

func (f *vulnFeeds) httpClient() *http.Client {
	if f.client != nil {
		return f.client
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return vfCheckURL(req.URL)
	}}
}

func vfCheckURL(u *url.URL) error {
	if vfInsecure {
		return nil
	}
	if u.Scheme != "https" || !vfHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("blocked outbound url (host %q not allowlisted or not https)", u.Hostname())
	}
	return nil
}

func (f *vulnFeeds) do(ctx context.Context, method, rawurl string, body []byte, limit int64) ([]byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if err := vfCheckURL(u); err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawurl, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kavach-vuln-feed")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: http %d", u.Hostname(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", u.Hostname(), limit)
	}
	return b, nil
}

// vfEcosystem maps an inventory row to an OSV ecosystem; "" = unsupported.
// Rows may carry "ecosystem" or "manager"; otherwise Linux hosts are assumed
// to be dpkg-based (what CollectPackages reads).
func vfEcosystem(row map[string]any) string {
	e := strings.ToLower(rowStr(row, "ecosystem"))
	if e == "" {
		e = strings.ToLower(rowStr(row, "manager"))
	}
	switch e {
	case "dpkg", "deb", "debian", "apt":
		return "Debian"
	case "ubuntu":
		return "Ubuntu"
	case "apk", "alpine":
		return "Alpine"
	case "rpm", "rocky":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "pip", "pypi", "python":
		return "PyPI"
	case "npm":
		return "npm"
	case "go", "golang":
		return "Go"
	case "cargo", "crates.io":
		return "crates.io"
	case "gem", "rubygems":
		return "RubyGems"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "":
		if runtime.GOOS == "linux" {
			return "Debian"
		}
	}
	return ""
}

type vfPkg struct{ eco, name, ver string }

func (p vfPkg) key() string { return p.eco + "|" + p.name + "|" + p.ver }

func vfInventory() []vfPkg {
	seen := map[string]bool{}
	var out []vfPkg
	for _, r := range Live.List("sbom") {
		p := vfPkg{vfEcosystem(r), rowStr(r, "component"), rowStr(r, "version")}
		if p.eco == "" || p.name == "" || p.ver == "" || seen[p.key()] {
			continue
		}
		seen[p.key()] = true
		out = append(out, p)
	}
	return out
}

// Refresh fetches enabled feeds and updates the cache. Errors are recorded.
func (f *vulnFeeds) Refresh(ctx context.Context) VulnFeedStatus {
	kev, osv, _ := vfEnabled()
	errs := []string{}
	if kev {
		if err := f.refreshKEV(ctx); err != nil {
			errs = append(errs, "kev: "+err.Error())
		}
	}
	if osv {
		errs = append(errs, f.refreshOSV(ctx)...)
	}
	f.mu.Lock()
	f.errs = errs
	f.last = time.Now().UTC()
	f.mu.Unlock()
	for _, e := range errs {
		log.Printf("kavach vuln feeds: %s", e)
	}
	f.save()
	return f.Status()
}

func (f *vulnFeeds) refreshKEV(ctx context.Context) error {
	b, err := f.do(ctx, "GET", vfKEVURL, nil, vfMaxKEVBytes)
	if err != nil {
		return err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE       string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return errors.New("parse: no vulnerabilities in catalog")
	}
	m := make(map[string]string, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		m[strings.ToUpper(v.CVE)] = v.DateAdded
	}
	f.mu.Lock()
	f.cache.KEV, f.cache.KEVFetched = m, time.Now().UTC()
	f.mu.Unlock()
	return nil
}

func (f *vulnFeeds) refreshOSV(ctx context.Context) []string {
	var errs []string
	f.mu.Lock()
	var todo []vfPkg
	for _, p := range vfInventory() {
		if e, ok := f.cache.OSV[p.key()]; !ok || time.Since(e.Fetched) > vfCacheTTL {
			todo = append(todo, p)
		}
	}
	f.mu.Unlock()
	type osvQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	for i := 0; i < len(todo); i += vfBatchSize {
		end := i + vfBatchSize
		if end > len(todo) {
			end = len(todo)
		}
		batch := todo[i:end]
		qs := make([]osvQuery, len(batch))
		for j, p := range batch {
			qs[j].Package.Name, qs[j].Package.Ecosystem, qs[j].Version = p.name, p.eco, p.ver
		}
		body, _ := json.Marshal(map[string]any{"queries": qs})
		b, err := f.do(ctx, "POST", vfOSVBase+"/v1/querybatch", body, vfMaxOSVBytes)
		if err != nil {
			errs = append(errs, "osv querybatch: "+err.Error())
			continue
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			errs = append(errs, "osv querybatch parse: "+err.Error())
			continue
		}
		if len(res.Results) != len(batch) {
			errs = append(errs, fmt.Sprintf("osv querybatch: got %d results for %d queries", len(res.Results), len(batch)))
			continue
		}
		f.mu.Lock()
		for j, r := range res.Results {
			ids := []string{}
			for _, v := range r.Vulns {
				ids = append(ids, v.ID)
			}
			f.cache.OSV[batch[j].key()] = vfOSVEntry{IDs: ids, Fetched: time.Now().UTC()}
		}
		f.mu.Unlock()
	}
	f.mu.Lock()
	need := map[string]string{} // id -> package name
	for _, p := range vfInventory() {
		for _, id := range f.cache.OSV[p.key()].IDs {
			if _, ok := f.cache.Vulns[id]; !ok {
				need[id] = p.name
			}
		}
	}
	f.mu.Unlock()
	ids := make([]string, 0, len(need))
	for id := range need {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > vfMaxDetails {
		errs = append(errs, fmt.Sprintf("osv details: %d ids pending, fetching first %d (rest next refresh)", len(ids), vfMaxDetails))
		ids = ids[:vfMaxDetails]
	}
	for _, id := range ids {
		b, err := f.do(ctx, "GET", vfOSVBase+"/v1/vulns/"+url.PathEscape(id), nil, vfMaxOSVBytes)
		if err != nil {
			errs = append(errs, "osv vuln "+id+": "+err.Error())
			continue
		}
		adv, err := vfParseOSV(b, need[id])
		if err != nil {
			errs = append(errs, "osv vuln "+id+" parse: "+err.Error())
			continue
		}
		f.mu.Lock()
		f.cache.Vulns[id] = adv
		f.mu.Unlock()
	}
	return errs
}

func vfParseOSV(b []byte, pkg string) (VMAdvisory, error) {
	var v struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
		DB struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return VMAdvisory{}, err
	}
	if v.ID == "" {
		return VMAdvisory{}, errors.New("missing id")
	}
	a := VMAdvisory{CVE: v.ID, Package: pkg, Summary: v.Summary}
	for _, al := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(al), "CVE-") {
			a.CVE = strings.ToUpper(al)
			break
		}
	}
	if a.Summary == "" {
		a.Summary = v.Details
		if len(a.Summary) > 200 {
			a.Summary = a.Summary[:200]
		}
	}
	for _, af := range v.Affected {
		if !strings.EqualFold(af.Package.Name, pkg) {
			continue
		}
		for _, r := range af.Ranges {
			for _, e := range r.Events {
				if fx := e["fixed"]; fx != "" {
					a.FixedIn = fx
				}
			}
		}
	}
	a.CVSS = map[string]float64{"LOW": 3.5, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 8.0, "CRITICAL": 9.5}[strings.ToUpper(v.DB.Severity)]
	if a.CVSS == 0 {
		a.CVSS = 5.0 // OSV record gave no severity label; neutral default
	}
	return a, nil
}

func (f *vulnFeeds) save() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cachePath == "" {
		return
	}
	b, err := json.Marshal(f.cache)
	if err == nil {
		tmp := f.cachePath + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, f.cachePath)
		}
	}
	if err != nil {
		f.errs = append(f.errs, "cache write: "+err.Error())
		log.Printf("kavach vuln feeds: cache write: %v", err)
	}
}

// Status reports feed state.
func (f *vulnFeeds) Status() VulnFeedStatus {
	_, _, names := vfEnabled()
	f.mu.Lock()
	defer f.mu.Unlock()
	st := VulnFeedStatus{Enabled: names, LastRefresh: f.last, KEVCount: len(f.cache.KEV),
		OSVPackages: len(f.cache.OSV), OSVVulns: len(f.cache.Vulns), FeedErrors: append([]string{}, f.errs...),
		OfflineFile: os.Getenv("KAVACH_CVE_FILE")}
	if st.Enabled == nil {
		st.Enabled = []string{}
	}
	if len(names) == 0 {
		st.Source = "embedded-sample"
		st.Note = "network feeds disabled (set KAVACH_VULN_FEED=kev,osv to opt in); results use the small embedded SAMPLE set unless KAVACH_CVE_FILE is set"
	} else {
		st.Source = "feeds:" + strings.Join(names, ",")
		st.Note = "osv.dev receives package name, ecosystem and version only; cisa.gov receives a plain GET"
	}
	return st
}

// Start launches the 6h background refresh when feeds are enabled.
func (f *vulnFeeds) Start() {
	if _, _, n := vfEnabled(); len(n) == 0 {
		return
	}
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return
	}
	f.started = true
	f.mu.Unlock()
	lctx := LifecycleContext()
	lc.bg.Add(1)
	go func() {
		defer lc.bg.Done()
		for lctx.Err() == nil {
			ctx, cancel := context.WithTimeout(lctx, 10*time.Minute)
			f.Refresh(ctx)
			cancel()
			lcSleep(lctx, vfInterval)
		}
	}()
}

// osvFindings returns OSV-derived findings from the cache.
func (f *vulnFeeds) osvFindings(pkgs []map[string]any) []VMFinding {
	_, osv, _ := vfEnabled()
	if !osv {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []VMFinding
	for _, r := range pkgs {
		p := vfPkg{vfEcosystem(r), rowStr(r, "component"), rowStr(r, "version")}
		for _, id := range f.cache.OSV[p.key()].IDs {
			a, ok := f.cache.Vulns[id]
			if !ok {
				continue
			}
			fix := a.FixedIn
			if fix == "" {
				fix = "a fixed release"
			}
			out = append(out, VMFinding{Host: rowStr(r, "host"), Package: p.name, Version: p.ver, CVE: a.CVE,
				CVSS: a.CVSS, FixedIn: a.FixedIn, Summary: a.Summary, Source: "osv",
				Guidance: "Advice only: upgrade " + p.name + " to " + fix + " via your package manager. Kavach does not apply patches."})
		}
	}
	return out
}

// markKEV flags findings whose CVE is in the CISA KEV catalog.
func (f *vulnFeeds) markKEV(fs []VMFinding) {
	kev, _, _ := vfEnabled()
	if !kev {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range fs {
		if d, ok := f.cache.KEV[strings.ToUpper(fs[i].CVE)]; ok {
			fs[i].KnownExploited, fs[i].KEVDateAdded = true, d
		}
	}
}

// vmFindings is the pluggable advisory source: advisory set (sample or
// KAVACH_CVE_FILE) + OSV cache, with KEV marking, plus a source_status map.
func vmFindings(pkgs []map[string]any) ([]VMFinding, map[string]any) {
	adv, src, loadErr := vmLoadAdvisoriesErr()
	fs := vmMatch(pkgs, adv)
	for i := range fs {
		fs[i].Source = src
	}
	fs = append(fs, vmFeeds.osvFindings(pkgs)...)
	vmFeeds.markKEV(fs)
	st := vmFeeds.Status()
	errs := st.FeedErrors
	if loadErr != nil {
		errs = append(errs, loadErr.Error())
	}
	return fs, map[string]any{"advisory_source": src, "source": st.Source, "enabled_feeds": st.Enabled,
		"last_refresh": st.LastRefresh, "kev_count": st.KEVCount, "feed_errors": errs, "note": st.Note}
}

func vmFindingsOnly(pkgs []map[string]any) []VMFinding { f, _ := vmFindings(pkgs); return f }

func vmAnyKEV(f []VMFinding) bool {
	for _, x := range f {
		if x.KnownExploited {
			return true
		}
	}
	return false
}

// registerVulnFeedRoutes adds /v1/vulns/feeds/{refresh,status}.
func registerVulnFeedRoutes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/vulns/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, vmFeeds.Status())
	})
	mux.HandleFunc("POST /v1/vulns/feeds/refresh", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if _, _, n := vfEnabled(); len(n) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "network feeds disabled; set KAVACH_VULN_FEED=kev,osv", "status": vmFeeds.Status()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		writeJSON(w, vmFeeds.Refresh(ctx))
	})
	vmFeeds.Start()
}
