// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Worldwide CERT advisory feeds (observation only). OPT-IN via
// KAVACH_CERT_FEEDS=cisa,ncsc-uk,... ; unset means no network traffic.
//
// Privacy: every request is a plain GET to a fixed, verified feed URL. No
// hostnames, package names, versions or any other inventory data is ever
// sent (no query string, no body, no custom headers beyond User-Agent and
// Accept). Matching advisories against the inventory happens locally.
// See docs/cert-feeds.md for sources, terms and verification dates.

type certFeedDef struct {
	ID    string
	Name  string
	URL   string
	Kind  string // "xml" (RSS 2.0, RSS 1.0/RDF, Atom) or "euvd" (ENISA JSON)
	Lang  string
	Hosts []string // hosts this feed may be fetched from (incl. known redirects)
}

// certFeedDefs lists ONLY feeds whose URL was fetched and verified (see docs).
var certFeedDefs = map[string]certFeedDef{
	"cisa":           {ID: "cisa", Name: "CISA all advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Kind: "xml", Lang: "en", Hosts: []string{"www.cisa.gov", "cisa.gov"}},
	"cisa-ics":       {ID: "cisa-ics", Name: "CISA ICS advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", Kind: "xml", Lang: "en", Hosts: []string{"www.cisa.gov", "cisa.gov"}},
	"ncsc-uk":        {ID: "ncsc-uk", Name: "NCSC UK (reports, guidance, news)", URL: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", Kind: "xml", Lang: "en", Hosts: []string{"www.ncsc.gov.uk", "ncsc.gov.uk"}},
	"cert-eu":        {ID: "cert-eu", Name: "CERT-EU security advisories", URL: "https://cert.europa.eu/publications/security-advisories-rss", Kind: "xml", Lang: "en", Hosts: []string{"cert.europa.eu"}},
	"jpcert":         {ID: "jpcert", Name: "JPCERT/CC alerts and weekly reports", URL: "https://www.jpcert.or.jp/rss/jpcert.rdf", Kind: "xml", Lang: "ja", Hosts: []string{"www.jpcert.or.jp", "jpcert.or.jp"}},
	"jvn":            {ID: "jvn", Name: "JVN (Japan Vulnerability Notes)", URL: "https://jvn.jp/en/rss/jvn.rdf", Kind: "xml", Lang: "en", Hosts: []string{"jvn.jp"}},
	"cert-bund":      {ID: "cert-bund", Name: "BSI WID / CERT-Bund security advisories", URL: "https://wid.cert-bund.de/content/public/securityAdvisory/rss", Kind: "xml", Lang: "de", Hosts: []string{"wid.cert-bund.de"}},
	"cert-fr":        {ID: "cert-fr", Name: "CERT-FR alerts", URL: "https://cert.cyber.gouv.fr/alerte/feed/", Kind: "xml", Lang: "fr", Hosts: []string{"cert.cyber.gouv.fr", "www.cert.cyber.gouv.fr", "www.cert.ssi.gouv.fr", "cert.ssi.gouv.fr"}},
	"cert-fr-avis":   {ID: "cert-fr-avis", Name: "CERT-FR security notices", URL: "https://cert.cyber.gouv.fr/avis/feed/", Kind: "xml", Lang: "fr", Hosts: []string{"cert.cyber.gouv.fr", "www.cert.cyber.gouv.fr", "www.cert.ssi.gouv.fr", "cert.ssi.gouv.fr"}},
	"cccs":           {ID: "cccs", Name: "Canadian Cyber Centre alerts and advisories", URL: "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en", Kind: "xml", Lang: "en", Hosts: []string{"www.cyber.gc.ca", "cyber.gc.ca"}},
	"singcert":       {ID: "singcert", Name: "SingCERT (CSA Singapore) alerts", URL: "https://www.csa.gov.sg/alerts-and-advisories/alerts/rss.xml", Kind: "xml", Lang: "en", Hosts: []string{"www.csa.gov.sg", "csa.gov.sg"}},
	"singcert-adv":   {ID: "singcert-adv", Name: "SingCERT (CSA Singapore) advisories", URL: "https://www.csa.gov.sg/alerts-and-advisories/advisories/rss.xml", Kind: "xml", Lang: "en", Hosts: []string{"www.csa.gov.sg", "csa.gov.sg"}},
	"euvd":           {ID: "euvd", Name: "ENISA EUVD latest vulnerabilities", URL: "https://euvdservices.enisa.europa.eu/api/lastvulnerabilities", Kind: "euvd", Lang: "en", Hosts: []string{"euvdservices.enisa.europa.eu"}},
	"euvd-exploited": {ID: "euvd-exploited", Name: "ENISA EUVD exploited vulnerabilities", URL: "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities", Kind: "euvd", Lang: "en", Hosts: []string{"euvdservices.enisa.europa.eu"}},
}

var (
	cfInsecure = false // tests only: allow http to httptest servers (host allowlist still applies)
	cfExtra    = map[string]bool{}
)

const (
	cfMaxBytes    = 16 << 20 // CISA all.xml is ~6 MB today
	cfMaxItems    = 300      // per feed
	cfMaxCVEs     = 50       // per advisory
	cfMaxField    = 400      // chars kept for title/id/url
	cfMaxBlob     = 64 << 10 // text scanned for CVE ids per item
	cfMaxRedirect = 3
	cfTimeout     = 30 * time.Second
	cfInterval    = 6 * time.Hour
)

// CertAdvisory is the normalised advisory record.
type CertAdvisory struct {
	Source       string   `json:"source"`
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Published    string   `json:"published,omitempty"` // RFC 3339 UTC
	URL          string   `json:"url"`
	CVEs         []string `json:"cves"`
	Severity     string   `json:"severity,omitempty"`
	Matched      bool     `json:"matched"`
	MatchedCVEs  []string `json:"matched_cves,omitempty"`
	MatchedHosts []string `json:"matched_hosts,omitempty"`
}

type cfCache struct {
	Items   map[string][]CertAdvisory `json:"items"`
	Fetched map[string]time.Time      `json:"fetched"`
}

// CertFeedStatus is exposed on /v1/advisories/feeds/status.
type CertFeedStatus struct {
	Enabled     []string             `json:"enabled"`
	Available   []string             `json:"available"`
	LastRefresh time.Time            `json:"last_refresh"`
	Counts      map[string]int       `json:"counts"`
	Fetched     map[string]time.Time `json:"fetched"`
	FeedErrors  []string             `json:"feed_errors"`
	Note        string               `json:"note"`
}

type certFeeds struct {
	mu        sync.Mutex
	cache     cfCache
	cachePath string
	last      time.Time
	errs      []string
	started   bool
	client    *http.Client
}

var certFeedStore = &certFeeds{cache: cfNewCache()}

func cfNewCache() cfCache {
	return cfCache{Items: map[string][]CertAdvisory{}, Fetched: map[string]time.Time{}}
}

// SetCertFeedsPath sets the on-disk cache location and loads it.
func SetCertFeedsPath(p string) {
	f := certFeedStore
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cachePath = p
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	c := cfNewCache()
	if err := json.Unmarshal(b, &c); err != nil {
		f.errs = append(f.errs, "cache parse: "+err.Error())
		log.Printf("kavach cert feeds: cache parse error: %v", err)
		return
	}
	if c.Items == nil {
		c.Items = map[string][]CertAdvisory{}
	}
	if c.Fetched == nil {
		c.Fetched = map[string]time.Time{}
	}
	f.cache = c
}

// cfEnabled parses KAVACH_CERT_FEEDS. Unknown names are returned separately.
func cfEnabled() (ids, unknown []string) {
	seen := map[string]bool{}
	for _, s := range strings.Split(os.Getenv("KAVACH_CERT_FEEDS"), ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		if _, ok := certFeedDefs[s]; ok {
			ids = append(ids, s)
		} else {
			unknown = append(unknown, s)
		}
	}
	return
}

func cfAllowed(host string) bool {
	host = strings.ToLower(host)
	if cfExtra[host] {
		return true
	}
	for _, d := range certFeedDefs {
		for _, h := range d.Hosts {
			if h == host {
				return true
			}
		}
	}
	return false
}

func cfCheckURL(u *url.URL) error {
	if (u.Scheme != "https" && !(cfInsecure && u.Scheme == "http")) || !cfAllowed(u.Hostname()) {
		return fmt.Errorf("blocked outbound url (host %q not allowlisted or not https)", u.Hostname())
	}
	return nil
}

func (f *certFeeds) httpClient() *http.Client {
	if f.client != nil {
		return f.client
	}
	return &http.Client{Timeout: cfTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= cfMaxRedirect {
			return errors.New("too many redirects")
		}
		return cfCheckURL(req.URL)
	}}
}

// get performs a plain, body-less GET. Nothing but the fixed URL is sent.
func (f *certFeeds) get(ctx context.Context, rawurl string) ([]byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if err := cfCheckURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kavach-cert-feed")
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, application/json, text/xml")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: http %d", u.Hostname(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, cfMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > cfMaxBytes {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", u.Hostname(), cfMaxBytes)
	}
	return b, nil
}

// Refresh fetches enabled feeds and updates the cache. Errors are recorded
// per feed; a failing feed keeps its previously cached items.
func (f *certFeeds) Refresh(ctx context.Context) CertFeedStatus {
	ids, unknown := cfEnabled()
	errs := []string{}
	for _, u := range unknown {
		errs = append(errs, "unknown feed "+u)
	}
	for _, id := range ids {
		def := certFeedDefs[id]
		b, err := f.get(ctx, def.URL)
		var items []CertAdvisory
		if err == nil {
			if def.Kind == "euvd" {
				items, err = cfParseEUVD(b, id)
			} else {
				items, err = cfParseFeed(b, id)
			}
		}
		if err != nil {
			errs = append(errs, id+": "+err.Error())
			continue
		}
		f.mu.Lock()
		f.cache.Items[id], f.cache.Fetched[id] = items, time.Now().UTC()
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.errs = errs
	f.last = time.Now().UTC()
	f.mu.Unlock()
	for _, e := range errs {
		log.Printf("kavach cert feeds: %s", e)
	}
	f.save()
	return f.Status()
}

func (f *certFeeds) save() {
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
		log.Printf("kavach cert feeds: cache write: %v", err)
	}
}

// Status reports feed state.
func (f *certFeeds) Status() CertFeedStatus {
	ids, _ := cfEnabled()
	f.mu.Lock()
	defer f.mu.Unlock()
	st := CertFeedStatus{Enabled: ids, LastRefresh: f.last, Counts: map[string]int{}, Fetched: map[string]time.Time{},
		FeedErrors: append([]string{}, f.errs...), Available: []string{}}
	for id := range certFeedDefs {
		st.Available = append(st.Available, id)
	}
	sort.Strings(st.Available)
	if st.Enabled == nil {
		st.Enabled = []string{}
	}
	for _, id := range ids {
		st.Counts[id] = len(f.cache.Items[id])
		if t, ok := f.cache.Fetched[id]; ok {
			st.Fetched[id] = t
		}
	}
	if len(ids) == 0 {
		st.Note = "CERT advisory feeds disabled (set KAVACH_CERT_FEEDS=cisa,ncsc-uk,... to opt in); no network traffic"
	} else {
		st.Note = "feeds are fetched with plain GETs to fixed allowlisted hosts; no host or inventory data is ever sent"
	}
	return st
}

// Start launches the background refresh when feeds are enabled.
func (f *certFeeds) Start() {
	if ids, _ := cfEnabled(); len(ids) == 0 {
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
			lcSleep(lctx, cfInterval)
		}
	}()
}

// ---- parsing ----

var cfCVERe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

func cfExtractCVEs(texts ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range texts {
		for _, m := range cfCVERe.FindAllString(t, -1) {
			m = strings.ToUpper(m)
			if !seen[m] && len(out) < cfMaxCVEs {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func cfClip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

var cfTimeLayouts = []string{
	time.RFC1123Z, time.RFC1123, "Mon, 2 Jan 06 15:04:05 -0700", "Mon, 02 Jan 06 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	time.RFC3339, "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05", "2006-01-02",
	"Jan 2, 2006, 3:04:05 PM", "Jan 2, 2006",
}

func cfParseTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, l := range cfTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func cfSeverityFromScore(s float64) string {
	switch {
	case s <= 0:
		return ""
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	}
	return "low"
}

// cfSeverityText maps severity words used by feeds (English, German) to
// critical|high|medium|low; "" when unknown.
func cfSeverityText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "kritisch", "sehr hoch":
		return "critical"
	case "high", "hoch":
		return "high"
	case "medium", "moderate", "mittel":
		return "medium"
	case "low", "niedrig":
		return "low"
	}
	return ""
}

func cfLatin1(charset string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8", "us-ascii", "":
		return in, nil
	case "iso-8859-1", "latin1", "windows-1252":
		b, err := io.ReadAll(io.LimitReader(in, cfMaxBytes))
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		for _, c := range b {
			buf.WriteRune(rune(c))
		}
		return &buf, nil
	}
	return nil, fmt.Errorf("unsupported charset %q", charset)
}

type cfRawItem struct {
	fields map[string]string
	blob   strings.Builder
}

func (r *cfRawItem) add(k, v string) {
	if v = strings.TrimSpace(v); v == "" {
		return
	}
	if _, ok := r.fields[k]; !ok {
		r.fields[k] = v
	}
}

func (r *cfRawItem) scan(s string) {
	if r.blob.Len() < cfMaxBlob {
		r.blob.WriteString(s)
		r.blob.WriteByte(' ')
	}
}

// cfParseFeed parses RSS 2.0, RSS 1.0 (RDF) and Atom into advisories. The
// decoder is namespace-agnostic (local names), never resolves entities or
// external DTDs (encoding/xml does not), rejects DOCTYPE entity
// declarations outright, and stops after cfMaxItems items.
func cfParseFeed(b []byte, source string) ([]CertAdvisory, error) {
	if bytes.Contains(bytes.ToUpper(b[:minInt(len(b), 4096)]), []byte("<!ENTITY")) || bytes.Contains(bytes.ToUpper(b[:minInt(len(b), 4096)]), []byte("<!DOCTYPE")) {
		return nil, errors.New("parse: DOCTYPE/ENTITY not accepted")
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.CharsetReader = cfLatin1
	dec.Strict = false // tolerate stray HTML entities; DTD entities are never expanded
	var out []CertAdvisory
	var cur *cfRawItem
	var path []string // element stack inside the current item
	var text strings.Builder
	sawRoot := false
	for len(out) < cfMaxItems {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(out) > 0 {
				break // keep what parsed before a truncation
			}
			return nil, fmt.Errorf("parse: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if !sawRoot {
				sawRoot = true
				if name != "rss" && name != "rdf" && name != "feed" {
					return nil, fmt.Errorf("parse: unexpected root element %q", t.Name.Local)
				}
			}
			if cur == nil {
				if name == "item" || name == "entry" {
					cur = &cfRawItem{fields: map[string]string{}}
					path = path[:0]
				}
				continue
			}
			if len(path) > 64 {
				return nil, errors.New("parse: nesting too deep")
			}
			path = append(path, name)
			text.Reset()
			for _, a := range t.Attr {
				cur.scan(a.Value)
			}
			if name == "link" && len(path) == 1 {
				var href, rel string
				for _, a := range t.Attr {
					switch strings.ToLower(a.Name.Local) {
					case "href":
						href = a.Value
					case "rel":
						rel = a.Value
					}
				}
				if href != "" && (rel == "" || rel == "alternate") {
					cur.add("link", href)
				}
			}
		case xml.CharData:
			if cur != nil && len(path) > 0 && text.Len() < cfMaxBlob {
				text.Write(t)
			}
		case xml.EndElement:
			if cur == nil {
				continue
			}
			if len(path) == 0 {
				out = append(out, cfNormalise(cur, source))
				cur = nil
				continue
			}
			s := text.String()
			cur.scan(s)
			if len(path) == 1 {
				cur.add(path[0], s)
			}
			path = path[:len(path)-1]
			text.Reset()
		}
	}
	if !sawRoot {
		return nil, errors.New("parse: not an XML feed")
	}
	if len(out) == 0 {
		return nil, errors.New("parse: no items in feed")
	}
	return out, nil
}

func cfFirst(f map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := f[k]; v != "" {
			return v
		}
	}
	return ""
}

func cfNormalise(r *cfRawItem, source string) CertAdvisory {
	f := r.fields
	title := cfClip(f["title"], cfMaxField)
	link := cfClip(f["link"], cfMaxField)
	if u, err := url.Parse(link); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		link = "" // never surface non-web schemes
	}
	id := cfClip(cfFirst(f, "identifier"), 120)
	if id == "" {
		if g := cfFirst(f, "guid", "id"); g != "" && !strings.HasPrefix(g, "http") && !strings.HasPrefix(g, "/") && !strings.HasPrefix(g, "urn:") && len(g) <= 120 {
			id = g
		}
	}
	if id == "" && link != "" {
		l := strings.TrimRight(link, "/")
		if i := strings.LastIndexAny(l, "/="); i >= 0 {
			id = l[i+1:]
		}
	}
	if id == "" {
		id = title
	}
	pub := cfParseTime(cfFirst(f, "pubdate", "published", "issued", "date", "updated"))
	sev := cfSeverityText(f["category"])
	if sev == "" && strings.HasPrefix(title, "[") { // BSI: "[UPDATE] [hoch] ..."
		for _, p := range strings.Split(title, "]") {
			if s := cfSeverityText(strings.Trim(p, "[ ")); s != "" {
				sev = s
				break
			}
		}
	}
	return CertAdvisory{Source: source, ID: id, Title: title, Published: pub, URL: link,
		CVEs: cfExtractCVEs(title, r.blob.String()), Severity: sev}
}

// cfParseEUVD parses the ENISA EUVD JSON array.
func cfParseEUVD(b []byte, source string) ([]CertAdvisory, error) {
	var doc struct {
		Items []euvdItem `json:"items"`
	}
	var arr []euvdItem
	if err := json.Unmarshal(b, &arr); err != nil {
		if err2 := json.Unmarshal(b, &doc); err2 != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		arr = doc.Items
	}
	if len(arr) == 0 {
		return nil, errors.New("parse: no items")
	}
	if len(arr) > cfMaxItems {
		arr = arr[:cfMaxItems]
	}
	out := make([]CertAdvisory, 0, len(arr))
	for _, v := range arr {
		if v.ID == "" {
			continue
		}
		title := v.ID
		if d := strings.TrimSpace(v.Description); d != "" {
			title = v.ID + ": " + cfClip(strings.Join(strings.Fields(d), " "), 200)
		}
		out = append(out, CertAdvisory{Source: source, ID: cfClip(v.ID, 120), Title: cfClip(title, cfMaxField),
			Published: cfParseTime(v.DatePublished), URL: "https://euvd.enisa.europa.eu/vulnerability/" + url.PathEscape(cfClip(v.ID, 120)),
			CVEs: cfExtractCVEs(v.Aliases, v.Description), Severity: cfSeverityFromScore(v.BaseScore)})
	}
	if len(out) == 0 {
		return nil, errors.New("parse: no usable items")
	}
	return out, nil
}

type euvdItem struct {
	ID            string  `json:"id"`
	Description   string  `json:"description"`
	DatePublished string  `json:"datePublished"`
	BaseScore     float64 `json:"baseScore"`
	Aliases       string  `json:"aliases"`
}

// ---- query / correlation ----

// cfInventoryCVEs maps CVE id -> hosts for CVEs the local inventory matches.
// Purely local; the result is never sent anywhere.
func cfInventoryCVEs() map[string][]string {
	m := map[string]map[string]bool{}
	for _, f := range vmFindingsOnly(vmPackages("")) {
		c := strings.ToUpper(f.CVE)
		if m[c] == nil {
			m[c] = map[string]bool{}
		}
		m[c][f.Host] = true
	}
	out := map[string][]string{}
	for c, hs := range m {
		for h := range hs {
			out[c] = append(out[c], h)
		}
		sort.Strings(out[c])
	}
	return out
}

type cfQuery struct {
	Sources []string
	CVE     string
	Since   string
	Q       string
	Matched bool
	Limit   int
}

func cfParseSince(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if t := cfParseTime(s); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("since must be RFC 3339 or YYYY-MM-DD")
}

// Query returns cached advisories from enabled feeds, newest first, with
// local inventory correlation. total counts matches before limit.
func (f *certFeeds) Query(q cfQuery) (items []CertAdvisory, total int) {
	ids, _ := cfEnabled()
	want := map[string]bool{}
	for _, s := range q.Sources {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	inv := cfInventoryCVEs()
	needle := strings.ToLower(q.Q)
	cve := strings.ToUpper(q.CVE)
	f.mu.Lock()
	var all []CertAdvisory
	for _, id := range ids {
		if len(want) > 0 && !want[id] {
			continue
		}
		all = append(all, f.cache.Items[id]...)
	}
	f.mu.Unlock()
	items = []CertAdvisory{}
	for _, a := range all {
		a.CVEs = append([]string{}, a.CVEs...)
		hosts := map[string]bool{}
		for _, c := range a.CVEs {
			if hs, ok := inv[c]; ok {
				a.Matched = true
				a.MatchedCVEs = append(a.MatchedCVEs, c)
				for _, h := range hs {
					hosts[h] = true
				}
			}
		}
		for h := range hosts {
			a.MatchedHosts = append(a.MatchedHosts, h)
		}
		sort.Strings(a.MatchedHosts)
		if q.Matched && !a.Matched {
			continue
		}
		if cve != "" {
			found := false
			for _, c := range a.CVEs {
				found = found || c == cve
			}
			if !found {
				continue
			}
		}
		if q.Since != "" && (a.Published == "" || a.Published < q.Since) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(a.Title+" "+a.ID+" "+strings.Join(a.CVEs, " ")), needle) {
			continue
		}
		items = append(items, a)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Published > items[j].Published })
	total = len(items)
	if q.Limit > 0 && len(items) > q.Limit {
		items = items[:q.Limit]
	}
	return items, total
}

// ---- API ----

// RegisterCertFeeds registers /v1/advisories and /v1/advisories/feeds/*.
func RegisterCertFeeds(mux *http.ServeMux, token string, store *Store) {
	SetCertFeedsPath(store.path + ".certfeeds.json")
	registerCertFeedRoutes(mux, token)
}

func registerCertFeedRoutes(mux *http.ServeMux, token string) {
	f := certFeedStore
	mux.HandleFunc("GET /v1/advisories", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		qv := r.URL.Query()
		q := cfQuery{CVE: strings.TrimSpace(qv.Get("cve")), Q: strings.TrimSpace(qv.Get("q")), Matched: qv.Get("matched") == "true", Limit: 100}
		if s := qv.Get("source"); s != "" {
			q.Sources = strings.Split(s, ",")
		}
		if q.CVE != "" && !cfCVERe.MatchString(q.CVE) {
			http.Error(w, `{"error":"cve must look like CVE-YYYY-NNNN"}`, http.StatusBadRequest)
			return
		}
		var err error
		if q.Since, err = cfParseSince(qv.Get("since")); err != nil {
			http.Error(w, `{"error":"since must be RFC 3339 or YYYY-MM-DD"}`, http.StatusBadRequest)
			return
		}
		if l := qv.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 {
				http.Error(w, `{"error":"limit must be a positive integer"}`, http.StatusBadRequest)
				return
			}
			q.Limit = minInt(n, 500)
		}
		items, total := f.Query(q)
		st := f.Status()
		writeJSON(w, map[string]any{"count": len(items), "total": total, "enabled_feeds": st.Enabled,
			"last_refresh": st.LastRefresh, "feed_errors": st.FeedErrors, "note": st.Note, "advisories": items})
	})
	mux.HandleFunc("GET /v1/advisories/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, f.Status())
	})
	mux.HandleFunc("POST /v1/advisories/feeds/refresh", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if ids, _ := cfEnabled(); len(ids) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "CERT advisory feeds disabled; set KAVACH_CERT_FEEDS=cisa,ncsc-uk,...", "status": f.Status()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		writeJSON(w, f.Refresh(ctx))
	})
	f.Start()
}
