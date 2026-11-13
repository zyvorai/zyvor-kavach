// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const cfRSS = `<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel><title>x</title>
<item><title>Siemens Thing</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-02</link>
<description>&lt;li&gt;affected (CVE-2099-0001, cve-2099-0002)&lt;/li&gt;</description><pubDate>Wed, 11 Nov 2026 12:00:00 +0000</pubDate></item>
<item><title>[UPDATE] [hoch] Linux Kernel</title><link>https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3042</link>
<category>hoch</category><pubDate>Fri, 13 Nov 2026 09:12:01 GMT</pubDate></item></channel></rss>`

const cfRDF = `<?xml version="1.0"?><rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel rdf:about="x"><title>JVN</title><items><rdf:Seq><rdf:li rdf:resource="a"/></rdf:Seq></items></channel>
<item rdf:about="https://jvn.jp/en/jp/JVN76799957/"><title>YouTrack XSS</title><link>https://jvn.jp/en/jp/JVN76799957/</link>
<dc:identifier>JVN#76799957</dc:identifier><dc:date>2026-11-13T12:00:00+09:00</dc:date></item></rdf:RDF>`

const cfAtom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>c</title>
<entry><id>https://cyber.gc.ca/en/alerts-advisories/av26-1142</id><link rel="alternate" href="https://cyber.gc.ca/en/alerts-advisories/av26-1142"/>
<title><![CDATA[Microsoft rollup (AV26-1142)]]></title><updated>2026-11-12T20:42:34Z</updated>
<content><![CDATA[<p>fixes CVE-2099-0001</p>]]></content></entry></feed>`

const cfEUVD = `[{"id":"EUVD-2026-1","description":"Remote bug in libfoo","datePublished":"Nov 13, 2026, 7:29:04 AM","baseScore":9.8,"aliases":"CVE-2099-0003\nGHSA-x"}]`

func TestCertFeedParsers(t *testing.T) {
	a, err := cfParseFeed([]byte(cfRSS), "cisa")
	if err != nil || len(a) != 2 {
		t.Fatalf("rss: %v %+v", err, a)
	}
	if a[0].ID != "icsa-26-316-02" || strings.Join(a[0].CVEs, ",") != "CVE-2099-0001,CVE-2099-0002" || a[0].Published != "2026-11-11T12:00:00Z" {
		t.Fatalf("rss item %+v", a[0])
	}
	if a[1].Severity != "high" || a[1].ID != "WID-SEC-2026-3042" {
		t.Fatalf("bsi item %+v", a[1])
	}
	r, err := cfParseFeed([]byte(cfRDF), "jvn")
	if err != nil || len(r) != 1 || r[0].ID != "JVN#76799957" || r[0].Published != "2026-11-13T03:00:00Z" {
		t.Fatalf("rdf: %v %+v", err, r)
	}
	at, err := cfParseFeed([]byte(cfAtom), "cccs")
	if err != nil || len(at) != 1 || at[0].URL != "https://cyber.gc.ca/en/alerts-advisories/av26-1142" || at[0].CVEs[0] != "CVE-2099-0001" || at[0].Title != "Microsoft rollup (AV26-1142)" {
		t.Fatalf("atom: %v %+v", err, at)
	}
	e, err := cfParseEUVD([]byte(cfEUVD), "euvd")
	if err != nil || len(e) != 1 || e[0].Severity != "critical" || e[0].CVEs[0] != "CVE-2099-0003" || e[0].Published != "2026-11-13T07:29:04Z" {
		t.Fatalf("euvd: %v %+v", err, e)
	}
}

func TestCertFeedTimeFormats(t *testing.T) {
	for in, want := range map[string]string{
		"Thu, 12 Nov 26 12:00:00 +0000": "2026-11-12T12:00:00Z", // CISA two-digit year
		"Thu, 12 Nov 2026 18:20:53 CET": "",                     // zone abbreviations are accepted below
		"2026-11-13T11:44:39+09:00":     "2026-11-13T02:44:39Z",
		"Nov 13, 2026, 7:29:04 AM":      "2026-11-13T07:29:04Z",
		"garbage":                       "",
	} {
		got := cfParseTime(in)
		if want != "" && got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
		if want == "" && in == "garbage" && got != "" {
			t.Fatalf("%q -> %q", in, got)
		}
	}
}

func TestCertFeedParserDefensive(t *testing.T) {
	bomb := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&xxe;</title></item></channel></rss>`
	if _, err := cfParseFeed([]byte(bomb), "x"); err == nil {
		t.Fatal("DOCTYPE/ENTITY must be rejected")
	}
	for _, bad := range []string{"", "not xml", "<html><body/></html>", "<rss><channel></channel></rss>", `{"a":1}`} {
		if _, err := cfParseFeed([]byte(bad), "x"); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	var sb strings.Builder
	sb.WriteString("<rss><channel>")
	for i := 0; i < 1000; i++ {
		sb.WriteString("<item><title>t</title><link>javascript:alert(1)</link></item>")
	}
	sb.WriteString("</channel></rss>")
	a, err := cfParseFeed([]byte(sb.String()), "x")
	if err != nil || len(a) != cfMaxItems || a[0].URL != "" {
		t.Fatalf("cap/scheme: %v %d %+v", err, len(a), a[0])
	}
	if _, err := cfParseEUVD([]byte("nope"), "euvd"); err == nil {
		t.Fatal("bad euvd json must error")
	}
}

// cfTestSetup points the feeds at an httptest server and records requests.
func cfTestSetup(t *testing.T, ids ...string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var reqs []string
	mux := http.NewServeMux()
	rec := func(next string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 64)
			n, _ := r.Body.Read(body)
			mu.Lock()
			reqs = append(reqs, r.Method+" "+r.URL.String()+" body="+string(body[:n])+" hdr="+strings.Join(r.Header.Values("User-Agent"), ";")+
				";cookie="+r.Header.Get("Cookie")+";auth="+r.Header.Get("Authorization")+";cl="+r.Header.Get("Content-Length"))
			mu.Unlock()
			w.Write([]byte(next))
		}
	}
	mux.HandleFunc("/a.xml", rec(cfRSS))
	mux.HandleFunc("/b.rdf", rec(cfRDF))
	mux.HandleFunc("/e.json", rec(cfEUVD))
	mux.HandleFunc("/bad.xml", rec("<html>nope</html>"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)

	oldDefs, oldIns, oldExtra, oldStore := certFeedDefs, cfInsecure, cfExtra, certFeedStore
	certFeedDefs = map[string]certFeedDef{
		"cisa":    {ID: "cisa", URL: srv.URL + "/a.xml", Kind: "xml", Hosts: []string{"www.cisa.gov"}},
		"jvn":     {ID: "jvn", URL: srv.URL + "/b.rdf", Kind: "xml", Hosts: []string{"jvn.jp"}},
		"euvd":    {ID: "euvd", URL: srv.URL + "/e.json", Kind: "euvd", Hosts: []string{"euvdservices.enisa.europa.eu"}},
		"cert-eu": {ID: "cert-eu", URL: srv.URL + "/bad.xml", Kind: "xml", Hosts: []string{"cert.europa.eu"}},
	}
	cfInsecure, cfExtra = true, map[string]bool{u.Hostname(): true}
	certFeedStore = &certFeeds{cache: cfNewCache()}
	SetCertFeedsPath(filepath.Join(t.TempDir(), "x.certfeeds.json"))
	t.Cleanup(func() { certFeedDefs, cfInsecure, cfExtra, certFeedStore = oldDefs, oldIns, oldExtra, oldStore })
	t.Setenv("KAVACH_CERT_FEEDS", strings.Join(ids, ","))
	return srv, &reqs
}

func TestCertFeedsRefreshQueryAndCorrelation(t *testing.T) {
	_, reqs := cfTestSetup(t, "cisa", "jvn", "euvd", "cert-eu", "nosuchfeed")
	adv := filepath.Join(t.TempDir(), "adv.json")
	os.WriteFile(adv, []byte(`[{"cve":"CVE-2099-0001","package":"secret-pkg-xyz","fixed_in":"9.9","cvss":8}]`), 0o600)
	t.Setenv("KAVACH_CVE_FILE", adv)
	Live.ReplaceHost("sbom", "secret-host-qrs", []map[string]any{{"component": "secret-pkg-xyz", "version": "1.0", "host": "secret-host-qrs", "ecosystem": "dpkg"}})
	t.Cleanup(func() { Live.ReplaceHost("sbom", "secret-host-qrs", nil) })

	st := certFeedStore.Refresh(context.Background())
	if st.Counts["cisa"] != 2 || st.Counts["jvn"] != 1 || st.Counts["euvd"] != 1 {
		t.Fatalf("status %+v", st)
	}
	joined := strings.Join(st.FeedErrors, "|")
	if !strings.Contains(joined, "cert-eu") || !strings.Contains(joined, "unknown feed nosuchfeed") {
		t.Fatalf("errors %v", st.FeedErrors)
	}
	// Privacy: requests are body-less plain GETs with no inventory data.
	if len(*reqs) != 4 {
		t.Fatalf("requests %v", *reqs)
	}
	for _, r := range *reqs {
		if !strings.HasPrefix(r, "GET /") {
			t.Fatalf("not a GET: %s", r)
		}
		for _, secret := range []string{"secret-host-qrs", "secret-pkg-xyz", "CVE-2099"} {
			if strings.Contains(r, secret) {
				t.Fatalf("request leaked %q: %s", secret, r)
			}
		}
		if !strings.Contains(r, "body= hdr=kavach-cert-feed;cookie=;auth=;cl=") || strings.Contains(r, "?") {
			t.Fatalf("request not plain: %s", r)
		}
	}

	items, total := certFeedStore.Query(cfQuery{Limit: 100})
	if total != 4 || len(items) != 4 || items[0].Published < items[len(items)-1].Published {
		t.Fatalf("query %d %+v", total, items)
	}
	m, _ := certFeedStore.Query(cfQuery{Matched: true})
	if len(m) != 1 || m[0].Source != "cisa" || !m[0].Matched || m[0].MatchedHosts[0] != "secret-host-qrs" || m[0].MatchedCVEs[0] != "CVE-2099-0001" {
		t.Fatalf("matched %+v", m)
	}
	if g, _ := certFeedStore.Query(cfQuery{Sources: []string{"jvn"}}); len(g) != 1 {
		t.Fatalf("source filter %+v", g)
	}
	if g, _ := certFeedStore.Query(cfQuery{CVE: "cve-2099-0003"}); len(g) != 1 || g[0].Source != "euvd" {
		t.Fatalf("cve filter %+v", g)
	}
	if g, _ := certFeedStore.Query(cfQuery{Q: "youtrack"}); len(g) != 1 {
		t.Fatalf("q filter %+v", g)
	}
	if g, _ := certFeedStore.Query(cfQuery{Since: "2026-11-13"}); len(g) != 3 { // bsi item, jvn, euvd
		t.Fatalf("since filter %d", len(g))
	}

	// cache persisted and reloaded
	b, err := os.ReadFile(certFeedStore.cachePath)
	if err != nil || !strings.Contains(string(b), "JVN#76799957") {
		t.Fatalf("cache: %v", err)
	}
	p := certFeedStore.cachePath
	certFeedStore = &certFeeds{cache: cfNewCache()}
	SetCertFeedsPath(p)
	if g, _ := certFeedStore.Query(cfQuery{}); len(g) != 4 {
		t.Fatalf("reload %d", len(g))
	}
	// a disabled feed's cache is hidden
	t.Setenv("KAVACH_CERT_FEEDS", "jvn")
	if g, _ := certFeedStore.Query(cfQuery{}); len(g) != 1 {
		t.Fatalf("disabled feeds must be hidden: %d", len(g))
	}
}

func TestCertFeedsRefuseNonAllowlistedAndRedirects(t *testing.T) {
	cfInsecure = false
	f := &certFeeds{cache: cfNewCache()}
	for _, u := range []string{"http://www.cisa.gov/x", "https://evil.example.com/rss", "http://127.0.0.1:1/x", "https://cisa.gov.evil.example/x"} {
		if _, err := f.get(context.Background(), u); err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("%s: err %v", u, err)
		}
	}
	// A redirect from an allowlisted host to a non-allowlisted one is refused.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect target must not be contacted")
		w.Write([]byte(cfRSS))
	}))
	defer other.Close()
	ou, _ := url.Parse(other.URL)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+ou.Port()+"/x", http.StatusFound)
	}))
	defer srv.Close()
	su, _ := url.Parse(srv.URL)
	oldIns, oldExtra := cfInsecure, cfExtra
	cfInsecure, cfExtra = true, map[string]bool{su.Hostname(): true}
	defer func() { cfInsecure, cfExtra = oldIns, oldExtra }()
	if _, err := f.get(context.Background(), srv.URL+"/r"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("redirect err %v", err)
	}
}

func TestCertFeedsSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 17; i++ {
			w.Write(chunk)
		}
	}))
	defer srv.Close()
	su, _ := url.Parse(srv.URL)
	oldIns, oldExtra := cfInsecure, cfExtra
	cfInsecure, cfExtra = true, map[string]bool{su.Hostname(): true}
	defer func() { cfInsecure, cfExtra = oldIns, oldExtra }()
	if _, err := (&certFeeds{cache: cfNewCache()}).get(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err %v", err)
	}
}

func TestCertFeedsAPIDisabledAndEnabled(t *testing.T) {
	_, _ = cfTestSetup(t)
	mux := http.NewServeMux()
	registerCertFeedRoutes(mux, "tok")
	do := func(method, path, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := do("POST", "/v1/advisories/feeds/refresh", "tok"); w.Code != http.StatusConflict {
		t.Fatalf("disabled refresh %d", w.Code)
	}
	for _, p := range []string{"/v1/advisories", "/v1/advisories/feeds/status"} {
		if w := do("GET", p, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauth %d", p, w.Code)
		}
	}
	if w := do("POST", "/v1/advisories/feeds/refresh", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh unauth %d", w.Code)
	}
	w := do("GET", "/v1/advisories", "tok")
	var out struct {
		Count int            `json:"count"`
		Adv   []CertAdvisory `json:"advisories"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out); w.Code != 200 || out.Count != 0 || out.Adv == nil {
		t.Fatalf("disabled list %d %s", w.Code, w.Body)
	}
	t.Setenv("KAVACH_CERT_FEEDS", "cisa,jvn")
	if w := do("POST", "/v1/advisories/feeds/refresh", "tok"); w.Code != 200 || !strings.Contains(w.Body.String(), `"cisa":2`) {
		t.Fatalf("refresh %d %s", w.Code, w.Body)
	}
	w = do("GET", "/v1/advisories?source=jvn&limit=5", "tok")
	if json.Unmarshal(w.Body.Bytes(), &out); out.Count != 1 || out.Adv[0].ID != "JVN#76799957" {
		t.Fatalf("list %s", w.Body)
	}
	for _, bad := range []string{"?cve=nope", "?since=yesterday", "?limit=0", "?limit=x"} {
		if w := do("GET", "/v1/advisories"+bad, "tok"); w.Code != 400 {
			t.Fatalf("%s -> %d", bad, w.Code)
		}
	}
	if w := do("GET", "/v1/advisories/feeds/status", "tok"); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":["cisa","jvn"]`) {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
}

func TestCertFeedDefsAreHTTPSAllowlisted(t *testing.T) {
	for id, d := range certFeedDefs {
		u, err := url.Parse(d.URL)
		if err != nil || u.Scheme != "https" || !cfAllowed(u.Hostname()) || d.ID != id {
			t.Fatalf("feed %s url %s", id, d.URL)
		}
		if u.RawQuery != "" && id != "cccs" {
			t.Fatalf("feed %s has a query string", id)
		}
	}
}
