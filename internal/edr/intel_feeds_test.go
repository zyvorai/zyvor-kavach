// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const intelTok = "0123456789abcdef"

func intelSetup(t *testing.T) (*httptest.Server, *IntelFeeds) {
	t.Helper()
	s, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	f := NewIntelFeeds(s)
	mux := http.NewServeMux()
	registerIntelRoutes(mux, intelTok, f)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func addFeed(t *testing.T, srv *httptest.Server, name, feedURL, format string) string {
	t.Helper()
	body := `{"name":"` + name + `","url":"` + feedURL + `","format":"` + format + `","interval":15,"tlp":"green"}`
	r, out := send(t, "POST", srv.URL+"/v1/intel/feeds", intelTok, body)
	if r.StatusCode != 201 {
		t.Fatalf("create: %d %s", r.StatusCode, out)
	}
	var fd IntelFeed
	_ = json.Unmarshal([]byte(out), &fd)
	t.Cleanup(func() { send(t, "DELETE", srv.URL+"/v1/intel/feeds?id="+fd.ID, intelTok, "") })
	return fd.ID
}

func hasIOC(value string) *IOC {
	iocMu.Lock()
	defer iocMu.Unlock()
	for _, i := range iocs {
		if i.Value == value {
			c := i
			return &c
		}
	}
	return nil
}

const h64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

func TestParseFormats(t *testing.T) {
	plain, err := parseFeed("plain", []byte("# c\n198.51.100.7\nbad.example.net  extra\n198.51.100.7\nnot an ioc\nhttp://x.example/p\n"+h64+"\n"))
	if err != nil || len(plain) != 4 {
		t.Fatalf("plain: %v %v", plain, err)
	}
	csvOut, err := parseFeed("csv", []byte("type,value,note\nip,198.51.100.8,x\ndomain,c2.example.org,y\n"))
	if err != nil || len(csvOut) != 2 || csvOut[0].typ != "ipv4" || csvOut[1].typ != "domain" {
		t.Fatalf("csv: %v %v", csvOut, err)
	}
	st, err := parseFeed("stix-lite-json", []byte(`{"objects":[
	 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.9']"},
	 {"type":"domain","value":"Stix.Example.com"},
	 {"type":"sha256","value":"`+h64+`"},
	 {"type":"url","value":"https://u.example/x"},
	 {"type":"domain","value":"stix.example.com"}]}`))
	if err != nil || len(st) != 4 {
		t.Fatalf("stix: %v %v", st, err)
	}
	arr, err := parseFeed("stix-lite-json", []byte(`[{"type":"ip","value":"2001:db8::1"}]`))
	if err != nil || len(arr) != 1 || arr[0].typ != "ipv6" {
		t.Fatalf("stix array: %v %v", arr, err)
	}
	if _, err := parseFeed("stix-lite-json", []byte("nope")); err == nil {
		t.Fatal("expected json error")
	}
}

func TestFeedFetchDedupeAnalystAndDelete(t *testing.T) {
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.21\n198.51.100.21\nfeed-a.example.net\nanalyst.example.net\n"))
	}))
	defer feedSrv.Close()
	srv, f := intelSetup(t)
	iocMu.Lock()
	iocs = append(iocs, IOC{ID: "ioc-analyst-x", Type: "domain", Value: "analyst.example.net", Source: "custom", Enabled: true})
	iocMu.Unlock()
	t.Cleanup(func() {
		iocMu.Lock()
		kept := iocs[:0]
		for _, i := range iocs {
			if i.ID != "ioc-analyst-x" {
				kept = append(kept, i)
			}
		}
		iocs = kept
		iocMu.Unlock()
	})
	id := addFeed(t, srv, "osint1", feedSrv.URL, "plain")
	st, ok := f.Fetch(context.Background(), id)
	if !ok || st.Status != "ok" || st.Added != 2 || st.Active != 2 {
		t.Fatalf("status: %+v", st)
	}
	if i := hasIOC("198.51.100.21"); i == nil || i.Source != "feed:osint1" || i.Action != "detect_only" || i.Type != "ipv4" {
		t.Fatalf("ioc: %+v", i)
	}
	if i := hasIOC("analyst.example.net"); i == nil || i.Source != "custom" {
		t.Fatalf("analyst ioc overwritten: %+v", i)
	}
	if len(MatchIOCs("connect to feed-a.example.net")) == 0 {
		t.Fatal("MatchIOCs should hit feed indicator")
	}
	// Refetch must not duplicate.
	st, _ = f.Fetch(context.Background(), id)
	if st.Added != 0 || st.Active != 2 {
		t.Fatalf("refetch: %+v", st)
	}
	r, _ := send(t, "DELETE", srv.URL+"/v1/intel/feeds?id="+id, intelTok, "")
	if r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	if hasIOC("198.51.100.21") != nil || hasIOC("feed-a.example.net") != nil {
		t.Fatal("feed indicators should be removed")
	}
	if hasIOC("analyst.example.net") == nil {
		t.Fatal("analyst ioc must survive feed deletion")
	}
}

func TestFeedExpiry(t *testing.T) {
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("exp-a.example.net\n"))
	}))
	defer feedSrv.Close()
	srv, f := intelSetup(t)
	id := addFeed(t, srv, "expiring", feedSrv.URL, "plain")
	base := time.Now().UTC()
	f.now = func() time.Time { return base }
	if st, _ := f.Fetch(context.Background(), id); st.Added != 1 {
		t.Fatalf("%+v", st)
	}
	f.now = func() time.Time { return base.Add(31 * 24 * time.Hour) }
	if n := f.sweep(id); n != 1 {
		t.Fatalf("sweep=%d", n)
	}
	if hasIOC("exp-a.example.net") != nil {
		t.Fatal("expired indicator still present")
	}
	var out struct{ Status []FeedStatus }
	_, body := send(t, "GET", srv.URL+"/v1/intel/feeds/status", intelTok, "")
	_ = json.Unmarshal([]byte(body), &out)
	if len(out.Status) != 1 || out.Status[0].Expired != 1 || out.Status[0].Active != 0 {
		t.Fatalf("status: %s", body)
	}
}

func TestFeedETag304(t *testing.T) {
	hits := 0
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("etag-a.example.net\n"))
	}))
	defer feedSrv.Close()
	srv, f := intelSetup(t)
	id := addFeed(t, srv, "etagfeed", feedSrv.URL, "plain")
	f.Fetch(context.Background(), id)
	st, _ := f.Fetch(context.Background(), id)
	if st.Status != "not_modified" || st.Active != 1 || hits != 2 {
		t.Fatalf("%+v hits=%d", st, hits)
	}
	if hasIOC("etag-a.example.net") == nil {
		t.Fatal("indicator lost on 304")
	}
}

func TestFeedOversizedAndRedirect(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("big-a.example.net\n", 100000)))
	}))
	defer big.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("redir-a.example.net\n"))
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()
	srv, f := intelSetup(t)
	bid := addFeed(t, srv, "bigfeed", big.URL, "plain")
	st, _ := f.Fetch(context.Background(), bid)
	if st.Status != "error" || !strings.Contains(st.Error, "1 MiB") || st.Active != 0 {
		t.Fatalf("%+v", st)
	}
	rid := addFeed(t, srv, "redirfeed", redir.URL, "plain")
	st, _ = f.Fetch(context.Background(), rid)
	if st.Status != "error" || !strings.Contains(st.Error, "redirect") || hasIOC("redir-a.example.net") != nil {
		t.Fatalf("%+v", st)
	}
}

func TestFeedSSRFAndValidation(t *testing.T) {
	srv, _ := intelSetup(t)
	for name, body := range map[string]string{
		"private":  `{"name":"a","url":"https://10.0.0.1/x","format":"plain"}`,
		"http":     `{"name":"b","url":"http://example.com/x","format":"plain"}`,
		"interval": `{"name":"c","url":"https://example.com/x","format":"plain","interval":5}`,
		"format":   `{"name":"d","url":"https://example.com/x","format":"xml"}`,
		"tlp":      `{"name":"e","url":"https://example.com/x","format":"plain","tlp":"pink"}`,
	} {
		if r, _ := send(t, "POST", srv.URL+"/v1/intel/feeds", intelTok, body); r.StatusCode != 400 {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
}

func TestIntelAuth(t *testing.T) {
	srv, _ := intelSetup(t)
	for _, c := range [][2]string{
		{"GET", "/v1/intel/feeds"}, {"GET", "/v1/intel/feeds/status"},
		{"POST", "/v1/intel/feeds"}, {"DELETE", "/v1/intel/feeds?id=x"}, {"POST", "/v1/intel/feeds/refresh?id=x"},
	} {
		if r, _ := send(t, c[0], srv.URL+c[1], "", ""); r.StatusCode != 401 && r.StatusCode != 403 {
			t.Errorf("%v unauthenticated: %d", c, r.StatusCode)
		}
	}
	if r, _ := send(t, "GET", srv.URL+"/v1/intel/feeds", intelTok, ""); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if r, _ := send(t, "POST", srv.URL+"/v1/intel/feeds/refresh?id=nope", intelTok, ""); r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
}
