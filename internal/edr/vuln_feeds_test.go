package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vfTestSetup(t *testing.T, handler http.Handler) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	oldK, oldO, oldI := vfKEVURL, vfOSVBase, vfInsecure
	vfKEVURL, vfOSVBase, vfInsecure = srv.URL+"/kev.json", srv.URL, true
	oldF := vmFeeds
	vmFeeds = &vulnFeeds{cache: vfNewCache()}
	SetVulnCachePath(filepath.Join(t.TempDir(), "x.vulncache.json"))
	t.Cleanup(func() { vfKEVURL, vfOSVBase, vfInsecure, vmFeeds = oldK, oldO, oldI, oldF })
	Live.ReplaceHost("sbom", "h1", []map[string]any{
		{"component": "libfoo", "version": "1.0", "host": "h1", "ecosystem": "dpkg"},
		{"component": "leftpad", "version": "2.0", "host": "h1", "ecosystem": "npm"},
	})
	t.Cleanup(func() { Live.ReplaceHost("sbom", "h1", nil) })
}

func fakeFeeds() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2099-0001","dateAdded":"2024-01-02"}]}`))
	})
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		json.NewDecoder(r.Body).Decode(&q)
		res := []map[string]any{}
		for _, x := range q.Queries {
			if x.Package.Name == "libfoo" && x.Package.Ecosystem == "Debian" {
				res = append(res, map[string]any{"vulns": []map[string]any{{"id": "DSA-1"}}})
			} else {
				res = append(res, map[string]any{})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	})
	mux.HandleFunc("/v1/vulns/DSA-1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"DSA-1","aliases":["CVE-2099-0001"],"summary":"bad","database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"name":"libfoo"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.5"}]}]}]}`))
	})
	return mux
}

func TestVulnFeedsKEVAndOSV(t *testing.T) {
	vfTestSetup(t, fakeFeeds())
	t.Setenv("KAVACH_VULN_FEED", "kev,osv")
	st := vmFeeds.Refresh(context.Background())
	if len(st.FeedErrors) != 0 || st.KEVCount != 1 || st.OSVVulns != 1 {
		t.Fatalf("status %+v", st)
	}
	f, status := vmFindings(vmPackages("h1"))
	var got *VMFinding
	for i := range f {
		if f[i].CVE == "CVE-2099-0001" {
			got = &f[i]
		}
	}
	if got == nil || !got.KnownExploited || got.FixedIn != "1.5" || got.CVSS != 8.0 || got.Source != "osv" {
		t.Fatalf("finding %+v", f)
	}
	if status["source"] != "feeds:kev,osv" {
		t.Fatalf("status %v", status)
	}
	if vmExposure([]VMFinding{{CVSS: 5}}) >= vmExposure([]VMFinding{{CVSS: 5, KnownExploited: true}}) {
		t.Fatal("kev should boost exposure")
	}
	// cache persisted
	b, err := os.ReadFile(vmFeeds.cachePath)
	if err != nil || !strings.Contains(string(b), "DSA-1") {
		t.Fatalf("cache not written: %v", err)
	}
}

func TestVulnFeedsParseErrorReported(t *testing.T) {
	vfTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) }))
	t.Setenv("KAVACH_VULN_FEED", "kev")
	st := vmFeeds.Refresh(context.Background())
	if len(st.FeedErrors) == 0 || !strings.Contains(st.FeedErrors[0], "kev") {
		t.Fatalf("expected kev error, got %+v", st)
	}
}

func TestVulnFeedsDisabledByDefault(t *testing.T) {
	vfTestSetup(t, fakeFeeds())
	t.Setenv("KAVACH_VULN_FEED", "")
	_, st := vmFindings(vmPackages("h1"))
	if st["source"] != "embedded-sample" {
		t.Fatalf("%v", st)
	}
	mux := http.NewServeMux()
	registerVulnFeedRoutes(mux, "tok")
	req := httptest.NewRequest("POST", "/v1/vulns/feeds/refresh", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("code %d", w.Code)
	}
	req = httptest.NewRequest("POST", "/v1/vulns/feeds/refresh", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", w.Code)
	}
}

func TestVulnCVEFileParseErrorNotSilent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte("{nope"), 0o600)
	t.Setenv("KAVACH_CVE_FILE", p)
	_, status := vmFindings(nil)
	errs, _ := status["feed_errors"].([]string)
	if len(errs) == 0 || !strings.Contains(errs[len(errs)-1], "KAVACH_CVE_FILE") {
		t.Fatalf("%v", status)
	}
}

func TestVulnFeedsBlocksNonAllowlisted(t *testing.T) {
	vfInsecure = false
	f := &vulnFeeds{cache: vfNewCache()}
	if _, err := f.do(context.Background(), "GET", "http://127.0.0.1:1/x", nil, 100); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("err %v", err)
	}
	if _, err := f.do(context.Background(), "GET", "https://evil.example/x", nil, 100); err == nil {
		t.Fatal("expected block")
	}
}

func TestVulnFeedsSizeLimit(t *testing.T) {
	vfTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 500)) }))
	if _, err := vmFeeds.do(context.Background(), "GET", vfKEVURL, nil, 100); err == nil {
		t.Fatal("expected size error")
	}
}

func TestVfEcosystem(t *testing.T) {
	for in, want := range map[string]string{"pip": "PyPI", "npm": "npm", "go": "Go", "apk": "Alpine", "rpm": "Rocky Linux", "weird": ""} {
		if g := vfEcosystem(map[string]any{"ecosystem": in}); g != want {
			t.Errorf("%s: %q", in, g)
		}
	}
}
