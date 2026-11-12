package edr

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMCmpVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"1.1.1k", "1.1.1n", -1}, {"8.4.0", "8.4.0", 0}, {"8.10", "8.4.0", 1}, {"1:9.2p1-4", "9.8", -1}}
	for _, c := range cases {
		if got := vmCmpVersion(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVulnMgmtEndpoints(t *testing.T) {
	Live.ReplaceHost("sbom", "vm-h1", []map[string]any{
		{"component": "curl", "version": "7.88.1", "id": "a"},
		{"component": "bash", "version": "5.2", "id": "b"},
	})
	mux := http.NewServeMux()
	RegisterVulnMgmt(mux, "tok-12345678")
	get := func(p string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer tok-12345678")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	for _, p := range []string{"/v1/vulns/software", "/v1/vulns/advisories", "/v1/vulns/findings", "/v1/vulns/exposure", "/v1/vulns/top"} {
		if c, _ := get(p); c != 200 {
			t.Fatalf("%s: %d", p, c)
		}
	}
	if _, b := get("/v1/vulns/findings?host=vm-h1"); !strings.Contains(b, "CVE-2023-38545") {
		t.Fatalf("expected curl CVE: %s", b)
	}
	if _, b := get("/v1/sbom/vm-h1"); !strings.Contains(b, "CycloneDX") || !strings.Contains(b, "pkg:generic/curl@7.88.1") {
		t.Fatalf("bad sbom: %s", b)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/vulns/top", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("expected auth required")
	}
}

func TestVMCVEFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(`[{"cve":"CVE-X","package":"bash","fixed_in":"6.0","cvss":5}]`), 0o600)
	t.Setenv("KAVACH_CVE_FILE", p)
	a, src := vmLoadAdvisories()
	if len(a) != 1 || !strings.HasPrefix(src, "file:") {
		t.Fatal(a, src)
	}
}
