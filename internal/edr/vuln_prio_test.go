package edr

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Table 9 of the CISA SSVC Guide, transcribed independently of the
// implementation: decision strings in row order 1..36.
var ssvcWant = []string{
	"Track", "Track", "Track", "Track", "Track", "Track*",
	"Track", "Track", "Attend", "Track", "Track", "Attend",
	"Track", "Track", "Track*", "Track", "Track*", "Attend",
	"Track", "Track", "Attend", "Track", "Track*", "Attend",
	"Track", "Track", "Attend", "Track", "Attend", "Act",
	"Attend", "Attend", "Act", "Attend", "Act", "Act",
}

func TestSSVCEveryLeaf(t *testing.T) {
	if len(ssvcTable) != 36 {
		t.Fatalf("rows %d", len(ssvcTable))
	}
	n := 0
	// Walk the full 3x2x2x3x3 = 108 input space; each must hit exactly one row.
	for _, e := range ssvcDomains["exploitation"] {
		for _, a := range ssvcDomains["automatable"] {
			for _, ti := range ssvcDomains["technical_impact"] {
				for _, m := range ssvcDomains["mission_prevalence"] {
					for _, w := range ssvcDomains["public_wellbeing"] {
						r := ssvcEvaluate(SSVCInput{e, a, ti, m, w})
						if len(r.Unknown) != 0 || r.Sensitive || r.BestCase != r.WorstCase || r.BestCase != r.Outcome {
							t.Fatalf("known input flagged unknown: %+v", r)
						}
						if r.Outcome != ssvcWant[r.Row-1] {
							t.Errorf("%s/%s/%s/%s/%s: row %d got %s want %s", e, a, ti, m, w, r.Row, r.Outcome, ssvcWant[r.Row-1])
						}
						n++
					}
				}
			}
		}
	}
	if n != 108 {
		t.Fatal(n)
	}
	for i, r := range ssvcTable {
		if r.N != i+1 || r.Decision != ssvcWant[i] {
			t.Errorf("row %d mismatch %+v", i+1, r)
		}
	}
	// Table 8 spot checks.
	for _, c := range [][3]string{{"minimal", "minimal", "low"}, {"support", "material", "medium"}, {"essential", "minimal", "high"}, {"minimal", "irreversible", "high"}} {
		if g := ssvcMissionWB(c[0], c[1]); g != c[2] {
			t.Errorf("table8 %v got %s", c, g)
		}
	}
}

func TestSSVCUnknownHandling(t *testing.T) {
	r := ssvcEvaluate(SSVCInput{})
	if len(r.Unknown) != 5 {
		t.Fatalf("unknown %v", r.Unknown)
	}
	// defaults none/no/partial/support/minimal -> row 2 Track
	if r.Outcome != "Track" || r.Row != 2 {
		t.Fatalf("default outcome %+v", r)
	}
	if r.BestCase != "Track" || r.WorstCase != "Act" || !r.Sensitive {
		t.Fatalf("range %+v", r)
	}
	// Invalid values are treated as unknown, not as a crash.
	r = ssvcEvaluate(SSVCInput{"bogus", "yes", "total", "essential", "irreversible"})
	if len(r.Unknown) != 1 || r.Unknown[0] != "exploitation" || r.BestCase != "Attend" || r.WorstCase != "Act" {
		t.Fatalf("%+v", r)
	}
	// Only active exploitation unknown-free + one unknown that cannot matter.
	r = ssvcEvaluate(SSVCInput{"active", "yes", "total", "essential", vpUnknown})
	if r.Outcome != "Act" || r.Sensitive {
		t.Fatalf("insensitive unknown flagged: %+v", r)
	}
}

func TestVPSortDeterministic(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	mk := func() []VPItem {
		return []VPItem{
			{CVE: "CVE-2024-0002", Host: "b", Outcome: "Track", CVSS: 9},
			{CVE: "CVE-2024-0001", Host: "a", Outcome: "Act", CVSS: 5},
			{CVE: "CVE-2024-0003", Host: "a", Outcome: "Track", CVSS: 9, EPSS: f(0.5)},
			{CVE: "CVE-2024-0002", Host: "a", Outcome: "Track", CVSS: 9},
			{CVE: "CVE-2024-0004", Host: "a", Outcome: "Track", CVSS: 3, EPSS: f(0.5)},
		}
	}
	a := mk()
	vpSort(a)
	want := []string{"CVE-2024-0001/a", "CVE-2024-0003/a", "CVE-2024-0004/a", "CVE-2024-0002/a", "CVE-2024-0002/b"}
	for i, it := range a {
		if g := it.CVE + "/" + it.Host; g != want[i] || it.Rank != i+1 {
			t.Fatalf("pos %d got %s rank %d want %s", i, g, it.Rank, want[i])
		}
	}
	// Reverse input order must give the identical result.
	b := mk()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	vpSort(b)
	for i := range a {
		if a[i].CVE != b[i].CVE || a[i].Host != b[i].Host {
			t.Fatalf("not deterministic at %d", i)
		}
	}
}

func TestVPParseVector(t *testing.T) {
	cases := []struct{ v, auto, tech string }{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "yes", "total"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "no", "partial"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "yes", "partial"},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", "yes", "total"},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/AU:N", "no", "partial"},
		{"", vpUnknown, vpUnknown},
		{"CVSS:3.1/AV:N", vpUnknown, vpUnknown},
		{"garbage", vpUnknown, vpUnknown},
		{"CVSS:2.0/AV:N", vpUnknown, vpUnknown},
	}
	for _, c := range cases {
		a, tc, _ := vpParseVector(c.v)
		if a != c.auto || tc != c.tech {
			t.Errorf("%q got %s/%s", c.v, a, tc)
		}
	}
}

func TestVPKEVPrecedence(t *testing.T) {
	old := vpEPSS
	vpEPSS = &vpEPSSFeed{cache: vpEPSSCache{Scores: map[string]vpEPSSScore{
		"CVE-2099-0001": {EPSS: 0.9, Percentile: 0.99}, "CVE-2099-0002": {EPSS: 0.01, Percentile: 0.2},
	}}}
	defer func() { vpEPSS = old }()

	in, _, _ := vpBuildFactors(VMFinding{CVE: "CVE-2099-0001", KnownExploited: true, KEVDateAdded: "2024-01-02"}, "", 0)
	if in.Exploitation != "active" {
		t.Fatalf("KEV must win: %s", in.Exploitation)
	}
	in, fs, _ := vpBuildFactors(VMFinding{CVE: "CVE-2099-0001"}, "", 0)
	if in.Exploitation != "poc" || fs[0].Source != "first-epss" {
		t.Fatalf("high EPSS -> poc: %+v", fs[0])
	}
	// Low EPSS must NOT become "none": stays unknown.
	in, fs, _ = vpBuildFactors(VMFinding{CVE: "CVE-2099-0002"}, "", 0)
	if in.Exploitation != vpUnknown || fs[0].Known {
		t.Fatalf("low EPSS must stay unknown: %+v", fs[0])
	}
	// KEV even with low EPSS.
	in, _, _ = vpBuildFactors(VMFinding{CVE: "CVE-2099-0002", KnownExploited: true}, "", 0)
	if in.Exploitation != "active" {
		t.Fatal("KEV with low EPSS")
	}
	// Mission mapping.
	for crit, want := range map[int]string{5: "essential", 4: "essential", 3: "support", 2: "minimal", 1: "minimal", 0: vpUnknown} {
		in, _, _ = vpBuildFactors(VMFinding{CVE: "CVE-2099-0009"}, "", crit)
		if in.MissionPrevalence != want {
			t.Errorf("crit %d got %s want %s", crit, in.MissionPrevalence, want)
		}
	}
}

func gzCSV(t *testing.T, body string) []byte {
	t.Helper()
	var sb strings.Builder
	zw := gzip.NewWriter(&sb)
	_, _ = zw.Write([]byte(body))
	_ = zw.Close()
	return []byte(sb.String())
}

const vpFeedBody = "#model_version:v2026.06.15,score_date:2026-11-12T12:00:25Z\ncve,epss,percentile\n" +
	"CVE-2023-38545,0.55000,0.97000\nCVE-2022-0778,0.02000,0.60000\nCVE-2000-0001,0.9,0.99\nBAD,x,y\n"

type vpRec struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []byte
}

func vpSetup(t *testing.T, rec *vpRec) (*http.ServeMux, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, r.Clone(r.Context()))
		rec.mu.Unlock()
		w.Write(rec.body)
	}))
	t.Cleanup(srv.Close)
	oldU, oldI, oldF := vpEPSSURL, vpEPSSInsecure, vpEPSS
	vpEPSSURL, vpEPSSInsecure = srv.URL+"/epss_scores-current.csv.gz", true
	vpEPSS = &vpEPSSFeed{cache: vpEPSSCache{Scores: map[string]vpEPSSScore{}}, started: true} // no background loop in tests
	t.Cleanup(func() { vpEPSSURL, vpEPSSInsecure, vpEPSS = oldU, oldI, oldF })
	vmOld := vmFeeds
	vmFeeds = &vulnFeeds{cache: vfNewCache()}
	t.Cleanup(func() { vmFeeds = vmOld })

	Live.ReplaceHost("sbom", "secret-host-xyz", []map[string]any{
		{"component": "curl", "version": "7.88.1", "host": "secret-host-xyz", "id": "a"},
		{"component": "openssl", "version": "1.1.1k", "host": "secret-host-xyz", "id": "b"},
	})
	t.Cleanup(func() { Live.ReplaceHost("sbom", "secret-host-xyz", nil) })

	dir := t.TempDir()
	store := &Store{path: filepath.Join(dir, "f.json")}
	posture := `{"assets":{"secret-host-xyz":{"host":"secret-host-xyz","criticality":5}}}`
	if err := os.WriteFile(store.path+".posture.json", []byte(posture), 0o600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterVulnPriority(mux, "tok-12345678", store)
	return mux, store.path
}

func vpGet(mux *http.ServeMux, method, p string, auth bool) (int, string) {
	req := httptest.NewRequest(method, p, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer tok-12345678")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestVPEndpointsFeedOff(t *testing.T) {
	t.Setenv("KAVACH_EPSS_FEED", "")
	rec := &vpRec{body: gzCSV(t, vpFeedBody)}
	mux, _ := vpSetup(t, rec)

	for _, p := range []string{"/v1/vulns/priority", "/v1/vulns/priority/status", "/v1/vulns/priority/CVE-2023-38545"} {
		if c, _ := vpGet(mux, "GET", p, false); c != 401 {
			t.Errorf("%s unauth: %d", p, c)
		}
	}
	if c, _ := vpGet(mux, "POST", "/v1/vulns/priority/refresh", false); c != 401 {
		t.Errorf("refresh unauth %d", c)
	}
	if c, b := vpGet(mux, "POST", "/v1/vulns/priority/refresh", true); c != 409 {
		t.Fatalf("refresh with feed off must be 409: %d %s", c, b)
	}
	if len(rec.reqs) != 0 {
		t.Fatal("feed off must make no network request")
	}
	c, b := vpGet(mux, "GET", "/v1/vulns/priority?host=secret-host-xyz&limit=10", true)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var out struct {
		Items []VPItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(b), &out); err != nil || len(out.Items) < 2 {
		t.Fatalf("items: %v %s", err, b)
	}
	for _, it := range out.Items {
		if it.EPSS != nil {
			t.Error("epss must be null when feed off")
		}
		unk := map[string]bool{}
		for _, f := range it.Factors {
			if !f.Known {
				unk[f.Name] = true
				if f.Assumed == "" {
					t.Errorf("unknown factor %s lacks assumed value", f.Name)
				}
			}
		}
		if !unk["exploitation"] || !unk["public_wellbeing"] || unk["mission_prevalence"] {
			t.Errorf("unknown markers: %v", unk)
		}
		if len(it.Explanation) < 6 {
			t.Errorf("explanation too short: %v", it.Explanation)
		}
	}
	if c, _ := vpGet(mux, "GET", "/v1/vulns/priority?limit=0", true); c != 400 {
		t.Errorf("limit=0 -> %d", c)
	}
	if c, _ := vpGet(mux, "GET", "/v1/vulns/priority/not-a-cve", true); c != 400 {
		t.Errorf("bad cve -> %d", c)
	}
	if c, _ := vpGet(mux, "GET", "/v1/vulns/priority/CVE-2000-9999", true); c != 404 {
		t.Errorf("unmatched cve -> %d", c)
	}
	if c, b := vpGet(mux, "GET", "/v1/vulns/priority/cve-2023-38545", true); c != 200 || !strings.Contains(b, `"top_outcome"`) {
		t.Errorf("cve detail %d %s", c, b)
	}
	if c, b := vpGet(mux, "GET", "/v1/vulns/priority/status", true); c != 200 || !strings.Contains(b, ssvcTreeVersion) || !strings.Contains(b, "limitations") {
		t.Errorf("status %d %s", c, b)
	}
	// Existing endpoint untouched.
	vm := http.NewServeMux()
	RegisterVulnMgmt(vm, "tok-12345678")
	if c, _ := vpGet(vm, "GET", "/v1/vulns/top", true); c != 200 {
		t.Errorf("/v1/vulns/top %d", c)
	}
}

func TestVPEPSSFeedOnNoInventoryLeak(t *testing.T) {
	t.Setenv("KAVACH_EPSS_FEED", "on")
	rec := &vpRec{body: gzCSV(t, vpFeedBody)}
	mux, storePath := vpSetup(t, rec)
	vpEPSS.wanted = nil // RegisterVulnPriority set it on the old feed; rebind below
	vpEPSS.wanted = func() map[string]bool {
		w := map[string]bool{}
		finds, _ := vmFindings(vmPackages(""))
		for _, f := range finds {
			w[f.CVE] = true
		}
		return w
	}

	c, b := vpGet(mux, "POST", "/v1/vulns/priority/refresh", true)
	if c != 200 {
		t.Fatalf("refresh %d %s", c, b)
	}
	if len(rec.reqs) != 1 {
		t.Fatalf("requests %d", len(rec.reqs))
	}
	r := rec.reqs[0]
	dump := r.Method + " " + r.URL.String() + fmt.Sprint(r.Header) + r.Host
	for _, secret := range []string{"secret-host-xyz", "curl", "openssl", "7.88.1", "CVE-2023", "CVE-2022"} {
		if strings.Contains(dump, secret) {
			t.Errorf("request leaked %q: %s", secret, dump)
		}
	}
	if r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength > 0 {
		t.Errorf("must be a bare GET: %s q=%q len=%d", r.Method, r.URL.RawQuery, r.ContentLength)
	}
	if got := r.Header.Get("User-Agent"); got != "kavach-epss-feed" {
		t.Errorf("UA %q", got)
	}
	if len(r.Header.Values("Authorization"))+len(r.Header.Values("Cookie")) != 0 {
		t.Error("no credentials may be sent")
	}

	// Filtered cache: only matched CVEs kept (not CVE-2000-0001), on disk too.
	if _, ok := vpEPSS.Lookup("CVE-2000-0001"); ok {
		t.Error("unmatched CVE must not be cached")
	}
	if s, ok := vpEPSS.Lookup("cve-2023-38545"); !ok || s.EPSS != 0.55 {
		t.Fatalf("lookup %+v %v", s, ok)
	}
	if st := vpEPSS.Status(); st["model_version"] != "v2026.06.15" || st["score_date"] != "2026-11-12T12:00:25Z" {
		t.Errorf("status %v", st)
	}
	if _, err := os.Stat(storePath + ".epss.json"); err != nil {
		t.Errorf("cache file: %v", err)
	}

	// 0.55 >= threshold: curl CVE becomes poc; 0.02 stays unknown.
	_, b = vpGet(mux, "GET", "/v1/vulns/priority?host=secret-host-xyz", true)
	var out struct {
		Items []VPItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(b), &out); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, it := range out.Items {
		seen[it.CVE] = it.Factors[0].Value
		if it.CVE == "CVE-2023-38545" && (it.EPSS == nil || *it.EPSS != 0.55) {
			t.Errorf("epss not surfaced: %+v", it)
		}
	}
	if seen["CVE-2023-38545"] != "poc" || seen["CVE-2022-0778"] != vpUnknown {
		t.Errorf("exploitation values %v", seen)
	}
	if out.Items[0].CVE != "CVE-2023-38545" {
		t.Errorf("highest EPSS/outcome should rank first: %s", out.Items[0].CVE)
	}

	// Cache reload from disk.
	vpEPSS.cache = vpEPSSCache{Scores: map[string]vpEPSSScore{}}
	SetEPSSCachePath(storePath + ".epss.json")
	if _, ok := vpEPSS.Lookup("CVE-2023-38545"); !ok {
		t.Error("cache not reloaded")
	}
}

func TestVPEPSSBlockedHostAndLimits(t *testing.T) {
	old := vpEPSSInsecure
	vpEPSSInsecure = false
	defer func() { vpEPSSInsecure = old }()
	f := &vpEPSSFeed{cache: vpEPSSCache{Scores: map[string]vpEPSSScore{}}}
	oldU := vpEPSSURL
	defer func() { vpEPSSURL = oldU }()
	for _, u := range []string{"http://epss.empiricalsecurity.com/x.csv.gz", "https://evil.example.com/x.csv.gz"} {
		vpEPSSURL = u
		if err := f.refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("%s: %v", u, err)
		}
	}
	// Garbage body and empty feed produce errors, not panics.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not gzip")) }))
	defer srv.Close()
	vpEPSSInsecure, vpEPSSURL = true, srv.URL
	if err := f.refresh(t.Context()); err == nil {
		t.Error("expected gzip error")
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzCSV(t, "#model_version:v1\ncve,epss,percentile\n"))
	}))
	defer srv2.Close()
	vpEPSSURL = srv2.URL
	if err := f.refresh(t.Context()); err == nil {
		t.Error("expected no-rows error")
	}
	// Redirect to a non-allowlisted host is blocked once the insecure flag is off.
	if !vpEPSSHosts["epss.empiricalsecurity.com"] || len(vpEPSSHosts) != 1 {
		t.Error("allowlist must be exactly epss.empiricalsecurity.com")
	}
}
