// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	h256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h256b = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	hMD5  = "d41d8cd98f00b204e9800998ecf8427e"
)

func iocTestSetup(t *testing.T) (http.Handler, string) {
	t.Helper()
	iocMu.Lock()
	saved, savedPath := iocs, iocPath
	iocLastSave = time.Now()
	iocs = []IOC{}
	iocMu.Unlock()
	t.Cleanup(func() {
		iocMu.Lock()
		iocs, iocPath, iocDirty = saved, savedPath, false
		iocMu.Unlock()
	})
	path := filepath.Join(t.TempDir(), "f.jsonl")
	s, err := testStore(t, path, 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterIOC(mux, evTok, s)
	return mux, path
}

func iocDo(h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		r.Header.Set("Authorization", "Bearer "+evTok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestParseSTIXPattern(t *testing.T) {
	good := map[string][]IOCValue{
		"[file:hashes.'SHA-256' = '" + strings.ToUpper(h256) + "']":            {{"sha256", h256}},
		"[file:hashes.MD5 = '" + hMD5 + "']":                                   {{"md5", hMD5}},
		"[ipv4-addr:value = '203.0.113.9']":                                    {{"ipv4", "203.0.113.9"}},
		"[ipv6-addr:value = '2001:db8::1']":                                    {{"ipv6", "2001:db8::1"}},
		"[domain-name:value = 'Evil.Example.']":                                {{"domain", "evil.example"}},
		"[url:value = 'http://evil.example/a?b=1']":                            {{"url", "http://evil.example/a?b=1"}},
		"[email-addr:value = 'Bad@evil.example']":                              {{"email", "bad@evil.example"}},
		"[domain-name:value = 'a.example' OR domain-name:value = 'b.example']": {{"domain", "a.example"}, {"domain", "b.example"}},
		"[url:value = 'http://x.example/it\\'s']":                              {{"url", "http://x.example/it's"}},
	}
	for p, want := range good {
		got, err := ParseSTIXPattern(p)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%q: %v %v", p, got, err)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: got %v want %v", p, got[i], want[i])
			}
		}
	}
	bad := []string{
		"", "[", "]", "[]", "domain-name:value = 'a.example'",
		"[domain-name:value = 'a.example' AND ipv4-addr:value = '1.2.3.4']",
		"[domain-name:value = 'a.example'] FOLLOWEDBY [ipv4-addr:value = '1.2.3.4']",
		"[domain-name:value = 'a.example'] WITHIN 5 SECONDS",
		"[domain-name:value = 'a.example'] REPEATS 2 TIMES",
		"[domain-name:value LIKE '%.example']", "[file:name MATCHES '.*']", "[ipv4-addr:value ISSUBSET '10.0.0.0/8']",
		"[ipv4-addr:value = '10.0.0.0/8']", "[domain-name:value NOT = 'a.example']", "[NOT domain-name:value = 'a.example']",
		"[ipv4-addr:value != '1.2.3.4']", "[ipv4-addr:value IN ('1.2.3.4')]", "[(ipv4-addr:value = '1.2.3.4')]",
		"[file:hashes.'SHA-512' = '" + h256 + "']", "[file:hashes.MD5 = '" + h256 + "']",
		"[process:name = 'x']", "[ipv4-addr:value = '999.1.1.1']", "[ipv4-addr:value = '::1']",
		"[domain-name:value = 'a.example", "[domain-name:value = 'a\\x.example']", "[domain-name:value = 'localhost']",
		"[url:value = 'javascript:alert(1)']", "[url:value = 'http://x y.example']", "[email-addr:value = 'a@b@c.example']",
		"[ipv4-addr:value = '1.2.3.4'] [ipv4-addr:value = '1.2.3.5']", "[ipv4-addr:value = '1.2.3.4' OR]",
		"[ipv4-addr:value = '1.2.3.4']]", "[ipv4-addr:value = \"1.2.3.4\"]", "[ipv4-addr:value = '1.2.3.4\x00']",
	}
	for _, p := range bad {
		if v, err := ParseSTIXPattern(p); err == nil {
			t.Errorf("%q should be rejected, got %v", p, v)
		}
	}
}

func TestParseSTIXPatternHostile(t *testing.T) {
	start := time.Now()
	for _, p := range []string{
		strings.Repeat("[", 100000),
		"[" + strings.Repeat("ipv4-addr:value = '1.2.3.4' OR ", 5000) + "ipv4-addr:value = '1.2.3.4']",
		"[domain-name:value = '" + strings.Repeat("a", 1<<20) + "']",
		"[domain-name:value = '" + strings.Repeat("\\'", 100000) + "']",
		strings.Repeat("(", 1<<16),
	} {
		if _, err := ParseSTIXPattern(p); err == nil {
			t.Error("hostile pattern accepted")
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("hostile patterns too slow: %v", time.Since(start))
	}
}

const stixFixture = `{"type":"bundle","id":"bundle--1","objects":[
 {"type":"marking-definition","id":"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82","definition_type":"tlp","definition":{"tlp":"amber"}},
 {"type":"identity","id":"identity--1","name":"x"},
 {"type":"indicator","id":"indicator--1","pattern_type":"stix","pattern":"[domain-name:value = 'c2.evil.example']","valid_from":"2026-01-01T00:00:00Z","valid_until":"2099-01-01T00:00:00Z","object_marking_refs":["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],"confidence":90,"name":"C2"},
 {"type":"indicator","id":"indicator--2","pattern_type":"stix","pattern":"[file:hashes.'SHA-256' = '` + h256b + `' OR ipv4-addr:value = '198.51.100.7']","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"indicator","id":"indicator--3","pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.8' AND domain-name:value = 'x.example']","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"indicator","id":"indicator--4","pattern_type":"sigma","pattern":"title: x"},
 {"type":"indicator","id":"indicator--5","pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.9']","valid_until":"2001-01-01T00:00:00Z"},
 {"type":"indicator","id":"indicator--6","pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.10']","revoked":true},
 {"type":"indicator","id":"indicator--7","pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.11']","valid_until":"not-a-date"}
]}`

func TestIOCImportSTIXDryRunThenApply(t *testing.T) {
	h, _ := iocTestSetup(t)
	w := iocDo(h, "POST", "/v1/ioc/import", stixFixture, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rep struct {
		DryRun  bool           `json:"dry_run"`
		Format  string         `json:"format"`
		Ignored int            `json:"ignored_objects"`
		Summary map[string]int `json:"summary"`
		Items   []iocImportItem
	}
	json.Unmarshal(w.Body.Bytes(), &rep)
	if !rep.DryRun || rep.Format != "stix" || rep.Ignored != 2 || rep.Summary["valid"] != 3 || rep.Summary["rejected"] != 5 {
		t.Fatalf("unexpected report: %s", w.Body.String())
	}
	reasons := ""
	for _, it := range rep.Items {
		reasons += it.Reason + "|"
	}
	for _, want := range []string{"AND", "pattern_type", "already expired", "revoked", "valid_until"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("missing rejection reason %q in %s", want, reasons)
		}
	}
	iocMu.Lock()
	n := len(iocs)
	iocMu.Unlock()
	if n != 0 {
		t.Fatalf("dry run stored %d iocs", n)
	}
	w = iocDo(h, "POST", "/v1/ioc/import?dry_run=false&source=feedA", stixFixture, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	iocMu.Lock()
	defer iocMu.Unlock()
	if len(iocs) != 3 {
		t.Fatalf("stored %d", len(iocs))
	}
	c2 := iocs[0]
	if c2.Value != "c2.evil.example" || c2.TLP != "amber" || c2.Source != "feedA" || c2.Severity != "high" || c2.Action != "detect_only" ||
		c2.ValidFrom == nil || c2.ValidUntil == nil || c2.ValidUntil.Year() != 2099 {
		t.Errorf("bad imported ioc: %+v", c2)
	}
	if iocs[1].ValidUntil == nil { // default TTL applied
		t.Errorf("default expiry not applied")
	}
}

func TestIOCImportAdminOnlyAndLimits(t *testing.T) {
	h, _ := iocTestSetup(t)
	if w := iocDo(h, "POST", "/v1/ioc/import", "1.2.3.4", false); w.Code != 401 {
		t.Errorf("unauthenticated: %d", w.Code)
	}
	if w := iocDo(h, "GET", "/v1/ioc/stats", "", false); w.Code != 401 {
		t.Errorf("stats unauthenticated: %d", w.Code)
	}
	if w := iocDo(h, "POST", "/v1/ioc/import", strings.Repeat("a", iocImportMaxBytes+1), true); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d", w.Code)
	}
	var sb strings.Builder
	for i := 0; i < iocImportMaxItems+1; i++ {
		sb.WriteString("10.0.")
		sb.WriteString(strings.Repeat("1", 1))
		sb.WriteString(".1\n")
	}
	if w := iocDo(h, "POST", "/v1/ioc/import?format=txt", sb.String(), true); w.Code != 400 {
		t.Errorf("item cap: %d %s", w.Code, w.Body.String()[:80])
	}
	if w := iocDo(h, "POST", "/v1/ioc/import?source=bad%20name", "1.2.3.4", true); w.Code != 400 {
		t.Errorf("bad source: %d", w.Code)
	}
	if w := iocDo(h, "POST", "/v1/ioc/import?dry_run=maybe", "1.2.3.4", true); w.Code != 400 {
		t.Errorf("bad dry_run: %d", w.Code)
	}
	if w := iocDo(h, "POST", "/v1/ioc/import?format=yaml", "1.2.3.4", true); w.Code != 400 {
		t.Errorf("bad format: %d", w.Code)
	}
	if w := iocDo(h, "POST", "/v1/ioc/import", `{"type":"bundle","objects":[`, true); w.Code != 400 {
		t.Errorf("truncated json: %d", w.Code)
	}
}

func TestIOCImportMISP(t *testing.T) {
	h, _ := iocTestSetup(t)
	body := `{"response":[{"Event":{"info":"campaign","uuid":"e1","Tag":[{"name":"tlp:green"},{"name":"misc:x"}],"Attribute":[
	 {"type":"domain","value":"m.evil.example","to_ids":true},
	 {"type":"ip-dst","value":"2001:db8::5","to_ids":"1"},
	 {"type":"filename|sha256","value":"a.exe|` + h256b + `","to_ids":true,"Tag":[{"name":"tlp:red"}]},
	 {"type":"md5","value":"` + hMD5 + `","to_ids":false},
	 {"type":"yara","value":"rule x {}","to_ids":true},
	 {"type":"url","value":"hxxp://evil[.]example","to_ids":true},
	 {"type":"domain","value":"gone.example","to_ids":true,"deleted":true},
	 {"type":"ip-src","value":"not-an-ip","to_ids":true},
	 {"type":"sha1","value":"` + strings.Repeat("a", 40) + `","to_ids":true,"Tag":[{"name":"tlp:purple"}]}],
	 "Object":[{"Attribute":[{"type":"email-src","value":"Phish@Evil.example","to_ids":true}]}]}}]}`
	w := iocDo(h, "POST", "/v1/ioc/import?dry_run=false", body, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rep struct {
		Format  string
		Summary map[string]int
	}
	json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.Format != "misp" || rep.Summary["imported"] != 4 || rep.Summary["rejected"] != 6 {
		t.Fatalf("%s", w.Body.String())
	}
	iocMu.Lock()
	defer iocMu.Unlock()
	for _, i := range iocs {
		if i.Type == "sha256" && i.TLP != "red" || i.Type == "domain" && i.TLP != "green" {
			t.Errorf("TLP not carried: %+v", i)
		}
	}
}

func TestIOCImportCSVAndTXT(t *testing.T) {
	h, _ := iocTestSetup(t)
	csvBody := "# comment\nvalue,type,tlp,valid_until,severity\n" +
		"198.51.100.1,,amber,2099-01-01T00:00:00Z,high\n" +
		"http://x.example/a,b,c,url,clear,,low\n" +
		"bad value,,,,\n" +
		"198.51.100.2,,mauve,,\n" +
		"198.51.100.3,,,2001-01-01T00:00:00Z,\n"
	w := iocDo(h, "POST", "/v1/ioc/import?dry_run=false&format=csv", csvBody, true)
	var rep struct {
		Summary map[string]int
	}
	json.Unmarshal(w.Body.Bytes(), &rep)
	if w.Code != 200 || rep.Summary["imported"] != 1 || rep.Summary["rejected"] != 4 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	txt := "# list\n" + h256 + "\n" + hMD5 + "\n203.0.113.20\nevil.example\nhttp://a.example/x,y\n\n203.0.113.20\n10.0.0.0/8\nhxxp://evil[.]example\n"
	w = iocDo(h, "POST", "/v1/ioc/import?dry_run=false&source=list1", txt, true)
	json.Unmarshal(w.Body.Bytes(), &rep)
	if w.Code != 200 || rep.Summary["imported"] != 5 || rep.Summary["duplicate"] != 1 || rep.Summary["rejected"] != 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Re-import refreshes instead of duplicating.
	w = iocDo(h, "POST", "/v1/ioc/import?dry_run=false&source=list1", "203.0.113.20\n", true)
	json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.Summary["updated"] != 1 {
		t.Fatalf("%s", w.Body.String())
	}
}

func TestIOCExpiryStopsMatchingAndSightings(t *testing.T) {
	h, path := iocTestSetup(t)
	t.Setenv("KAVACH_IOC_SOURCE_TTL_DAYS", "shortlived=1")
	iocDo(h, "POST", "/v1/ioc/import?dry_run=false&source=shortlived", "evil1.example\n", true)
	iocDo(h, "POST", "/v1/ioc/import?dry_run=false&source=other", "evil2.example\n", true)
	iocMu.Lock()
	var short *IOC
	for k := range iocs {
		if iocs[k].Source == "shortlived" {
			short = &iocs[k]
		}
	}
	if short == nil || short.ValidUntil == nil || short.ValidUntil.After(time.Now().Add(25*time.Hour)) {
		iocMu.Unlock()
		t.Fatalf("per-source ttl not applied: %+v", short)
	}
	iocMu.Unlock()
	if m := MatchIOCs("connect evil1.example and evil2.example"); len(m) != 2 {
		t.Fatalf("matches %d", len(m))
	}
	MatchIOCs("evil2.example")
	// Age the short-lived one.
	iocMu.Lock()
	past := time.Now().Add(-time.Hour)
	short.ValidUntil = &past
	iocMu.Unlock()
	m := MatchIOCs("evil1.example evil2.example")
	if len(m) != 1 || m[0].Value != "evil2.example" || m[0].Sightings != 3 {
		t.Fatalf("expired still matching or counter wrong: %+v", m)
	}
	w := iocDo(h, "GET", "/v1/ioc/stats", "", true)
	var st struct {
		Total, Active, Expired int
		Sightings              int                      `json:"sightings_total"`
		BySource               map[string]iocSourceStat `json:"by_source"`
		ByTLP                  map[string]int           `json:"by_tlp"`
		ByType                 map[string]int           `json:"by_type"`
	}
	json.Unmarshal(w.Body.Bytes(), &st)
	if st.Total != 2 || st.Active != 1 || st.Expired != 1 || st.BySource["shortlived"].Expired != 1 || st.BySource["other"].Sightings != 3 || st.ByTLP["unmarked"] != 2 || st.ByType["domain"] != 2 {
		t.Fatalf("stats: %s", w.Body.String())
	}
	// Retained and persisted for audit, including the counter.
	iocSave()
	b, err := os.ReadFile(path + ".iocimport.json")
	if err != nil || !strings.Contains(string(b), "evil1.example") || !strings.Contains(string(b), `"sightings": 3`) {
		t.Fatalf("state file: %v %s", err, b)
	}
	if fi, _ := os.Stat(path + ".iocimport.json"); fi.Mode().Perm() != 0600 {
		t.Errorf("mode %v", fi.Mode())
	}
	// Reload into a clean slate.
	iocMu.Lock()
	iocs = []IOC{}
	iocMu.Unlock()
	iocLoad(path + ".iocimport.json")
	iocMu.Lock()
	defer iocMu.Unlock()
	if len(iocs) != 2 {
		t.Fatalf("reloaded %d", len(iocs))
	}
}

func TestIOCNotYetValidDoesNotMatch(t *testing.T) {
	iocTestSetup(t)
	f := time.Now().Add(time.Hour)
	iocMu.Lock()
	iocs = append(iocs, IOC{ID: "x", Type: "domain", Value: "future.example", Enabled: true, ValidFrom: &f})
	iocMu.Unlock()
	if m := MatchIOCs("future.example"); len(m) != 0 {
		t.Fatal("not-yet-valid indicator matched")
	}
}

func TestIOCImportHostileJSON(t *testing.T) {
	h, _ := iocTestSetup(t)
	for _, b := range []string{
		strings.Repeat("[", 50000), `{"type":"bundle","objects":"x"}`, `{"type":"bundle","objects":[null,1,"a",[],{"type":"indicator"}]}`,
		`{"Event":{"Attribute":"x"}}`, `{"Event":null}`, `{"response":[null,{}]}`, "\x00\x01\x02", `{"type":"bundle","objects":[{"type":"indicator","pattern_type":"stix","pattern":"` + strings.Repeat(`\u0000`, 5000) + `"}]}`,
	} {
		w := iocDo(h, "POST", "/v1/ioc/import", b, true)
		if w.Code != 200 && w.Code != 400 {
			t.Errorf("%.30q: status %d", b, w.Code)
		}
	}
}

func FuzzParseSTIXPattern(f *testing.F) {
	for _, s := range []string{"[ipv4-addr:value = '1.2.3.4']", "[file:hashes.'SHA-256' = '" + h256 + "']", "[a:b = 'c' OR d:e = 'f']", "[[", "'", "\\'"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		vals, err := ParseSTIXPattern(p)
		if err != nil {
			return
		}
		if len(vals) == 0 {
			t.Fatal("success with no values")
		}
		for _, v := range vals {
			n, err := NormalizeIOCValue(v.Type, v.Value)
			if err != nil || n != v.Value {
				t.Fatalf("accepted value %v is not canonical/valid (%q, %v)", v, n, err)
			}
		}
	})
}
