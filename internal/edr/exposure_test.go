// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func expFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "exposure", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func expServer(t *testing.T) (*http.ServeMux, *Store) {
	t.Helper()
	store := newTestStore(t)
	mux := http.NewServeMux()
	RegisterExposure(mux, "tok", store)
	return mux, store
}

func expDo(mux *http.ServeMux, method, path, tok string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestExpParsePURL(t *testing.T) {
	k, v, typ, ok := expParsePURL("pkg:npm/%40Scope/Pkg@1.2.3?arch=x#sub")
	if !ok || k != "npm/@scope/pkg" || v != "1.2.3" || typ != "npm" {
		t.Fatalf("%q %q %q %v", k, v, typ, ok)
	}
	if k, _, _, _ := expParsePURL("pkg:pypi/Foo_Bar@1"); k != "pypi/foo-bar" {
		t.Fatal(k)
	}
	if _, _, _, ok := expParsePURL("npm/lodash"); ok {
		t.Fatal("must require pkg:")
	}
}

func TestExpParseSBOMs(t *testing.T) {
	cdx, err := ExpParseSBOM(expFixture(t, "cyclonedx.json"))
	if err != nil || cdx.Format != "cyclonedx" || len(cdx.Components) != 4 {
		t.Fatalf("%v %+v", err, cdx)
	}
	if cdx.Components[0].Name != "org.apache.logging.log4j/log4j-core" {
		t.Fatal(cdx.Components[0])
	}
	b, _ := json.Marshal(cdx)
	if strings.Contains(string(b), "aaaa") || strings.Contains(string(b), "Apache-2.0") {
		t.Fatal("hashes/licences must not be retained")
	}
	sp, err := ExpParseSBOM(expFixture(t, "spdx.json"))
	if err != nil || sp.Format != "spdx" || len(sp.Components) != 3 || sp.Components[0].PURL == "" {
		t.Fatalf("%v %+v", err, sp)
	}
	if _, err := ExpParseSBOM([]byte(`{"hello":1}`)); err == nil {
		t.Fatal("unknown format must fail")
	}
	if _, err := ExpParseSBOM([]byte(`nope`)); err == nil {
		t.Fatal("invalid json must fail")
	}
}

func TestExpAffectedRanges(t *testing.T) {
	a := ExpAdvisory{Ranges: []ExpRange{{Introduced: "2.0-beta9", Fixed: "2.15.0"}}}
	for v, want := range map[string]bool{"2.14.1": true, "2.15.0": false, "2.16.0": false, "1.2.17": false} {
		got, det := expAffected("maven", a, v)
		if !det || got != want {
			t.Errorf("maven %s: got %v det %v", v, got, det)
		}
	}
	l := ExpAdvisory{Ranges: []ExpRange{{Introduced: "4.17.0", LastAffected: "4.17.20"}}}
	if got, _ := expAffected("npm", l, "4.17.20"); !got {
		t.Error("last_affected is inclusive")
	}
	if got, _ := expAffected("npm", l, "4.17.21"); got {
		t.Error("past last_affected")
	}
	if got, det := expAffected("generic", l, "1.0"); got || det {
		t.Error("unknown scheme must be indeterminate, not affected")
	}
	if got, _ := expAffected("npm", ExpAdvisory{Versions: []string{"1.0.0"}}, "1.0.0"); !got {
		t.Error("exact version")
	}
}

func TestExposureEndToEndSample(t *testing.T) {
	mux, _ := expServer(t)
	// write requires the admin token; reads need auth
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/web1", "", expFixture(t, "cyclonedx.json")); w.Code != 401 {
		t.Fatalf("unauth write %d", w.Code)
	}
	if w := expDo(mux, "GET", "/v1/exposure/report", "", nil); w.Code != 401 {
		t.Fatalf("unauth read %d", w.Code)
	}
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/web1", "tok", expFixture(t, "cyclonedx.json")); w.Code != 200 {
		t.Fatalf("ingest %d %s", w.Code, w.Body)
	}
	if w := expDo(mux, "POST", "/v1/exposure/sboms/api1", "tok", expFixture(t, "spdx.json")); w.Code != 200 {
		t.Fatalf("ingest spdx %d %s", w.Code, w.Body)
	}
	w := expDo(mux, "GET", "/v1/exposure/report", "tok", nil)
	var rep struct {
		Sample  bool       `json:"advisory_sample"`
		Offline bool       `json:"offline"`
		Note    string     `json:"note"`
		Assets  []ExpAsset `json:"assets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Sample || !rep.Offline || !strings.Contains(rep.Note, "NOT a complete") {
		t.Fatalf("labelling: %+v", rep)
	}
	// web1: log4j 2.14.1 (KEV, critical) + requests 2.28.0 (medium); lodash 4.17.21 fixed.
	// api1: lodash 4.17.20 affected; x/net v0.17.0 is fixed -> exposed but lower.
	if len(rep.Assets) != 2 || rep.Assets[0].Host != "web1" || rep.Assets[1].Host != "api1" {
		t.Fatalf("assets: %+v", rep.Assets)
	}
	web := rep.Assets[0]
	if web.ExposedPackages != 2 || !web.Matches[0].KEV || web.Matches[0].ID != "CVE-2021-44228" || web.Matches[0].FixedIn != "2.15.0" {
		t.Fatalf("web: %+v", web)
	}
	if web.Score <= rep.Assets[1].Score || len(web.Factors) < 3 || web.Level == "none" {
		t.Fatalf("score ordering/factors: %+v %+v", web, rep.Assets[1])
	}
	if rep.Assets[1].Components != 3 || rep.Assets[1].WithPURL != 2 {
		t.Fatalf("api counts: %+v", rep.Assets[1])
	}
	// listing exposes component metadata, not raw SBOM
	var ls struct {
		Components []ExpComponent `json:"components"`
	}
	w = expDo(mux, "GET", "/v1/exposure/sboms/web1", "tok", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &ls)
	if len(ls.Components) != 4 {
		t.Fatalf("components %d", len(ls.Components))
	}
	if w := expDo(mux, "DELETE", "/v1/exposure/sboms/web1", "tok", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := expDo(mux, "GET", "/v1/exposure/sboms/web1", "tok", nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestExposureImportOSVAndKEV(t *testing.T) {
	mux, _ := expServer(t)
	if w := expDo(mux, "POST", "/v1/exposure/advisories/import", "", expFixture(t, "osv.json")); w.Code != 401 {
		t.Fatal(w.Code)
	}
	// KEV before any advisories: rejected with an explanation
	if w := expDo(mux, "POST", "/v1/exposure/advisories/import", "tok", expFixture(t, "kev.json")); w.Code != 400 {
		t.Fatalf("kev first %d", w.Code)
	}
	w := expDo(mux, "POST", "/v1/exposure/advisories/import?source=fixture-osv", "tok", expFixture(t, "osv.json"))
	if w.Code != 200 {
		t.Fatalf("osv %d %s", w.Code, w.Body)
	}
	// Debian ecosystem has no purl mapping and is skipped, not guessed
	if !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatal(w.Body)
	}
	w = expDo(mux, "POST", "/v1/exposure/advisories/import", "tok", expFixture(t, "kev.json"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"kev_flagged":1`) {
		t.Fatalf("kev %d %s", w.Code, w.Body)
	}
	sb := `{"bomFormat":"CycloneDX","components":[{"name":"left-pad","version":"1.1.0","purl":"pkg:npm/left-pad@1.1.0"}]}`
	expDo(mux, "PUT", "/v1/exposure/sboms/h", "tok", []byte(sb))
	var rep struct {
		Sample bool       `json:"advisory_sample"`
		Source string     `json:"advisory_source"`
		Assets []ExpAsset `json:"assets"`
	}
	_ = json.Unmarshal(expDo(mux, "GET", "/v1/exposure/report", "tok", nil).Body.Bytes(), &rep)
	if rep.Sample || rep.Source != "imported:fixture-osv" || len(rep.Assets) != 1 || !rep.Assets[0].Matches[0].KEV || rep.Assets[0].Matches[0].ID != "GHSA-test-0001" {
		t.Fatalf("%+v", rep)
	}
	// native format merges; replace mode swaps the dataset
	if w := expDo(mux, "POST", "/v1/exposure/advisories/import", "tok", expFixture(t, "advisories.json")); w.Code != 200 || !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("merge %s", w.Body)
	}
	if w := expDo(mux, "POST", "/v1/exposure/advisories/import?mode=replace", "tok", expFixture(t, "advisories.json")); !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("replace %s", w.Body)
	}
	if w := expDo(mux, "DELETE", "/v1/exposure/advisories", "tok", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := expDo(mux, "GET", "/v1/exposure/advisories", "tok", nil); !strings.Contains(w.Body.String(), `"sample":true`) {
		t.Fatal(w.Body)
	}
}

func TestExposureValidationAndCaps(t *testing.T) {
	mux, _ := expServer(t)
	bad := []string{`{"format":"kavach-advisories/1","advisories":[{"id":"X","purl":"nope","versions":["1"]}]}`,
		`{"format":"kavach-advisories/1","advisories":[{"id":"X","purl":"pkg:npm/a"}]}`,
		`{"format":"other/9","advisories":[]}`, `{"x":1}`, `not json`}
	for _, b := range bad {
		if w := expDo(mux, "POST", "/v1/exposure/advisories/import", "tok", []byte(b)); w.Code != 400 {
			t.Errorf("%s -> %d", b, w.Code)
		}
	}
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/h", "tok", []byte(`{"x":1}`)); w.Code != 400 {
		t.Fatal(w.Code)
	}
	big := make([]byte, expMaxSBOMBytes+1024)
	for i := range big {
		big[i] = ' '
	}
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/h", "tok", big); w.Code != 413 {
		t.Fatalf("size cap %d", w.Code)
	}
	var sb strings.Builder
	sb.WriteString(`{"bomFormat":"CycloneDX","components":[`)
	for i := 0; i <= expMaxComponents; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"name":"c"}`)
	}
	sb.WriteString(`]}`)
	if w := expDo(mux, "PUT", "/v1/exposure/sboms/h", "tok", []byte(sb.String())); w.Code != 400 {
		t.Fatalf("component cap %d", w.Code)
	}
}

func TestExposurePersistsAndPriorityFactor(t *testing.T) {
	store := newTestStore(t)
	mux := http.NewServeMux()
	RegisterExposure(mux, "tok", store)
	expDo(mux, "PUT", "/v1/exposure/sboms/web1", "tok", expFixture(t, "cyclonedx.json"))
	mux2 := http.NewServeMux()
	RegisterExposure(mux2, "tok", store) // reload from <store>.exposure.json
	if w := expDo(mux2, "GET", "/v1/exposure/sboms/web1", "tok", nil); w.Code != 200 {
		t.Fatalf("not persisted: %d", w.Code)
	}
	if fi, err := os.Stat(store.path + ".exposure.json"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v", err)
	}
	s := &expSvc{}
	s.load()
	s.st.SBOMs["web1"], _ = ExpParseSBOM(expFixture(t, "cyclonedx.json"))
	fn := expPriorityFn(s.hostScore)
	expPriorityHook.Store(&fn)
	defer expPriorityHook.CompareAndSwap(&fn, nil)
	ctx := newPriorityCtx(store, nil)
	res := ctx.score(Finding{ID: "f1", Host: "web1", Rule: "r", Severity: "high"})
	found := false
	for _, f := range res.Factors {
		if f.Name == "exposure" && f.Value > 0.5 {
			found = true
		}
	}
	if !found {
		t.Fatalf("exposure factor missing: %+v", res)
	}
	res = ctx.score(Finding{ID: "f2", Host: "nohost", Rule: "r", Severity: "high"})
	for _, f := range res.Factors {
		if f.Name == "exposure" {
			t.Fatal("host without SBOM must omit the factor")
		}
	}
	omitted := strings.Join(res.Omitted, "|")
	if !strings.Contains(omitted, "exposure:") {
		t.Fatalf("omission note missing: %v", res.Omitted)
	}
}
