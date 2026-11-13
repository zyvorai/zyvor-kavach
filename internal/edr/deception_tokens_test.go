package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func deceptSetup(t *testing.T, dir string) (*http.ServeMux, *Store) {
	t.Helper()
	st, err := testStore(t, filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterDeceptionTokens(mux, "tok", st)
	return mux, st
}

func deceptDo(mux *http.ServeMux, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("User-Agent", "curl/8")
	if auth {
		r.Header.Set("Authorization", "Bearer tok")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func deceptMake(t *testing.T, mux *http.ServeMux, kind string) deceptCanary {
	t.Helper()
	w := deceptDo(mux, "POST", "/v1/deception/canaries", `{"kind":"`+kind+`","name":"n","placement":"p","owner":"o"}`, true)
	if w.Code != 201 {
		t.Fatalf("create %s: %d %s", kind, w.Code, w.Body)
	}
	var c deceptCanary
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func deceptFindings(st *Store) int {
	n := 0
	for _, f := range st.List() {
		if f.Rule == deceptRule {
			n++
		}
	}
	return n
}

func TestDeceptionIDAndKinds(t *testing.T) {
	mux, _ := deceptSetup(t, t.TempDir())
	seen := map[string]bool{}
	for _, k := range []string{"credential", "document-beacon", "dns-name"} {
		c := deceptMake(t, mux, k)
		if !deceptValidID(c.ID) || seen[c.ID] {
			t.Fatalf("bad id %q", c.ID)
		}
		seen[c.ID] = true
	}
	if w := deceptDo(mux, "POST", "/v1/deception/canaries", `{"kind":"x","name":"n"}`, true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	c := deceptMake(t, mux, "credential")
	if !strings.Contains(c.Value, "NON-FUNCTIONAL") || !strings.Contains(c.Value, "AKIA") {
		t.Fatal(c.Value)
	}
}

func TestDeceptionNoOracleAndFinding(t *testing.T) {
	mux, st := deceptSetup(t, t.TempDir())
	c := deceptMake(t, mux, "document-beacon")
	good := deceptDo(mux, "GET", "/c/"+c.ID, "", false)
	bad := deceptDo(mux, "GET", "/c/"+strings.Repeat("0", 32), "", false)
	junk := deceptDo(mux, "POST", "/c/zzz", "body", false)
	for _, w := range []*httptest.ResponseRecorder{bad, junk} {
		if w.Code != good.Code || w.Body.String() != good.Body.String() || w.Header().Get("Content-Type") != good.Header().Get("Content-Type") {
			t.Fatal("responses differ")
		}
	}
	if good.Code != 200 || deceptFindings(st) != 1 {
		t.Fatalf("code %d findings %d", good.Code, deceptFindings(st))
	}
	deceptDo(mux, "GET", "/c/"+c.ID, "", false)
	deceptDo(mux, "POST", "/c/"+c.ID, "x", false)
	if deceptFindings(st) != 1 {
		t.Fatal("not coalesced")
	}
	var f Finding
	for _, x := range st.List() {
		if x.Rule == deceptRule {
			f = x
		}
	}
	if f.Severity != "high" || len(f.Tags) != 2 || f.Tags[0] != "deception" {
		t.Fatalf("%+v", f)
	}
	if m, ok := ruleMITRE[deceptRule]; !ok || m.ID != "T1552" {
		t.Fatal("no mitre")
	}
	w := deceptDo(mux, "GET", "/v1/deception/trips", "", true)
	if !strings.Contains(w.Body.String(), c.ID) || !strings.Contains(w.Body.String(), "203.0.113.9") {
		t.Fatal(w.Body)
	}
}

func TestDeceptionRateLimit(t *testing.T) {
	mux, _ := deceptSetup(t, t.TempDir())
	c := deceptMake(t, mux, "document-beacon")
	for i := 0; i < 50; i++ {
		if w := deceptDo(mux, "GET", "/c/"+c.ID, "", false); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	w := deceptDo(mux, "GET", "/v1/deception/canaries", "", true)
	var out struct{ Canaries []deceptCanary }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Canaries[0].Trips < 1 || out.Canaries[0].Trips > 12 {
		t.Fatalf("rate limit not applied: %d", out.Canaries[0].Trips)
	}
}

func TestDeceptionAdminTripPersistenceAuth(t *testing.T) {
	dir := t.TempDir()
	mux, st := deceptSetup(t, dir)
	c := deceptMake(t, mux, "credential")
	if w := deceptDo(mux, "POST", "/v1/deception/trip", `{"host":"h","path":"/p"}`, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, p := range [][2]string{{"GET", "/v1/deception/canaries"}, {"GET", "/v1/deception/trips"}, {"POST", "/v1/deception/canaries"}, {"DELETE", "/v1/deception/canaries/" + c.ID}} {
		if w := deceptDo(mux, p[0], p[1], "{}", false); w.Code != 401 {
			t.Fatal(p, w.Code)
		}
	}
	if w := deceptDo(mux, "POST", "/v1/deception/trip", `{"canary_id":"`+c.ID+`","host":"h1","path":"/root/.aws/credentials"}`, true); w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	if w := deceptDo(mux, "POST", "/v1/deception/trip", `{"canary_id":"nope","host":"h","path":"/p"}`, true); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if deceptFindings(st) != 1 || st.List()[0].Host != "h1" {
		t.Fatal("finding missing")
	}
	mux2, st2 := deceptSetup(t, dir)
	if w := deceptDo(mux2, "GET", "/v1/deception/canaries", "", true); !strings.Contains(w.Body.String(), c.ID) {
		t.Fatal("canary not persisted")
	}
	if w := deceptDo(mux2, "GET", "/v1/deception/trips", "", true); !strings.Contains(w.Body.String(), "h1") {
		t.Fatal("trip not persisted")
	}
	deceptDo(mux2, "POST", "/v1/deception/trip", `{"canary_id":"`+c.ID+`","host":"h1","path":"/x"}`, true)
	if deceptFindings(st2) != 1 {
		t.Fatal("coalesce after restart")
	}
	if w := deceptDo(mux2, "DELETE", "/v1/deception/canaries/"+c.ID, "", true); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := deceptDo(mux2, "DELETE", "/v1/deception/canaries/"+c.ID, "", true); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestDeceptionLimiter(t *testing.T) {
	l := &deceptLimiter{rate: 1, burst: 2, m: map[string]*deceptBucket{}}
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) || !l.allow("b", now) {
		t.Fatal("limiter")
	}
}
