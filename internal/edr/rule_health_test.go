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

func ruleSetup(t *testing.T, dir string) (*http.ServeMux, *Store) {
	t.Helper()
	st, err := NewStore(filepath.Join(dir, "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCustomContent(mux, "tok", st)
	RegisterRuleHealth(mux, "tok", st)
	t.Cleanup(func() {
		ruleSvc.Store(nil)
		(&customStore{rules: map[string]*ContentRule{}}).apply()
	})
	return mux, st
}

func TestRuleHealthMetrics(t *testing.T) {
	now := time.Now()
	var fs []Finding
	add := func(rule, host string, ago time.Duration) {
		fs = append(fs, Finding{ID: rule + host + ago.String(), Rule: rule, Host: host, Time: now.Add(-ago)})
	}
	add("a", "h1", time.Hour)
	add("a", "h2", 2*time.Hour)
	add("a", "h1", 3*24*time.Hour)
	add("a", "h1", 10*24*time.Hour)
	add("b", "h1", 20*24*time.Hour)
	rows := BuildRuleHealth(fs, nil, nil, now)
	m := map[string]RuleHealth{}
	for _, r := range rows {
		m[r.Rule] = r
	}
	a := m["a"]
	if a.Hits24h != 2 || a.Hits7d != 3 || a.Hits30d != 4 || a.DistinctHost != 2 || a.Trend != "up" {
		t.Fatalf("a: %+v", a)
	}
	if a.Share30d != 0.8 || a.LastFired == nil {
		t.Fatalf("share/last: %+v", a)
	}
	if b := m["b"]; b.Hits7d != 0 || b.Trend != "none" || b.Hits30d != 1 {
		t.Fatalf("b: %+v", b)
	}
	if ruleNoisy(2000, 0.9, 8000, 3) < ruleNoisyAt || ruleNoisy(1, 0.01, 1, 1) >= ruleNoisyAt {
		t.Fatal("noisy score calibration")
	}
	if err := LoadContentPacks(); err != nil {
		t.Fatal(err)
	}
	silent := 0
	for _, r := range BuildRuleHealth(nil, nil, nil, now) {
		if r.Silent {
			silent++
		}
	}
	if silent == 0 {
		t.Fatal("expected silent registry rules")
	}
}

func TestRuleLifecycleShadowAndHistory(t *testing.T) {
	dir := t.TempDir()
	mux, st := ruleSetup(t, dir)
	if w := customDo(mux, "POST", "/v1/content/custom", customGood); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	id := "acme-evil-tool"
	if w := customDo(mux, "PUT", "/v1/rules/lifecycle/nope", `{"state":"testing"}`); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := customDo(mux, "PUT", "/v1/rules/lifecycle/"+id, `{"state":"bogus"}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
	ev := Event{ID: "e1", Time: time.Now(), Host: "h1", PID: 5, Executable: "/opt/x", Command: "/opt/acme-evil-tool --pwn now"}
	if _, err := st.Ingest(ev); err != nil {
		t.Fatal(err)
	}
	if n := countRule(st, id); n != 1 {
		t.Fatalf("production hits %d", n)
	}
	if w := customDo(mux, "PUT", "/v1/rules/lifecycle/"+id, `{"state":"testing","note":"trial"}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	ev.ID = "e2"
	ev.PID = 6
	ev.Time = time.Now().Add(time.Second)
	if _, err := st.Ingest(ev); err != nil {
		t.Fatal(err)
	}
	if n := countRule(st, id); n != 1 {
		t.Fatalf("testing leaked into main list: %d", n)
	}
	w := customDo(mux, "GET", "/v1/rules/health/"+id, "")
	if !strings.Contains(w.Body.String(), `"shadow_hits":1`) || !strings.Contains(w.Body.String(), `"state":"testing"`) {
		t.Fatalf("health: %s", w.Body)
	}
	customDo(mux, "PUT", "/v1/rules/lifecycle/"+id, `{"state":"retired"}`)
	var lst struct {
		Rules []RuleHealth `json:"rules"`
	}
	_ = json.Unmarshal(customDo(mux, "GET", "/v1/rules/health?state=retired", "").Body.Bytes(), &lst)
	if len(lst.Rules) != 1 || lst.Rules[0].Rule != id {
		t.Fatalf("retired not last")
	}
	changed := strings.Replace(customGood, `"severity":"high"`, `"severity":"medium"`, 1)
	customDo(mux, "POST", "/v1/content/custom", changed)
	customDo(mux, "DELETE", "/v1/content/custom/"+id, "")
	var h struct {
		ChainOK bool               `json:"chain_ok"`
		Entries []RuleHistoryEntry `json:"entries"`
	}
	_ = json.Unmarshal(customDo(mux, "GET", "/v1/rules/history/"+id, "").Body.Bytes(), &h)
	actions := ""
	for _, e := range h.Entries {
		actions += e.Action + ","
	}
	if !h.ChainOK || actions != "custom-rule.created,lifecycle,lifecycle,custom-rule.updated,custom-rule.deleted," {
		t.Fatalf("history %v %s", h.ChainOK, actions)
	}
	if !strings.Contains(h.Entries[3].Detail, "changed=severity") || h.Entries[1].Actor != "admin-token" {
		t.Fatalf("detail/actor: %+v", h.Entries[3])
	}
	svc := ruleSvc.Load()
	svc.mu.Lock()
	svc.d.History[1].Detail = "edited"
	svc.mu.Unlock()
	_ = json.Unmarshal(customDo(mux, "GET", "/v1/rules/history/"+id, "").Body.Bytes(), &h)
	if h.ChainOK {
		t.Fatal("tamper not detected")
	}
	mux2, _ := ruleSetup(t, dir)
	if w := customDo(mux2, "GET", "/v1/rules/lifecycle/"+id, ""); !strings.Contains(w.Body.String(), `"state":"retired"`) {
		t.Fatalf("not persisted: %s", w.Body)
	}
}

func TestRuleEndpointsRequireAuth(t *testing.T) {
	mux, _ := ruleSetup(t, t.TempDir())
	for _, p := range []string{"GET /v1/rules/health", "GET /v1/rules/health/x", "GET /v1/rules/lifecycle/x", "PUT /v1/rules/lifecycle/x", "GET /v1/rules/history/x"} {
		m, path, _ := strings.Cut(p, " ")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(m, path, nil))
		if w.Code != 401 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

func countRule(st *Store, id string) int {
	n := 0
	for _, f := range st.List() {
		if f.Rule == id {
			n++
		}
	}
	return n
}
