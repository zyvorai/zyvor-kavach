// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type schedEnv struct {
	st  *Store
	ws  *Workspace
	s   *schedService
	exc *exceptionService
	clk *fakeClock
	mux *http.ServeMux
}

func newSchedEnv(t *testing.T) *schedEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	ws := &Workspace{}
	exc := newExceptionService(st.path+".exceptions.json", clk.Now)
	excSvc.Store(exc)
	s := newSchedService(st, ws, clk.Now)
	mux := http.NewServeMux()
	registerExceptionRoutes(mux, "tok", exc)
	s.routes(mux, "tok")
	schedSvc.Store(s)
	t.Cleanup(func() { excSvc.Store(nil); schedSvc.Store(nil); ruleSvc.Store(nil) })
	return &schedEnv{st, ws, s, exc, clk, mux}
}

func (e *schedEnv) call(method, path, body, auth string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return rr.Code, m
}

func (e *schedEnv) seed(t *testing.T, id, rule, host, exe string) {
	t.Helper()
	e.st.mu.Lock()
	defer e.st.mu.Unlock()
	if err := e.st.appendFindingLocked(Finding{ID: id, Time: e.clk.Now(), Host: host, Rule: rule, Severity: "low",
		Description: "seed " + id, Evidence: Event{Executable: exe}}); err != nil {
		t.Fatal(err)
	}
}

func (e *schedEnv) mainRules(rule string) int {
	n := 0
	for _, f := range e.st.List() {
		if f.Rule == rule {
			n++
		}
	}
	return n
}

func (e *schedEnv) addSearch(query string) {
	e.ws.mu.Lock()
	e.ws.data.Searches = append(e.ws.data.Searches, SavedSearch{ID: "ss1", Name: "n", Scope: "detections", Query: query})
	e.ws.mu.Unlock()
}

func (e *schedEnv) create(t *testing.T, extra string) string {
	t.Helper()
	body := `{"name":"d","severity":"high","technique":"T1059","state":"production","interval_sec":60,"source":{"kind":"saved_search","saved_search_id":"ss1"}` + extra + `}`
	code, m := e.call("POST", "/v1/detections/scheduled", body, "tok")
	if code != 201 {
		t.Fatalf("create %d %v", code, m)
	}
	return m["id"].(string)
}

func TestSchedValidationAndAuth(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("zzz")
	if c, _ := e.call("GET", "/v1/detections/scheduled", "", ""); c != 401 {
		t.Fatal("read needs auth", c)
	}
	if c, _ := e.call("POST", "/v1/detections/scheduled", `{}`, ""); c != 401 {
		t.Fatal("create needs auth", c)
	}
	if c, _ := e.call("PUT", "/v1/hunts/limits", `{}`, ""); c != 401 {
		t.Fatal("limits need auth", c)
	}
	for _, bad := range []string{
		`{"name":"x","severity":"critical","source":{"kind":"saved_search","saved_search_id":"ss1"}}`,
		`{"name":"x","severity":"high","interval_sec":30,"source":{"kind":"saved_search","saved_search_id":"ss1"}}`,
		`{"name":"x","severity":"high","interval_sec":90000,"source":{"kind":"saved_search","saved_search_id":"ss1"}}`,
		`{"name":"x","severity":"high","technique":"bogus","source":{"kind":"saved_search","saved_search_id":"ss1"}}`,
		`{"name":"x","severity":"high","source":{"kind":"saved_search","saved_search_id":"missing"}}`,
		`{"name":"x","severity":"high","source":{"kind":"seq","query":"not a query ["}}`,
	} {
		if c, _ := e.call("POST", "/v1/detections/scheduled", bad, "tok"); c != 400 {
			t.Fatalf("want 400 for %s got %d", bad, c)
		}
	}
	e.create(t, "")
	if c, m := e.call("GET", "/v1/detections/scheduled", "", "tok"); c != 200 || m["count"].(float64) != 1 {
		t.Fatal(c, m)
	}
}

func TestSchedSchedulerFakeClockDedupNoOverlap(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	e.seed(t, "a1", "seed-rule", "h1", "/bin/needle")
	id := e.create(t, "")
	ctx := context.Background()

	e.clk.Add(30 * time.Second)
	e.s.tick(ctx, e.clk.Now())
	if e.mainRules("hunt-"+id) != 0 {
		t.Fatal("ran before the interval")
	}
	e.clk.Add(31 * time.Second)
	e.s.tick(ctx, e.clk.Now())
	if n := e.mainRules("hunt-" + id); n != 1 {
		t.Fatalf("want 1 finding got %d", n)
	}
	f := e.st.List()[1]
	if f.Severity != "high" || !strings.Contains(strings.Join(f.Tags, ","), "attack:T1059") {
		t.Fatalf("bad finding %+v", f)
	}
	// next interval: same match key, de-duplicated
	e.clk.Add(61 * time.Second)
	e.s.tick(ctx, e.clk.Now())
	if n := e.mainRules("hunt-" + id); n != 1 {
		t.Fatalf("dedup failed: %d", n)
	}
	_, h := e.call("GET", "/v1/detections/scheduled/"+id+"/history", "", "tok")
	hist := h["history"].([]any)
	if len(hist) != 2 || hist[1].(map[string]any)["deduped"].(float64) != 1 {
		t.Fatalf("history %v", hist)
	}
	// after the dedup window the key is reported again
	e.clk.Add(25 * time.Hour)
	e.s.tick(ctx, e.clk.Now())
	if n := e.mainRules("hunt-" + id); n != 2 {
		t.Fatalf("window expiry: %d", n)
	}
	// no overlap
	e.s.mu.Lock()
	e.s.running[id] = true
	e.s.mu.Unlock()
	if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok"); c != 409 {
		t.Fatal("overlap must be refused", c)
	}
	e.clk.Add(2 * time.Minute)
	before := len(e.s.d.History[id])
	e.s.tick(ctx, e.clk.Now())
	if len(e.s.d.History[id]) != before {
		t.Fatal("tick overlapped a running detection")
	}
	e.s.release(id)
}

func TestSchedBackwardClockJumpDoesNotStall(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	e.seed(t, "a1", "seed-rule", "h1", "/bin/needle")
	id := e.create(t, "")
	e.clk.Add(-2 * time.Hour)
	e.s.tick(context.Background(), e.clk.Now()) // re-anchors
	e.clk.Add(61 * time.Second)
	e.s.tick(context.Background(), e.clk.Now())
	if e.mainRules("hunt-"+id) != 1 {
		t.Fatal("scheduler stalled after a backwards clock jump")
	}
}

func TestSchedDryRunRecordsNothing(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	e.seed(t, "a1", "seed-rule", "h1", "/bin/needle")
	id := e.create(t, "")
	c, m := e.call("POST", "/v1/detections/scheduled/"+id+"/dryrun", "", "tok")
	run := m["run"].(map[string]any)
	if c != 200 || run["recorded"].(float64) != 1 || run["dry_run"] != true {
		t.Fatal(c, m)
	}
	if e.mainRules("hunt-"+id) != 0 || len(e.s.d.History[id]) != 0 || len(e.s.d.Dedup[id]) != 0 {
		t.Fatal("dry run must not record findings, history or dedup state")
	}
	if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok"); c != 200 || e.mainRules("hunt-"+id) != 1 {
		t.Fatal("real run should record")
	}
}

func TestSchedTestingIsShadowAndDraftRefusesRun(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	e.seed(t, "a1", "seed-rule", "h1", "/bin/needle")
	id := e.create(t, `,"state":"testing"`)
	// the duplicate "state" key: last one wins in encoding/json, so make sure via PUT
	e.call("PUT", "/v1/detections/scheduled/"+id, `{"state":"testing"}`, "tok")
	c, m := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok")
	run := m["run"].(map[string]any)
	if c != 200 || run["shadow"].(float64) != 1 || run["recorded"].(float64) != 0 {
		t.Fatal(c, m)
	}
	if e.mainRules("hunt-"+id) != 0 || len(e.s.d.Shadow[id]) != 1 {
		t.Fatal("testing must be shadow only")
	}
	e.call("PUT", "/v1/detections/scheduled/"+id, `{"state":"draft"}`, "tok")
	if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok"); c != 409 {
		t.Fatal("draft must not record", c)
	}
	if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/dryrun", "", "tok"); c != 200 {
		t.Fatal("dry run of a draft is allowed", c)
	}
}

func TestSchedLifecycleMirrorsRuleHealth(t *testing.T) {
	e := newSchedEnv(t)
	rs := &ruleService{path: filepath.Join(t.TempDir(), "r.json"), store: e.st, now: time.Now}
	rs.load()
	ruleSvc.Store(rs)
	e.addSearch("needle")
	id := e.create(t, "")
	e.call("PUT", "/v1/detections/scheduled/"+id, `{"state":"testing"}`, "tok")
	if rs.d.Lifecycle["hunt-"+id].State != "testing" {
		t.Fatal("lifecycle not mirrored")
	}
	if ok, _ := rs.verifyLocked(); !ok {
		t.Fatal("rule history chain broken")
	}
}

func TestSchedSeqSourceAndCaps(t *testing.T) {
	e := newSchedEnv(t)
	e.st.mu.Lock()
	for i := 0; i < 8; i++ {
		e.st.recentEvents = append(e.st.recentEvents, Event{ID: "e" + string(rune('a'+i)), Time: e.clk.Now().Add(-time.Minute), Host: "h" + string(rune('a'+i)),
			PID: 100 + i, Executable: "/tmp/evil", Command: "evil"})
	}
	e.st.mu.Unlock()
	body := `{"name":"seq","severity":"medium","state":"production","max_matches":3,"source":{"kind":"seq","query":"process where executable startswith \"/tmp/\""}}`
	c, m := e.call("POST", "/v1/detections/scheduled", body, "tok")
	if c != 201 {
		t.Fatal(c, m)
	}
	id := m["id"].(string)
	c, m = e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok")
	run := m["run"].(map[string]any)
	if c != 200 || run["matched"].(float64) != 3 || run["truncated"] != true || run["recorded"].(float64) != 3 {
		t.Fatal(c, m)
	}
	// raising max_matches above the configured per-run limit is refused
	e.call("PUT", "/v1/hunts/limits", `{"max_matches_per_run":2}`, "tok")
	if c, _ := e.call("PUT", "/v1/detections/scheduled/"+id, `{"max_matches":5}`, "tok"); c != 400 {
		t.Fatal("max_matches above limit", c)
	}
}

func TestHuntQuotas(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	if c, _ := e.call("PUT", "/v1/hunts/limits", `{"max_scheduled":1,"max_runs_per_hour":2,"history_retention":2}`, "tok"); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.call("PUT", "/v1/hunts/limits", `{"max_scheduled":9999}`, "tok"); c != 400 {
		t.Fatal("out of range accepted")
	}
	id := e.create(t, "")
	if c, _ := e.call("POST", "/v1/detections/scheduled", `{"name":"x","severity":"low","source":{"kind":"saved_search","saved_search_id":"ss1"}}`, "tok"); c != 429 {
		t.Fatal("max_scheduled not enforced", c)
	}
	for i := 0; i < 2; i++ {
		if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok"); c != 200 {
			t.Fatal(c)
		}
	}
	if c, _ := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok"); c != 429 {
		t.Fatal("max_runs_per_hour not enforced", c)
	}
	_, l := e.call("GET", "/v1/hunts/limits", "", "tok")
	ref := l["refused"].(map[string]any)["counts"].(map[string]any)
	usage := l["usage"].(map[string]any)
	if ref["create"].(float64) != 1 || ref["run"].(float64) != 1 || usage["runs_last_hour"].(float64) != 2 || usage["scheduled_detections"].(float64) != 1 {
		t.Fatalf("usage/refusals %v", l)
	}
	e.clk.Add(61 * time.Minute) // quota window slides
	for i := 0; i < 2; i++ {
		e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok")
	}
	if n := len(e.s.d.History[id]); n != 2 {
		t.Fatalf("history retention: %d", n)
	}
}

func TestSchedPersistsAndDeletes(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	id := e.create(t, "")
	s2 := newSchedService(e.st, e.ws, e.clk.Now)
	if len(s2.d.Detections) != 1 || s2.d.Detections[0].ID != id {
		t.Fatal("not persisted")
	}
	if c, _ := e.call("DELETE", "/v1/detections/scheduled/"+id, "", "tok"); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.call("GET", "/v1/detections/scheduled/"+id, "", "tok"); c != 404 {
		t.Fatal(c)
	}
}

func TestSchedStopIsIdempotent(t *testing.T) {
	e := newSchedEnv(t)
	e.s.start()
	e.s.Stop()
	e.s.Stop()
}
