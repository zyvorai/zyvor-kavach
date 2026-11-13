package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ut(y int, m time.Month, d, h, mi int) time.Time {
	return time.Date(y, m, d, h, mi, 0, 0, time.UTC)
}

func TestRSNextArithmetic(t *testing.T) {
	cases := []struct {
		name  string
		s     rsSchedule
		after time.Time
		want  time.Time
	}{
		{"hourly before minute", rsSchedule{Frequency: "hourly", Minute: 30}, ut(2026, 1, 1, 10, 10), ut(2026, 1, 1, 10, 30)},
		{"hourly at minute is strictly after", rsSchedule{Frequency: "hourly", Minute: 30}, ut(2026, 1, 1, 10, 30), ut(2026, 1, 1, 11, 30)},
		{"hourly across midnight", rsSchedule{Frequency: "hourly", Minute: 0}, ut(2026, 12, 31, 23, 30), ut(2027, 1, 1, 0, 0)},
		{"daily later today", rsSchedule{Frequency: "daily", Hour: 6, Minute: 15}, ut(2026, 3, 1, 5, 0), ut(2026, 3, 1, 6, 15)},
		{"daily tomorrow across month end", rsSchedule{Frequency: "daily", Hour: 6}, ut(2026, 2, 28, 7, 0), ut(2026, 3, 1, 6, 0)},
		{"daily leap day", rsSchedule{Frequency: "daily", Hour: 6}, ut(2028, 2, 28, 7, 0), ut(2028, 2, 29, 6, 0)},
		{"weekly same day later", rsSchedule{Frequency: "weekly", Weekday: "mon", Hour: 9}, ut(2026, 11, 9, 8, 0), ut(2026, 11, 9, 9, 0)}, // 2026-11-09 is a Monday
		{"weekly next week", rsSchedule{Frequency: "weekly", Weekday: "mon", Hour: 9}, ut(2026, 11, 9, 9, 0), ut(2026, 11, 16, 9, 0)},
		{"weekly over month end", rsSchedule{Frequency: "weekly", Weekday: "sun", Hour: 0}, ut(2026, 12, 29, 0, 0), ut(2027, 1, 3, 0, 0)},
		{"monthly this month", rsSchedule{Frequency: "monthly", DayOfMonth: 15, Hour: 1}, ut(2026, 5, 10, 0, 0), ut(2026, 5, 15, 1, 0)},
		{"monthly clamps 31 to Apr 30", rsSchedule{Frequency: "monthly", DayOfMonth: 31, Hour: 2}, ut(2026, 4, 1, 0, 0), ut(2026, 4, 30, 2, 0)},
		{"monthly Jan 31 then Feb 28", rsSchedule{Frequency: "monthly", DayOfMonth: 31, Hour: 2}, ut(2026, 1, 31, 2, 0), ut(2026, 2, 28, 2, 0)},
		{"monthly Feb leap 29", rsSchedule{Frequency: "monthly", DayOfMonth: 30, Hour: 2}, ut(2028, 1, 30, 2, 0), ut(2028, 2, 29, 2, 0)},
		{"monthly Dec to Jan", rsSchedule{Frequency: "monthly", DayOfMonth: 1, Hour: 0}, ut(2026, 12, 1, 0, 0), ut(2027, 1, 1, 0, 0)},
		{"monthly Nov 30 to Dec 31", rsSchedule{Frequency: "monthly", DayOfMonth: 31, Hour: 0}, ut(2026, 11, 30, 0, 0), ut(2026, 12, 31, 0, 0)},
	}
	for _, c := range cases {
		if got := rsNext(c.s, c.after); !got.Equal(c.want) {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	// non-UTC input is normalised
	loc := time.FixedZone("x", 5*3600)
	got := rsNext(rsSchedule{Frequency: "daily", Hour: 1}, time.Date(2026, 1, 1, 5, 0, 0, 0, loc)) // = 00:00Z
	if !got.Equal(ut(2026, 1, 1, 1, 0)) {
		t.Errorf("tz normalise: %s", got)
	}
}

func TestRSValidation(t *testing.T) {
	good := rsSchedule{Template: "tuning-digest", Frequency: "daily", Hour: 1, Format: "csv"}
	if err := rsNormalize(&good); err != nil {
		t.Fatal(err)
	}
	bad := []rsSchedule{
		{Template: "nope", Frequency: "daily"},
		{Template: "tuning-digest", Frequency: "yearly"},
		{Template: "tuning-digest", Frequency: "weekly", Weekday: "xyz"},
		{Template: "tuning-digest", Frequency: "monthly", DayOfMonth: 32},
		{Template: "tuning-digest", Frequency: "daily", Format: "pdf"},
		{Template: "tuning-digest", Frequency: "daily", Retention: 1000},
		{Template: "tuning-digest", Frequency: "daily", Params: map[string]string{"evil": "1"}},
		{Template: "tuning-digest", Frequency: "daily", Params: map[string]string{"since_hours": "0"}},
	}
	for i, b := range bad {
		if rsNormalize(&b) == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
	// a template made only of manual sections has no csv
	for _, tp := range ReportTemplates() {
		if !rsTemplateSupportsCSV(tp) {
			s := rsSchedule{Template: tp.ID, Frequency: "daily", Format: "csv"}
			if rsNormalize(&s) == nil {
				t.Errorf("%s: csv should be refused", tp.ID)
			}
		}
	}
	if _, _, err := rsParseHHMM("25:00"); err == nil {
		t.Error("HH:MM range")
	}
}

type rsClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *rsClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *rsClock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

func rsTestEngine(t *testing.T, clk *rsClock) *rsEngine {
	t.Helper()
	e := newRSEngine(filepath.Join(t.TempDir(), "f.jsonl"), clk.now)
	e.render = func(s rsSchedule, now time.Time) ([]byte, bool, error) {
		return []byte("report " + s.Template + " " + now.Format(time.RFC3339)), false, nil
	}
	return e
}

func rsMake(t *testing.T, e *rsEngine, s rsSchedule) rsSchedule {
	t.Helper()
	c, err := e.Create(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRSCatchUpRunsOnceNoBacklog(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	s := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Minute: 0, Retention: 50, Enabled: true})
	if !s.NextRun.Equal(ut(2026, 6, 1, 1, 0)) {
		t.Fatalf("next %s", s.NextRun)
	}
	if n := e.tick(ut(2026, 6, 1, 0, 30)); n != 0 {
		t.Fatalf("not yet due, ran %d", n)
	}
	// server was down for 3 days: 72 hourly runs missed, exactly one runs
	clk.set(ut(2026, 6, 4, 0, 10))
	if n := e.tick(clk.now()); n != 1 {
		t.Fatalf("catch-up ran %d", n)
	}
	runs := e.Runs(s.ID)
	if len(runs) != 1 || runs[0].Trigger != "catchup" || runs[0].Status != "ok" {
		t.Fatalf("%+v", runs)
	}
	if n := e.tick(clk.now()); n != 0 {
		t.Fatalf("second tick must not re-run, ran %d", n)
	}
	if got := e.List()[0].NextRun; !got.Equal(ut(2026, 6, 4, 1, 0)) {
		t.Fatalf("next after catch-up %s", got)
	}
	// persisted state survives a restart; overdue schedule catches up once more
	e2 := newRSEngine(e.path[:len(e.path)-len(".reportschedules.json")], clk.now)
	e2.render = e.render
	if len(e2.List()) != 1 || len(e2.Runs(s.ID)) != 1 {
		t.Fatal("state not reloaded")
	}
	clk.set(ut(2026, 6, 9, 0, 0))
	if n := e2.tick(clk.now()); n != 1 {
		t.Fatalf("restart catch-up ran %d", n)
	}
}

func TestRSDisabledAndPerTickCap(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	off := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 5, Enabled: false})
	for i := 0; i < 8; i++ {
		rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 5, Enabled: true})
	}
	if n := e.tick(ut(2026, 6, 2, 0, 0)); n != rsMaxPerTick {
		t.Fatalf("per-tick cap: ran %d", n)
	}
	if n := e.tick(ut(2026, 6, 2, 0, 0)); n != 8-rsMaxPerTick {
		t.Fatalf("remaining due: ran %d", n)
	}
	if len(e.Runs(off.ID)) != 0 {
		t.Fatal("disabled schedule ran")
	}
}

func TestRSRetentionByCountAndSize(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	s := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 3, Enabled: true})
	var ids []string
	for i := 0; i < 6; i++ {
		clk.set(clk.now().Add(time.Minute))
		r, err := e.execute(s.ID, "manual", clk.now())
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.RunID)
	}
	runs := e.Runs(s.ID)
	if len(runs) != 3 || runs[0].RunID != ids[5] || runs[2].RunID != ids[3] {
		t.Fatalf("count retention: %+v", runs)
	}
	for _, id := range ids[:3] {
		if _, err := os.Stat(filepath.Join(e.dir, id+".md")); !os.IsNotExist(err) {
			t.Fatalf("pruned artefact %s still on disk", id)
		}
		if _, err := os.Stat(filepath.Join(e.dir, id+".meta.json")); !os.IsNotExist(err) {
			t.Fatalf("pruned meta %s still on disk", id)
		}
	}
	// size cap: allow only ~2 reports in total across the archive
	one := runs[0].Bytes
	e.maxTotal = int64(2*one + one/2)
	e.mu.Lock()
	e.pruneLocked()
	e.mu.Unlock()
	runs = e.Runs(s.ID)
	if len(runs) != 2 || runs[0].RunID != ids[5] {
		t.Fatalf("size retention kept %d: %+v", len(runs), runs)
	}
	// file cap
	e.maxTotal, e.maxFiles = 1<<30, 1
	e.mu.Lock()
	e.pruneLocked()
	e.mu.Unlock()
	if runs = e.Runs(s.ID); len(runs) != 1 || runs[0].RunID != ids[5] {
		t.Fatalf("file cap: %+v", runs)
	}
	// oversized single report is refused, not stored
	e.maxBytes = 5
	r, _ := e.execute(s.ID, "manual", clk.now())
	if r.Status != "failed" || r.Bytes != 0 || !strings.Contains(r.Error, "limit") {
		t.Fatalf("oversize: %+v", r)
	}
}

func TestRSNoOverlap(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	e.render = func(s rsSchedule, now time.Time) ([]byte, bool, error) {
		started <- struct{}{}
		<-release
		return []byte("x"), false, nil
	}
	a := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 5, Enabled: true})
	b := rsMake(t, e, rsSchedule{Template: "quarterly-trend", Frequency: "hourly", Retention: 5, Enabled: true})
	done := make(chan error, 1)
	go func() { _, err := e.execute(a.ID, "manual", clk.now()); done <- err }()
	<-started
	if _, err := e.execute(a.ID, "manual", clk.now()); !errors.Is(err, errRSBusy) {
		t.Fatalf("same schedule overlap allowed: %v", err)
	}
	if _, err := e.execute(b.ID, "manual", clk.now()); !errors.Is(err, errRSBusy) {
		t.Fatalf("second concurrent run allowed: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := e.execute(b.ID, "manual", clk.now()); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}

func TestRSTimeoutKeepsSlotUntilRenderFinishes(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	e.timeout = 50 * time.Millisecond
	release := make(chan struct{})
	var calls int32
	e.render = func(s rsSchedule, now time.Time) ([]byte, bool, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			<-release
		}
		return []byte("late"), false, nil
	}
	a := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 5, Enabled: true})
	r, err := e.execute(a.ID, "manual", clk.now())
	if err != nil || r.Status != "timeout" || r.Bytes != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := e.execute(a.ID, "manual", clk.now()); !errors.Is(err, errRSBusy) {
		t.Fatalf("overlap after timeout: %v", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r, err := e.execute(a.ID, "manual", clk.now()); err == nil && r.Status == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRSRenderPanicIsContained(t *testing.T) {
	clk := &rsClock{t: ut(2026, 6, 1, 0, 0)}
	e := rsTestEngine(t, clk)
	e.render = func(s rsSchedule, now time.Time) ([]byte, bool, error) { panic("boom") }
	a := rsMake(t, e, rsSchedule{Template: "tuning-digest", Frequency: "hourly", Retention: 5, Enabled: true})
	r, err := e.execute(a.ID, "manual", clk.now())
	if err != nil || r.Status != "failed" || !strings.Contains(r.Error, "boom") {
		t.Fatalf("%+v %v", r, err)
	}
}

func rsAPI(t *testing.T) (http.Handler, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := OpenCredentialRegistry(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	const tok = "report-sched-admin-secret-token"
	RegisterReportSched(mux, tok, store, reg)
	return mux, store, tok
}

func rsDo(h http.Handler, method, path, tok, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRSAPIFlowAndArchive(t *testing.T) {
	h, store, tok := rsAPI(t)
	if rsDo(h, "GET", "/v1/reports/scheduled", "", "").Code != 401 {
		t.Fatal("list needs auth")
	}
	if rsDo(h, "POST", "/v1/reports/scheduled", "", `{}`).Code != 401 {
		t.Fatal("create needs auth")
	}
	if c := rsDo(h, "POST", "/v1/reports/scheduled", tok, `{"template":"tuning-digest","frequency":"daily","time":"25:00"}`).Code; c != 400 {
		t.Fatalf("bad time %d", c)
	}
	w := rsDo(h, "POST", "/v1/reports/scheduled", tok, `{"template":"tuning-digest","frequency":"weekly","weekday":"fri","time":"07:30","format":"csv","retention":2}`)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var s rsSchedule
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.NextRun.Weekday() != time.Friday || s.NextRun.Hour() != 7 || s.NextRun.Minute() != 30 {
		t.Fatalf("next %s", s.NextRun)
	}
	w = rsDo(h, "PUT", "/v1/reports/scheduled/"+s.ID, tok, `{"template":"tuning-digest","frequency":"daily","time":"01:00","format":"json"}`)
	if w.Code != 200 {
		t.Fatalf("put %d %s", w.Code, w.Body)
	}
	if rsDo(h, "PUT", "/v1/reports/scheduled/snope0000", tok, `{"template":"tuning-digest","frequency":"daily","time":"01:00"}`).Code != 404 {
		t.Fatal("put missing")
	}
	w = rsDo(h, "POST", "/v1/reports/scheduled/"+s.ID+"/run", tok, "")
	if w.Code != 200 {
		t.Fatalf("run %d %s", w.Code, w.Body)
	}
	var run rsRun
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	if run.Status != "ok" || run.SHA256 == "" || run.Format != "json" || run.Trigger != "manual" {
		t.Fatalf("%+v", run)
	}
	a := rsDo(h, "GET", "/v1/reports/archive/"+run.RunID, tok, "")
	sum := sha256.Sum256(a.Body.Bytes())
	if a.Code != 200 || hex.EncodeToString(sum[:]) != run.SHA256 || a.Body.Len() != run.Bytes || !strings.Contains(a.Header().Get("Content-Type"), "json") {
		t.Fatalf("archive %d", a.Code)
	}
	if rsDo(h, "GET", "/v1/reports/archive/"+run.RunID, "", "").Code != 401 {
		t.Fatal("archive needs auth")
	}
	if rsDo(h, "GET", "/v1/reports/archive/..%2f..%2fetc", tok, "").Code != 404 {
		t.Fatal("traversal id must 404")
	}
	if rsDo(h, "GET", "/v1/reports/archive/r0000000", tok, "").Code != 404 {
		t.Fatal("unknown run")
	}
	l := rsDo(h, "GET", "/v1/reports/scheduled/"+s.ID+"/runs", tok, "")
	if l.Code != 200 || !strings.Contains(l.Body.String(), run.RunID) {
		t.Fatalf("runs %s", l.Body)
	}
	if rsDo(h, "GET", "/v1/reports/scheduled/snope0000/runs", tok, "").Code != 404 {
		t.Fatal("runs missing schedule")
	}
	g := rsDo(h, "GET", "/v1/reports/scheduled", tok, "")
	if !strings.Contains(g.Body.String(), "pull-only") || !strings.Contains(g.Body.String(), "templates_with_host_names") {
		t.Fatalf("list lacks pull-only/host statement: %s", g.Body)
	}
	_ = store
	if rsDo(h, "DELETE", "/v1/reports/scheduled/"+s.ID, tok, "").Code != 204 {
		t.Fatal("delete")
	}
	if rsDo(h, "GET", "/v1/reports/archive/"+run.RunID, tok, "").Code != 404 {
		t.Fatal("artefact must go with its schedule")
	}
}

func TestRSRenderRedactionAndFormats(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	tpl, ok := rsFindTemplate("tuning-digest")
	if !ok {
		t.Fatal("tpl")
	}
	now := ut(2026, 6, 1, 0, 0)
	if err := store.Append(Finding{ID: "x1", Time: now.Add(-time.Hour), Host: "h1", Rule: "rule contact bob@example.com", Severity: "high"}); err != nil {
		t.Skipf("cannot seed findings: %v", err)
	}
	md, red, _ := rsRenderTemplate(tpl, rsSchedule{Format: "markdown"}, now, store, nil)
	if red || !strings.Contains(string(md), "bob@example.com") {
		t.Fatalf("unredacted baseline expected:\n%s", md)
	}
	if err := os.WriteFile(store.path+govRedactionExt, []byte(`{"enabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	md, red, _ = rsRenderTemplate(tpl, rsSchedule{Format: "markdown"}, now, store, nil)
	if !red || strings.Contains(string(md), "bob@example.com") || !strings.Contains(string(md), "REDACTED:email") {
		t.Fatalf("redaction not honoured:\n%s", md)
	}
	js, _, _ := rsRenderTemplate(tpl, rsSchedule{Format: "json", Params: map[string]string{"min_severity": "high"}}, now, store, nil)
	var v map[string]any
	if json.Unmarshal(js, &v) != nil || v["redacted"] != true {
		t.Fatalf("json: %s", js)
	}
	cs, _, _ := rsRenderTemplate(tpl, rsSchedule{Format: "csv"}, now, store, nil)
	if !strings.HasPrefix(string(cs), "section,item,value") {
		t.Fatalf("csv: %s", cs)
	}
	// severity filter drops the finding
	md, _, _ = rsRenderTemplate(tpl, rsSchedule{Format: "markdown", Params: map[string]string{"min_severity": "critical"}}, now, store, nil)
	if strings.Contains(string(md), "REDACTED") {
		t.Fatalf("filter ignored:\n%s", md)
	}
	if rsCSVSafe("=cmd()") != "'=cmd()" {
		t.Fatal("csv injection guard")
	}
	if len(rsHostTemplates()) == 0 {
		t.Fatal("expected at least one template with host names")
	}
}

// TestRSPullOnlyStructure asserts the scheduled-report and SLO code contains
// no outbound networking primitive: reports are never pushed anywhere.
func TestRSPullOnlyStructure(t *testing.T) {
	files, _ := filepath.Glob("report_sched_*.go")
	more, _ := filepath.Glob("fleet_slo_*.go")
	files = append(files, more...)
	banned := []string{"net.Dial", "net.Listen", "http.Get(", "http.Post(", "http.PostForm(", "http.Head(", "http.NewRequest", "http.Client", "http.DefaultClient",
		"net/smtp", "net/rpc", "\"os/exec\"", "websocket", "syscall.Connect", "DialContext", "tls.Dial", "net/url"}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range banned {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains outbound primitive %q", f, bad)
			}
		}
	}
	if n < 5 {
		t.Fatalf("expected to scan the sched and slo files, scanned %d", n)
	}
}
