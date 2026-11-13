package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type chainEnv struct {
	mux   *http.ServeMux
	store *Store
}

func newChainEnv(t *testing.T) *chainEnv {
	t.Helper()
	store, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCaseManagement(mux, "tok", store, RegisterAnalystWorkspace(mux, "tok", store))
	RegisterChainsAndTemplates(mux, "tok", store)
	return &chainEnv{mux, store}
}

func (e *chainEnv) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *chainEnv) add(id, host, rule, sev, dest string, at time.Time) {
	_ = e.store.Append(Finding{ID: id, Time: at, Host: host, Rule: rule, Severity: sev, Destination: dest,
		Description: rule, Evidence: Event{Host: host, Time: at}})
}

func (e *chainEnv) seed() {
	t0 := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	e.add("a1", "host-a", "download-execute", "medium", "", t0)
	e.add("a2", "host-a", "download-chmod-execute", "high", "", t0.Add(3*time.Minute))
	e.add("a3", "host-a", "shell-network-redirection", "medium", "198.51.100.7:443", t0.Add(6*time.Minute))
	e.add("b1", "host-b", "lolbin-netcat-shell", "medium", "", t0.Add(5*time.Hour))
	e.add("b2", "host-b", "ransomware-burst", "critical", "", t0.Add(5*time.Hour+4*time.Minute))
	// noise: lone findings on other hosts, far apart
	e.add("n1", "host-c", "mass-file-activity", "low", "", t0.Add(2*time.Hour))
	e.add("n2", "host-d", "netra-denied-process", "low", "", t0.Add(9*time.Hour))
}

type chainList struct {
	Chains []Chain  `json:"chains"`
	Method string   `json:"method"`
	Limits []string `json:"limitations"`
}

func TestChainsTwoAttacksPlusNoise(t *testing.T) {
	e := newChainEnv(t)
	e.seed()
	w := e.do("GET", "/v1/chains", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var l chainList
	_ = json.Unmarshal(w.Body.Bytes(), &l)
	if len(l.Chains) != 2 {
		t.Fatalf("want 2 chains got %d: %s", len(l.Chains), w.Body.String())
	}
	if l.Method == "" || len(l.Limits) == 0 {
		t.Fatal("missing method/limitations")
	}
	sizes := map[string]int{}
	for _, c := range l.Chains {
		sizes[c.Hosts[0]] = c.Size
		if len(c.WhySummary) == 0 {
			t.Fatal("no why")
		}
	}
	if sizes["host-a"] != 3 || sizes["host-b"] != 2 {
		t.Fatalf("sizes %v", sizes)
	}
	// host filter and min_score
	var lh chainList
	_ = json.Unmarshal(e.do("GET", "/v1/chains?host=host-b", "").Body.Bytes(), &lh)
	if len(lh.Chains) != 1 {
		t.Fatal("host filter")
	}
	var lm chainList
	_ = json.Unmarshal(e.do("GET", "/v1/chains?min_score=1000", "").Body.Bytes(), &lm)
	if len(lm.Chains) != 0 {
		t.Fatal("min_score")
	}
	// detail
	var d struct {
		Members   []ChainMember `json:"members"`
		Links     []ChainLink   `json:"links"`
		Tactics   []string      `json:"tactics_in_order"`
		Questions []string      `json:"suggested_questions"`
	}
	for _, c := range l.Chains {
		if c.Hosts[0] != "host-a" {
			continue
		}
		wd := e.do("GET", "/v1/chains/"+c.ID, "")
		_ = json.Unmarshal(wd.Body.Bytes(), &d)
	}
	if len(d.Members) != 3 || len(d.Links) == 0 || len(d.Links[0].Reasons) == 0 {
		t.Fatalf("detail %+v", d)
	}
	if !reflect.DeepEqual(d.Tactics, []string{"Execution", "Defense Evasion", "Command and Control"}) {
		t.Fatalf("tactics %v", d.Tactics)
	}
	if len(d.Questions) == 0 {
		t.Fatal("expected hints")
	}
	if e.do("GET", "/v1/chains/chn-nope", "").Code != 404 {
		t.Fatal("want 404")
	}
}

func TestChainsDeterministic(t *testing.T) {
	e := newChainEnv(t)
	e.seed()
	a := e.do("GET", "/v1/chains", "").Body.String()
	b := e.do("GET", "/v1/chains", "").Body.String()
	if a != b {
		t.Fatal("not deterministic")
	}
	// input order must not matter
	fs := e.store.List()
	for i, j := 0, len(fs)-1; i < j; i, j = i+1, j-1 {
		fs[i], fs[j] = fs[j], fs[i]
	}
	c1 := BuildChains(e.store.List(), nil, "", 0)
	c2 := BuildChains(fs, nil, "", 0)
	if len(c1) != len(c2) {
		t.Fatal("order dependent")
	}
	for i := range c1 {
		if c1[i].ID != c2[i].ID || c1[i].Score != c2[i].Score {
			t.Fatal("order dependent ids/scores")
		}
	}
}

func TestChainsAuth(t *testing.T) {
	e := newChainEnv(t)
	for _, p := range [][2]string{{"GET", "/v1/chains"}, {"GET", "/v1/chains/x"}, {"POST", "/v1/chains/x/case"},
		{"GET", "/v1/case-templates"}, {"POST", "/v1/case-templates"}, {"GET", "/v1/cases/x/workflow"},
		{"POST", "/v1/cases/x/assign"}, {"POST", "/v1/cases/x/apply-template"}, {"POST", "/v1/cases/x/checklist/1"}} {
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, httptest.NewRequest(p[0], p[1], strings.NewReader("{}")))
		if w.Code != 401 {
			t.Fatalf("%v want 401 got %d", p, w.Code)
		}
	}
}

func TestChainCaseIdempotent(t *testing.T) {
	e := newChainEnv(t)
	e.seed()
	var l chainList
	_ = json.Unmarshal(e.do("GET", "/v1/chains?host=host-b", "").Body.Bytes(), &l)
	id := l.Chains[0].ID
	w1 := e.do("POST", "/v1/chains/"+id+"/case", "")
	if w1.Code != 201 {
		t.Fatal(w1.Code, w1.Body.String())
	}
	var r1 struct {
		Created bool    `json:"created"`
		Case    IncCase `json:"case"`
	}
	_ = json.Unmarshal(w1.Body.Bytes(), &r1)
	if !r1.Created || r1.Case.Severity != "critical" || len(r1.Case.FindingIDs) != 2 || len(r1.Case.Comments) == 0 {
		t.Fatalf("bad case %+v", r1.Case)
	}
	w2 := e.do("POST", "/v1/chains/"+id+"/case", "")
	var r2 struct {
		Created bool    `json:"created"`
		Case    IncCase `json:"case"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &r2)
	if w2.Code != 200 || r2.Created || r2.Case.ID != r1.Case.ID {
		t.Fatalf("not idempotent %d %+v", w2.Code, r2)
	}
	var cases []IncCase
	_ = json.Unmarshal(e.do("GET", "/v1/cases", "").Body.Bytes(), &cases)
	if len(cases) != 1 {
		t.Fatalf("want 1 case got %d", len(cases))
	}
	// chain list now shows the case
	var l2 chainList
	_ = json.Unmarshal(e.do("GET", "/v1/chains?host=host-b", "").Body.Bytes(), &l2)
	if l2.Chains[0].CaseID != r1.Case.ID {
		t.Fatal("case_id missing on chain")
	}
	if e.do("POST", "/v1/chains/chn-zzz/case", "").Code != 404 {
		t.Fatal("unknown chain")
	}
}

func mkCase(t *testing.T, e *chainEnv, sev string) IncCase {
	t.Helper()
	w := e.do("POST", "/v1/cases", `{"title":"T","severity":"`+sev+`"}`)
	var c IncCase
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	if c.ID == "" {
		t.Fatal(w.Body.String())
	}
	return c
}

func TestTemplatesApplyChecklistAssign(t *testing.T) {
	e := newChainEnv(t)
	var tpls []CaseTemplate
	_ = json.Unmarshal(e.do("GET", "/v1/case-templates", "").Body.Bytes(), &tpls)
	if len(tpls) < 6 {
		t.Fatal("defaults missing")
	}
	if e.do("PUT", "/v1/case-templates/tpl-malware-execution", `{}`).Code != 403 {
		t.Fatal("built-in must be read-only")
	}
	// custom CRUD
	w := e.do("POST", "/v1/case-templates", `{"name":"Mine","case_type":"x","default_severity":"low","checklist":["one","two"],"sla_hours":{"low":2},"default_tags":["mine"]}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var mine CaseTemplate
	_ = json.Unmarshal(w.Body.Bytes(), &mine)
	if e.do("POST", "/v1/case-templates", `{"name":"","checklist":[]}`).Code != 400 {
		t.Fatal("validation")
	}
	if e.do("PUT", "/v1/case-templates/"+mine.ID, `{"name":"Mine2","case_type":"x","checklist":["a"],"sla_hours":{"low":3}}`).Code != 200 {
		t.Fatal("update")
	}
	// session (non-admin) cannot mutate templates
	r := httptest.NewRequest("POST", "/v1/case-templates", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatal("bad token")
	}

	c := mkCase(t, e, "high")
	if e.do("POST", "/v1/cases/"+c.ID+"/apply-template", `{"template_id":"nope"}`).Code != 404 {
		t.Fatal("unknown template")
	}
	wa := e.do("POST", "/v1/cases/"+c.ID+"/apply-template", `{"template_id":"tpl-malware-execution"}`)
	if wa.Code != 200 {
		t.Fatal(wa.Code, wa.Body.String())
	}
	var wf struct {
		Checklist []ChecklistItem           `json:"checklist"`
		Progress  struct{ Done, Total int } `json:"checklist_progress"`
		SLA       ctSLAView                 `json:"template_sla"`
	}
	_ = json.Unmarshal(wa.Body.Bytes(), &wf)
	if wf.Progress.Total != 6 || wf.SLA.ResolveHours != 8 {
		t.Fatalf("workflow %+v", wf)
	}
	// case got a comment and tags through existing mechanisms
	var got IncCase
	_ = json.Unmarshal(e.do("GET", "/v1/cases/"+c.ID, "").Body.Bytes(), &got)
	if len(got.Comments) == 0 || len(got.Tags) == 0 {
		t.Fatalf("case not annotated %+v", got)
	}
	// checklist
	if e.do("POST", "/v1/cases/"+c.ID+"/checklist/2", `{"done":true}`).Code != 200 {
		t.Fatal("check")
	}
	if e.do("POST", "/v1/cases/"+c.ID+"/checklist/9", `{"done":true}`).Code != 404 {
		t.Fatal("range")
	}
	if e.do("POST", "/v1/cases/"+c.ID+"/checklist/1", `{}`).Code != 400 {
		t.Fatal("done required")
	}
	var wv struct {
		Progress  struct{ Done, Total int } `json:"checklist_progress"`
		Checklist []ChecklistItem           `json:"checklist"`
	}
	_ = json.Unmarshal(e.do("GET", "/v1/cases/"+c.ID+"/workflow", "").Body.Bytes(), &wv)
	if wv.Progress.Done != 1 || wv.Checklist[1].By != "admin" || wv.Checklist[1].DoneAt == nil {
		t.Fatalf("progress %+v", wv)
	}
	// re-apply keeps done state
	e.do("POST", "/v1/cases/"+c.ID+"/apply-template", `{"template_id":"tpl-malware-execution"}`)
	_ = json.Unmarshal(e.do("GET", "/v1/cases/"+c.ID+"/workflow", "").Body.Bytes(), &wv)
	if wv.Progress.Done != 1 {
		t.Fatal("re-apply lost state")
	}
	// assign
	if e.do("POST", "/v1/cases/"+c.ID+"/assign", `{"assignee":"night-shift"}`).Code != 200 {
		t.Fatal("assign")
	}
	_ = json.Unmarshal(e.do("GET", "/v1/cases/"+c.ID, "").Body.Bytes(), &got)
	if got.Assignee != "night-shift" {
		t.Fatal("assignee not set on case")
	}
	if e.do("POST", "/v1/cases/nope/assign", `{"assignee":"x"}`).Code != 404 {
		t.Fatal("assign unknown case")
	}
	// delete custom, 404 afterwards
	if e.do("DELETE", "/v1/case-templates/"+mine.ID, "").Code != 200 || e.do("GET", "/v1/case-templates/"+mine.ID, "").Code != 404 {
		t.Fatal("delete")
	}
}

func TestSLAOverdueFakeClock(t *testing.T) {
	created := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	c := IncCase{ID: "c1", Severity: "high", Status: "open", CreatedAt: created}
	wf := &CaseWorkflow{SLAHours: map[string]int{"high": 8}}
	get := func(c IncCase, now time.Time) ctSLAView {
		return computeWorkflow(c, wf, now)["template_sla"].(ctSLAView)
	}
	if v := get(c, created.Add(7*time.Hour)); v.Overdue || v.RemainingMinutes != 60 {
		t.Fatalf("%+v", v)
	}
	if v := get(c, created.Add(9*time.Hour)); !v.Overdue || v.RemainingMinutes != -60 {
		t.Fatalf("%+v", v)
	}
	closed := created.Add(2 * time.Hour)
	c.Status, c.ClosedAt = "closed", &closed
	if v := get(c, created.Add(100*time.Hour)); v.Overdue {
		t.Fatal("closed in time must not be overdue")
	}
	late := created.Add(10 * time.Hour)
	c.ClosedAt = &late
	if v := get(c, created.Add(100*time.Hour)); !v.Overdue {
		t.Fatal("closed late must be overdue")
	}
	// no hours for severity -> no template SLA
	c.Severity = "low"
	if _, ok := computeWorkflow(c, wf, created)["template_sla"]; ok {
		t.Fatal("unexpected sla")
	}
}

func TestWorkflowJournalHashChain(t *testing.T) {
	e := newChainEnv(t)
	c := mkCase(t, e, "medium")
	e.do("POST", "/v1/cases/"+c.ID+"/apply-template", `{"template_id":"tpl-suspicious-login"}`)
	e.do("POST", "/v1/cases/"+c.ID+"/checklist/1", `{"done":true}`)
	e.do("POST", "/v1/cases/"+c.ID+"/assign", `{"assignee":"a"}`)
	var j struct {
		Intact  bool           `json:"intact"`
		Entries []JournalEntry `json:"entries"`
	}
	_ = json.Unmarshal(e.do("GET", "/v1/case-workflow/journal", "").Body.Bytes(), &j)
	if !j.Intact || len(j.Entries) != 3 {
		t.Fatalf("journal %+v", j)
	}
	// tamper with a persisted state and re-load
	st := newCTState(filepathOf(e))
	st.mu.Lock()
	if seq, _ := st.verifyLocked(); seq != 0 {
		t.Fatal("fresh journal should verify")
	}
	st.d.Journal[1].Target = "forged"
	seq, why := st.verifyLocked()
	st.mu.Unlock()
	if seq != 2 || why == "" {
		t.Fatalf("tamper not detected: %d %s", seq, why)
	}
	// removed middle entry breaks the chain
	st.mu.Lock()
	st.d.Journal[1].Target = "x"
	st.d.Journal = append(st.d.Journal[:1:1], st.d.Journal[2:]...)
	seq, _ = st.verifyLocked()
	st.mu.Unlock()
	if seq == 0 {
		t.Fatal("deletion not detected")
	}
}

func filepathOf(e *chainEnv) string { return e.store.path + ".casetemplates.json" }
