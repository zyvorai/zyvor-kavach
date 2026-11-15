// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nxReq struct{ method, path, query, body string }

// nxServer records every request and answers from a path -> JSON table (any method).
func nxServer(t *testing.T, routes map[string]string) *[]nxReq {
	t.Helper()
	var reqs []nxReq
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs = append(reqs, nxReq{r.Method, r.URL.Path, r.URL.RawQuery, string(b)})
		body, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			http.Error(w, "no route", 404)
			return
		}
		code := 200
		if strings.HasPrefix(body, "409:") {
			code, body = 409, body[4:]
		} else if strings.HasPrefix(body, "400:") {
			code, body = 400, body[4:]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
	setupMock(t, mux)
	old := mlInteractive
	mlInteractive = func() bool { return false }
	t.Cleanup(func() { mlInteractive = old })
	return &reqs
}

func nxRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	h, err := nxDispatch(args, &buf)
	if !h {
		t.Fatalf("not handled: %v", args)
	}
	return buf.String(), err
}

func nxWant(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Fatalf("output missing %q:\n%s", w, got)
		}
	}
}

func TestNxFallsThrough(t *testing.T) {
	for _, a := range [][]string{{"validate"}, {"vulns", "software"}, {"hunt", "packs"}, {"case", "list"}, {"content", "list"}, {"coverage"}, {"status"}} {
		if h, _ := nxDispatch(a, io.Discard); h {
			t.Fatalf("must not claim %v", a)
		}
	}
}

func TestNxValidate(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"GET /v1/validate/scenarios":    `{"count":1,"scenarios":[{"id":"s1","name":"Mimikatz","kind":"single","platform":"linux","steps":2,"benign":false,"techniques":["T1003"]}]}`,
		"GET /v1/validate/scenarios/s1": `{"scenario":{"id":"s1","name":"Mimikatz","kind":"single","platform":"linux","steps":[{"a":1}]}}`,
		"POST /v1/validate/run":         `{"count":1,"recorded":false,"results":[{"id":"s1","kind":"single","pass":true,"fired":[{"rule":"r"}],"outcomes":[{"expect":"T1003","status":"detected"}]}]}`,
		"GET /v1/validate/coverage":     `{"counts":{"detected":1,"missed":1,"not_testable":1},"claimed_techniques":3,"missed":[{"id":"T1","name":"Missed tech"}],"not_testable":[{"id":"T2","name":"NT tech","reason":"needs kernel"}]}`,
	})
	out, err := nxRun(t, "validate", "scenarios", "--kind", "chain", "--technique", "T1003")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "s1", "Synthetic data, not a guarantee")
	if r := (*reqs)[0]; r.method != "GET" || r.path != "/v1/validate/scenarios" || r.query != "kind=chain&technique=T1003" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "validate", "show", "s1"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "Mimikatz", "1 steps")
	if out, err = nxRun(t, "validate", "run", "--ids", "s1,s2"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "1 of 1 scenarios passed", "not a guarantee")
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/validate/run" || r.body != `{"ids":["s1","s2"]}` {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "validate", "run"); err == nil {
		t.Fatal("run needs --ids or --all")
	}
	if _, err = nxRun(t, "validate", "run", "--all", "--include-custom"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.body != `{"all":true,"include_custom":true}` {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "validate", "coverage"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "not a guarantee", "Missed (1)", "Missed tech", "Not testable (1)", "needs kernel")
	raw, err := nxRun(t, "validate", "coverage", "--include-custom", "--json")
	if err != nil || !json.Valid([]byte(raw)) || !strings.Contains(raw, `"claimed_techniques":3`) {
		t.Fatalf("%v %s", err, raw)
	}
	if r := (*reqs)[len(*reqs)-1]; r.query != "include_custom=true" {
		t.Fatalf("%+v", r)
	}
}

func TestNxVulns(t *testing.T) {
	item := `{"rank":1,"host":"h1","package":"openssl","version":"1.0","cve":"CVE-2099-1","ssvc_outcome":"Act","epss":null,"cvss":9.8,"known_exploited":true,
"factors":[{"decision_point":"exploitation","value":"unknown","source":"epss","known":false,"assumed_value":"poc","evidence":"feed off"}],
"ssvc":{"unknown_inputs":["exploitation"],"outcome_if_unknowns_favourable":"Attend","outcome_if_unknowns_adverse":"Act","outcome_depends_on_unknowns":true},"explanation":["why"]}`
	feed := true
	reqs := nxServer(t, map[string]string{
		"GET /v1/vulns/priority":            `{"tree_version":"v1","total":2,"count":1,"ranking":"r","items":[` + item + `],"limitations":["lim one"]}`,
		"GET /v1/vulns/priority/CVE-2099-1": `{"cve":"CVE-2099-1","hosts":1,"top_outcome":"Act","items":[` + item + `],"limitations":["lim one"]}`,
		"GET /v1/vulns/priority/status":     `{"tree_version":"v1","epss_feed":{"enabled":false},"thresholds":{},"defaults_for_unknown":{},"limitations":["lim one"]}`,
		"POST /v1/vulns/priority/refresh":   `{"refreshed":3}`,
	})
	out, err := nxRun(t, "vulns", "priority", "--host", "h1", "--limit", "5")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "CVE-2099-1", "unknown", "exploitation", "limitation: lim one")
	if r := (*reqs)[0]; r.query != "host=h1&limit=5" {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "vulns", "priority", "--limit", "0"); err == nil {
		t.Fatal("limit validated")
	}
	if out, err = nxRun(t, "vulns", "show", "CVE-2099-1"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "FACTOR", "unknown", "feed off", "best case Attend", "worst case Act", "- why")
	if out, err = nxRun(t, "vulns", "status"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "ssvc tree: v1")
	if out, err = nxRun(t, "vulns", "refresh", "--json"); err != nil || strings.TrimSpace(out) != `{"refreshed":3}` {
		t.Fatalf("%v %q", err, out)
	}
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/vulns/priority/refresh" {
		t.Fatalf("%+v", r)
	}
	_ = feed
}

func TestNxVulnsRefresh409(t *testing.T) {
	nxServer(t, map[string]string{"POST /v1/vulns/priority/refresh": `409:{"error":"EPSS feed disabled"}`})
	if _, err := nxRun(t, "vulns", "refresh"); err == nil || !strings.Contains(err.Error(), "KAVACH_EPSS_FEED") {
		t.Fatalf("%v", err)
	}
}

func TestNxHuntSeq(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"POST /v1/hunt/seq":         `{"kind":"sequence","count":1,"matches":[{"key":"h1","span_ms":5,"events":[{"step":1,"category":"process","id":"e1","time":"t","fields":{"pid":1}}]}],"truncated":true,"timed_out":true,"scan_capped":true,"scanned":10,"scanned_total":20,"elapsed_ms":3,"semantics":"skip-till"}`,
		"GET /v1/hunt/seq/fields":   `{"categories":[{"category":"process","source":"ledger","fields":[{"name":"pid","type":"int"}],"absent":[{"name":"hash","reason":"no hash recorded"}]}],"join_keys":["host","pid"],"operators":{},"notes":["n1"],"limits":{}}`,
		"GET /v1/hunt/seq/examples": `{"count":1,"examples":[{"id":"x1","name":"Ex","tactic":"t","technique":"T1","description":"d","query":"q","noisy":true}]}`,
		"POST /v1/hunt/seq/explain": `{"ok":false,"kind":"sequence","unavailable_fields":[{"category":"process","field":"hash","line":1,"col":5,"reason":"no hash recorded"}],"semantics":"s"}`,
	})
	out, err := nxRun(t, "hunt", "seq", "sequence", "by", "host", "[process]", "--since", "24h", "--limit", "7")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "1 match", "TRUNCATED", "TIMED OUT", "SCAN CAPPED", "scanned 10 of 20")
	r := (*reqs)[0]
	if r.method != "POST" || r.path != "/v1/hunt/seq" || r.body != `{"limit":7,"query":"sequence by host [process]","since":"24h"}` {
		t.Fatalf("%+v", r)
	}
	f := filepath.Join(t.TempDir(), "q.eql")
	_ = os.WriteFile(f, []byte("sequence [process]\n"), 0o600)
	if _, err = nxRun(t, "hunt", "seq", "--file", f); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; !strings.Contains(r.body, `"query":"sequence [process]"`) {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "hunt", "seq", "fields"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "process", "not available: hash: no hash recorded", "join keys: host,pid")
	if out, err = nxRun(t, "hunt", "seq", "examples"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "x1", "noisy")
	if out, err = nxRun(t, "hunt", "seq", "explain", "sequence [process where hash == 1]"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "unavailable field: process.hash", "no hash recorded")
	if r := (*reqs)[len(*reqs)-1]; r.path != "/v1/hunt/seq/explain" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "hunt", "seq", "--json", "q"); err != nil || !strings.HasPrefix(out, `{"kind":"sequence"`) {
		t.Fatalf("%v %q", err, out)
	}
	if _, err = nxRun(t, "hunt", "seq"); err == nil {
		t.Fatal("query required")
	}
}

func TestNxHuntSeqUnavailableFields(t *testing.T) {
	nxServer(t, map[string]string{"POST /v1/hunt/seq": `400:{"error":"query uses unavailable fields","problems":[{"line":1,"col":9,"category":"process","field":"user","reason":"numeric uid only"}]}`})
	out, err := nxRun(t, "hunt", "seq", "q")
	if err == nil || !strings.Contains(err.Error(), "unavailable fields") {
		t.Fatalf("%v", err)
	}
	nxWant(t, out, "process.user: numeric uid only")
}

func TestNxFeedback(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"POST /v1/feedback":        `{"seq":3,"finding_id":"f1","verdict":"false_positive","actor":"a","rule":"r1","host":"h1"}`,
		"GET /v1/feedback":         `{"entries":[{"seq":3,"time":"2026-11-13T10:00:00Z","finding_id":"f1","verdict":"false_positive","rule":"r1","host":"h1","actor":"a"}]}`,
		"GET /v1/feedback/rules":   `{"method":{"min_verdicts":5,"review_below":0.3},"ranked_by_shrunk_precision":[],"not_enough_verdicts":[{"rule":"r9","decided_findings":1,"note":"too few"}],"review_candidates":["r2"]}`,
		"GET /v1/feedback/summary": `{"entries_total":4,"findings_with_verdict":3,"recent_days":7,"verdict_coverage":null,"mean_seconds_to_first_verdict":null,"note":"biased subset"}`,
		"GET /v1/feedback/verify":  `{"ok":true,"entries":4}`,
		"POST /v1/feedback/export": `{"redacted":true,"chain_ok":true,"labels":[],"entries":[],"label_rule":"lr","caveat":"labels are noisy"}`,
	})
	if _, err := nxRun(t, "feedback", "record", "--finding", "f1", "--verdict", "false_positive"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("confirmation required: %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatalf("no request without confirmation: %v", *reqs)
	}
	if _, err := nxRun(t, "feedback", "record", "--finding", "f1", "--verdict", "bogus", "--yes"); err == nil {
		t.Fatal("verdict validated")
	}
	out, err := nxRun(t, "feedback", "record", "--finding", "f1", "--verdict", "false_positive", "--note", "ok", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "recorded #3")
	if r := (*reqs)[0]; r.method != "POST" || r.body != `{"finding_id":"f1","note":"ok","verdict":"false_positive"}` {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "feedback", "list", "--finding", "f1", "--rule", "r1", "--host", "h1", "--limit", "9"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "false_positive")
	if r := (*reqs)[len(*reqs)-1]; r.query != "finding_id=f1&host=h1&limit=9&rule=r1" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "feedback", "rules", "--min-verdicts", "3"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "not_enough_verdicts (1 rules)", "r9", "too few", "r2")
	if r := (*reqs)[len(*reqs)-1]; r.query != "min_verdicts=3" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "feedback", "summary", "--days", "30"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "coverage unknown", "biased subset")
	if out, err = nxRun(t, "feedback", "verify"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "intact")
	if out, err = nxRun(t, "feedback", "export", "--redact", "--out", filepath.Join(t.TempDir(), "x.json")); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "labels are noisy", "redacted=true")
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/feedback/export" || r.query != "redact=1" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "feedback", "export", "--json"); err != nil || !json.Valid([]byte(out)) {
		t.Fatalf("%v %q", err, out)
	}
	if r := (*reqs)[len(*reqs)-1]; r.query != "" {
		t.Fatalf("%+v", r)
	}
}

func TestNxCompetitive(t *testing.T) {
	reqs := nxServer(t, map[string]string{"GET /v1/world/competitive": `{"last_researched":"2026-11-13","note":"srv note","products":[{"id":"a","name":"A"},{"id":"kavach","name":"K"}],
"areas":[{"id":"tel","name":"Telemetry"}],"matrix":{"tel":{"a":{"status":"Not documented"},"kavach":{"status":"Partial"}}},
"backlog":[{"id":1,"title":"Hashing","effort":"M","telemetry_sufficient":"No","conflicts_with_observation_only":"No"}],"sources":[{"id":"S1"}]}`})
	out, err := nxRun(t, "competitive")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "public documentation, may be out of date", "Telemetry", "n/d", "Part", "backlog: 1 candidate", "Hashing", "M=1")
	if r := (*reqs)[0]; r.method != "GET" || r.path != "/v1/world/competitive" || r.query != "" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "competitive", "--json"); err != nil || !strings.Contains(out, `"last_researched"`) || strings.Contains(out, "backlog:") {
		t.Fatalf("%v %q", err, out)
	}
}

func TestNxChains(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"GET /v1/chains":           `{"total":2,"returned":1,"method":"m","limitations":["heuristic"],"chains":[{"id":"c-1","hosts":["h1"],"score":3.5,"severity":"high","size":2,"tactics":["Execution","Impact"]}]}`,
		"GET /v1/chains/c-1":       `{"chain":{"id":"c-1","hosts":["h1"],"score":3.5,"severity":"high","size":2,"why_summary":[{"reason":"same story","weight":2}]},"members":[{"id":"f1","host":"h1","rule":"r","severity":"high"}],"tactics_in_order":["Execution"],"suggested_questions":["q?"],"questions_note":"hints","limitations":["heuristic"]}`,
		"POST /v1/chains/c-1/case": `{"created":true,"case":{"id":"case-9","title":"T","severity":"high","status":"open"}}`,
	})
	out, err := nxRun(t, "chains", "list", "--host", "h1", "--min-score", "2.5", "--limit", "10")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "c-1", "Execution > Impact", "limitation: heuristic")
	if r := (*reqs)[0]; r.query != "host=h1&limit=10&min_score=2.5" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "chains", "show", "c-1"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "same story", "q?", "limitation: heuristic")
	n := len(*reqs)
	if _, err = nxRun(t, "chains", "case", "c-1"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("%v", err)
	}
	if len(*reqs) != n {
		t.Fatal("request sent without confirmation")
	}
	if out, err = nxRun(t, "chains", "case", "c-1", "--yes"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "case created: case-9")
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/chains/c-1/case" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "chains", "list", "--json"); err != nil || !strings.HasPrefix(out, `{"chains"`) && !strings.HasPrefix(out, `{"total"`) {
		t.Fatalf("%v %q", err, out)
	}
}

const nxWF = `{"case_id":"c1","assignee":"alice","assignee_note":"free text","severity":"high","status":"open","template_name":"Ransomware","template_id":"t1","checklist":[{"text":"Isolate","done":true,"by":"a"},{"text":"Report","done":false}],"checklist_progress":{"done":1,"total":2}}`

func TestNxCaseTemplates(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"GET /v1/case-templates":          `[{"id":"t1","name":"Ransom","case_type":"ransomware","default_severity":"high","checklist":["a","b"],"built_in":true}]`,
		"GET /v1/case-templates/t1":       `{"id":"t1","name":"Ransom","case_type":"ransomware","default_severity":"high","checklist":["a","b"],"built_in":true}`,
		"POST /v1/case-templates":         `{"id":"tpl-1","name":"N"}`,
		"PUT /v1/case-templates/tpl-1":    `{"id":"tpl-1","name":"N2"}`,
		"DELETE /v1/case-templates/tpl-1": `{"deleted":"tpl-1"}`,
	})
	out, err := nxRun(t, "casetemplates", "list")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "t1", "ransomware")
	if out, err = nxRun(t, "casetemplates", "show", "t1"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "1. a", "2. b")
	f := filepath.Join(t.TempDir(), "t.json")
	_ = os.WriteFile(f, []byte(`{"name":"N","case_type":"x","checklist":["s"]}`), 0o600)
	n := len(*reqs)
	for _, a := range [][]string{{"create", "--file", f}, {"update", "tpl-1", "--file", f}, {"delete", "tpl-1"}} {
		if _, err = nxRun(t, append([]string{"casetemplates"}, a...)...); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("%v: %v", a, err)
		}
	}
	if len(*reqs) != n {
		t.Fatal("requests sent without confirmation")
	}
	if _, err = nxRun(t, "casetemplates", "create", "--file", f, "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/case-templates" || r.body != `{"name":"N","case_type":"x","checklist":["s"]}` {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "casetemplates", "update", "tpl-1", "--file", f, "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.method != "PUT" || r.path != "/v1/case-templates/tpl-1" {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "casetemplates", "delete", "tpl-1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.method != "DELETE" || r.path != "/v1/case-templates/tpl-1" {
		t.Fatalf("%+v", r)
	}
}

func TestNxCaseWorkflow(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"GET /v1/cases/c1/workflow":        nxWF,
		"POST /v1/cases/c1/assign":         nxWF,
		"POST /v1/cases/c1/apply-template": nxWF,
		"POST /v1/cases/c1/checklist/2":    nxWF,
		"GET /v1/case-workflow/journal":    `{"intact":true,"entries":[{"seq":1,"time":"2026-11-13T10:00:00Z","actor":"a","action":"case.assign","target":"c1 -> alice"}]}`,
	})
	out, err := nxRun(t, "case", "workflow", "c1")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "assignee alice", "checklist 1 of 2 done", "[x] Isolate", "[ ] Report")
	n := len(*reqs)
	for _, a := range [][]string{{"assign", "c1", "--to", "bob"}, {"apply-template", "c1", "--template", "t1"}, {"checklist", "c1", "2", "--done"}} {
		if _, err = nxRun(t, append([]string{"case"}, a...)...); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("%v: %v", a, err)
		}
	}
	if len(*reqs) != n {
		t.Fatal("requests sent without confirmation")
	}
	if _, err = nxRun(t, "case", "assign", "c1", "--to", "bob", "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.method != "POST" || r.path != "/v1/cases/c1/assign" || r.body != `{"assignee":"bob"}` {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "case", "apply-template", "c1", "--template", "t1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.path != "/v1/cases/c1/apply-template" || r.body != `{"template_id":"t1"}` {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "case", "checklist", "c1", "2", "--done", "--yes"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.path != "/v1/cases/c1/checklist/2" || r.body != `{"done":true}` {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "case", "checklist", "c1", "2", "--yes"); err == nil {
		t.Fatal("--done or --undo required")
	}
	if out, err = nxRun(t, "case", "journal"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "journal chain intact", "case.assign")
	if out, err = nxRun(t, "case", "workflow", "c1", "--json"); err != nil || strings.TrimSpace(out) != nxWF {
		t.Fatalf("%v %q", err, out)
	}
}

func TestNxContentAndCoverage(t *testing.T) {
	reqs := nxServer(t, map[string]string{
		"GET /v1/content/versions":    `{"count":1,"history_cap":50,"note":"newest first","snapshots":[{"seq":2,"time":"t","build":"b","hash":"abcdef1234567890","total_items":9,"packs":[{"name":"p","kind":"detection","hash":"h","count":9,"items":[{"id":"r1","hash":"zz"}]}]}]}`,
		"GET /v1/content/changes":     `{"from":{"seq":1,"time":"t1"},"to":{"seq":2,"time":"t2"},"diff":{"identical":false,"added":[{"pack":"p","kind":"detection","id":"r2"}],"removed":[],"modified":[{"pack":"p","kind":"detection","id":"r1","fields_changed":["severity"],"highlights":["severity"]}]}}`,
		"GET /v1/content/changelog":   `{"count":1,"changelog":[{"seq":2,"time":"t","build":"b","total_items":9,"summary":"vs snapshot 1: 1 added"}]}`,
		"GET /v1/coverage/blindspots": `{"caveat":"No events received may mean none happened, not that collection is broken.","stale_after_hours":168,"techniques_claimed":5,"techniques_unobservable_count":1,"techniques_unobservable":[{"technique":"T1","categories_required":["dns"],"reason":"zero events"}],"techniques_at_risk_stale":[],"collection_gaps":[{"category":"dns","state":"never_seen","message":"no dns events received"}],"enable_first":[{"rank":1,"advice":"Enable dns telemetry collection"}],"validation":{"available":true,"missed":[],"not_testable":[],"note":"synthetic"},"telemetry":[{"category":"dns","state":"never_seen","events_held":0}]}`,
		"GET /v1/coverage/telemetry":  `{"caveat":"srv caveat","stale_after_hours":72,"categories":[{"category":"process","state":"active","events_held":4,"last_seen":"t","age_hours":1}]}`,
	})
	out, err := nxRun(t, "content", "versions", "--items")
	if err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "abcdef123456", "r1", "history cap 50")
	if r := (*reqs)[0]; r.query != "items=1" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "content", "changes", "--from", "1", "--to", "latest"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "added (1)", "r2", "HIGHLIGHT: severity")
	if r := (*reqs)[len(*reqs)-1]; r.query != "from=1&to=latest" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "content", "changelog"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "1 added")
	if out, err = nxRun(t, "coverage", "blindspots", "--stale-days", "14"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "No events received may mean none happened", "dns", "Enable dns telemetry", "T1")
	if r := (*reqs)[len(*reqs)-1]; r.query != "stale_days=14" {
		t.Fatalf("%+v", r)
	}
	if out, err = nxRun(t, "coverage", "telemetry", "--stale-days", "3"); err != nil {
		t.Fatal(err)
	}
	nxWant(t, out, "No events received may mean none happened", "process", "active")
	if r := (*reqs)[len(*reqs)-1]; r.path != "/v1/coverage/telemetry" || r.query != "stale_days=3" {
		t.Fatalf("%+v", r)
	}
	if _, err = nxRun(t, "coverage", "blindspots", "--stale-days", "x"); err == nil {
		t.Fatal("stale-days validated")
	}
	if out, err = nxRun(t, "coverage", "telemetry", "--json"); err != nil || strings.Contains(out, "CAVEAT") || !json.Valid([]byte(out)) {
		t.Fatalf("%v %q", err, out)
	}
}
