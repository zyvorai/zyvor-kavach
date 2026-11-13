package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type schedRec struct{ reqs []string }

// schedMock serves every path with the given status/body and records "METHOD URI body".
func schedMock(t *testing.T, status int, body string, ctype string) *schedRec {
	t.Helper()
	rec := &schedRec{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.reqs = append(rec.reqs, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		if ctype != "" {
			w.Header().Set("Content-Type", ctype)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	setupMock(t, mux)
	return rec
}

func schedDo(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf strings.Builder
	ok, err := schedDispatch(args, &buf)
	if !ok {
		t.Fatalf("%v not handled", args)
	}
	return buf.String(), err
}

func schedFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noTTY(t *testing.T) {
	old := mlInteractive
	mlInteractive = func() bool { return false }
	t.Cleanup(func() { mlInteractive = old })
}

func TestSchedFallsThrough(t *testing.T) {
	for _, a := range [][]string{{"inspect", "file", "x"}, {"detections"}, {"detections", "list"}, {"fleet", "health"}, {"report", "x"}, {"reports"}, {"reports", "other"}} {
		var buf strings.Builder
		if ok, _ := schedDispatch(a, &buf); ok {
			t.Fatalf("%v should fall through", a)
		}
	}
}

func TestDetSchedReads(t *testing.T) {
	rec := schedMock(t, 200, `{"detections":[{"id":"sd-1","name":"n","state":"testing","severity":"high","interval_sec":60,"source":{"kind":"seq"}}],"count":1,"history":[{"time":"t","trigger":"dryrun","recorded":3}],"retention":20,"semantics":"never block"}`, "application/json")
	out, err := schedDo(t, "detections", "scheduled", "list")
	if err != nil || !strings.Contains(out, "sd-1") || !strings.Contains(out, "never block") {
		t.Fatalf("%v %s", err, out)
	}
	out, _ = schedDo(t, "detections", "scheduled", "history", "sd-1")
	if !strings.Contains(out, "'recorded' means 'would be reported'") {
		t.Fatal(out)
	}
	out, _ = schedDo(t, "detections", "scheduled", "list", "--json")
	if !strings.HasPrefix(out, `{"detections"`) {
		t.Fatalf("json passthrough: %s", out)
	}
	schedDo(t, "detections", "scheduled", "show", "sd-1")
	want := []string{"GET /v1/detections/scheduled ", "GET /v1/detections/scheduled/sd-1/history ", "GET /v1/detections/scheduled ", "GET /v1/detections/scheduled/sd-1 "}
	for i, w := range want {
		if rec.reqs[i] != w {
			t.Fatalf("req %d = %q want %q", i, rec.reqs[i], w)
		}
	}
}

func TestDetSchedDryrunNoConfirm(t *testing.T) {
	noTTY(t)
	rec := schedMock(t, 200, `{"run":{"recorded":2},"dry_run":true}`, "application/json")
	out, err := schedDo(t, "detections", "scheduled", "dryrun", "sd-1")
	if err != nil || !strings.Contains(out, "would be reported") || !strings.Contains(out, "nothing was recorded") {
		t.Fatalf("%v %s", err, out)
	}
	if rec.reqs[0] != "POST /v1/detections/scheduled/sd-1/dryrun {}" {
		t.Fatal(rec.reqs)
	}
}

func TestSchedMutatingNeedsYes(t *testing.T) {
	noTTY(t)
	f := schedFile(t, `{"name":"x"}`)
	cases := [][]string{
		{"detections", "scheduled", "create", "--file", f},
		{"detections", "scheduled", "update", "sd-1", "--file", f},
		{"detections", "scheduled", "delete", "sd-1"},
		{"detections", "scheduled", "run", "sd-1"},
		{"hunts", "limits", "--set", "max_scheduled=5"},
		{"exceptions", "create", "--file", f},
		{"exceptions", "update", "ex-1", "--file", f},
		{"exceptions", "expire", "ex-1"},
		{"exceptions", "delete", "ex-1"},
		{"reports", "scheduled", "create", "--file", f},
		{"reports", "scheduled", "update", "rs-1", "--file", f},
		{"reports", "scheduled", "delete", "rs-1"},
		{"reports", "scheduled", "run", "rs-1"},
		{"fleet", "slo", "set", "--file", f},
	}
	rec := schedMock(t, 200, `{}`, "application/json")
	for _, c := range cases {
		if _, err := schedDo(t, c...); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("%v: want --yes error, got %v", c, err)
		}
	}
	if len(rec.reqs) != 0 {
		t.Fatalf("requests sent without confirmation: %v", rec.reqs)
	}
}

func TestSchedMutatingWithYes(t *testing.T) {
	noTTY(t)
	f := schedFile(t, `{"name":"x"}`)
	rec := schedMock(t, 200, `{"ok":true}`, "application/json")
	for _, c := range [][]string{
		{"detections", "scheduled", "create", "--file", f, "--yes"},
		{"detections", "scheduled", "update", "sd-1", "--file", f, "--yes"},
		{"detections", "scheduled", "delete", "sd-1", "--yes"},
		{"detections", "scheduled", "run", "sd-1", "--yes"},
		{"hunts", "limits", "--set", "max_scheduled=5", "--set=max_runs_per_hour=9", "--yes"},
		{"exceptions", "create", "--file", f, "--yes"},
		{"exceptions", "update", "ex-1", "--file", f, "--yes"},
		{"exceptions", "expire", "ex-1", "--yes"},
		{"exceptions", "delete", "ex-1", "--yes"},
		{"reports", "scheduled", "create", "--file", f, "--yes"},
		{"reports", "scheduled", "update", "rs-1", "--file", f, "--yes"},
		{"reports", "scheduled", "delete", "rs-1", "--yes"},
		{"reports", "scheduled", "run", "rs-1", "--yes"},
		{"fleet", "slo", "set", "--file", f, "--yes"},
	} {
		if _, err := schedDo(t, c...); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	want := []string{
		`POST /v1/detections/scheduled {"name":"x"}`,
		`PUT /v1/detections/scheduled/sd-1 {"name":"x"}`,
		`DELETE /v1/detections/scheduled/sd-1 `,
		`POST /v1/detections/scheduled/sd-1/run {}`,
		`PUT /v1/hunts/limits {"max_runs_per_hour":9,"max_scheduled":5}`,
		`POST /v1/exceptions {"name":"x"}`,
		`PUT /v1/exceptions/ex-1 {"name":"x"}`,
		`PUT /v1/exceptions/ex-1 {"expire_now":true}`,
		`DELETE /v1/exceptions/ex-1 `,
		`POST /v1/reports/scheduled {"name":"x"}`,
		`PUT /v1/reports/scheduled/rs-1 {"name":"x"}`,
		`DELETE /v1/reports/scheduled/rs-1 `,
		`POST /v1/reports/scheduled/rs-1/run {}`,
		`PUT /v1/fleet/slo {"name":"x"}`,
	}
	if len(rec.reqs) != len(want) {
		t.Fatalf("got %v", rec.reqs)
	}
	for i := range want {
		if rec.reqs[i] != want[i] {
			t.Fatalf("req %d = %q want %q", i, rec.reqs[i], want[i])
		}
	}
}

func TestSched403Clear(t *testing.T) {
	schedMock(t, 403, `{"error":"admin token required to change hunt limits"}`, "application/json")
	_, err := schedDo(t, "hunts", "limits", "--set", "max_scheduled=5", "--yes")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "admin token required") {
		t.Fatalf("%v", err)
	}
}

func TestSchedFileCapAndBadSet(t *testing.T) {
	noTTY(t)
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(`{"a":"`+strings.Repeat("x", schedFileMax)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := schedMock(t, 200, `{}`, "application/json")
	if _, err := schedDo(t, "exceptions", "create", "--file", big, "--yes"); err == nil || !strings.Contains(err.Error(), "accepts at most") {
		t.Fatalf("%v", err)
	}
	if _, err := schedDo(t, "hunts", "limits", "--set", "bogus=1", "--yes"); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := schedDo(t, "exceptions", "create", "--file", schedFile(t, "[1]"), "--yes"); err == nil {
		t.Fatal("non-object accepted")
	}
	if len(rec.reqs) != 0 {
		t.Fatal(rec.reqs)
	}
}

func TestExceptionsReads(t *testing.T) {
	rec := schedMock(t, 200, `{"exceptions":[{"id":"ex-1","status":"active","rule":"r","owner":"o","reason":"why","suppressed_count":2}],"count":1,"chain":{"ok":false,"broken_at_seq":4,"entries":5},"history":[],"chain_ok":true,"suppressed":[{"exception_id":"ex-1","finding":{"id":"f1"}}],"total_suppressed":1}`, "application/json")
	out, _ := schedDo(t, "exceptions", "list", "--status", "active")
	if !strings.Contains(out, "nothing is blocked") || !strings.Contains(out, "BROKEN at seq 4") {
		t.Fatal(out)
	}
	out, _ = schedDo(t, "exceptions", "suppressed", "--exception", "ex-1")
	if !strings.Contains(out, "Reporting was suppressed") {
		t.Fatal(out)
	}
	out, _ = schedDo(t, "exceptions", "history")
	if !strings.Contains(out, "Chain integrity: OK") {
		t.Fatal(out)
	}
	out, _ = schedDo(t, "exceptions", "list", "--json")
	if !strings.HasPrefix(out, `{"exceptions"`) {
		t.Fatal(out)
	}
	want := []string{"GET /v1/exceptions?status=active ", "GET /v1/exceptions/suppressed?exception=ex-1 ", "GET /v1/exceptions/history ", "GET /v1/exceptions "}
	for i, w := range want {
		if rec.reqs[i] != w {
			t.Fatalf("req %d = %q want %q", i, rec.reqs[i], w)
		}
	}
}

func TestReportsArchive(t *testing.T) {
	rec := schedMock(t, 200, "REPORT-BYTES", "text/html")
	dir := t.TempDir()
	// no --out: nothing written anywhere
	out, err := schedDo(t, "reports", "archive", "get", "run-1")
	if err != nil || !strings.Contains(out, "Nothing was written") {
		t.Fatalf("%v %s", err, out)
	}
	if ents, _ := os.ReadDir("."); func() bool {
		for _, e := range ents {
			if strings.Contains(e.Name(), "run-1") {
				return true
			}
		}
		return false
	}() {
		t.Fatal("file written without --out")
	}
	dst := filepath.Join(dir, "r.html")
	out, err = schedDo(t, "reports", "archive", "get", "run-1", "--out", dst)
	if err != nil || !strings.Contains(out, "Wrote 12 bytes") {
		t.Fatalf("%v %s", err, out)
	}
	if b, _ := os.ReadFile(dst); string(b) != "REPORT-BYTES" {
		t.Fatal(string(b))
	}
	if _, err := schedDo(t, "reports", "archive", "get", "run-1", "--out", dst); err == nil {
		t.Fatal("overwrite without --force")
	}
	if _, err := schedDo(t, "reports", "scheduled", "archive", "get", "run-1", "--out", dst, "--force", "--json"); err != nil {
		t.Fatal(err)
	}
	if _, err := schedDo(t, "reports", "archive", "get", "../x"); err == nil {
		t.Fatal("bad id")
	}
	if rec.reqs[0] != "GET /v1/reports/archive/run-1 " {
		t.Fatal(rec.reqs)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatal("unexpected files", ents)
	}
}

func TestReportsScheduledReads(t *testing.T) {
	rec := schedMock(t, 200, `{"schedules":[{"id":"rs-1","template":"t","frequency":"daily","enabled":true}],"delivery":"pull-only: x","runs":[{"run_id":"r1","status":"ok"}]}`, "application/json")
	out, _ := schedDo(t, "reports", "scheduled", "list")
	if !strings.Contains(out, "pull-only") {
		t.Fatal(out)
	}
	out, _ = schedDo(t, "reports", "scheduled", "runs", "rs-1")
	if !strings.Contains(out, "r1") || rec.reqs[1] != "GET /v1/reports/scheduled/rs-1/runs " {
		t.Fatal(out, rec.reqs)
	}
}

func TestFleetSLO(t *testing.T) {
	rec := schedMock(t, 200, `{"generated_at":"g","targets":{"window_hours":24},"fleet":{"active":1},"agents":[{"host":"h1","state":"online","heartbeat_current":"fresh","samples_in_window":3}],"breaches":[],"not_reported_by_agent":["agent_cpu_percent"],"points":[],"window":"6h0m0s","step_seconds":300}`, "application/json")
	out, _ := schedDo(t, "fleet", "slo")
	if !strings.Contains(out, "agent_cpu_percent: not reported by agent") || !strings.Contains(out, "h1") {
		t.Fatal(out)
	}
	schedDo(t, "fleet", "slo", "status", "--json")
	schedDo(t, "fleet", "slo", "history", "--agent", "h 1", "--window", "6h")
	schedDo(t, "fleet", "slo", "definitions")
	want := []string{"GET /v1/fleet/slo ", "GET /v1/fleet/slo ", "GET /v1/fleet/slo/history?agent=h+1&window=6h ", "GET /v1/fleet/slo/definitions "}
	for i, w := range want {
		if rec.reqs[i] != w {
			t.Fatalf("req %d = %q want %q", i, rec.reqs[i], w)
		}
	}
}

func TestSyslog(t *testing.T) {
	rec := schedMock(t, 200, `{"enabled":false,"note":"Disabled by default.","samples":["a"],"count":1,"parsed":true,"ingested":false}`, "application/json")
	out, _ := schedDo(t, "syslog", "status")
	if !strings.Contains(out, "DISABLED") {
		t.Fatal(out)
	}
	schedDo(t, "syslog", "samples")
	out, err := schedDo(t, "syslog", "parse", "Oct", "11", "x", "--sender", "10.0.0.1")
	if err != nil || !strings.Contains(out, "nothing was ingested") {
		t.Fatalf("%v %s", err, out)
	}
	old := omStdin
	omStdin = strings.NewReader("line from stdin\n")
	defer func() { omStdin = old }()
	schedDo(t, "syslog", "parse", "-")
	want := []string{"GET /v1/syslog/status ", "GET /v1/syslog/samples ", `POST /v1/syslog/parse {"line":"Oct 11 x","sender":"10.0.0.1"}`, `POST /v1/syslog/parse {"line":"line from stdin","sender":""}`}
	for i, w := range want {
		if rec.reqs[i] != w {
			t.Fatalf("req %d = %q want %q", i, rec.reqs[i], w)
		}
	}
	if _, err := schedDo(t, "syslog", "parse", strings.Repeat("a", syslogMaxLine+1)); err == nil {
		t.Fatal("oversize line accepted")
	}
}

func TestInspectConfig(t *testing.T) {
	rec := schedMock(t, 200, `{"id":"r1","name":"sshd_config","level":"not_scored","factors":["configuration assessment: no verdict score"],"meta":{"config-assess.summary":{"format":"sshd","counts":{"pass":3,"fail":1,"unknown":0,"not_applicable":2},"compliance_pct":75,"policies_for_format":6,"results":[{"policy_id":"p1","title":"Root login","severity":"high","status":"fail","remediation":"Set PermitRootLogin no"},{"policy_id":"p2","status":"pass"}],"note":"not an audit of the host"}}}`, "application/json")
	p := filepath.Join(t.TempDir(), "sshd_config")
	os.WriteFile(p, []byte("PermitRootLogin yes\n"), 0o600)
	out, err := schedDo(t, "inspect", "config", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"not a malware verdict", "fail=1", "pass=3", "[high] Root login", "remediation: Set PermitRootLogin no", "not_scored", "not an audit"} {
		if !strings.Contains(out, s) {
			t.Fatalf("missing %q in\n%s", s, out)
		}
	}
	if rec.reqs[0] != "POST /v1/inspect/config?name=sshd_config PermitRootLogin yes\n" {
		t.Fatal(rec.reqs)
	}
	out, _ = schedDo(t, "inspect", "config", p, "--json")
	if !strings.HasPrefix(out, `{"id":"r1"`) {
		t.Fatal(out)
	}
	// size cap: sparse 32 MiB + 1 file refused before any request
	big := filepath.Join(t.TempDir(), "big")
	fh, _ := os.Create(big)
	fh.Truncate(inspectMaxFile + 1)
	fh.Close()
	n := len(rec.reqs)
	if _, err := schedDo(t, "inspect", "config", big); err == nil || !strings.Contains(err.Error(), "accepts at most") {
		t.Fatalf("%v", err)
	}
	if len(rec.reqs) != n {
		t.Fatal("oversize file was sent")
	}
}
