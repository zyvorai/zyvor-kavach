package edr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const govTok = "0123456789abcdef"

func govReq(t *testing.T, method, url, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// govSeed writes 2 old + 1 new finding and ledger rows, then opens the store.
func govSeed(t *testing.T) (*httptest.Server, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "f.jsonl")
	now := time.Now().UTC()
	old := now.Add(-60 * 24 * time.Hour)
	var fb, eb strings.Builder
	for i, tm := range []time.Time{old, old, now} {
		f := Finding{ID: fmt.Sprintf("f%d", i), Time: tm, Host: "host-a", Rule: "r", Severity: "high",
			Description: "login by alice@example.com", Evidence: Event{Host: "host-a", Command: "curl --password hunter2 10.1.2.3"}}
		b, _ := json.Marshal(f)
		fb.Write(b)
		fb.WriteString("\n")
	}
	for i, tm := range []time.Time{old, now} {
		p, _ := json.Marshal(ledgerEntry{Process: &Event{ID: fmt.Sprintf("p%d", i), Time: tm, Host: "h", Command: "x"}})
		n, _ := json.Marshal(ledgerEntry{Network: &NetworkEvent{ID: fmt.Sprintf("n%d", i), Time: tm, Host: "h", Destination: "1.1.1.1"}})
		fe, _ := json.Marshal(ledgerEntry{File: &FileEvent{ID: fmt.Sprintf("fe%d", i), Time: tm, Host: "h", Path: "/tmp/x", Operation: "create"}})
		eb.Write(p)
		eb.WriteString("\n")
		eb.Write(n)
		eb.WriteString("\n")
		eb.Write(fe)
		eb.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(fb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".events", []byte(eb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := workspaceData{Notes: []Note{{ID: "n1", FindingID: "f0", Author: "bob", Text: "contacted alice@example.com", Created: now}}}
	wb, _ := json.Marshal(ws)
	_ = os.WriteFile(path+".workspace.json", wb, 0o600)
	s, err := NewStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterDataGovernance(mux, govTok, s, nil)
	RegisterExport(mux, govTok, s, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s, path
}

func TestGovInventory(t *testing.T) {
	srv, _, _ := govSeed(t)
	code, body := govReq(t, "GET", srv.URL+"/v1/governance/inventory", govTok, "")
	if code != 200 {
		t.Fatal(code, body)
	}
	var out struct {
		Classes []govStat `json:"classes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]govStat{}
	for _, c := range out.Classes {
		got[c.Class] = c
	}
	want := map[string]int{"findings": 3, "process_events": 2, "network_events": 2, "file_events": 2, "notes": 1, "journal": 0, "saved_searches": 0, "alert_rules": 0, "credentials_registry": 0}
	for k, v := range want {
		if got[k].Records != v {
			t.Errorf("%s records=%d want %d", k, got[k].Records, v)
		}
	}
	if got["findings"].Oldest == nil || got["findings"].Bytes == 0 || got["findings"].Where != "f.jsonl" {
		t.Errorf("findings stat %+v", got["findings"])
	}
}

func TestGovRetentionPreviewApplyAndGuard(t *testing.T) {
	srv, s, path := govSeed(t)
	u := srv.URL + "/v1/governance/retention"
	if c, b := govReq(t, "POST", u, govTok, `{"days":{"findings":0}}`); c != 400 {
		t.Fatal("days 0 accepted", c, b)
	}
	if c, _ := govReq(t, "POST", u, govTok, `{"days":{"journal":5}}`); c != 400 {
		t.Fatal("unknown class accepted")
	}
	if c, b := govReq(t, "POST", u, govTok, `{"days":{"findings":30,"process_events":30,"network_events":30,"file_events":30}}`); c != 200 {
		t.Fatal(c, b)
	}
	_, b := govReq(t, "GET", u, govTok, "")
	if !strings.Contains(b, `"findings": 30`) && !strings.Contains(b, `"findings":30`) {
		t.Fatal(b)
	}
	before, _ := os.ReadFile(path)
	c, pb := govReq(t, "POST", u+"/preview", govTok, "")
	if c != 200 || !strings.Contains(pb, `"findings":2`) || !strings.Contains(pb, `"network_events":1`) {
		t.Fatal(c, pb)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || len(s.List()) != 3 {
		t.Fatal("preview mutated store")
	}
	// confirm guard
	for _, body := range []string{``, `{}`, `{"confirm":"yes"}`} {
		if c, _ := govReq(t, "POST", u+"/apply", govTok, body); c != 400 {
			t.Fatalf("body %q got %d", body, c)
		}
	}
	if len(s.List()) != 3 {
		t.Fatal("guard failed")
	}
	if c, _ := govReq(t, "POST", u+"/apply", "", `{"confirm":"purge"}`); c != 401 {
		t.Fatal("unauth apply", c)
	}
	c, ab := govReq(t, "POST", u+"/apply", govTok, `{"confirm":"purge"}`)
	if c != 200 || !strings.Contains(ab, `"findings":2`) {
		t.Fatal(c, ab)
	}
	if len(s.List()) != 1 || len(s.networkEvents) != 1 || len(s.fileEvents) != 1 || len(s.recentEvents) != 1 {
		t.Fatalf("memory not purged: %d", len(s.List()))
	}
	s2, err := NewStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 1 || len(s2.networkEvents) != 1 || len(s2.recentEvents) != 1 || len(s2.fileEvents) != 1 {
		t.Fatal("disk not purged")
	}
	au, err := os.ReadFile(path + govAuditExt)
	if err != nil || !strings.Contains(string(au), "retention.apply") {
		t.Fatal("no audit line", err)
	}
	if _, err := os.Stat(path + ".gov.tmp"); err == nil {
		t.Fatal("tmp left behind")
	}
	// append still works after rewrite
	if err := s.Append(Finding{ID: "new", Time: time.Now()}); err != nil || len(s.List()) != 2 {
		t.Fatal(err)
	}
}

func TestGovRetentionUnlimitedByDefault(t *testing.T) {
	srv, s, _ := govSeed(t)
	c, b := govReq(t, "POST", srv.URL+"/v1/governance/retention/apply", govTok, `{"confirm":"purge"}`)
	if c != 200 || len(s.List()) != 3 {
		t.Fatal(c, b)
	}
}

func TestGovRedactRules(t *testing.T) {
	cases := map[string]string{
		"mail bob@example.com now":               "mail [REDACTED:email] now",
		"conn 192.168.1.20:22":                   "conn [REDACTED:ip]:22",
		"to fe80::1 and 2001:db8:0:0:0:0:0:1":    "to [REDACTED:ip] and [REDACTED:ip]",
		"key AKIAIOSFODNN7EXAMPLE":               "key [REDACTED:aws-key]",
		"Authorization: Bearer abc123def456ghi":  "Authorization: Bearer [REDACTED:token]",
		"mysql --password=hunter2 -h x":          "mysql --password=[REDACTED:secret] -h x",
		"login password=s3cr3t&x=1":              "login password=[REDACTED:secret]",
		"sum 0123456789abcdef0123456789abcdef01": "sum [REDACTED:hex]",
		"time 12:34:56 ls -la":                   "time 12:34:56 ls -la",
		"std::string version 1.2.3":              "std::string version 1.2.3",
	}
	for in, want := range cases {
		if got := govRedact(in); got != want {
			t.Errorf("govRedact(%q)=%q want %q", in, got, want)
		}
	}
	// pathological input must stay fast (RE2)
	big := strings.Repeat("a:", 5000) + strings.Repeat("1", 5000) + strings.Repeat("a@", 3000)
	start := time.Now()
	govRedact(big)
	if time.Since(start) > 3*time.Second {
		t.Fatal("redaction too slow")
	}
}

func TestGovRedactionEndpointsAndExportHook(t *testing.T) {
	srv, _, path := govSeed(t)
	c, b := govReq(t, "POST", srv.URL+"/v1/governance/redact/preview", govTok, `{"text":"a@b.io 10.0.0.1"}`)
	if c != 200 || strings.Contains(b, "a@b.io") || !strings.Contains(b, `"email":1`) {
		t.Fatal(c, b)
	}
	_, b = govReq(t, "GET", srv.URL+"/v1/governance/redaction", govTok, "")
	if !strings.Contains(b, `"enabled":false`) || !strings.Contains(b, "aws_key") {
		t.Fatal(b)
	}
	_, ex := govReq(t, "GET", srv.URL+"/v1/export/findings?format=ndjson", govTok, "")
	if !strings.Contains(ex, "hunter2") {
		t.Fatal("expected raw export when toggle off")
	}
	if c, _ := govReq(t, "POST", srv.URL+"/v1/governance/redaction", govTok, `{}`); c != 400 {
		t.Fatal("missing enabled accepted")
	}
	if c, b := govReq(t, "POST", srv.URL+"/v1/governance/redaction", govTok, `{"enabled":true}`); c != 200 {
		t.Fatal(c, b)
	}
	if raw, err := os.ReadFile(path + govRedactionExt); err != nil || !strings.Contains(string(raw), "true") {
		t.Fatal("toggle not persisted", err)
	}
	_, ex = govReq(t, "GET", srv.URL+"/v1/export/findings?format=ndjson", govTok, "")
	if strings.Contains(ex, "hunter2") || strings.Contains(ex, "10.1.2.3") || !strings.Contains(ex, "REDACTED") {
		t.Fatal("export not redacted:", ex)
	}
}

func TestGovSubject(t *testing.T) {
	srv, _, _ := govSeed(t)
	c, b := govReq(t, "GET", srv.URL+"/v1/governance/subject?q=ALICE@example.com", govTok, "")
	if c != 200 {
		t.Fatal(c, b)
	}
	var out struct {
		Findings struct {
			Count int      `json:"count"`
			IDs   []string `json:"ids"`
		} `json:"findings"`
		Notes struct {
			Count int `json:"count"`
		} `json:"notes"`
	}
	if err := json.Unmarshal([]byte(b), &out); err != nil {
		t.Fatal(err)
	}
	if out.Findings.Count != 3 || len(out.Findings.IDs) != 3 || out.Notes.Count != 1 {
		t.Fatalf("%+v", out)
	}
	if strings.Contains(b, "hunter2") {
		t.Fatal("record body leaked")
	}
	if c, _ := govReq(t, "GET", srv.URL+"/v1/governance/subject?q=ab", govTok, ""); c != 400 {
		t.Fatal("short q accepted")
	}
	_, b = govReq(t, "GET", srv.URL+"/v1/governance/subject?q=%3Cscript%3E", govTok, "")
	if strings.Contains(b, "<script>") {
		t.Fatal("unescaped echo")
	}
}

func TestGovAuth(t *testing.T) {
	srv, _, _ := govSeed(t)
	for _, r := range [][2]string{
		{"GET", "/v1/governance/inventory"}, {"GET", "/v1/governance/retention"}, {"POST", "/v1/governance/retention"},
		{"POST", "/v1/governance/retention/preview"}, {"POST", "/v1/governance/retention/apply"},
		{"GET", "/v1/governance/redaction"}, {"POST", "/v1/governance/redaction"},
		{"POST", "/v1/governance/redact/preview"}, {"GET", "/v1/governance/subject?q=abc"},
	} {
		if c, _ := govReq(t, r[0], srv.URL+r[1], "", `{}`); c != 401 {
			t.Errorf("%s %s without auth = %d", r[0], r[1], c)
		}
		if c, _ := govReq(t, r[0], srv.URL+r[1], "wrong-token-value", `{}`); c != 401 {
			t.Errorf("%s %s bad token = %d", r[0], r[1], c)
		}
	}
}
