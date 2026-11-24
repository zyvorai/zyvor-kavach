// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestZscalerRulesHaveMITREAndGuidance(t *testing.T) {
	var ids []string
	techs := map[string]string{}
	for _, r := range zsRules {
		ids, techs[r.ID] = append(ids, r.ID), r.TechID
	}
	for _, r := range zsPolRules {
		ids, techs[r.ID] = append(ids, r.ID), r.TechID
	}
	for _, r := range zdxRules {
		ids, techs[r.ID] = append(ids, r.ID), r.TechID
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate %s", id)
		}
		seen[id] = true
		if m, ok := mitreFor(id); !ok || m.ID != techs[id] {
			t.Errorf("%s not mapped to %s", id, techs[id])
		}
		if e, ok := ResolveGuidance(id); !ok || e.Kind != "rule" || len(e.HowToInvestigate) == 0 || len(e.HowToRemediate) == 0 {
			t.Errorf("%s has no rule guidance", id)
		}
		if _, ok := guidanceByID(techs[id]); !ok {
			t.Errorf("technique %s has no guidance entry", techs[id])
		}
	}
	if len(ids) != 35 {
		t.Errorf("rule count %d, docs say 35", len(ids))
	}
}

func TestZscalerSelfTestCoversEveryRule(t *testing.T) {
	st, err := SelfTest(HarnessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range st.Rules {
		if strings.HasPrefix(r.ID, "zs-an-") || strings.HasPrefix(r.ID, "zspol-") || strings.HasPrefix(r.ID, "zdx-an-") {
			if r.Positive == 0 || r.Negative == 0 || r.Status != "ok" {
				t.Errorf("%s: positive %d negative %d status %s", r.ID, r.Positive, r.Negative, r.Status)
			}
			got[r.ID] = true
		}
	}
	if len(got) != 35 {
		t.Errorf("selftest covers %d Zscaler rules, want 35", len(got))
	}
}

const zsWebJSON = `{"datetime":"Nov 20 10:00:00 2026","user":"a@example.test","hostname":"x.example.test","url":"https://x.example.test/p?token=Canary-Secret-7","action":"Allowed","urlcategory":"Newly Registered Domains","requestmethod":"GET"}`

func TestZscalerParseFormats(t *testing.T) {
	jl := zsWebJSON + "\n" + strings.Replace(zsWebJSON, "a@", "b@", 1)
	cases := map[string]string{
		"jsonl": jl,
		"array": "[" + strings.ReplaceAll(jl, "\n", ",") + "]",
		"hec":   `{"sourcetype":"zscalernss-web","event":` + zsWebJSON + `}` + "\n" + `{"sourcetype":"zscalernss-web","event":` + strings.Replace(zsWebJSON, "a@", "b@", 1) + `}`,
		"csv":   "datetime,user,hostname,url,action,urlcategory,requestmethod\nNov 20 10:00:00 2026,a@example.test,x.example.test,https://x.example.test/p?token=Canary-Secret-7,Allowed,Newly Registered Domains,GET\nNov 20 10:00:00 2026,b@example.test,x.example.test,https://x.example.test/p?token=Canary-Secret-7,Allowed,Newly Registered Domains,GET\n",
		"tsv":   "datetime\tuser\thostname\turl\taction\turlcategory\trequestmethod\nNov 20 10:00:00 2026\ta@example.test\tx.example.test\thttps://x.example.test/p?token=Canary-Secret-7\tAllowed\tNewly Registered Domains\tGET\nNov 20 10:00:00 2026\tb@example.test\tx.example.test\thttps://x.example.test/p?token=Canary-Secret-7\tAllowed\tNewly Registered Domains\tGET\n",
	}
	for name, body := range cases {
		rep, fs, err := ZscalerRun([]byte(body), "", ZsOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Parsed != 2 || rep.ByKind["web"] != 2 || rep.ByRule["zs-an-risky-category-allowed"] != 2 || rep.Users != 2 || rep.From == nil || rep.From.Year() != 2026 {
			t.Errorf("%s: %+v", name, rep)
		}
		b, _ := json.Marshal([]any{rep, fs})
		if strings.Contains(string(b), "Canary-Secret-7") {
			t.Errorf("%s: URL query leaked", name)
		}
	}
}

func TestZscalerKindsAndActions(t *testing.T) {
	body := `{"datetime":"2026-11-20T10:00:00Z","user":"a","dns_req":"example.test.","reqaction":"REQ_ALLOW","resaction":"RES_BLOCK"}
{"datetime":"2026-11-20T10:00:01Z","user":"a","csip":"10.0.0.1","cdip":"203.0.113.1","cdport":"23","action":"Allow"}
{"LogTimestamp":"2026-11-20T10:00:02Z","Username":"a","Application":"hr","Connector":"c","ConnectionStatus":"AUTHENTICATION_FAILED"}
{"nothing":"useful"}`
	p, err := zsParseLog([]byte(body), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ByKind["dns"] != 1 || p.ByKind["fw"] != 1 || p.ByKind["zpa"] != 1 || p.Rejected != 1 || len(p.Errors) != 1 {
		t.Fatalf("%+v", p)
	}
	for _, e := range p.Events {
		if (e.Kind == "dns" || e.Kind == "zpa") && e.Action != "block" {
			t.Errorf("%s action %q, want block", e.Kind, e.Action)
		}
		if e.Kind == "fw" && (e.Action != "allow" || e.DPort != 23) {
			t.Errorf("fw %+v", e)
		}
	}
}

func TestZscalerBadInput(t *testing.T) {
	for _, c := range []struct{ body, format string }{{"", ""}, {"   ", ""}, {"{", ""}, {"a,b\n1,2\n", ""}, {"x", "bogus"}, {`[1,2]`, ""}} {
		if rep, _, err := ZscalerRun([]byte(c.body), c.format, ZsOptions{}); err == nil && rep.Parsed != 0 {
			t.Errorf("%q: parsed %d", c.body, rep.Parsed)
		}
	}
	// hostile text in fields is stripped and bounded
	evil := `{"datetime":"2026-11-20T10:00:00Z","user":"a\u001b[31m@x","hostname":"h","url":"https://u:pw@h/` + strings.Repeat("A", 5000) + `","action":"Allowed","urlcategory":"Anonymizer"}`
	_, fs, err := ZscalerRun([]byte(evil), "", ZsOptions{})
	if err != nil || len(fs) == 0 {
		t.Fatalf("%v %d", err, len(fs))
	}
	for _, f := range fs {
		if strings.ContainsRune(f.Description+f.Evidence.Command, 0x1b) || strings.Contains(f.Evidence.Command, "pw@") || len(f.Evidence.Command) > 320 {
			t.Errorf("unsanitised: %q", f.Evidence.Command)
		}
	}
}

func TestZscalerRecordCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("user,url,action\n")
	for i := 0; i < zsRecordsMax+1; i++ {
		b.WriteString("u,https://h/,Allowed\n")
	}
	if _, _, err := ZscalerRun([]byte(b.String()), "", ZsOptions{}); err != errNetTooMany {
		t.Errorf("got %v, want too many records", err)
	}
}

func TestZscalerUserRiskAndOptions(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, `{"datetime":"2026-11-20T10:%02d:00Z","user":"bad@example.test","hostname":"h%d.example.test","action":"Allowed","threatname":"Synthetic.Test","threatcategory":"Malware","appname":"Randomshare","appclass":"File Sharing","requestsize":3000000}`+"\n", i, i)
	}
	b.WriteString(`{"datetime":"2026-11-20T10:00:00Z","user":"ok@example.test","hostname":"ok.example.test","action":"Allowed"}` + "\n")
	rep, _, err := ZscalerRun([]byte(b.String()), "", ZsOptions{Sanctioned: map[string]bool{"sanctioned-drive": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.TopUsers) == 0 || rep.TopUsers[0].User != "bad@example.test" || rep.TopUsers[0].Level != "high" || rep.TopUsers[0].Score > 100 {
		t.Fatalf("users %+v", rep.TopUsers)
	}
	if len(rep.TopApps) == 0 || rep.TopApps[0].App != "Randomshare" || rep.TopApps[0].Sanctioned != "no" || rep.ByRule["zs-an-unsanctioned-saas"] != 1 {
		t.Fatalf("apps %+v rules %v", rep.TopApps, rep.ByRule)
	}
	// without a sanctioned list the app rule stays silent
	rep, _, _ = ZscalerRun([]byte(b.String()), "", ZsOptions{})
	if rep.ByRule["zs-an-unsanctioned-saas"] != 0 || rep.TopApps[0].Sanctioned != "unknown" {
		t.Errorf("rule fired without a sanctioned list: %v", rep.ByRule)
	}
}

func TestZspolRun(t *testing.T) {
	good := `{"url_filtering_rules":[{"name":"news","state":"ENABLED","order":1,"action":"ALLOW","urlCategories":["NEWS_AND_MEDIA"],"lastModifiedTime":1790000000}],
"dlp_web_rules":[{"name":"d","state":"ENABLED","action":"BLOCK"}],"ssl_inspection_rules":[{"name":"dec","state":"ENABLED","action":{"type":"DECRYPT"}}]}`
	rep, fs, err := ZspolRun([]byte(good), ZspolOptions{Now: ncNow})
	if err != nil || rep.Findings != 0 || len(fs) != 0 || rep.Score != 100 || rep.Grade != "A" {
		t.Fatalf("clean export: %+v %v", rep, err)
	}
	bad := `{"firewall_filtering_rules":[{"name":"any","state":"ENABLED","action":"ALLOW"}],"url_filtering_rules":[{"name":"all","state":"ENABLED","action":"ALLOW"}]}`
	rep, fs, err = ZspolRun([]byte(bad), ZspolOptions{Now: ncNow, Host: "zscaler:t"})
	if err != nil || rep.ByRule["zspol-fw-any-any-allow"] != 1 || rep.ByRule["zspol-url-allow-any"] != 1 || rep.Score >= 75 || len(fs) != rep.Findings {
		t.Fatalf("%+v %v", rep, err)
	}
	disabled := `{"firewall_filtering_rules":[{"name":"any","state":"DISABLED","action":"ALLOW"}]}`
	if rep, _, _ = ZspolRun([]byte(disabled), ZspolOptions{Now: ncNow}); rep.ByRule["zspol-fw-any-any-allow"] != 0 {
		t.Error("disabled rule flagged")
	}
	for _, body := range []string{"", "[]", "{}", `{"other":[]}`, "not json"} {
		if _, _, err := ZspolRun([]byte(body), ZspolOptions{}); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
}

func TestZdxScore(t *testing.T) {
	rows := "user,app,page_fetch_ms,dns_ms,packet_loss_pct,cpu_pct\n"
	for i := 0; i < 3; i++ {
		rows += "u1,a1,500,10,0,20\nu2,a1,9000,800,20,100\n"
	}
	rep, _, err := ZdxRun([]byte(rows), "")
	if err != nil {
		t.Fatal(err)
	}
	var good, poor *ZdxEntry
	for i := range rep.ByUser {
		switch rep.ByUser[i].User {
		case "u1":
			good = &rep.ByUser[i]
		case "u2":
			poor = &rep.ByUser[i]
		}
	}
	if good == nil || poor == nil || good.Score < 90 || good.Band != "good" || poor.Score > 10 || poor.Band != "poor" || rep.ByUser[0].User != "u2" {
		t.Fatalf("%+v", rep.ByUser)
	}
	if rep.Score < 0 || rep.Score > 100 || ZdxBand(34) != "okay" || ZdxBand(33) != "poor" || ZdxBand(66) != "good" {
		t.Errorf("bands or range: %d", rep.Score)
	}
	for _, bad := range []string{"", "a,b\n1,2\n", "[]", `{"x":1}`} {
		if _, _, err := ZdxRun([]byte(bad), ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestZscalerHTTP(t *testing.T) {
	h := telHandler(t)
	for _, p := range []string{"/v1/zscaler/logs", "/v1/zscaler/policy", "/v1/zscaler/zdx"} {
		if c, _ := netDo(t, h, "POST", p, "x", ""); c != 401 {
			t.Errorf("%s unauthenticated %d", p, c)
		}
	}
	if c, _ := netDo(t, h, "GET", "/v1/zscaler/sources", "", ""); c != 401 {
		t.Errorf("sources unauth %d", c)
	}
	code, body := netDo(t, h, "POST", "/v1/zscaler/logs?host=Tenant-A", zsWebJSON+"\n"+zsWebJSON, "tok")
	if code != 200 || !strings.Contains(string(body), "zs-an-risky-category-allowed") || strings.Contains(string(body), "Canary-Secret-7") {
		t.Fatalf("logs %d %s", code, body)
	}
	if c, b := netDo(t, h, "GET", "/v1/findings", "", "tok"); c != 200 || !strings.Contains(string(b), "zscaler:tenant-a") {
		t.Errorf("stored findings %d", c)
	}
	env, _ := json.Marshal(map[string]any{"log": `{"datetime":"2026-11-20T10:00:00Z","user":"a","hostname":"h","action":"Allowed","appname":"Randomshare","appclass":"File Sharing","requestsize":9000000}`, "sanctioned_apps": []string{"sanctioned-drive"}, "work_start_hour": 8, "work_end_hour": 18})
	if c, b := netDo(t, h, "POST", "/v1/zscaler/logs", string(env), "tok"); c != 200 || !strings.Contains(string(b), "zs-an-unsanctioned-saas") {
		t.Errorf("envelope %d %s", c, b)
	}
	if code, body = netDo(t, h, "POST", "/v1/zscaler/policy", `{"firewall_filtering_rules":[{"name":"any","state":"ENABLED","action":"ALLOW"}]}`, "tok"); code != 200 || !strings.Contains(string(body), "zspol-fw-any-any-allow") {
		t.Errorf("policy %d %s", code, body)
	}
	penv, _ := json.Marshal(map[string]any{"policy": map[string]any{"firewall_filtering_rules": []any{map[string]any{"name": "any", "state": "ENABLED", "action": "ALLOW"}}}, "now": "2026-11-23T00:00:00Z"})
	if c, b := netDo(t, h, "POST", "/v1/zscaler/policy", string(penv), "tok"); c != 200 || !strings.Contains(string(b), "posture_score") {
		t.Errorf("policy envelope %d %s", c, b)
	}
	if code, body = netDo(t, h, "POST", "/v1/zscaler/zdx", "user,app,cpu_pct\nu,a,99\nu,a,99\nu,a,99\n", "tok"); code != 200 || !strings.Contains(string(body), "zdx-an-device-pressure") {
		t.Errorf("zdx %d %s", code, body)
	}
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/v1/zscaler/logs", "", 400}, {"/v1/zscaler/logs", "just words", 400}, {"/v1/zscaler/logs?format=bogus", zsWebJSON, 400},
		{"/v1/zscaler/logs", `{"log":"x","work_start_hour":20,"work_end_hour":4}`, 400}, {"/v1/zscaler/policy", "", 400}, {"/v1/zscaler/policy", `{"x":1}`, 400},
		{"/v1/zscaler/policy", `{"policy":{"url_filtering_rules":[]},"now":"yesterday"}`, 400}, {"/v1/zscaler/zdx", "", 400}, {"/v1/zscaler/zdx", "a,b\n1,2\n", 400},
	} {
		if code, _ := netDo(t, h, "POST", c.path, c.body, "tok"); code != c.want {
			t.Errorf("%s %q: %d, want %d", c.path, c.body, code, c.want)
		}
	}
	if code, body = netDo(t, h, "GET", "/v1/zscaler/sources", "", "tok"); code != 200 || !strings.Contains(string(body), "zspol-zpa-wildcard-segment") || !strings.Contains(string(body), "zdx-an-dns-slow") {
		t.Errorf("sources %d", code)
	}
}

func TestZscalerZPADenialFromInternalReason(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, `{"LogTimestamp":"2026-11-20T10:%02d:00Z","Username":"u@example.test","Application":"App%d","ConnectionStatus":"close","InternalReason":"ZPN_STATUS_AUTH_FAILED","ClientPublicIP":"203.0.113.9"}`+"\n", i, i)
	}
	rep, fs, err := ZscalerRun([]byte(b.String()), "", ZsOptions{})
	if err != nil || rep.ByKind["zpa"] != 10 {
		t.Fatalf("%v %+v", err, rep)
	}
	found := false
	for _, f := range fs {
		found = found || f.Rule == "zs-an-zpa-denied-burst"
	}
	if !found {
		t.Error("ten refusals carried in InternalReason did not raise zs-an-zpa-denied-burst")
	}
	ok := strings.ReplaceAll(b.String(), "ZPN_STATUS_AUTH_FAILED", "BRK_MT_TERMINATED")
	_, fs, _ = ZscalerRun([]byte(ok), "", ZsOptions{})
	for _, f := range fs {
		if f.Rule == "zs-an-zpa-denied-burst" {
			t.Error("a normal close raised the denied burst")
		}
	}
}
