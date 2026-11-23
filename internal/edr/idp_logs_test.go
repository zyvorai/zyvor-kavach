// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var idpBase = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func oktaRec(t time.Time, et, user, ip, result string, extra map[string]any) map[string]any {
	m := map[string]any{"eventType": et, "published": t.Format(time.RFC3339), "actor": map[string]any{"alternateId": user},
		"outcome": map[string]any{"result": result}, "client": map[string]any{"ipAddress": ip}}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func entraSign(t time.Time, upn, ip string, code int, extra map[string]any) map[string]any {
	m := map[string]any{"createdDateTime": t.Format(time.RFC3339), "userPrincipalName": upn, "ipAddress": ip, "status": map[string]any{"errorCode": float64(code)}}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func entraAudit(t time.Time, act, actor, target, role string) map[string]any {
	tr := []any{map[string]any{"type": "User", "userPrincipalName": target}}
	if role != "" {
		tr = append(tr, map[string]any{"type": "Role", "displayName": role})
	}
	return map[string]any{"activityDateTime": t.Format(time.RFC3339), "activityDisplayName": act, "result": "success",
		"initiatedBy": map[string]any{"user": map[string]any{"userPrincipalName": actor}}, "targetResources": tr}
}

func geoRec(ip string, lat, lon float64, c string) map[string]any {
	return map[string]any{"client": map[string]any{"ipAddress": ip, "geographicalContext": map[string]any{"country": c, "geolocation": map[string]any{"lat": lat, "lon": lon}}}}
}

func idpRules2(rep *IdpReport) string { return fmt.Sprint(rep.ByRule) }

func TestIdpDetections(t *testing.T) {
	min := func(n int) time.Time { return idpBase.Add(time.Duration(n) * time.Minute) }
	var fatigue []map[string]any
	for i := 0; i < 5; i++ {
		fatigue = append(fatigue, oktaRec(min(i), "user.mfa.okta_verify.deny_push", "alice@x.org", "198.51.100.9", "FAILURE", nil))
	}
	var spray []map[string]any
	for i := 0; i < 12; i++ {
		spray = append(spray, entraSign(min(0).Add(time.Duration(i)*time.Second), fmt.Sprintf("u%d@x.org", i), "203.0.113.50", 50126, nil))
	}
	// baseline of three sign-ins, then new device, then a role grant for the same user
	base := []map[string]any{}
	for i := 0; i < 3; i++ {
		base = append(base, entraSign(min(i), "dave@x.org", "192.0.2.1", 0, map[string]any{"deviceDetail": map[string]any{"deviceId": "dev-1"}}))
	}
	cases := []struct {
		name string
		recs []map[string]any
		want []string
		not  []string
	}{
		{"fatigue only", fatigue, []string{"idp-an-mfa-fatigue"}, []string{"idp-an-mfa-fatigue-then-success"}},
		{"fatigue then success", append(append([]map[string]any{}, fatigue...), oktaRec(min(8), "user.session.start", "alice@x.org", "198.51.100.9", "SUCCESS", nil)),
			[]string{"idp-an-mfa-fatigue", "idp-an-mfa-fatigue-then-success"}, nil},
		{"success long after fatigue", append(append([]map[string]any{}, fatigue...), oktaRec(min(120), "user.session.start", "alice@x.org", "198.51.100.9", "SUCCESS", nil)),
			[]string{"idp-an-mfa-fatigue"}, []string{"idp-an-mfa-fatigue-then-success"}},
		{"four prompts is quiet", fatigue[:4], nil, []string{"idp-an-mfa-fatigue"}},
		{"entra 500121 counts", []map[string]any{entraSign(min(0), "a@x", "1.1.1.1", 500121, nil), entraSign(min(1), "a@x", "1.1.1.1", 500121, nil), entraSign(min(2), "a@x", "1.1.1.1", 500121, nil), entraSign(min(3), "a@x", "1.1.1.1", 500121, nil), entraSign(min(4), "a@x", "1.1.1.1", 500121, nil)},
			[]string{"idp-an-mfa-fatigue"}, nil},
		{"spray", spray, []string{"idp-an-password-spray"}, nil},
		{"spray heavy per user is stuffing not spray", func() []map[string]any {
			var r []map[string]any
			for i := 0; i < 40; i++ {
				r = append(r, entraSign(min(0).Add(time.Duration(i)*time.Second), fmt.Sprintf("u%d@x.org", i/4), "203.0.113.50", 50126, nil))
			}
			return r
		}(), nil, []string{"idp-an-password-spray"}},
		{"impossible travel", []map[string]any{oktaRec(min(0), "user.session.start", "e@x", "1.1.1.1", "SUCCESS", geoRec("1.1.1.1", 52.5, 13.4, "DE")), oktaRec(min(20), "user.session.start", "e@x", "2.2.2.2", "SUCCESS", geoRec("2.2.2.2", 40.7, -74, "US"))},
			[]string{"idp-an-impossible-travel"}, nil},
		{"same city is quiet", []map[string]any{oktaRec(min(0), "user.session.start", "e@x", "1.1.1.1", "SUCCESS", geoRec("1.1.1.1", 52.5, 13.4, "DE")), oktaRec(min(20), "user.session.start", "e@x", "2.2.2.2", "SUCCESS", geoRec("2.2.2.2", 52.6, 13.5, "DE"))},
			nil, []string{"idp-an-impossible-travel"}},
		{"role grant privileged", []map[string]any{entraAudit(min(0), "Add member to role", "adm@x", "bob@x", "Global Administrator")}, []string{"idp-an-admin-role-grant"}, nil},
		{"role grant pim eligible", []map[string]any{entraAudit(min(0), "Add eligible member to role", "adm@x", "bob@x", "Helpdesk Operator")}, []string{"idp-an-admin-role-grant"}, nil},
		{"role approval requested ignored", []map[string]any{entraAudit(min(0), "Add member to role approval requested (PIM activation)", "adm@x", "bob@x", "Global Administrator")}, nil, []string{"idp-an-admin-role-grant"}},
		{"okta privilege grant", []map[string]any{oktaRec(min(0), "user.account.privilege.grant", "adm@x", "1.1.1.1", "SUCCESS", map[string]any{"target": []any{map[string]any{"type": "User", "alternateId": "bob@x"}}, "debugContext": map[string]any{"debugData": map[string]any{"privilegeGranted": "Super administrator"}}})}, []string{"idp-an-admin-role-grant"}, nil},
		{"mfa removed okta", []map[string]any{oktaRec(min(0), "user.mfa.factor.reset_all", "adm@x", "1.1.1.1", "SUCCESS", nil)}, []string{"idp-an-mfa-removed"}, nil},
		{"mfa removed entra", []map[string]any{entraAudit(min(0), "Admin deleted security info", "adm@x", "bob@x", "")}, []string{"idp-an-mfa-removed"}, nil},
		{"reset then enroll", []map[string]any{entraAudit(min(0), "Reset password", "adm@x", "bob@x", ""), entraAudit(min(10), "User registered security info", "bob@x", "bob@x", "")}, []string{"idp-an-reset-then-mfa-enroll"}, nil},
		{"enroll long after reset", []map[string]any{entraAudit(min(0), "Reset password", "adm@x", "bob@x", ""), entraAudit(min(300), "User registered security info", "bob@x", "bob@x", "")}, nil, []string{"idp-an-reset-then-mfa-enroll"}},
		{"legacy auth success", []map[string]any{entraSign(min(0), "c@x", "1.1.1.1", 0, map[string]any{"clientAppUsed": "IMAP4"})}, []string{"idp-an-legacy-auth-success"}, nil},
		{"modern client quiet", []map[string]any{entraSign(min(0), "c@x", "1.1.1.1", 0, map[string]any{"clientAppUsed": "Browser"})}, nil, []string{"idp-an-legacy-auth-success"}},
		{"legacy auth failure quiet", []map[string]any{entraSign(min(0), "c@x", "1.1.1.1", 50126, map[string]any{"clientAppUsed": "IMAP4"})}, nil, []string{"idp-an-legacy-auth-success"}},
		{"dormant", []map[string]any{entraSign(min(0), "old@x", "1.1.1.1", 0, nil), entraSign(min(0).Add(120*24*time.Hour), "old@x", "1.1.1.1", 0, nil)}, []string{"idp-an-dormant-account-use"}, nil},
		{"active quiet", []map[string]any{entraSign(min(0), "old@x", "1.1.1.1", 0, nil), entraSign(min(0).Add(10*24*time.Hour), "old@x", "1.1.1.1", 0, nil)}, nil, []string{"idp-an-dormant-account-use"}},
		{"session multi source", []map[string]any{
			oktaRec(min(0), "user.session.start", "s@x", "1.1.1.1", "SUCCESS", map[string]any{"authenticationContext": map[string]any{"externalSessionId": "sid1"}, "client": map[string]any{"ipAddress": "1.1.1.1", "geographicalContext": map[string]any{"country": "DE"}}}),
			oktaRec(min(2), "user.authentication.sso", "s@x", "9.9.9.9", "SUCCESS", map[string]any{"authenticationContext": map[string]any{"externalSessionId": "sid1"}, "client": map[string]any{"ipAddress": "9.9.9.9", "geographicalContext": map[string]any{"country": "BR"}}}),
			oktaRec(min(3), "user.session.start", "s@x", "9.9.9.9", "SUCCESS", map[string]any{"authenticationContext": map[string]any{"externalSessionId": "sid1"}, "client": map[string]any{"ipAddress": "9.9.9.9", "geographicalContext": map[string]any{"country": "BR"}}})},
			[]string{"idp-an-session-multi-source"}, nil},
		{"policy weakened", []map[string]any{oktaRec(min(0), "policy.rule.deactivate", "adm@x", "1.1.1.1", "SUCCESS", nil)}, []string{"idp-an-auth-policy-weakened"}, nil},
		{"ca policy disabled", []map[string]any{func() map[string]any {
			m := entraAudit(min(0), "Update conditional access policy", "adm@x", "x@x", "")
			m["targetResources"] = []any{map[string]any{"type": "Policy", "modifiedProperties": []any{map[string]any{"displayName": "State", "newValue": "\"disabled\""}}}}
			return m
		}()}, []string{"idp-an-auth-policy-weakened"}, nil},
		{"ca policy update quiet", []map[string]any{entraAudit(min(0), "Update conditional access policy", "adm@x", "x@x", "")}, nil, []string{"idp-an-auth-policy-weakened"}},
		{"app credential", []map[string]any{entraAudit(min(0), "Add service principal credentials", "adm@x", "x@x", "")}, []string{"idp-an-app-credential-or-consent"}, nil},
		{"provider risk", []map[string]any{entraSign(min(0), "r@x", "1.1.1.1", 0, map[string]any{"riskLevelDuringSignIn": "high"})}, []string{"idp-an-provider-risk-signal"}, nil},
		{"risk but failed is quiet", []map[string]any{entraSign(min(0), "r@x", "1.1.1.1", 50126, map[string]any{"riskLevelDuringSignIn": "high"})}, nil, []string{"idp-an-provider-risk-signal"}},
		{"new device then role grant", append(append([]map[string]any{}, base...),
			entraSign(min(10), "dave@x.org", "198.51.100.99", 0, map[string]any{"deviceDetail": map[string]any{"deviceId": "dev-2"}}),
			entraAudit(min(15), "Add member to role", "dave@x.org", "dave@x.org", "Helpdesk Operator")),
			[]string{"idp-an-newdevice-privilege-change", "idp-an-admin-role-grant"}, nil},
		{"known device then role grant quiet", append(append([]map[string]any{}, base...),
			entraSign(min(10), "dave@x.org", "192.0.2.1", 0, map[string]any{"deviceDetail": map[string]any{"deviceId": "dev-1"}}),
			entraAudit(min(15), "Add member to role", "adm@x", "dave@x.org", "Helpdesk Operator")),
			nil, []string{"idp-an-newdevice-privilege-change"}},
		{"new device without baseline quiet", []map[string]any{entraSign(min(0), "n@x", "1.1.1.1", 0, map[string]any{"deviceDetail": map[string]any{"deviceId": "d9"}}), entraAudit(min(5), "User registered security info", "n@x", "n@x", "")}, nil, []string{"idp-an-newdevice-privilege-change"}},
	}
	for _, c := range cases {
		rep, fs := AnalyzeIdpLogs(c.recs, "", 0)
		for _, w := range c.want {
			if rep.ByRule[w] == 0 {
				t.Errorf("%s: missing %s (got %s, errors %v)", c.name, w, idpRules2(rep), rep.Errors)
			}
		}
		for _, n := range c.not {
			if rep.ByRule[n] != 0 {
				t.Errorf("%s: unexpected %s", c.name, n)
			}
		}
		for _, f := range fs {
			if f.Host != "idp:logs" || !strings.HasPrefix(f.Rule, "idp-an-") || len(f.Tags) == 0 {
				t.Errorf("%s: bad finding %+v", c.name, f)
			}
		}
	}
}

func TestIdpSeverityAndNormalisation(t *testing.T) {
	_, fs := AnalyzeIdpLogs([]map[string]any{entraAudit(idpBase, "Add member to role", "adm@x", "b@x", "Helpdesk Operator"), entraAudit(idpBase.Add(time.Minute), "Add member to role", "adm@x", "b@x", "Global Administrator")}, "", 0)
	if len(fs) != 2 || fs[0].Severity != "medium" || fs[1].Severity != "high" {
		t.Fatalf("severities %+v", fs)
	}
	e, why := idpNormalize(entraSign(idpBase, "Mixed.Case@X.org", "1.2.3.4", 0, nil))
	if why != "" || e.User != "mixed.case@x.org" || !e.Success || e.Provider != "entra" {
		t.Errorf("%+v %s", e, why)
	}
	e, why = idpNormalize(oktaRec(idpBase, "user.mfa.factor.activate", "u@x", "1.1.1.1", "SUCCESS", map[string]any{"target": []any{map[string]any{"type": "User", "alternateId": "T@x"}}}))
	if why != "" || e.Class != "mfa_enroll" || e.User != "t@x" || e.Actor != "u@x" {
		t.Errorf("%+v %s", e, why)
	}
}

func TestIdpAllowListNoSecrets(t *testing.T) {
	m := oktaRec(idpBase, "user.mfa.okta_verify.deny_push", "u@x", "1.1.1.1", "FAILURE", map[string]any{"password": "hunter2-secret", "accessToken": "tok-secret", "debugContext": map[string]any{"debugData": map[string]any{"requestUri": "/x?token=abc-secret"}}})
	var recs []map[string]any
	for i := 0; i < 5; i++ {
		recs = append(recs, m)
	}
	_, fs := AnalyzeIdpLogs(recs, "", 0)
	b, _ := json.Marshal(fs)
	for _, s := range []string{"hunter2", "tok-secret", "abc-secret"} {
		if strings.Contains(string(b), s) {
			t.Errorf("secret %s leaked into findings", s)
		}
	}
	if len(fs) == 0 {
		t.Fatal("expected a finding")
	}
}

func TestIdpHostileInput(t *testing.T) {
	var recs []map[string]any
	recs = append(recs, nil, map[string]any{}, map[string]any{"published": strings.Repeat("9", 500), "eventType": "x", "actor": map[string]any{"alternateId": "u"}},
		map[string]any{"eventType": 5, "published": idpBase.Format(time.RFC3339), "actor": "not-an-object"},
		map[string]any{"createdDateTime": idpBase.Format(time.RFC3339), "userPrincipalName": strings.Repeat("U", 100000) + "\x00\n", "status": map[string]any{"errorCode": "NaN"}, "location": map[string]any{"geoCoordinates": map[string]any{"latitude": "1e999", "longitude": "x"}}},
		map[string]any{"activityDateTime": idpBase.Format(time.RFC3339), "activityDisplayName": "Add member to role", "targetResources": "not-an-array", "initiatedBy": []any{1, 2}})
	big := make([]any, 5000)
	for i := range big {
		big[i] = map[string]any{"type": "User", "userPrincipalName": fmt.Sprintf("u%d", i)}
	}
	recs = append(recs, map[string]any{"activityDateTime": idpBase.Format(time.RFC3339), "activityDisplayName": "Add member to role", "targetResources": big})
	nested := map[string]any{}
	cur := nested
	for i := 0; i < 5000; i++ {
		n := map[string]any{}
		cur["a"] = n
		cur = n
	}
	recs = append(recs, entraSign(idpBase, "deep@x", "2.2.2.2", 0, map[string]any{"deviceDetail": nested}))
	for i := 0; i < 30000; i++ {
		recs = append(recs, entraSign(idpBase.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("u%d@x", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), 50126, nil))
	}
	start := time.Now()
	rep, fs := AnalyzeIdpLogs(recs, "", 0)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	if rep.Rejected < 4 || rep.Parsed < 30000 {
		t.Errorf("rejected=%d parsed=%d", rep.Rejected, rep.Parsed)
	}
	for _, f := range fs {
		if len(f.Description) > 2000 || strings.ContainsAny(f.Description, "\x00\n") {
			t.Errorf("unsanitised description %q", f.Description[:50])
		}
	}
	per := map[string]int{}
	for _, f := range fs {
		per[f.Rule]++
	}
	for r, n := range per {
		if n > idpFindCapPerRule {
			t.Errorf("%s exceeded cap: %d", r, n)
		}
	}
}

func TestIdpRulesRegistered(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range idpRules {
		if seen[a.ID] {
			t.Errorf("dup %s", a.ID)
		}
		seen[a.ID] = true
		if m, ok := ruleMITRE[a.ID]; !ok || m.ID != a.TechID {
			t.Errorf("%s not registered", a.ID)
		}
		if _, ok := ResolveGuidance(a.ID); !ok {
			t.Errorf("no guidance for %s", a.ID)
		}
	}
}

func TestIdpSampleFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/idp/okta_entra_sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := authUnwrap(raw)
	if err != nil || len(recs) != 4 {
		t.Fatalf("%v %d", err, len(recs))
	}
	rep, _ := AnalyzeIdpLogs(recs, "", 0)
	if rep.Parsed != 4 || rep.Providers["okta"] != 2 || rep.Providers["entra"] != 2 || rep.ByRule["idp-an-admin-role-grant"] != 1 || rep.ByRule["idp-an-legacy-auth-success"] != 1 {
		t.Errorf("%+v", rep)
	}
}

func TestIdpLogsHTTP(t *testing.T) {
	h := telHandler(t)
	var lines []string
	for i := 0; i < 5; i++ {
		b, _ := json.Marshal(oktaRec(idpBase.Add(time.Duration(i)*time.Minute), "user.mfa.okta_verify.deny_push", "alice@x.org", "198.51.100.9", "FAILURE", nil))
		lines = append(lines, string(b))
	}
	body := strings.Join(lines, "\n")
	if w := telDo(h, "POST", "/v1/idp/logs", body, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", w.Code)
	}
	w := telDo(h, "POST", "/v1/idp/logs?host=Okta", body, "tok")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var rep IdpReport
	_ = json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.Findings != 1 || rep.ByRule["idp-an-mfa-fatigue"] != 1 {
		t.Fatalf("%+v", rep)
	}
	if g := telDo(h, "GET", "/v1/findings", "", "tok"); !strings.Contains(g.Body.String(), "idp-an-mfa-fatigue") || !strings.Contains(g.Body.String(), "idp:okta") {
		t.Errorf("not stored")
	}
	if g := telDo(h, "GET", "/v1/idp/sources", "", "tok"); g.Code != 200 || !strings.Contains(g.Body.String(), "idp-an-password-spray") {
		t.Errorf("sources %d", g.Code)
	}
	if g := telDo(h, "GET", "/v1/idp/sources", "", ""); g.Code != 401 {
		t.Errorf("sources unauth %d", g.Code)
	}
	for _, c := range []struct {
		path, body string
		code       int
	}{{"/v1/idp/logs", "", 400}, {"/v1/idp/logs", "[]", 400}, {"/v1/idp/logs", `[{"x":1}]`, 400}, {"/v1/idp/logs?dormant_days=1", body, 400},
		{"/v1/idp/logs", strings.Repeat("a", webBodyMax+1), 413}} {
		if w := telDo(h, "POST", c.path, c.body, "tok"); w.Code != c.code {
			t.Errorf("%s %.20q -> %d want %d", c.path, c.body, w.Code, c.code)
		}
	}
}
