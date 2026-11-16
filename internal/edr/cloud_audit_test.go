// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cloudRules(t *testing.T) []*ContentRule {
	t.Helper()
	var out []*ContentRule
	for _, r := range loadTestRegistry(t).rules {
		if strings.HasPrefix(r.ID, "cld-") {
			out = append(out, r)
		}
	}
	return out
}

func TestCloudAuditPackShape(t *testing.T) {
	rules := cloudRules(t)
	if len(rules) < 80 {
		t.Fatalf("want at least 80 cld- rules, got %d", len(rules))
	}
	techs := map[string]bool{}
	for _, r := range rules {
		if r.Batch != cloudBatchTag || r.EventType != "process" {
			t.Errorf("%s: batch/event_type %q/%q", r.ID, r.Batch, r.EventType)
		}
		if r.Tests == nil || len(r.Tests.Positive) == 0 || len(r.Tests.Negative) < 3 {
			t.Errorf("%s: needs positive and several negative fixtures", r.ID)
		}
		techs[r.Technique] = true
	}
	if len(techs) < 30 {
		t.Errorf("only %d distinct techniques", len(techs))
	}
	// every rule id in the pack must carry the prefix
	raw, err := os.ReadFile("content/cloud_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var p contentPack
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Rules {
		if !strings.HasPrefix(r.ID, "cld-") {
			t.Errorf("%s lacks cld- prefix", r.ID)
		}
	}
}

func TestCloudAuditRuleFixtures(t *testing.T) {
	for _, r := range cloudRules(t) {
		for i, ev := range r.Tests.Positive {
			if !r.Matches(ev) {
				t.Errorf("%s: positive %d did not match", r.ID, i)
			}
		}
		for i, ev := range r.Tests.Negative {
			if r.Matches(ev) {
				t.Errorf("%s: negative %d matched", r.ID, i)
			}
		}
	}
}

// TestCloudAuditBenignCorpus: realistic routine cloud events must not raise medium+ findings from
// any embedded rule (the cld- rules and every other pack).
func TestCloudAuditBenignCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "benign_corpus_cloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus []LabEvent
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 60 {
		t.Fatalf("cloud benign corpus too small: %d", len(corpus))
	}
	for _, r := range loadTestRegistry(t).rules {
		if r.EventType != "process" || r.Severity == "low" {
			continue
		}
		for _, ev := range corpus {
			if r.Matches(ev) {
				t.Errorf("%s (%s) fires on benign %s | %s", r.ID, r.Severity, ev.Executable, ev.Command)
			}
		}
	}
}

func rawJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCloudAuditNormalizersFireRules feeds provider-shaped raw records through the normalizers and
// the live rule registry and checks the expected rule fires.
func TestCloudAuditNormalizersFireRules(t *testing.T) {
	cases := []struct{ name, raw, want, wantSource string }{
		{"cloudtrail stoplogging", `{"eventVersion":"1.08","eventTime":"2026-02-01T10:00:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9","recipientAccountId":"111122223333","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/eve"},"requestParameters":{"name":"org-trail"}}`, "cld-aws-stop-logging", "aws:cloudtrail"},
		{"cloudtrail root login", `{"eventTime":"2026-02-01T10:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root"},"additionalEventData":{"MFAUsed":"No"},"responseElements":{"ConsoleLogin":"Success"},"sourceIPAddress":"198.51.100.4"}`, "cld-aws-root-console-login", "aws:cloudtrail"},
		{"cloudtrail admin policy", `{"eventTime":"2026-02-01T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","userIdentity":{"type":"IAMUser","userName":"bob"},"requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"bob"}}`, "cld-aws-attach-admin-user", "aws:cloudtrail"},
		{"azure activity elevate", `{"operationName":"Microsoft.Authorization/elevateAccess/action","status":{"value":"Succeeded"},"caller":"admin@contoso.example","callerIpAddress":"203.0.113.7","eventTimestamp":"2026-02-01T10:00:00Z","resourceId":"/subscriptions/abc-123/providers/Microsoft.Authorization","category":{"value":"Administrative"}}`, "cld-azure-elevate-access", "azure:activity"},
		{"azure activity object opname", `{"operationName":{"value":"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"},"status":{"value":"Succeeded"},"caller":"a@contoso.example","eventTimestamp":"2026-02-01T10:00:00Z"}`, "cld-azure-vm-run-command", "azure:activity"},
		{"entra signin high risk", `{"createdDateTime":"2026-02-01T10:00:00Z","userPrincipalName":"u@contoso.example","appDisplayName":"Office 365","ipAddress":"203.0.113.50","status":{"errorCode":0},"riskLevelDuringSignIn":"high","clientAppUsed":"Browser"}`, "cld-entra-signin-risk-high", "azure:signin"},
		{"entra signin legacy", `{"createdDateTime":"2026-02-01T10:00:00Z","userPrincipalName":"u@contoso.example","appDisplayName":"Exchange Online","ipAddress":"203.0.113.50","status":{"errorCode":0},"clientAppUsed":"IMAP4"}`, "cld-entra-signin-legacy-auth", "azure:signin"},
		{"entra audit role add", `{"activityDateTime":"2026-02-01T10:00:00Z","activityDisplayName":"Add member to role","result":"success","initiatedBy":{"user":{"userPrincipalName":"a@contoso.example","ipAddress":"203.0.113.1"}},"targetResources":[{"userPrincipalName":"v@contoso.example"}]}`, "cld-entra-entra-role-add", "azure:audit"},
		{"gcp sa key", `{"timestamp":"2026-02-01T10:00:00Z","resource":{"type":"service_account","labels":{"project_id":"proj-1"}},"protoPayload":{"methodName":"google.iam.admin.v1.CreateServiceAccountKey","serviceName":"iam.googleapis.com","authenticationInfo":{"principalEmail":"x@proj-1.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"203.0.113.2"},"resourceName":"projects/-/serviceAccounts/1"}}`, "cld-gcp-sa-key-create", "gcp:audit"},
		{"gcp public iam", `{"timestamp":"2026-02-01T10:00:00Z","protoPayload":{"methodName":"storage.setIamPermissions","authenticationInfo":{"principalEmail":"x@example.com"},"request":{"policy":{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}}}}`, "cld-gcp-iam-policy-public", "gcp:audit"},
		{"okta mfa deactivate", `{"eventType":"user.mfa.factor.deactivate","published":"2026-02-01T10:00:00.123Z","actor":{"alternateId":"admin@example.com"},"client":{"ipAddress":"203.0.113.3"},"outcome":{"result":"SUCCESS"},"target":[{"alternateId":"victim@example.com"}]}`, "cld-okta-mfa-deactivate", "okta:system"},
		{"okta risky session", `{"eventType":"user.session.start","published":"2026-02-01T10:00:00Z","actor":{"alternateId":"u@example.com"},"client":{"ipAddress":"203.0.113.3"},"outcome":{"result":"SUCCESS"},"debugContext":{"debugData":{"risk":"{level=HIGH, reasons=Anomalous Location}"}}}`, "cld-okta-session-risk-high", "okta:system"},
		{"m365 inbox rule", `{"CreationTime":"2026-02-01T10:00:00","Operation":"New-InboxRule","Workload":"Exchange","UserId":"u@contoso.example","ClientIP":"203.0.113.4","ResultStatus":"True","OrganizationId":"org-1","Parameters":[{"Name":"ForwardTo","Value":"x@evil.example"},{"Name":"Name","Value":"."}]}`, "cld-m365-inbox-rule-forward", "m365:audit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce, err := NormalizeCloudAuditRecord(rawJSON(t, c.raw), "")
			if err != nil {
				t.Fatal(err)
			}
			if ce.Source != c.wantSource || ce.Time.IsZero() {
				t.Fatalf("source/time: %+v", ce)
			}
			if c.want == "" {
				return
			}
			fired := false
			var ids []string
			for _, r := range loadTestRegistry(t).byType["process"] {
				if r.Matches(ce.Lab()) {
					ids = append(ids, r.ID)
					fired = fired || r.ID == c.want
				}
			}
			if !fired {
				t.Fatalf("%s did not fire; command=%q fired=%v", c.want, ce.Command(), ids)
			}
		})
	}
}

func TestCloudAuditNormalizerRejects(t *testing.T) {
	for _, s := range []string{`{}`, `{"eventName":"X"}`, `{"protoPayload":{}}`, `{"eventType":"x"}`, `{"Operation":"x"}`, `{"foo":1}`} {
		if _, err := NormalizeCloudAuditRecord(rawJSON(t, s), ""); err == nil {
			t.Errorf("%s should be rejected", s)
		}
	}
	if _, err := NormalizeCloudAuditRecord(rawJSON(t, `{"eventName":"X","eventSource":"s"}`), "gcp"); err == nil {
		t.Error("source mismatch must be rejected")
	}
	// control characters and overlong values are neutralised
	ce, err := NormalizeCloudTrail(rawJSON(t, `{"eventName":"Evil\nName outcome=success","eventSource":"s","userIdentity":{"type":"IAMUser","arn":"`+strings.Repeat("a", 2000)+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ce.Command(), "\n\r") || len(ce.Actor) > cloudFieldMax {
		t.Fatalf("not sanitised: %q", ce.Command())
	}
	if strings.Count(ce.Command(), " ") > 6 {
		t.Fatalf("action whitespace not collapsed: %q", ce.Command())
	}
}

func TestCloudAuditEndpoint(t *testing.T) {
	store, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	h := API("tok", store)
	body := `{"Records":[` +
		`{"eventTime":"2026-02-01T10:00:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/eve"},"recipientAccountId":"1"},` +
		`{"eventTime":"2026-02-01T10:00:01Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"type":"IAMUser"}},` +
		`{"junk":true}]}`
	if w := telDo(h, "POST", "/v1/cloud/audit/events", body, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/cloud/audit/events", body, "nope"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", w.Code)
	}
	w := telDo(h, "POST", "/v1/cloud/audit/events?source=aws", body, "tok")
	if w.Code != 200 {
		t.Fatalf("post: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Received, Normalized, Rejected, Findings int
		BySource                                 map[string]int `json:"by_source"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Received != 3 || resp.Normalized != 2 || resp.Rejected != 1 || resp.Findings < 1 || resp.BySource["aws:cloudtrail"] != 2 {
		t.Fatalf("resp: %+v", resp)
	}
	found := false
	for _, f := range store.List() {
		if f.Rule == "cld-aws-stop-logging" {
			found = true
		}
	}
	if !found {
		t.Fatal("finding not stored")
	}
	if w := telDo(h, "POST", "/v1/cloud/audit/events?source=bogus", body, "tok"); w.Code != 400 {
		t.Fatalf("bad source: %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/cloud/audit/events", "not json", "tok"); w.Code != 400 {
		t.Fatalf("bad json: %d", w.Code)
	}
	if w := telDo(h, "POST", "/v1/cloud/audit/events", "[]", "tok"); w.Code != 400 {
		t.Fatalf("empty: %d", w.Code)
	}
	big := `{"events":[` + strings.Repeat(`{"Operation":"x","Workload":"w"},`, cloudBatchMax) + `{"Operation":"x","Workload":"w"}]}`
	if w := telDo(h, "POST", "/v1/cloud/audit/events", big, "tok"); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too many records: %d", w.Code)
	}
	huge := `{"Operation":"x","Workload":"` + strings.Repeat("a", cloudBodyMax+10) + `"}`
	if w := telDo(h, "POST", "/v1/cloud/audit/events", huge, "tok"); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body cap: %d", w.Code)
	}
	if w := telDo(h, "GET", "/v1/cloud/audit/sources", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("sources unauth: %d", w.Code)
	}
	w = telDo(h, "GET", "/v1/cloud/audit/sources", "", "tok")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "AWS CloudTrail") || !strings.Contains(w.Body.String(), `"rule_prefix":"cld-"`) {
		t.Fatalf("sources: %d %s", w.Code, w.Body)
	}
}

func TestCloudAuditBudget(t *testing.T) {
	recs := []map[string]any{rawJSON(t, `{"Operation":"x","Workload":"w"}`), rawJSON(t, `{"Operation":"x","Workload":"w"}`)}
	_, by, rej, _, skipped := ProcessCloudAudit(recs, "", time.Duration(-1))
	if rej != 0 || by["m365:audit"] != 2 || skipped != 1 {
		t.Fatalf("budget accounting: by=%v rej=%d skipped=%d", by, rej, skipped)
	}
}
