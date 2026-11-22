// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Cloud and SaaS audit-log ingestion (observation only). Raw audit records from AWS CloudTrail,
// Azure Activity / Entra, GCP Cloud Audit Logs, Okta System Log and Microsoft 365 unified audit are
// normalised into a flat LabEvent and evaluated by the content rules with the `cld-` prefix
// (content/cloud_audit.json). Nothing is executed, fetched or changed in any cloud tenant.
//
// Canonical mapping onto the process-shaped event the rule engine matches:
//
//	executable  = source, one of aws:cloudtrail azure:activity azure:signin azure:audit gcp:audit okta:system m365:audit
//	command     = "<action> outcome=<success|failure|started|unknown> [key=value ...] [params=<compact>]"
//	parent_exe  = acting principal (ARN, UPN, e-mail, user id)
//	path        = affected resource
//	destination = client IP address
//	host        = account / subscription / project / tenant label (cloud:<provider>:<id>)
const (
	cloudBodyMax    = 4 << 20 // request body cap
	cloudBatchMax   = 1000    // events per request
	cloudFieldMax   = 300     // truncation for scalar values
	cloudParamsMax  = 600     // truncation for the compact params blob
	cloudErrorsMax  = 5       // example rejection reasons echoed back
	cloudEvalBudget = 2 * time.Second
	cloudBatchTag   = "cloud-audit-v1"
)

// CloudSource describes one supported audit-log source.
type CloudSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sources string `json:"normalized_sources"`
	Shape   string `json:"expected_shape"`
}

// CloudSources lists the supported inputs (also served by GET /v1/cloud/audit/sources).
var CloudSources = []CloudSource{
	{"aws", "AWS CloudTrail", "aws:cloudtrail", "record with eventName/eventSource, or {\"Records\":[...]}"},
	{"azure", "Azure Activity Log, Entra sign-in and Entra audit", "azure:activity azure:signin azure:audit", "operationName records, sign-in records (userPrincipalName+appDisplayName), audit records (activityDisplayName), or {\"value\":[...]}"},
	{"gcp", "GCP Cloud Audit Logs", "gcp:audit", "LogEntry with protoPayload.methodName"},
	{"okta", "Okta System Log", "okta:system", "event with eventType and actor"},
	{"m365", "Microsoft 365 unified audit log", "m365:audit", "record with Operation and Workload"},
}

// CloudEvent is the provider-neutral intermediate form.
type CloudEvent struct {
	Source   string // aws:cloudtrail ...
	Time     time.Time
	Account  string
	Action   string
	Actor    string
	Resource string
	IP       string
	Outcome  string
	Extra    [][2]string // ordered key/value pairs rendered after outcome
	Params   string
}

var cloudCtrlRe = regexp.MustCompile(`[\x00-\x1f\x7f]+`)

func cloudClean(s string, max int) string {
	s = strings.TrimSpace(cloudCtrlRe.ReplaceAllString(s, " "))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// cloudAction makes an action name token-safe: no whitespace, no trailing dot.
func cloudAction(s string) string {
	s = strings.Join(strings.Fields(cloudClean(s, 160)), "_")
	return strings.TrimRight(s, ".")
}

// Command renders the canonical command string.
func (c CloudEvent) Command() string {
	var b strings.Builder
	b.WriteString(c.Action)
	b.WriteString(" outcome=" + c.Outcome)
	for _, kv := range c.Extra {
		if kv[1] != "" {
			b.WriteString(" " + kv[0] + "=" + cloudClean(strings.ReplaceAll(kv[1], " ", "_"), 120))
		}
	}
	if c.Params != "" {
		b.WriteString(" params=" + c.Params)
	}
	return b.String()
}

// Lab converts the event to the rule-engine event.
func (c CloudEvent) Lab() LabEvent {
	return LabEvent{Kind: "process", Time: c.Time, Host: c.host(), Executable: c.Source, Command: c.Command(),
		ParentExe: c.Actor, Path: c.Resource, Destination: c.IP}
}

func (c CloudEvent) host() string {
	p := c.Source
	if i := strings.IndexByte(p, ':'); i > 0 {
		p = p[:i]
	}
	if c.Account == "" {
		return "cloud:" + p
	}
	return "cloud:" + p + ":" + c.Account
}

// ---- generic JSON helpers (decoded with encoding/json into map[string]any) ----

func jm(v any, path ...string) map[string]any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	m, _ := v.(map[string]any)
	return m
}

// js returns the string at the path (numbers and bools are rendered, objects are not).
func js(v any, path ...string) string {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[p]
	}
	switch x := v.(type) {
	case string:
		return cloudClean(x, cloudFieldMax)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprintf("%t", x)
	}
	return ""
}

func jfirst(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func compactJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if s == "null" || s == "{}" || s == "[]" {
		return ""
	}
	return cloudClean(s, cloudParamsMax)
}

var cloudTimeLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05"}

func cloudTime(vals ...string) time.Time {
	for _, v := range vals {
		for _, l := range cloudTimeLayouts {
			if t, err := time.Parse(l, v); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Now().UTC()
}

// ---- per-source normalizers ----

// NormalizeCloudTrail converts one CloudTrail record.
func NormalizeCloudTrail(m map[string]any) (CloudEvent, error) {
	name := js(m, "eventName")
	if name == "" || js(m, "eventSource") == "" {
		return CloudEvent{}, errors.New("cloudtrail: eventName and eventSource are required")
	}
	ev := CloudEvent{Source: "aws:cloudtrail", Action: cloudAction(name), Time: cloudTime(js(m, "eventTime")),
		Account: jfirst(js(m, "recipientAccountId"), js(m, "userIdentity", "accountId")),
		Actor:   jfirst(js(m, "userIdentity", "arn"), js(m, "userIdentity", "userName"), js(m, "userIdentity", "principalId")),
		IP:      js(m, "sourceIPAddress"), Outcome: "success"}
	if arr, ok := m["resources"].([]any); ok && len(arr) > 0 {
		ev.Resource = js(arr[0], "ARN")
	}
	if ev.Resource == "" {
		ev.Resource = jfirst(js(m, "requestParameters", "bucketName"), js(m, "requestParameters", "userName"), js(m, "requestParameters", "roleName"))
	}
	errCode := js(m, "errorCode")
	if errCode != "" || strings.EqualFold(js(m, "responseElements", "ConsoleLogin"), "Failure") {
		ev.Outcome = "failure"
	}
	mfa := ""
	if name == "ConsoleLogin" {
		mfa = "false"
		if strings.EqualFold(js(m, "additionalEventData", "MFAUsed"), "Yes") {
			mfa = "true"
		}
	}
	ev.Extra = [][2]string{{"user_type", js(m, "userIdentity", "type")}, {"mfa", mfa}, {"region", js(m, "awsRegion")}, {"error", errCode}}
	ev.Params = compactJSON(m["requestParameters"])
	return ev, nil
}

// NormalizeAzure converts an Azure Activity Log record, an Entra sign-in record or an Entra
// directory audit record (detected by shape).
func NormalizeAzure(m map[string]any) (CloudEvent, error) {
	switch {
	case js(m, "userPrincipalName") != "" && js(m, "appDisplayName") != "":
		ev := CloudEvent{Source: "azure:signin", Action: "SignIn", Time: cloudTime(js(m, "createdDateTime")),
			Account: js(m, "tenantId"), Actor: js(m, "userPrincipalName"), IP: js(m, "ipAddress"), Resource: js(m, "appDisplayName")}
		code := jfirst(js(m, "status", "errorCode"), "0")
		ev.Outcome = "success"
		if code != "0" {
			ev.Outcome = "failure"
		}
		errExtra := ""
		if code != "0" {
			errExtra = code
		}
		mfa := ""
		if strings.EqualFold(js(m, "authenticationRequirement"), "multiFactorAuthentication") {
			mfa = "true"
		}
		risk := jfirst(js(m, "riskLevelDuringSignIn"), js(m, "riskLevelAggregated"))
		if strings.EqualFold(risk, "none") {
			risk = ""
		}
		ev.Extra = [][2]string{{"error", errExtra}, {"risk", strings.ToLower(risk)}, {"mfa", mfa},
			{"client", js(m, "clientAppUsed")}, {"app", js(m, "appDisplayName")}, {"ca", js(m, "conditionalAccessStatus")}}
		return ev, nil
	case js(m, "activityDisplayName") != "":
		ev := CloudEvent{Source: "azure:audit", Action: cloudAction(js(m, "activityDisplayName")), Time: cloudTime(js(m, "activityDateTime")),
			Account: js(m, "tenantId"), Outcome: "success",
			Actor: jfirst(js(m, "initiatedBy", "user", "userPrincipalName"), js(m, "initiatedBy", "app", "displayName"))}
		ev.IP = js(m, "initiatedBy", "user", "ipAddress")
		if arr, ok := m["targetResources"].([]any); ok && len(arr) > 0 {
			ev.Resource = jfirst(js(arr[0], "userPrincipalName"), js(arr[0], "displayName"), js(arr[0], "id"))
			if t0, ok := arr[0].(map[string]any); ok {
				ev.Params = compactJSON(t0["modifiedProperties"])
			}
		}
		if r := strings.ToLower(js(m, "result")); r != "" && r != "success" {
			ev.Outcome = "failure"
		}
		return ev, nil
	case js(m, "operationName") != "" || jm(m, "operationName") != nil:
		op := jfirst(js(m, "operationName"), js(m, "operationName", "value"))
		ev := CloudEvent{Source: "azure:activity", Action: cloudAction(op),
			Time:    cloudTime(js(m, "eventTimestamp"), js(m, "time")),
			Account: jfirst(js(m, "subscriptionId"), azureSub(js(m, "resourceId"))),
			Actor:   jfirst(js(m, "caller"), js(m, "identity", "claims", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")),
			IP:      jfirst(js(m, "callerIpAddress"), js(m, "httpRequest", "clientIpAddress")), Resource: js(m, "resourceId")}
		st := strings.ToLower(jfirst(js(m, "status", "value"), js(m, "status"), js(m, "resultType")))
		switch st {
		case "succeeded", "success", "":
			ev.Outcome = "success"
		case "started", "accepted", "inprogress", "start":
			ev.Outcome = "started"
		case "failed", "failure":
			ev.Outcome = "failure"
		default:
			ev.Outcome = "unknown"
		}
		ev.Extra = [][2]string{{"category", jfirst(js(m, "category", "value"), js(m, "category"))}}
		if p := jm(m, "properties"); p != nil {
			ev.Params = compactJSON(p)
		}
		return ev, nil
	}
	return CloudEvent{}, errors.New("azure: not an Activity, sign-in or audit record")
}

func azureSub(resourceID string) string {
	parts := strings.Split(strings.ToLower(resourceID), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "subscriptions" {
			return parts[i+1]
		}
	}
	return ""
}

// NormalizeGCP converts a Cloud Audit Logs LogEntry.
func NormalizeGCP(m map[string]any) (CloudEvent, error) {
	pp := jm(m, "protoPayload")
	method := js(pp, "methodName")
	if pp == nil || method == "" {
		return CloudEvent{}, errors.New("gcp: protoPayload.methodName is required")
	}
	ev := CloudEvent{Source: "gcp:audit", Action: cloudAction(method), Time: cloudTime(js(m, "timestamp")),
		Account: jfirst(js(m, "resource", "labels", "project_id"), js(m, "resource", "labels", "project")),
		Actor:   js(pp, "authenticationInfo", "principalEmail"), IP: js(pp, "requestMetadata", "callerIp"),
		Resource: jfirst(js(pp, "resourceName"), js(m, "resource", "type")), Outcome: "success"}
	if c := js(pp, "status", "code"); c != "" && c != "0" {
		ev.Outcome = "failure"
	}
	ev.Extra = [][2]string{{"service", js(pp, "serviceName")}}
	req := map[string]any{}
	if r := jm(pp, "request"); r != nil {
		req["request"] = r
	}
	if sd := jm(pp, "serviceData"); sd != nil {
		req["serviceData"] = sd
	}
	if len(req) > 0 {
		ev.Params = compactJSON(req)
	}
	return ev, nil
}

var oktaRiskRe = regexp.MustCompile(`(?i)level=(\w+)`)

// NormalizeOkta converts an Okta System Log event.
func NormalizeOkta(m map[string]any) (CloudEvent, error) {
	et := js(m, "eventType")
	if et == "" || jm(m, "actor") == nil {
		return CloudEvent{}, errors.New("okta: eventType and actor are required")
	}
	ev := CloudEvent{Source: "okta:system", Action: cloudAction(et), Time: cloudTime(js(m, "published")),
		Actor: jfirst(js(m, "actor", "alternateId"), js(m, "actor", "id")), IP: js(m, "client", "ipAddress"), Outcome: "success"}
	if arr, ok := m["target"].([]any); ok && len(arr) > 0 {
		ev.Resource = jfirst(js(arr[0], "alternateId"), js(arr[0], "displayName"), js(arr[0], "id"))
	}
	switch strings.ToUpper(js(m, "outcome", "result")) {
	case "FAILURE", "DENY":
		ev.Outcome = "failure"
	case "SUCCESS", "ALLOW", "":
	default:
		ev.Outcome = "unknown"
	}
	risk := ""
	if dd := jm(m, "debugContext", "debugData"); dd != nil {
		if mm := oktaRiskRe.FindStringSubmatch(js(dd, "risk")); mm != nil {
			risk = strings.ToLower(mm[1])
		}
		keys := make([]string, 0, len(dd))
		for k := range dd {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var kv []string
		for _, k := range keys {
			if k == "requestUri" || k == "url" || k == "requestId" {
				continue
			}
			if v := js(dd, k); v != "" {
				kv = append(kv, k+"="+v)
			}
		}
		ev.Params = cloudClean(strings.Join(kv, ";"), cloudParamsMax)
	}
	ev.Extra = [][2]string{{"risk", risk}, {"auth", js(m, "authenticationContext", "credentialType")}}
	return ev, nil
}

// NormalizeM365 converts a Microsoft 365 unified audit log record.
func NormalizeM365(m map[string]any) (CloudEvent, error) {
	op := js(m, "Operation")
	if op == "" || js(m, "Workload") == "" {
		return CloudEvent{}, errors.New("m365: Operation and Workload are required")
	}
	ev := CloudEvent{Source: "m365:audit", Action: cloudAction(op), Time: cloudTime(js(m, "CreationTime")),
		Account: js(m, "OrganizationId"), Actor: js(m, "UserId"), IP: js(m, "ClientIP"), Resource: js(m, "ObjectId"), Outcome: "success"}
	if strings.EqualFold(js(m, "ResultStatus"), "Failed") || strings.EqualFold(js(m, "ResultStatus"), "False") {
		ev.Outcome = "failure"
	}
	var kv []string
	if arr, ok := m["Parameters"].([]any); ok {
		for _, p := range arr {
			if n := js(p, "Name"); n != "" {
				kv = append(kv, n+"="+js(p, "Value"))
			}
		}
	}
	ev.Params = cloudClean(strings.Join(kv, ";"), cloudParamsMax)
	ev.Extra = [][2]string{{"workload", js(m, "Workload")}}
	return ev, nil
}

// NormalizeCloudAuditRecord detects the source by shape (or uses want when non-empty) and normalises.
func NormalizeCloudAuditRecord(m map[string]any, want string) (CloudEvent, error) {
	det := ""
	switch {
	case m["protoPayload"] != nil:
		det = "gcp"
	case m["eventName"] != nil && m["eventSource"] != nil:
		det = "aws"
	case m["Operation"] != nil && m["Workload"] != nil:
		det = "m365"
	case m["eventType"] != nil && m["actor"] != nil:
		det = "okta"
	case m["operationName"] != nil || m["activityDisplayName"] != nil || m["userPrincipalName"] != nil:
		det = "azure"
	}
	if want != "" && det != want {
		return CloudEvent{}, fmt.Errorf("record does not look like %s", want)
	}
	switch det {
	case "aws":
		return NormalizeCloudTrail(m)
	case "azure":
		return NormalizeAzure(m)
	case "gcp":
		return NormalizeGCP(m)
	case "okta":
		return NormalizeOkta(m)
	case "m365":
		return NormalizeM365(m)
	}
	return CloudEvent{}, errors.New("unrecognised audit record shape")
}

// cloudUnwrap extracts the record list from a body: an array, a known wrapper object, or one record.
func cloudUnwrap(raw []byte) ([]map[string]any, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	conv := func(arr []any) []map[string]any {
		out := make([]map[string]any, 0, len(arr))
		for _, x := range arr {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			} else {
				out = append(out, nil)
			}
		}
		return out
	}
	switch x := v.(type) {
	case []any:
		return conv(x), nil
	case map[string]any:
		for _, k := range []string{"Records", "value", "events", "items", "entries"} {
			if arr, ok := x[k].([]any); ok {
				return conv(arr), nil
			}
		}
		return []map[string]any{x}, nil
	}
	return nil, errors.New("body must be a JSON object or array")
}

// ProcessCloudAudit normalises and evaluates records, returning findings plus accounting.
func ProcessCloudAudit(recs []map[string]any, want string, budget time.Duration) (findings []Finding, bySource map[string]int, rejected int, errs []string, skipped int) {
	bySource = map[string]int{}
	deadline := time.Now().Add(budget)
	for i, m := range recs {
		if m == nil {
			rejected++
			if len(errs) < cloudErrorsMax {
				errs = append(errs, fmt.Sprintf("record %d: not a JSON object", i))
			}
			continue
		}
		ce, err := NormalizeCloudAuditRecord(m, want)
		if err != nil {
			rejected++
			if len(errs) < cloudErrorsMax {
				errs = append(errs, fmt.Sprintf("record %d: %v", i, err))
			}
			continue
		}
		bySource[ce.Source]++
		if i > 0 && time.Now().After(deadline) {
			skipped++
			continue
		}
		lab := ce.Lab()
		ev := Event{Time: ce.Time, Host: lab.Host, Executable: ce.Source, ParentExe: ce.Actor, Command: ce.Command()}
		fs := contentEvaluate("process", lab, Finding{Time: ce.Time, Host: lab.Host, Destination: ce.IP, Evidence: ev})
		if len(fs) > 0 {
			h := fnv.New32a()
			_, _ = h.Write([]byte(ce.Source + "|" + ce.Actor + "|" + ce.Command() + "|" + ce.Time.String()))
			for j := range fs {
				fs[j].ID = fmt.Sprintf("%s:%08x", fs[j].ID, h.Sum32())
				fs[j].Tags = append(fs[j].Tags, "cloud-audit", ce.Source)
			}
			findings = append(findings, FilterExcluded(fs)...)
		}
	}
	return
}

// RegisterCloudAudit mounts POST /v1/cloud/audit/events (admin token only) and
// GET /v1/cloud/audit/sources (any authenticated caller).
func RegisterCloudAudit(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/cloud/audit/events", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !secureEqual(got, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		want := strings.ToLower(r.URL.Query().Get("source"))
		if want != "" {
			ok := false
			for _, s := range CloudSources {
				ok = ok || s.ID == want
			}
			if !ok {
				http.Error(w, "unknown source (aws|azure|gcp|okta|m365)", http.StatusBadRequest)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, cloudBodyMax)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		recs, err := cloudUnwrap(raw)
		if err != nil || len(recs) == 0 {
			http.Error(w, "invalid audit payload", http.StatusBadRequest)
			return
		}
		if len(recs) > cloudBatchMax {
			http.Error(w, fmt.Sprintf("too many records (max %d)", cloudBatchMax), http.StatusRequestEntityTooLarge)
			return
		}
		findings, bySource, rejected, errs, skipped := ProcessCloudAudit(recs, want, cloudEvalBudget)
		stored := 0
		if store != nil && len(findings) > 0 {
			store.mu.Lock()
			for _, f := range findings {
				if err := store.appendFindingLocked(f); err != nil {
					store.mu.Unlock()
					http.Error(w, "storage error", http.StatusInternalServerError)
					return
				}
				stored++
			}
			store.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"received": len(recs), "normalized": len(recs) - rejected,
			"rejected": rejected, "not_evaluated": skipped, "findings": stored, "by_source": bySource, "errors": errs})
	})
	mux.HandleFunc("GET /v1/cloud/audit/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rules := 0
		if reg := contentReg.Load(); reg != nil {
			for _, x := range reg.rules {
				if x.Batch == cloudBatchTag {
					rules++
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sources": CloudSources, "rules": rules, "rule_prefix": "cld-",
			"observation_only": true, "limits": map[string]int{"body_bytes": cloudBodyMax, "records_per_request": cloudBatchMax}})
	})
}
