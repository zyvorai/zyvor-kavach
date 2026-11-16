# Cloud and SaaS audit-log detection

Kavach can ingest exported audit records from AWS CloudTrail, Azure (Activity Log, Entra sign-in and Entra audit), GCP Cloud Audit Logs, Okta System Log and the Microsoft 365 unified audit log, normalise them and evaluate them with the `cld-` content rules. It is observation only: it reads records you send it, raises findings, and never calls a cloud API, fetches logs, or changes anything in a tenant.

## Ingest

`POST /v1/cloud/audit/events` (admin token only; per-host credentials and sessions are refused).

- Body: one record, a JSON array, or a wrapper object using `Records`, `value`, `events`, `items` or `entries` (so a CloudTrail log file, an Azure `value` page or an Event Hub export body can be posted unchanged).
- Caps: 4 MiB body (413), 1000 records per request (413), evaluation budget 2 s per request (the rest are counted in `not_evaluated`).
- Optional `?source=aws|azure|gcp|okta|m365`: records of any other shape are rejected instead of auto-detected.
- Response: `received`, `normalized`, `rejected`, `not_evaluated`, `findings`, `by_source`, and up to five example `errors`.
- Findings are stored like any other content-rule finding (rule id `cld-...`, tags `cloud-audit` and the normalised source) and respect exceptions and rule lifecycle.

`GET /v1/cloud/audit/sources` lists the sources and the loaded `cld-` rule count; `kavachctl cloudaudit sources` prints the same.

## Normalisation

Records become a process-shaped event so the existing rule engine, validation lab and benign corpus apply unchanged:

| field | content |
|-------|---------|
| `executable` | `aws:cloudtrail`, `azure:activity`, `azure:signin`, `azure:audit`, `gcp:audit`, `okta:system`, `m365:audit` |
| `command` | `<action> outcome=<success\|failure\|started\|unknown> [key=value ...] [params=<compact>]` |
| `parent_exe` | acting principal (ARN, UPN, e-mail) |
| `path` | affected resource |
| `destination` | client IP |
| `host` | `cloud:<provider>:<account/subscription/project/tenant>` |

Actions have whitespace collapsed to `_` (for example `Add_member_to_role`). Per-source extras: CloudTrail `user_type`, `mfa` (ConsoleLogin), `region`, `error`; Entra sign-in `error`, `risk`, `mfa`, `client`, `app`, `ca`; GCP `service`; Okta `risk`, `auth`; Microsoft 365 `workload`. `params` is the compact request parameters (CloudTrail, GCP request and policy delta, Entra modified properties, Okta debug data, Microsoft 365 parameters as `Name=Value;...`). Control characters are stripped and every value is length-capped.

## Rule pack

`internal/edr/content/cloud_audit.json`, batch `cloud-audit-v1`, 159 rules, ids prefixed `cld-<source>-`. Coverage: defense evasion (log, monitor and firewall tampering, MFA and Conditional Access removal, federation trust changes), persistence and privilege escalation (keys, service accounts, role and policy grants, mailbox delegation), credential access (secret stores, MFA fatigue, risky sign-ins), collection and exfiltration (public buckets, snapshot sharing, mail forwarding, mailbox export), impact (key, bucket, vault, project deletion), execution (serverless, SSM, VM run command) and discovery. Each rule carries ATT&CK technique and tactic, one or more positive fixtures and at least three negative fixtures (wrong outcome, wrong source, benign action, missing required parameter). Severity `low` marks routine administrative actions that are worth recording but excluded from the benign-corpus gate.

Validation lab: `internal/edr/scenarios/cloud_audit.json` holds one emulation scenario per medium-or-higher rule (T1078.004 rules are excluded because the lab declares that technique not testable; their fixtures still cover them) plus three benign negative controls. Benign corpus: `internal/edr/testdata/benign_corpus_cloud.json`, checked by `TestCloudAuditBenignCorpus` against every embedded rule.

Rule counts by id prefix (read from the pack, 2026-11-16): `cld-aws-` 59, `cld-gcp-` 24, `cld-azure-` 20, `cld-okta-` 19, `cld-m365-` 19, `cld-entra-` 18. By severity: 2 critical, 63 high, 57 medium, 37 low. All rules are `event_type: process`, `os: any`, batch `cloud-audit-v1`.

Scenario coverage (measured by replay): 115 of the 159 rules fire in at least one validation-lab scenario. The 37 low rules are not given scenarios, and 7 medium-or-higher rules have none because their technique, T1078.004, is declared not testable: `cld-aws-root-console-login`, `cld-aws-root-api-activity`, `cld-entra-signin-risk-high`, `cld-entra-signin-legacy-auth`, `cld-okta-session-risk-high`, `cld-okta-impersonation`, `cld-okta-threat-detected`. Those seven are covered only by their own fixtures and by `TestCloudAuditNormalizersFireRules`, which feeds raw provider records through the normalisers. Separately, 17 cloud and SaaS techniques claimed by these rules (for example T1098.002, T1114.003, T1556.006, T1578.001 to T1578.003, T1621, T1666) appear as `untested` in the validation lab coverage report.

## Worked example: send a record and see a finding

```sh
curl -H "Authorization: Bearer $KAVACH_TOKEN" -X POST 'localhost:8080/v1/cloud/audit/events?source=aws' -d '{"Records":[
 {"eventTime":"2026-02-01T10:00:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging",
  "awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9","recipientAccountId":"111122223333",
  "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/eve"},
  "requestParameters":{"name":"org-trail"}}]}'
```

The record normalises to `executable=aws:cloudtrail`, `command=StopLogging outcome=success ...`, `parent_exe=arn:aws:iam::111122223333:user/eve`, and fires `cld-aws-stop-logging` (T1562.008, high). The record is the one used by `TestCloudAuditNormalizersFireRules`; the response shape is `{"received":1,"normalized":1,"rejected":0,"not_evaluated":0,"findings":N,"by_source":{...}}` (exact finding count depends on which other rules match the same normalised event).

## Authoring a cld- rule

1. Normalise a real or documented record first: `NormalizeCloudAuditRecord` (in `cloud_audit.go`) defines the `command` string your rule sees. Find the action name and the `outcome=` token, and any `key=value` extras or `params=` text you need.
2. Add the rule to `internal/edr/content/cloud_audit.json` with id `cld-<source>-<what>`, batch `cloud-audit-v1`, `event_type: process`, an `executable` equals match for the normalised source, a `command` regex anchored on the action (the shipped rules use `^(?:\S*[./])?(?:ActionName)\s`) and an `outcome=success` contains, plus any extras. Required by `TestCloudAuditPackShape`: at least one positive and at least three negative fixtures (wrong outcome, wrong source, benign action; add a missing-parameter negative when the rule needs a parameter).
3. Run `go test ./internal/edr/ -run 'TestCloudAudit|TestContentHarness|TestContentBenignCorpus'`. The cloud benign corpus (`testdata/benign_corpus_cloud.json`, 71 events) must not trip any non-low rule; add routine events there when you see a near miss.
4. Add a scenario to `internal/edr/scenarios/cloud_audit.json` (ids `emu-cld-...`, one `process` step with the normalised `executable`, `command` and `parent_exe`, `expect` the rule id) and run `go test ./internal/edr/ -run TestVal`. The shipped scenarios expect the rule id, not the technique, because the lab marks T1078.004 not testable.
5. If you add a new source or change normalisation, add a case to `TestCloudAuditNormalizersFireRules` with a raw provider record; rule fixtures alone do not prove the normaliser produces what the rule expects.

## Limits and honesty

- Rules match on the action name plus a few extracted fields; they do not understand full provider schemas. Field shapes were written from public provider documentation and have not been replayed against production exports from real tenants, so expect gaps in `params` extraction and in less common event variants.
- Single-event rules cannot see bursts (failed sign-in storms, mass downloads); those need the auth-burst and ML analysers fed with equivalent events.
- The fixtures, the benign corpus, the validation scenarios and the rules were all written by the same team from public documentation, so agreement between them shows consistency, not coverage of real exports.
- Single-event rules treat each record in isolation: nothing correlates a role grant with a later use, and a rule for a routine administrative action (the low severity ones) will fire for legitimate administrators.
- Kavach does not poll or authenticate to any cloud API; you (or your log forwarder) must send the records, so detection is only as timely as your forwarder.
- Telemetry gaps: only the fields the normalisers extract are matchable; other fields of the original record are dropped, and `params` is truncated by the per-value length cap.
- Time is taken from the record; records without a parseable timestamp are stamped with the receive time.
