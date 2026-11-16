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

## Limits and honesty

- Rules match on the action name plus a few extracted fields; they do not understand full provider schemas. Field shapes were written from public provider documentation and have not been replayed against production exports from real tenants, so expect gaps in `params` extraction and in less common event variants.
- Single-event rules cannot see bursts (failed sign-in storms, mass downloads); those need the auth-burst and ML analysers fed with equivalent events.
- Time is taken from the record; records without a parseable timestamp are stamped with the receive time.
