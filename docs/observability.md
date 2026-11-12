# Observability & posture

All endpoints are read-only. Kavach observes; it never contains.

| Endpoint | Auth | What |
|---|---|---|
| `GET /livez` · `/readyz` | none | Probes (Helm uses both) |
| `GET /metrics` | bearer/session | Prometheus: findings by severity, agents online, request counts and latency |
| `GET /v1/attack/matrix` | bearer/session | MITRE ATT&CK tactics → techniques, rule coverage, observed hits |
| `GET /v1/compliance/score` | bearer/session | Overall grade + per-framework score (CIS, NIST CSF, SOC2, ISO 27001) |
| `GET /v1/export/findings` | bearer/session | Download findings, `format=csv`, `json` or `ndjson`; filters `severity`, `host`, `rule`, `since` (RFC3339); CSV neutralises formula injection; capped at 50k rows |
| `GET /v1/export/report` | bearer/session | Self-contained executive posture report, `format=html` or `json` (severity counts, top hosts, ATT&CK, compliance) |
| `GET /v1/risk/hosts` | bearer/session | Per-host risk 0-100 (ScoreFinding weight, 72h half-life decay), top rules, last seen, rank; `/metrics` exports `kavach_host_risk{host}` for the top 20 |
| `GET /v1/risk/summary` | bearer/session | Fleet risk index and host counts by band (low <25, medium <50, high <75, critical) |
| `GET /v1/trends?days=7\|14\|30&bucket=hour\|day` | bearer/session | Finding counts per UTC-aligned bucket by severity, delta vs previous period, top rules |
| `GET /v1/stream` | bearer/session | Server-Sent Events, `event: finding` with a detection payload |

```bash
kavachctl attack
kavachctl compliance score
kavachctl metrics
curl -N -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/stream
```

Console: **Browse → Observe** shows the ATT&CK heatmap, compliance gauges and live feed.

## Prometheus scrape

```yaml
scrape_configs:
  - job_name: kavach
    scheme: https
    tls_config: {insecure_skip_verify: true}   # lab self-signed cert
    authorization: {credentials: "<KAVACH_TOKEN>"}
    static_configs: [{targets: ["HOST:30899"]}]
```

## Hardening

Every response carries `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy` and a CSP.
`POST /v1/session` is limited to a burst of 10 then 1 per 2 s per IP. Other POST/DELETE requests are
limited per IP by `KAVACH_RATE_LIMIT` (requests/sec, default `100`; `0` disables). Exceeding returns `429`.

## Alert rules and notifications

Observation-only notifications: Kavach reports matching findings; it never blocks or kills anything.

- `GET/POST/DELETE /v1/alerts/rules` manage rules (`min_severity`, optional `rule_contains` / `host_contains`
  substrings, `type` of `webhook` or `slack`, and `url`). Rules persist in `<findings file>.alerts.json`.
- Threat-intel feeds: `GET/POST/DELETE /v1/intel/feeds` (name, https `url`, `format` of `csv`, `plain` or
  `stix-lite-json`, `interval` minutes (min 15), `tlp`, `ttl_days` (default 30), `enabled`) persist in
  `<findings file>.intel.json`. A background fetcher polls each feed (15s timeout, 1 MiB cap, ETag
  support, redirects not followed, same SSRF guards as alert URLs), normalises ip/domain/sha256/url
  indicators and adds them to the IOC store tagged `source=feed:<name>`, always `detect_only`. Analyst-created
  IOCs are never overwritten; indicators expire after the feed TTL; deleting a feed removes only its
  indicators. `GET /v1/intel/feeds/status` reports last fetch, status, added/expired/active counts and errors;
  `POST /v1/intel/feeds/refresh?id=` fetches one feed now.
- Analyst workspace, persisted in `<findings file>.workspace.json`: `GET/POST/DELETE /v1/saved-searches`
  (name, scope `detections|findings|hosts`, query; max 100), `GET/POST/DELETE /v1/notes` (`?finding_id=`
  to list, `?id=` to delete; text max 2000 chars, max 200 per finding, author is `admin` or `session`),
  and a SHA-256 hash-chained activity journal at `GET /v1/journal`. Note and saved-search mutations are
  journaled automatically; alert-rule changes are recorded by `POST /v1/journal` with action
  `alert_rule.create|delete`. `GET /v1/journal/verify` re-walks the chain and returns `valid` plus
  `first_broken_seq` and `reason` on tampering. Input is HTML-escaped; writes need admin token or session.
- `GET /v1/alerts/deliveries` returns the last 100 delivery results (newest first).
- A dispatcher polls the store each second, notifies once per (rule, finding), and retries failures 4 times
  with exponential backoff. Findings that already exist at startup are not re-notified.
- Webhook bodies are signed: header `X-Kavach-Signature: sha256=<hex HMAC-SHA256 of body>` using
  `KAVACH_WEBHOOK_SECRET`. Slack rules post `{"text": ...}`. The API token is never included.
- SSRF controls: https only (http for localhost/127.0.0.1), private/loopback/link-local destinations are rejected at
  creation and again at connect time, redirects are not followed. Set `KAVACH_ALERT_ALLOW_PRIVATE=1` to allow
  internal receivers.

## Detection-as-code lab (sandbox)

A sandbox for authoring detections. Lab rules are **never** promoted into live detection or the
ATT&CK `ruleMITRE` mapping; every response carries `mode: sandbox`. Observation-only.

- Rule JSON: `id`, `name`, `technique` (e.g. `T1059.004`), `enabled`, `condition`, optional
  `threshold {count, within_seconds, group_by}`. A condition is a leaf `{field, op, value}` (or `values`
  for `in`; `case_sensitive` optional, default off) or a boolean node `all`, `any` or `not`.
  Fields: `executable command parent_exe host uid path destination kind rule severity operation`.
  Operators: `equals contains startswith endswith regex in`. Regex is Go RE2 (no backtracking), max 256 chars.
  A field absent on an event never matches (so `not` of it does). Validation errors name the field
  (e.g. `condition.all[1].field: unknown field "x"`).
- `POST /v1/lab/rules/validate` checks a rule. `POST /v1/lab/rules/test` takes `{rule | rule_id, events}`
  (max 1000 samples) and returns per-event match plus a per-condition trace and threshold hits.
  `POST /v1/lab/rules/backtest` replays a rule over stored process, file and network events plus findings
  (cap 50,000) and returns `hit_count`, `hit_sample` (max 20), `top_hosts`, `hits_per_day` and
  `noise_per_host_per_day` (hits / hosts observed / days spanned).
- `GET/POST/DELETE /v1/lab/rules` persist rules to `<findings file>.labrules.json` (max 200; POST upserts
  by id). Reads need auth; writes, validate, test and backtest need the admin token or a session.
  Body cap 256 KB (4 MB for test), nesting depth 6, 50 nodes per rule.
## SOC operations analytics

Read-only analytics for SOC management (all require the bearer token or a session):

- `GET /v1/soc/metrics?days=30` (max 365): MTTA (first status change away from new/open), MTTR (first change to
  `closed|true_positive|false_positive|resolved`), open backlog by severity and age bucket
  (`lt_1h|1h_24h|1d_7d|gt_7d`), false-positive rate per rule, top noisy rules and SLA breach counts per severity.
  MTTA/MTTR are `null` when nothing qualifies. Timestamps come from the incident ledger (`<findings>.incidents`)
  plus an append-only transition log (`<findings>.transitions`) written by detection triage.
- SLA targets: `KAVACH_SLA_ACK_MIN` (minutes) and `KAVACH_SLA_RESOLVE_HOURS`. Each is one number for all
  severities or pairs such as `critical=15,high=60`. Defaults: ack 15/60/240/1440 min and resolve 4/24/72/168 h
  for critical/high/medium/low. The effective targets are echoed in `sla_targets`.
- `GET /v1/storyline/host?host=&hours=24` (max 720): findings, process, network and file events for one host
  merged by time. Each step has `tactic`, `phase` (ATT&CK tactic order, 1-14), `tactic_source`
  (`rule`, `pid-correlation` with a finding for the same PID, or `default` per event kind) and `burst`.
  A gap over 15 minutes starts a new burst; its first step carries `gap_seconds`. `host` is required (400).
- `GET /v1/soc/shift-report?hours=12` (max 168): counts of new/open/closed, top 5 risk hosts, unresolved
  criticals and deterministic template questions for the next shift (no LLM).
