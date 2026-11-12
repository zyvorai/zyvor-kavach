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

## Exposure posture (Spotlight/Exposure class, observe only)
- `GET/POST/DELETE /v1/posture/assets`: asset criticality (`host`, `criticality` 1-5, `owner`, `tags`; max 1000
  assets, 10 tags), persisted in `<findings file>.posture.json`. Text is HTML-escaped; writes need admin token or session.
- `GET /v1/posture/vuln-priority[?limit=]` ranks spotlight vulnerabilities with a transparent 0-100 score and a
  per-item `breakdown`: CVSS/ExPRT x4 (40, falls back to severity) + criticality x6 (30, default 3 when the host is
  unregistered) + host also has high/critical findings (5 + min(n,5), 10) + internet tag (`internet`, `internet-facing`,
  `public`, `exposed`, `dmz`; 10) + `exploited_in_wild` (10).
- `POST /v1/posture/baseline[?host=]` snapshots SBOM, FIM and persistence inventory (all observed hosts when `host`
  is omitted; max 200 hosts, 2000 items per domain). `GET /v1/posture/drift?host=` returns `added`, `removed`,
  `changed` with a `severity_hint`: new persistence entry high (critical if risk high/critical), setuid FIM
  add/change critical, other FIM add/change high, SBOM add/change medium, removals low/medium. Max 200 items per class.
- `GET /v1/posture/summary` rolls up asset criticality mix, top-5 priorities, and baselined hosts with drift.

## Alert rules and notifications

Observation-only notifications: Kavach reports matching findings; it never blocks or kills anything.

- `GET/POST/DELETE /v1/alerts/rules` manage rules (`min_severity`, optional `rule_contains` / `host_contains`
  substrings, `type` of `webhook` or `slack`, and `url`). Rules persist in `<findings file>.alerts.json`.
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
