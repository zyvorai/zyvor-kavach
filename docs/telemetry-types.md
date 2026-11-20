# Telemetry types

Observation-only event types: registry, dns, auth, module. Ingest with
`POST /v1/events/{type}` (object or array, max 500, body max 1 MiB; admin token
or per-host credential). Read with `GET /v1/events/{type}?host=&limit=` (limit
1-1000) and `GET /v1/events/summary`. Ring buffer: 5000 events per type,
persisted to `<events ledger>.telemetry`. Metric: `kavach_telemetry_events_total{type}`.

Go API: `RecentTelemetry(type, host, n) []map[string]any` and
`TelemetryMatchView(type, TelemetryEvent) map[string]string`.

Match view fields (all values strings; empty fields omitted; `signed` is
`"true"`/`"false"`; `answers` joined with `,`). Common to all: `type`, `host`,
`time` (RFC3339 UTC), `pid` (if > 0), `user` (if set).

| type | fields |
|------|--------|
| registry | key, value_name, value_data (truncated to 256 chars), operation (set\|create\|delete\|rename) |
| dns | query, qtype, answers, resolver |
| auth | user, source_ip, method (ssh\|sudo\|rdp\|console\|kerberos\|ntlm\|oauth), outcome (success\|failure) |
| module | module_path, hash, signed, signer, kind (dll\|so\|kext\|driver) |

Required: registry key+operation; dns query; auth user+method+outcome; module
module_path+kind; all need host and time. Unknown JSON fields are rejected.

## Detection

Accepted events feed content rules (`docs/content-framework.md`). After the batch is validated and
persisted, each event is evaluated against the live content rules whose `event_type` equals the
endpoint type, using the match view above (module `kind` is exposed to rules as `module_kind`).
Matches become Findings (same per-event cap and truncation as process/network/file rules) and the
response is `{"accepted":N,"findings":M,"not_evaluated":K}`. Evaluation is bounded to 150 ms per
request; events beyond that are stored but not evaluated (logged, counted in
`kavach_telemetry_eval_skipped_total`). Registry, dns, auth and module rules are included in
`/v1/attack/matrix` coverage and are no longer `pending_telemetry`.

If the persisted `<events ledger>.telemetry` file is corrupt at startup, the corrupt file is moved
aside to `<ledger>.telemetry.corrupt-<timestamp>`, a log line names the file and line number, and
persistence restarts on an empty file.

## Auth failure bursts (built-in detector)

Besides content rules, accepted `auth` events feed a small built-in counter
(`internal/edr/auth_burst.go`, observation only, it never locks or blocks anything).
It keeps a sliding 60 second window per `host|source_ip` (at most 10,000 keys) and
considers only events with `outcome: failure` and a `source_ip`. It raises
`auth-failed-login-burst` (T1110) or `auth-password-guessing` (T1110.001) when 8 failures
arrive from one source in the window, and `auth-password-spray` (T1110.003) when 5 distinct
user names fail from one source in the window. Each rule re-alerts at most once per 5
minutes per source. Events normalised from the syslog listener
([syslog-listener.md](syslog-listener.md)) take the same path.

## Authentication and limits

| Item | Value |
|---|---|
| Write auth | Admin token, or a per-host enrollment credential that matches the `host` of **every** event in the batch. Otherwise `401` |
| Batch | One object or an array, 1..500 events; empty or larger is `400 invalid telemetry event` |
| Body | 1 MiB; unknown JSON fields are rejected (`400`) |
| Validation | A single invalid event rejects the whole batch (`400`), nothing is stored |
| Read auth | Bearer token or console session; `limit` outside 1..1000 is `400 invalid limit`; `host` over 255 chars is `400` |
| Order of checks | The body is decoded and validated before the credential is checked, so an unauthenticated caller can make the server parse up to 1 MiB before a `401` (accepted risk, see [security-review.md](security-review.md)) |
| Storage error | `500 storage error`; nothing is evaluated |

## Examples

```bash
export KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN='Admin@321'
H="Authorization: Bearer $KAVACH_TOKEN"

# ingest one failed ssh login
curl -s -X POST -H "$H" $KAVACH_URL/v1/events/auth \
  -d '{"host":"web-01","time":"2026-11-16T10:00:00Z","user":"root","source_ip":"203.0.113.9","method":"ssh","outcome":"failure"}'
# {"accepted":1,"findings":0,"not_evaluated":0}

# read it back
curl -s -H "$H" "$KAVACH_URL/v1/events/auth?host=web-01&limit=5"
# {"events":[{"host":"web-01","method":"ssh","outcome":"failure","source_ip":"203.0.113.9","time":"2026-11-16T10:00:00Z","type":"auth","user":"root"}],"type":"auth"}

# counts per type
curl -s -H "$H" $KAVACH_URL/v1/events/summary

# same data from the CLI (read-only)
kavachctl events auth --host web-01 --limit 5
kavachctl events summary
```

MCP (read-only): `kavach_events_auth`, `kavach_events_dns`, `kavach_events_module`,
`kavach_events_registry`, `kavach_events_summary`. Categories that never arrive on an
install are listed by `GET /v1/coverage/telemetry` (`kavachctl coverage telemetry`).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `400 invalid telemetry event` | Missing required field, unknown field, bad enum value (`method`, `outcome`, `kind`, `operation`), more than 500 events, or body over 1 MiB |
| `401 unauthorized` from an agent | The credential is bound to a different `host` than an event in the batch |
| `findings: 0` for a suspicious event | No loaded content rule targets that `event_type`, or the rule did not match; check `GET /v1/content/rules` and use the validation lab |
| `not_evaluated` above 0 | The 150 ms evaluation budget ran out; the events are stored but not evaluated (`kavach_telemetry_eval_skipped_total` in `/metrics`) |
| Counts lower than expected | The ring keeps 5000 events per type; older events are dropped |
