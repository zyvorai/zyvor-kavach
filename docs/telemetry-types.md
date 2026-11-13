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
