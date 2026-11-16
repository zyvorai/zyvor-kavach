# Posture trend, executive digest and auditor bundle

All three are pull-only and observation-only. Kavach never emails, sends or pushes any of this.

| Endpoint | Purpose |
|---|---|
| `GET /v1/posture/trend?days=` | Capped (400) counts-only snapshots, oldest first. Persisted in `<store>.posturetrend.json` |
| `GET /v1/posture/trend/diff?from=YYYY-MM-DD&to=` | Deltas between the newest snapshots at or before the end of each UTC day; 404 when none that old |
| `GET/PUT /v1/posture/trend/config` | `interval_hours` 1..168 (default 6) and `enabled`. PUT needs the admin token |
| `GET /v1/reports/digest?format=json\|md\|html&days=` | Executive digest. Each statement carries the measured factors behind it; unmeasured items (for example SLO budget with no judged samples) appear under `not_assessed`, never estimated. HTML is self-contained and printable |
| `GET /v1/compliance/auditor-bundle[?manifest=1]` | Zip built in memory: compliance evidence and score, content versions, validation-lab coverage, config-assessment policy catalogue, posture trend, `CAVEATS.md`, `MANIFEST.json` and `MANIFEST.sha256`. Keys that look like secrets and the API token are removed; per-file cap 4 MiB, total 24 MiB. Output is deterministic for the same inputs and clock |

CLI: `kavachctl posture-trend [diff]`, `kavachctl digest`, `kavachctl auditor-bundle --out f.zip|--manifest`.
MCP (read-only): `kavach_posture_trend`, `kavach_posture_diff`, `kavach_exec_digest`, `kavach_auditor_bundle_manifest`.
Console: `#/trend` (g ^), `#/digest` (g &), `#/auditor` (g *).

Limits: snapshots exist only while Kavach runs; the first one is taken about 15 seconds after start. Findings counts come from the bounded findings store. The bundle is indicative evidence, not an audit opinion or certification; the config-assessment part is the policy catalogue only because Kavach stores no submitted configuration text.

## Parameters and exact limits

| Endpoint | Parameters and errors |
|---|---|
| `GET /v1/posture/trend` | `days` 1-400 (default 30), otherwise 400. Returns `{mode, count, days, history_cap: 400, interval_hours, enabled, snapshots, note}` |
| `GET /v1/posture/trend/diff` | `from` required, `YYYY-MM-DD` (400 otherwise); `to` optional (default now; end of that UTC day); 400 when `from` is after `to`; 404 `{"error":..., "snapshots_held": N}` when there is no snapshot at or before either end. Returns `{from, to, delta, note}` where each side is a full snapshot and `delta` is to minus from |
| `GET /v1/posture/trend/config` / `PUT` | `{"interval_hours": 1..168, "enabled": bool}`; PUT needs the admin token (403 for a session), body max 2 KiB, unknown fields rejected |
| `GET /v1/reports/digest` | `days` 1-90 (default 7), `format` `json` (default), `md` or `html`; otherwise 400. The comparison baseline is the newest stored snapshot at or before `now - days`; without one the change statement is listed under `not_assessed` |
| `GET /v1/compliance/auditor-bundle` | `manifest=1` returns only the manifest JSON. Otherwise `application/zip`, `Content-Disposition: attachment`, header `X-Kavach-Bundle-Files`. 507 `bundle too large` when the caps are exceeded |

A trend snapshot (`PostureSnapshot`) holds only counts and scores: `time`, `compliance_score`, `compliance_grade`, `framework_scores`, `attack_tactics_covered/_total`, `findings_total`, `findings_by_severity`, `agents_active`, `slo_heartbeat_budget_remaining_pct` and `slo_continuity_budget_remaining_pct` (null when no samples were judged), `rules_total/_silent/_noisy`, `rules_by_state`, and `unavailable` (parts that could not be collected). The history is capped at 400 snapshots; at the default 6 h interval that is about 100 days.

Auditor bundle contents (from `gatherBundleParts`): `compliance/evidence.json`, `compliance/score.json`, `content/versions.json`, `lab/validation-coverage.json`, `config-assessment/policy-catalog.json`, `posture/trend.json`, `CAVEATS.md`, `MANIFEST.json` and `MANIFEST.sha256`. A source that fails is replaced by a stub saying so rather than being omitted silently. Secret-looking keys and the API token are scrubbed from the JSON parts.

## Worked examples

```sh
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/posture/trend?days=14"
# {"mode":"observe-only","count":56,"days":14,"history_cap":400,"interval_hours":6,"enabled":true,
#  "snapshots":[{"time":"...","compliance_score":71,"compliance_grade":"C","findings_total":120,...}],"note":"Counts only. ..."}

curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/posture/trend/diff?from=2026-11-01&to=2026-11-15"
curl -s -X PUT -H "Authorization: Bearer $KAVACH_ADMIN_TOKEN" -d '{"interval_hours":12,"enabled":true}' \
  http://127.0.0.1:8099/v1/posture/trend/config
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/reports/digest?format=md&days=30" -o digest.md
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/auditor-bundle" -o bundle.zip
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/auditor-bundle?manifest=1"
```

Digest JSON shape: `{generated_at, period_days, baseline_snapshot_time (when a baseline exists), mode: "observe-only", statements: [{text, factors: [{name, value, source}]}], not_assessed: [...], caveats: [...]}`. Values in the trend example are illustrative.
