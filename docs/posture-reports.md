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
