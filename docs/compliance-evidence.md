# Compliance evidence

Kavach maps live telemetry to control-level evidence. It is observation-only and **never certifies compliance**. Controls it cannot evidence are reported as `manual` or `not_applicable`.

## Frameworks

`framework` values: `cis-v8`, `nist-csf-2`, `soc2`, `iso27001`, `rbi`, `cert-in`, `dpdp`. Control lists are representative subsets. Unknown values return `400`.

## Endpoints (bearer or session auth)

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/compliance/controls?framework=` | Each control with status `pass`, `partial`, `fail`, `manual` or `not_applicable`, plus the live evidence counts used |
| `GET /v1/compliance/evidence?framework=&format=json\|html` | Auditor-ready pack: scope, generated-at, controls, evidence counts, limitations. HTML is self-contained, printable and fully escaped |
| `GET /v1/compliance/cert-in-clock` | Open high/critical incidents with time remaining against the 6-hour CERT-In window, measured from first detection. Informational only |

## Status derivation

Each evidence-based control requires one or more signals: detections coverage (ATT&CK), fleet agents online, audit log / findings ledger, SBOM, FIM, incident workflow, alert routing, findings telemetry, and no overdue high/critical incidents. All signals met gives `pass`, some gives `partial`, none gives `fail`.

## Limitations

- Indicative evidence, not an audit opinion or certification.
- Retention periods, policies, training, physical security and legal notification decisions (for example DPDP notification) are manual.
- Kavach does not file CERT-In reports or notify any authority; the clock is a reminder.

## Catalogue and signals (verified against `compliance_evidence.go`)

The built-in catalogue has 43 controls: `cis-v8` 9, `nist-csf-2` 8, `soc2` 7, `iso27001` 8, `rbi` 5, `cert-in` 3, `dpdp` 3. Control ids are of the form `CIS 8.2`, `ID.AM-01`, `CC7.2`, `A.8.15`, `RBI-SOC`, `CI-6H`, `DPDP-DET`. Eight are fixed `manual` or `not_applicable` ( `CIS 14.1`, `GV.PO-01`, `CC6.1`, `CC7.5`, `A.7.1`, `RBI-BOARD`, `CI-POC`, `DPDP-NOT`). Omitting `framework` returns every framework; the field is case-insensitive.

How each signal is measured, and when it counts as met (level 2) or partial (level 1):

| Signal | Met | Partial | Source |
|---|---|---|---|
| `detections_coverage` | at least half of the ATT&CK tactics have a shipped rule | some covered | the static ATT&CK matrix of shipped rules, not live detections |
| `fleet_agents_online` | every non-revoked agent online (heartbeat within 90 s) | some online | credential registry |
| `audit_log` | audit log or findings ledger has entries | none | audit log, findings store |
| `sbom_present` | derived SBOM has items | none | `deriveSBOM()` |
| `fim_present` | at least one file-integrity event | none | file events |
| `incident_workflow` | incident transitions recorded | always partial (capability exists) | incident store |
| `alert_routing` | at least one alert rule | none | dispatcher |
| `findings_telemetry` | at least one finding | none | findings store |
| `no_overdue_high` | no open high/critical incident past the 6 h window | none | CERT-In clock |

A control is `pass` when all its signals are met, `fail` when none has any evidence, otherwise `partial`. Evidence-based controls carry the full `counts` map (`findings_total`, `attack_tactics_covered/_total`, `agents_total/_online`, `audit_entries`, `sbom_items`, `fim_events`, `incident_transitions`, `alert_rules`, `alert_deliveries`, `open_high_critical`, `open_high_critical_overdue`).

## Worked examples

```sh
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/controls?framework=soc2"
# {"generated_at":"...","framework":"soc2","mode":"observe-only","certification":false,
#  "counts":{"findings_total":120,...},
#  "controls":[{"id":"CC7.2","framework":"soc2","title":"...","status":"partial","note":"...",
#               "signals":["detections_coverage","fleet_agents_online","audit_log"],"evidence":{...}}]}

curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/evidence?framework=iso27001&format=html" -o evidence.html
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/cert-in-clock"
# {"generated_at":"...","window_hours":6,"incidents":[...],"informational":true,"note":"..."}
```

`format` other than `json` or `html` is 400; an unknown `framework` is 400 `unknown framework`. The JSON evidence pack is `{generated_at, scope, controls, counts, limitations, mode, certification: false}`. Values above are illustrative.

## Limits

Statuses reflect the moment of the request, derived from counts, and say nothing about the quality of the evidence behind a count. Control lists are representative subsets and may not match the latest published framework revisions (also stated in the pack's `limitations`). Regional frameworks with their verification status are in [regional-frameworks.md](regional-frameworks.md); the posture trend and auditor bundle that embed this evidence are in [posture-reports.md](posture-reports.md).

## Two status vocabularies

`/v1/compliance/controls` and `/v1/compliance/evidence` use `pass`, `partial`, `fail`, `manual`, `not_applicable`. `GET /v1/compliance/score` (which scores every framework in the same catalogue, including the regional ones) uses `met`, `partial`, `unmet`, `not_observable`, with `score` null for `not_observable` controls; those are excluded from the framework average and never counted as met. Framework score = mean of observable control scores; `overall` = mean of the framework scores that have at least one observable control; grade `n/a` when none.
