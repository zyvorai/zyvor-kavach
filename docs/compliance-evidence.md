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
