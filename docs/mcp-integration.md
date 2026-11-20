# Kavach MCP integration

`kavach-mcp` exposes a running Kavach controller as [Model Context Protocol](https://modelcontextprotocol.io/) tools over **stdio** — the sister of `netra-mcp`.

## Build

```bash
go build -o bin/kavach-mcp ./cmd/kavach-mcp
```

## Run

```bash
export KAVACH_URL=https://kavach.80.79.5.173.sslip.io:30943
export KAVACH_TOKEN='Admin@321'
export KAVACH_MCP_TLS_INSECURE=true   # self-signed lab certs
# optional ledger mutations (still observation-only on the controller):
# export KAVACH_MCP_ALLOW_MUTATIONS=true
./bin/kavach-mcp
```

Stdout is JSON-RPC only; diagnostics go to stderr (a start line `kavach-mcp 0.1.0 → <url> (mutations=false)`).

| Variable | Meaning |
|---|---|
| `KAVACH_URL` (alias `KAVACH_MCP_URL`) | Controller base URL; default `https://127.0.0.1:30899` |
| `KAVACH_TOKEN` (aliases `KAVACH_MCP_TOKEN`, `ZYVOR_EDR_TOKEN`) | Bearer token. Without it every tool call returns `set KAVACH_TOKEN (or KAVACH_MCP_TOKEN)` |
| `KAVACH_MCP_TLS_INSECURE` or `KAVACH_TLS_INSECURE` | `true` skips certificate verification. Unlike `kavachctl`, there is no automatic skip on loopback |
| `KAVACH_MCP_ALLOW_MUTATIONS` | `true` registers the mutating tools (below); anything else keeps the server read-only |
| `KAVACH_MCP_ACTOR` | Read into the client (default `kavach-mcp`); no code path that sends it as a header was found, so do not rely on it for attribution |

HTTP calls have a 30 second timeout. The server speaks MCP over stdio only; there is no network listener.

## Claude Desktop / Cursor config

```json
{
  "mcpServers": {
    "kavach": {
      "command": "/path/to/bin/kavach-mcp",
      "env": {
        "KAVACH_URL": "https://127.0.0.1:30899",
        "KAVACH_TOKEN": "your-token",
        "KAVACH_MCP_TLS_INSECURE": "true"
      }
    }
  }
}
```

## How many tools

Measured at this commit with `tools/list`: **425 tools in the default read-only mode, 499 with
`KAVACH_MCP_ALLOW_MUTATIONS=true`**. Names are mostly `kavach_<area>_<thing>`, but several families use a bare prefix
(`fleet_*`, `ml_*`, `vulns_*`, `inspect_*`, `syslog_*`, `detections_scheduled_*`, `exceptions_*`, `reports_scheduled_*`,
`tuning_*`, `digest_*`, `global_search`, `export_*`). Use your client's tool list rather than guessing names. The counts
change as tools are added; [cli-reference.md](cli-reference.md) shows how to re-measure.

## Tools

- **Read-only (default):** findings, detections, fleet, hosts, SIEM, IOC/IOA, Discover/Spotlight, OverWatch, Identity, Fusion, cases, threat-graph, modules, and the full AI surface (`kavach_ai_*`).
- **Mutations (`KAVACH_MCP_ALLOW_MUTATIONS=true`):** NL hunt, chat, triage, IOC create, cases, containment *requests*, RTR read-only diagnostics, enroll/revoke. Containment is never enforced by Kavach.
- **Analyst and risk tools:** read-only `kavach_risk_hosts`, `kavach_risk_summary`, `kavach_trends` (`days` 7|14|30, `bucket` hour|day), `kavach_export_findings` (json or ndjson only, severity/host/rule/since filters, `limit` default 200, max 1000), `kavach_notes`, `kavach_saved_searches`, `kavach_alert_rules`, `kavach_alert_deliveries`, `kavach_journal`, `kavach_journal_verify`. With mutations enabled: `kavach_note_add` and `kavach_saved_search_add` (both journaled). Alert rule and webhook create/delete are deliberately not exposed (SSRF and notification risk); manage those through the console or HTTP API.
- **Ops, posture and compliance tools (read-only):** `kavach_intel_feeds`, `kavach_intel_feed_status`, `kavach_lab_rules`, `kavach_soc_metrics` (`days`), `kavach_host_storyline` (`host`, `hours`), `kavach_shift_report` (`hours`), `kavach_posture_summary`, `kavach_vuln_priority` (`limit`), `kavach_posture_assets`, `kavach_posture_drift` (`host`), `kavach_compliance_controls` and `kavach_compliance_evidence` (`framework` one of cis-v8, nist-csf-2, soc2, iso27001, rbi, cert-in, dpdp; evidence `format` is json only, HTML is never served through MCP), `kavach_cert_in_clock` (informational; Kavach files no CERT-In reports).
- **Detection lab and posture (mutation flag):** `kavach_lab_validate`, `kavach_lab_test` and `kavach_lab_backtest` are sandbox-only and persist nothing, but they are HTTP POSTs. Existing gating treats every POST as mutating (`kavach_hunt_query` is likewise a read-in-effect POST behind the flag), so they register only when `KAVACH_MCP_ALLOW_MUTATIONS=true`. `kavach_posture_asset_set` (criticality 1-5, ledger only) is also behind the flag.
- **Never exposed:** creating or deleting intel feeds, lab rules or posture assets, feed refresh and posture baseline (SSRF and state-change risk). Humans manage those through the console or HTTP API.

- **Newer read-only families (examples):** `fleet_health`, `fleet_slo`, `fleet_coverage_gaps`, `fleet_stale`; `ml_status`,
  `ml_beacons`, `ml_dns`, `ml_users`, `ml_peers`, `ml_priority`; `vulns_priority`, `vuln_advisories`; `inspect_reports`,
  `inspect_similar`, `inspect_sarif`; `kavach_posture_trend`, `kavach_posture_diff`; `kavach_regression_*`; `global_search`;
  `syslog_status`, `syslog_samples`; `kavach_siem_status`; `export_findings_siem`, `export_iocs_stix`, `export_attack_layer`;
  and the surface-parity set listed in [cli-reference.md](cli-reference.md).
- **Mutation-flag tools added by later work (all write only Kavach's own state):** `exceptions_create|update|expire|delete`,
  `detections_scheduled_create|update|delete|run`, `reports_scheduled_create|update|delete|run`, `tuning_apply|revert`,
  `digest_set|send_now`, `fleet_slo_set`, `feedback_record`, `canary_create|delete`, `case_*` write tools, `hunt_run`,
  `hunt_schedule_add|remove`, `kavach_agents_enroll|revoke`, `kavach_rtr_open|execute` (allowlisted read-only diagnostics),
  `kavach_containment_request` (request ledger only).
- **Not available over MCP at this commit:** the software-exposure routes (`/v1/exposure/*`), cloud audit ingest and sources, and
  the URL/e-mail inspector endpoints. Use HTTP or `kavachctl` for those ([exposure.md](exposure.md),
  [cloud-audit.md](cloud-audit.md), [url-email-inspection.md](url-email-inspection.md)).

## Worked example (raw JSON-RPC)

```bash
export KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN='Admin@321'
(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kavach_summary","arguments":{}}}'; sleep 1) | ./bin/kavach-mcp
```

A mutating tool called without `KAVACH_MCP_ALLOW_MUTATIONS=true` is simply not registered, so the client sees an unknown-tool
error rather than a refusal from the controller. Even with the flag on, the controller still enforces its own auth (an admin
token for writes) and observation-only rules.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Client shows no tools or a parse error | Something wrote to stdout. Only JSON-RPC may go to stdout; keep wrappers quiet |
| Tool result `set KAVACH_TOKEN` | Token is not in the server's `env` block of the client config |
| `x509: certificate signed by unknown authority` | Set `KAVACH_MCP_TLS_INSECURE=true` for a self-signed lab certificate |
| `HTTP 403` on a write tool | The token is not the admin token, or the controller refuses (for example session-only routes) |
| A tool you expected is missing | Either it needs `KAVACH_MCP_ALLOW_MUTATIONS=true`, or it is one of the gaps above |

## Prompts & resources

Prompts: `kavach_triage`, `kavach_hunt`, `kavach_incident_report`, `kavach_host_risk_briefing`, `kavach_shift_handoff` (`hours`), `kavach_compliance_gap_review` (`framework`), `kavach_xdr`.  
Resources: `kavach://summary`, `kavach://ai/briefing`, `kavach://ai/capabilities`, `kavach://modules`.

## Safety

Same as the HTTP API: observation-first. MCP mutations that “contain” only write the request ledger. No process kill, host isolate, or prevent actions.
