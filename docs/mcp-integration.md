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

Stdout is JSON-RPC only; diagnostics go to stderr.

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

## Tools

- **Read-only (default):** findings, detections, fleet, hosts, SIEM, IOC/IOA, Discover/Spotlight, OverWatch, Identity, Fusion, cases, threat-graph, modules, and the full AI surface (`kavach_ai_*`).
- **Mutations (`KAVACH_MCP_ALLOW_MUTATIONS=true`):** NL hunt, chat, triage, IOC create, cases, containment *requests*, RTR read-only diagnostics, enroll/revoke. Containment is never enforced by Kavach.
- **Analyst and risk tools:** read-only `kavach_risk_hosts`, `kavach_risk_summary`, `kavach_trends` (`days` 7|14|30, `bucket` hour|day), `kavach_export_findings` (json or ndjson only, severity/host/rule/since filters, `limit` default 200, max 1000), `kavach_notes`, `kavach_saved_searches`, `kavach_alert_rules`, `kavach_alert_deliveries`, `kavach_journal`, `kavach_journal_verify`. With mutations enabled: `kavach_note_add` and `kavach_saved_search_add` (both journaled). Alert rule and webhook create/delete are deliberately not exposed (SSRF and notification risk); manage those through the console or HTTP API.
- **Ops, posture and compliance tools (read-only):** `kavach_intel_feeds`, `kavach_intel_feed_status`, `kavach_lab_rules`, `kavach_soc_metrics` (`days`), `kavach_host_storyline` (`host`, `hours`), `kavach_shift_report` (`hours`), `kavach_posture_summary`, `kavach_vuln_priority` (`limit`), `kavach_posture_assets`, `kavach_posture_drift` (`host`), `kavach_compliance_controls` and `kavach_compliance_evidence` (`framework` one of cis-v8, nist-csf-2, soc2, iso27001, rbi, cert-in, dpdp; evidence `format` is json only, HTML is never served through MCP), `kavach_cert_in_clock` (informational; Kavach files no CERT-In reports).
- **Detection lab and posture (mutation flag):** `kavach_lab_validate`, `kavach_lab_test` and `kavach_lab_backtest` are sandbox-only and persist nothing, but they are HTTP POSTs. Existing gating treats every POST as mutating (`kavach_hunt_query` is likewise a read-in-effect POST behind the flag), so they register only when `KAVACH_MCP_ALLOW_MUTATIONS=true`. `kavach_posture_asset_set` (criticality 1-5, ledger only) is also behind the flag.
- **Never exposed:** creating or deleting intel feeds, lab rules or posture assets, feed refresh and posture baseline (SSRF and state-change risk). Humans manage those through the console or HTTP API.

## Prompts & resources

Prompts: `kavach_triage`, `kavach_hunt`, `kavach_incident_report`, `kavach_host_risk_briefing`, `kavach_shift_handoff` (`hours`), `kavach_compliance_gap_review` (`framework`), `kavach_xdr`.  
Resources: `kavach://summary`, `kavach://ai/briefing`, `kavach://ai/capabilities`, `kavach://modules`.

## Safety

Same as the HTTP API: observation-first. MCP mutations that “contain” only write the request ledger. No process kill, host isolate, or prevent actions.
