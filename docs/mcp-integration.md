# Kavach MCP integration

`kavach-mcp` exposes a running Kavach controller as [Model Context Protocol](https://modelcontextprotocol.io/) tools over **stdio** — the sister of `netra-mcp`.

## Build

```bash
go build -o bin/kavach-mcp ./cmd/kavach-mcp
```

## Run

```bash
export KAVACH_URL=https://kavach.80.79.5.173.sslip.io:30943
export KAVACH_TOKEN='Admin@321Admin@321'
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

## Prompts & resources

Prompts: `kavach_triage`, `kavach_hunt`, `kavach_incident_report`, `kavach_xdr`.  
Resources: `kavach://summary`, `kavach://ai/briefing`, `kavach://ai/capabilities`, `kavach://modules`.

## Safety

Same as the HTTP API: observation-first. MCP mutations that “contain” only write the request ledger. No process kill, host isolate, or prevent actions.
