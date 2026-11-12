# KAVACH

**Security without compromise.**

by ZYVOR

Zyvor Kavach — Unified Endpoint, Cloud & AI Security.

[![License](https://img.shields.io/badge/License-Zyvor%20Production%20v1.0-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/Docs-zyvorai.github.io-0a84ff)](https://zyvorai.github.io/zyvor-kavach/)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/eBPF-scaffold-30d158)](bpf/)

<p align="center">
  <img src="docs/social/kavach-hero-dark.jpg" alt="Kavach — Security without compromise" width="100%">
</p>

## Quickstart

```bash
export KAVACH_TOKEN='replace-with-at-least-16-random-characters'
go test ./...
go run ./cmd/kavach -mode server
# second terminal, same token:
go run ./cmd/kavach -mode agent
curl -H "Authorization: Bearer $KAVACH_TOKEN" http://127.0.0.1:8099/v1/findings
```

## Deploy

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
# → https://HOST:30899
```

See [docs/deploy-remote.md](docs/deploy-remote.md).

## Features

Honest about what ships today:

| Capability | CrowdStrike analogue | Status |
|---|---|---|
| Insight detections + MITRE | Falcon Insight XDR | Shipping — observation only |
| Prevent IOA/IOC + policies | Falcon Prevent | Detect-only — IOC/IOA/custom rules drive `Detect()`; never quarantine |
| Device Control / Firewall inventory | Device Control / Firewall Mgmt | Visibility + persisted USB observations |
| Discover assets & apps | Falcon Discover | Shipping (inventory + seeds) |
| Spotlight CVEs | Falcon Spotlight | Shipping (inventory + seeds) |
| OverWatch hunting alerts | Falcon OverWatch | Shipping (feed API) |
| Adversary intel / actors | Falcon X | Shipping (profiles + indicators) |
| Identity + UEBA | Falcon Identity | Shipping (events + UEBA scores) |
| Fusion playbooks / cases | Falcon Fusion / NG-SIEM | Ledger-only SOAR |
| RTR diagnostics | Falcon RTR | Read-only store-backed commands |
| Host containment requests | Host Management | Request ledger — never enforced |
| Hunt (FQL-lite) + threat graph + timeline | Falcon Hunt / Threat Graph / Insight | Shipping |
| Charlotte-lite assist | Charlotte AI | Assistive triage (+ optional `KAVACH_LLM_URL`) |
| **Kavach AI Platform (22+)** | **Beyond Charlotte / Complete** | Chat, NL hunt, narratives, clusters, attack-path, forecast, multi-agent SOC, what-if, Guardian, XDR fusion, autopilot |
| **World catalog (35+)** | **S1 / Defender / Cortex / Elastic / Trend / Cisco…** | Storyline, AIR, KQL, Ranger, deception, CASB/email/DLP/CNAPP/ASRM, forensics, FIM, YARA/Sigma, BAS, ZT, MDR — APIs + console domain loader |
| Cloud / Mobile / OT / Browser | Falcon Cloud / Mobile / IoT | Live inventory ingest (`POST /v1/inventory`) + agent browser scan |
| CASB / Email / DLP / DNS / MDR / ZT / Compliance | World vendors | Derived from network/findings/fleet + connector ingest |
| FIM / Persistence / Firewall / SBOM | Host sensors | Agent collectors (default `/etc` FIM) |
| XDR via Netra | Insight XDR network | Bridge / poller (`KAVACH_NETRA_POLLER_ENABLED`) |
| SIEM export + connectors | Next-Gen SIEM | Live status from env + webhook/syslog/NDJSON |
| eBPF exec sensor | Sensor | Pin watch → proc connector → poll (`bpf/` CO-RE object) |
| RBAC | Enterprise consoles | Catalog + optional `KAVACH_RBAC=1` enforcement |
| Agent mTLS / Envoy Gateway | Platform | Opt-in docs |
| MCP server | AI agent tooling | `kavach-mcp` stdio (read + opt-in mutations) |

No automatic containment, process kill, or malware prevention is claimed. See `GET /v1/modules` and `GET /v1/world/modules`.

### Lab demo

Against a running server (admin token required):

```bash
export KAVACH_URL=https://127.0.0.1:8099
export KAVACH_TOKEN='…'
./scripts/demo-lab.sh
```

API surface: [docs/openapi.yaml](docs/openapi.yaml).

### MCP server

```bash
go build -o bin/kavach-mcp ./cmd/kavach-mcp
KAVACH_URL=https://127.0.0.1:30899 KAVACH_TOKEN="$KAVACH_TOKEN" KAVACH_MCP_TLS_INSECURE=true ./bin/kavach-mcp
```

See [docs/mcp-integration.md](docs/mcp-integration.md). Sister to `netra-mcp`.

## Docs

- [Architecture](docs/architecture.md)
- [Agent mTLS](docs/agent-mtls.md)
- [Envoy Gateway](docs/envoy-gateway.md)
- [Remote deploy](docs/deploy-remote.md)
- [MCP integration](docs/mcp-integration.md)
- [OpenAPI](docs/openapi.yaml)
- Site: https://zyvorai.github.io/zyvor-kavach/

## License

Zyvor Production License v1.0 — free for evaluation and non-production use; commercial license required for production. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Repository

https://github.com/zyvorai/zyvor-kavach
