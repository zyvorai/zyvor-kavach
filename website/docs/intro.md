---
sidebar_position: 1
title: Intro
---

# Kavach.

**Security without compromise.**

Observation-first endpoint, cloud, and AI security — the sister console to Netra. Detect and report. Never contain, kill, or isolate.

Start with the [product story](/), then the [tutorial](./tutorial.md) for a first-hour path from install to hunt.

## Quickstart

```bash
export KAVACH_TOKEN='Admin@321'
go test ./...
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
# second terminal:
go run ./cmd/kavach -mode agent -url http://127.0.0.1:8099
```

Console: http://127.0.0.1:8099/ — sign in **`admin` / `Admin@321`**.

## Documentation map

| Guide | |
|-------|--|
| [Tutorial](./tutorial.md) | First hour end-to-end |
| [Architecture](./architecture.md) | Components and data path |
| [Use cases](./use-cases.md) | SOC, hunt, XDR, compliance |
| [Testing](./testing.md) | Unit, smoke, lab |
| [Console](./console.md) | Login and UX |
| [kavachctl](./kavachctl.md) | Operator CLI |
| [eBPF](./ebpf.md) | Observe-only sensors |
| [Finance](./finance.md) | Banks / markets / insurance |
| [Sectors](./sectors.md) | Rail, fleets, industry, space |
| [Remote deploy](./deploy-remote.md) | Helm / k3s |
| [Envoy Gateway](./envoy-gateway.md) | Gateway API |
| [Agent mTLS](./agent-mtls.md) | Client certificates |
| [MCP](./mcp-integration.md) | AI agent tooling |

API contract: [openapi.yaml](https://github.com/zyvorai/zyvor-kavach/blob/main/docs/openapi.yaml)

Site: https://zyvorai.github.io/zyvor-kavach/  
Repo: https://github.com/zyvorai/zyvor-kavach
