# Kavach

**Security without compromise.**

by [ZYVOR](https://zyvor.dev)

Zyvor Kavach is observation-first endpoint, cloud, and AI security — the sister console to [Netra](https://github.com/zyvorai/netra). Detect and report. **Never** contain, kill, or isolate.

[![License](https://img.shields.io/badge/License-Zyvor%20Production%20v1.0-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/Docs-zyvorai.github.io-0a84ff)](https://zyvorai.github.io/zyvor-kavach/)
[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/eBPF-observe--only-30d158)](bpf/)
[![CLI](https://img.shields.io/badge/kavachctl-netra%20sister-ff5a15)](docs/kavachctl.md)

<p align="center">
  <img src="docs/social/kavach-hero-dark.jpg" alt="Kavach — Security without compromise" width="100%">
</p>

---

## Why Kavach?

| | |
|---|---|
| **Observation only** | Findings, fleet, hunt, AI assist — no automatic containment |
| **Module map** | Insight, Prevent, Discover, Spotlight, OverWatch, Identity, Fusion, Hunt, … |
| **AI + World + Finance + Sectors** | AI, world catalog, eBPF, banks/markets, railways/govt/infra observe |
| **Netra sister** | Network XDR via bridge/poller; shared Zyvor UX and CLI patterns |
| **Operator tools** | Apple.com-style console, `kavachctl`, MCP server for agents |

Hard rule: **detect and report.** Containment is a request ledger. eBPF never drops packets. Prevention policies never quarantine.

---

## Quickstart (60 seconds)

```bash
git clone https://github.com/zyvorai/zyvor-kavach.git && cd zyvor-kavach
export KAVACH_TOKEN='Admin@321'   # demo default (≥8 chars)

go test ./...
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
```

Second terminal:

```bash
export KAVACH_TOKEN='Admin@321'
go run ./cmd/kavach -mode agent -url http://127.0.0.1:8099
go build -o bin/kavachctl ./cmd/kavachctl
KAVACH_URL=http://127.0.0.1:8099 ./bin/kavachctl status
open http://127.0.0.1:8099/   # Sign in: admin / Admin@321
```

---

## Table of contents

- [Architecture](#architecture-at-a-glance)
- [Deploy](#deploy)
- [Console login](#console-login)
- [kavachctl](#kavachctl)
- [eBPF](#ebpf-observe-only)
- [Features](#features)
- [Tutorials & docs](#documentation)
- [Testing](#testing)
- [Use cases](#use-cases)
- [MCP](#mcp-server)
- [License](#license)

---

## Architecture at a glance

```text
  Browser / kavachctl / MCP / SIEM
              │
              ▼
     ┌────────────────────┐
     │  kavach controller │  HTTPS :30899 / Envoy :30943
     │  findings · AI Hub │  Apple.com console · /v1/*
     │  eBPF platform API │
     └─────────┬──────────┘
               │ bearer / session / optional mTLS
     ┌─────────▼──────────┐      ┌─────────────────┐
     │  kavach agent      │      │ Netra poller /  │
     │  /proc · eBPF pins │      │ netra-bridge    │
     │  host collectors   │      │ (network XDR)   │
     └────────────────────┘      └─────────────────┘
```

Full diagram and data paths: **[docs/architecture.md](docs/architecture.md)**.

---

## Deploy

### Local

```bash
export KAVACH_TOKEN='Admin@321'
go run ./cmd/kavach -mode server -listen 0.0.0.0:8099
```

### Kubernetes lab (PacketWolf/Netra demo host)

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
# Controller NodePort  → https://HOST:30899/
# Envoy Gateway HTTPS  → https://kavach.HOST.sslip.io:30943/
```

Default lab token: **`Admin@321`**. Console username: **`admin`**.

| Guide | |
|-------|--|
| [Tutorial](docs/tutorial.md) | End-to-end first hour |
| [Remote deploy](docs/deploy-remote.md) | SSH sync, Helm, image import |
| [Envoy Gateway](docs/envoy-gateway.md) | Gateway API front door |
| [Agent mTLS](docs/agent-mtls.md) | Mutual TLS agents |

---

## Console login

1. Open `https://kavach.<ip>.sslip.io:30943/` (or NodePort `:30899`).
2. Sign in with **username `admin`** and **password `Admin@321`** (password = `KAVACH_TOKEN`).
3. Full-width Apple/Netra sister UI — Overview story, Browse menu, eBPF, Finance, AI Hub, World.

Details: **[docs/console.md](docs/console.md)**.

---

## kavachctl

Sister CLI to `netractl`.

```bash
go build -o bin/kavachctl ./cmd/kavachctl
export KAVACH_URL=https://kavach.80.79.5.173.sslip.io:30943
export KAVACH_TOKEN=Admin@321 KAVACH_TLS_INSECURE=true

./bin/kavachctl status
./bin/kavachctl findings --severity high
./bin/kavachctl fleet
./bin/kavachctl hunt query 'severity:high'
./bin/kavachctl ai briefing
./bin/kavachctl ebpf health
./bin/kavachctl finance summary
./bin/kavachctl sectors railways
./bin/kavachctl world modules
```

→ **[docs/kavachctl.md](docs/kavachctl.md)**

---

## Finance (banks & markets)

Dalal Street module for banks, NBFCs, BSE/NSE/GIFT, UPI, cards, SWIFT, fraud/KYC/sanctions, RBI/SEBI posture — **observe only** (never freezes money).

```bash
./bin/kavachctl finance summary
./bin/kavachctl finance exchanges
./bin/kavachctl finance upi
./bin/kavachctl finance sebi
```

APIs under `/v1/finance/*`. Console: **Browse → Finance**.

→ **[docs/finance.md](docs/finance.md)**

---

## Sectors (railways, government & more)

Critical infrastructure observe — railways, metro, gov portals, power/SCADA, telecom, aviation, ports, health, education, smart city — **never** stops services.

```bash
./bin/kavachctl sectors summary
./bin/kavachctl sectors railways
./bin/kavachctl sectors airports
./bin/kavachctl sectors flights
./bin/kavachctl sectors defence
./bin/kavachctl sectors gov-portals
./bin/kavachctl sectors critical-sites
```

APIs under `/v1/sectors/*`. Console: **Browse → Sectors**.

→ **[docs/sectors.md](docs/sectors.md)**

---

## eBPF (observe only)

CO-RE programs for exec, fork/exit, file open, privilege/abuse, and host connect — **never** kill or drop.

```bash
./scripts/build-bpf.sh          # Linux + clang
./bin/kavachctl ebpf status
./bin/kavachctl ebpf events --type exec
```

APIs under `/v1/ebpf/*`. Netra datapath enforce is mirrored as XDR input only.

→ **[docs/ebpf.md](docs/ebpf.md)** · [`bpf/README.md`](bpf/README.md)

---

## Features

Honest about what ships:

| Capability | Status |
|---|---|
| Insight + MITRE detections | Observation only |
| Prevent IOA/IOC/policies | Detect-only — never quarantine |
| Discover / Spotlight / OverWatch | Live inventory + feeds |
| Identity + UEBA | Events + scores |
| Fusion / cases / RTR ledger | Ledger & read-only |
| Containment requests | **Ledger only — never enforced** |
| Hunt + threat graph + timeline | Shipping |
| AI Platform (22+) | Chat, NL hunt, forecast, multi-agent, … |
| World catalog (35+) | Storyline, AIR, CNAPP, FIM, … |
| eBPF observe platform | `/v1/ebpf/*` + CO-RE objects |
| Banks / markets / UPI / fraud | `/v1/finance/*` — never freezes money |
| Railways / govt / energy / aviation / … | `/v1/sectors/*` — never stops services |
| Netra XDR | Bridge / poller |
| SIEM export · MCP · mTLS · Envoy | Opt-in docs |

`GET /v1/modules` · `GET /v1/world/modules` · `GET /v1/ebpf/capabilities` · `GET /v1/finance/summary` · `GET /v1/sectors/summary`

---

## Documentation

| Doc | What you’ll learn |
|-----|-------------------|
| **[Tutorial](docs/tutorial.md)** | Install → deploy → login → hunt → AI → eBPF → finance |
| **[Architecture](docs/architecture.md)** | Components, data path, trust boundaries |
| **[Use cases](docs/use-cases.md)** | SOC, IR, hunt, compliance, banks/markets, AI assist |
| **[Testing](docs/testing.md)** | Unit, API, lab smoke, CI |
| **[Console](docs/console.md)** | Login, UX, pages |
| **[kavachctl](docs/kavachctl.md)** | Operator CLI |
| **[eBPF](docs/ebpf.md)** | Sensors, pins, APIs |
| **[Finance](docs/finance.md)** | Banks, stock markets, UPI, RBI/SEBI |
| **[Sectors](docs/sectors.md)** | Railways, government, energy, aviation, … |
| **[Deploy remote](docs/deploy-remote.md)** | Helm / k3s lab |
| **[Envoy Gateway](docs/envoy-gateway.md)** | Gateway API |
| **[Agent mTLS](docs/agent-mtls.md)** | Client certs |
| **[MCP](docs/mcp-integration.md)** | Agent tooling |
| **[OpenAPI](docs/openapi.yaml)** | HTTP contract |
| **Site** | https://zyvorai.github.io/zyvor-kavach/ |

---

## Testing

```bash
go test ./...
go test ./internal/edr/ -count=1
./scripts/demo-lab.sh          # needs running server + token
```

→ **[docs/testing.md](docs/testing.md)**

---

## Use cases

- **SOC triage** — findings → detections → AI briefing → incident ledger  
- **Threat hunt** — `kavachctl hunt` / NL hunt / KQL / storyline  
- **Fleet hygiene** — enroll agents, Discover, Spotlight, sensor health  
- **XDR with Netra** — network drops/flows correlated to host process  
- **Compliance posture** — zero-trust / CIS-style scorecards (observe)  

→ **[docs/use-cases.md](docs/use-cases.md)**

---

## MCP server

```bash
go build -o bin/kavach-mcp ./cmd/kavach-mcp
KAVACH_URL=https://127.0.0.1:30899 \
KAVACH_TOKEN="$KAVACH_TOKEN" \
KAVACH_MCP_TLS_INSECURE=true \
./bin/kavach-mcp
```

→ **[docs/mcp-integration.md](docs/mcp-integration.md)**

---

## Repository layout

```text
cmd/kavach          Controller + agent
cmd/kavachctl       Operator CLI (netractl sister)
cmd/kavach-mcp      MCP stdio server
cmd/netra-bridge    Netra → Kavach network ingest
internal/edr        Store, rules, APIs, console, eBPF platform
bpf/                CO-RE observation programs
helm/kavach         Kubernetes chart
scripts/            deploy-remote, build-bpf, demo-lab
docs/               Tutorials and references
website/            Docusaurus (GitHub Pages)
```

---

## License

Zyvor Production License v1.0 — free for evaluation and non-production use; commercial license required for production. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**Repo:** https://github.com/zyvorai/zyvor-kavach
