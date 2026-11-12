# Kavach.

**Security without compromise.**

Observation-first endpoint, cloud, and AI security by [ZYVOR](https://zyvor.dev) — sister to [Netra](https://github.com/zyvorai/netra).

[![Docs](https://img.shields.io/badge/Docs-zyvorai.github.io-0071e3)](https://zyvorai.github.io/zyvor-kavach/)
[![License](https://img.shields.io/badge/License-Zyvor%20Production%20v1.0-6e6e73)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

<p align="center">
  <img src="docs/social/kavach-hero-dark.jpg" alt="Kavach — Security without compromise" width="100%">
</p>

**Detect and report. Never contain.**

- **Observation only** — findings, fleet, hunt, AI assist. Containment stays a request ledger.
- **Quiet console + CLI** — Apple-style investigate UI, `kavachctl`, MCP for agents.
- **Finance & sectors** — banks, insurance, public fleets, industry, space, eBPF. Observe only.

→ **[Product docs & story](https://zyvorai.github.io/zyvor-kavach/)**

---

## Quickstart

```bash
git clone https://github.com/zyvorai/zyvor-kavach.git && cd zyvor-kavach
export KAVACH_TOKEN='Admin@321'

go test ./...
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
```

Second terminal:

```bash
export KAVACH_TOKEN='Admin@321'
go run ./cmd/kavach -mode agent -url http://127.0.0.1:8099
go build -o bin/kavachctl ./cmd/kavachctl
KAVACH_URL=http://127.0.0.1:8099 ./bin/kavachctl status
open http://127.0.0.1:8099/   # admin / Admin@321
```

---

## Deploy

**Local**

```bash
export KAVACH_TOKEN='Admin@321'
go run ./cmd/kavach -mode server -listen 0.0.0.0:8099
```

**Kubernetes lab**

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
# NodePort  → https://HOST:30899/
# Envoy     → https://kavach.HOST.sslip.io:30943/
```

→ [Tutorial](docs/tutorial.md) · [Remote deploy](docs/deploy-remote.md) · [Envoy](docs/envoy-gateway.md) · [mTLS](docs/agent-mtls.md)

---

## Operator surfaces

| Surface | |
|---------|--|
| **Console** | Sign in `admin` / `Admin@321` — [console.md](docs/console.md) |
| **kavachctl** | `status` · `findings` · `finance` · `sectors` · `ebpf` — [kavachctl.md](docs/kavachctl.md) |
| **Finance** | Banks, UPI, insurance, IRDAI — never freezes money — [finance.md](docs/finance.md) |
| **Sectors** | Rail, fleets, industry, space — never immobilizes — [sectors.md](docs/sectors.md) |
| **eBPF** | Observe-only CO-RE — [ebpf.md](docs/ebpf.md) |
| **Observe** | ATT&CK matrix · compliance grade · live SSE · Prometheus — [observability.md](docs/observability.md) |
| **MCP** | Agent tooling — [mcp-integration.md](docs/mcp-integration.md) |

```bash
./bin/kavachctl finance summary
./bin/kavachctl sectors public-vehicles
./bin/kavachctl ebpf health
```

---

## Architecture

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
     └────────────────────┘      └─────────────────┘
```

→ [architecture.md](docs/architecture.md)

---

## Docs

| | |
|--|--|
| [Site](https://zyvorai.github.io/zyvor-kavach/) | Story + full guides |
| [Tutorial](docs/tutorial.md) | First hour |
| [Use cases](docs/use-cases.md) | SOC, hunt, XDR |
| [Testing](docs/testing.md) | Unit, smoke, lab |
| [OpenAPI](docs/openapi.yaml) | HTTP contract |

```bash
go test ./...
```

---

## License

Zyvor Production License v1.0 — free for evaluation and non-production use; commercial license required for production. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**Repo:** https://github.com/zyvorai/zyvor-kavach
