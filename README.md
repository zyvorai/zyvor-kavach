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
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s
# → https://HOST:30899
```

See [docs/deploy-remote.md](docs/deploy-remote.md).

## Features

Honest about what ships today:

| Capability | Status |
|---|---|
| EDR observation (process, file-activity signals, fleet heartbeats) | Shipping — observation only |
| XDR correlation with Netra network events | Bridge / poller; normalized ingest |
| Ransomware signals (mass file-activity) | Investigative signal, not prevention |
| eBPF exec sensor | Scaffold (`bpf/`); loader path optional |
| SIEM export | JSONL / API findings for downstream sinks |
| AI assistive scoring | Assistive ranking of findings — not autonomous response |
| Agent ↔ controller mTLS | Opt-in (`docs/agent-mtls.md`) |
| Gateway API / Envoy front door | Opt-in (`docs/envoy-gateway.md`) |

No automatic containment, process kill, or malware prevention is claimed.

## Docs

- [Architecture](docs/architecture.md)
- [Agent mTLS](docs/agent-mtls.md)
- [Envoy Gateway](docs/envoy-gateway.md)
- [Remote deploy](docs/deploy-remote.md)
- Site: https://zyvorai.github.io/zyvor-kavach/

## License

Zyvor Production License v1.0 — free for evaluation and non-production use; commercial license required for production. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Repository

https://github.com/zyvorai/zyvor-kavach
