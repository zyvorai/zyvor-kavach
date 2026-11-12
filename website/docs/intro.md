---
sidebar_position: 1
title: Intro
---

# Kavach

**Security without compromise.** Zyvor Kavach is unified endpoint, cloud and AI
security — observation-first EDR with Netra XDR correlation for Linux and
Kubernetes.

## Quickstart

```bash
export KAVACH_TOKEN='replace-with-at-least-16-random-characters'
go run ./cmd/kavach -mode server
# second terminal:
go run ./cmd/kavach -mode agent
```

## Next

- [Architecture](./architecture.md)
- [Remote deploy](./deploy-remote.md)
- [Agent mTLS](./agent-mtls.md)
- [Envoy Gateway](./envoy-gateway.md)
- API stub: [docs/openapi.yaml](https://github.com/zyvorai/zyvor-kavach/blob/main/docs/openapi.yaml)
- Lab demo: [scripts/demo-lab.sh](https://github.com/zyvorai/zyvor-kavach/blob/main/scripts/demo-lab.sh)

Site: https://zyvorai.github.io/zyvor-kavach/  
Repo: https://github.com/zyvorai/zyvor-kavach
