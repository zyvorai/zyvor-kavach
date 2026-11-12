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

Site: https://zyvorai.github.io/zyvor-kavach/  
Repo: https://github.com/zyvorai/zyvor-kavach
