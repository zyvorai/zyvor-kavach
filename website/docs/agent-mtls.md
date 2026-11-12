# Agent ↔ controller mutual TLS

By default an agent authenticates with a bearer token (`KAVACH_TOKEN` or a
host-scoped enrollment token). Mutual TLS adds a second factor: the agent must
also present a client certificate signed by a CA you control.

**Off by default.** With `mtls.mode=off` (Helm default), nothing about an install
changes.

## Modes

| Mode | Behaviour |
|---|---|
| `off` (default) | No client certificate requested |
| `optional` | Controller verifies a certificate when offered; agents without one still work |
| `required` | Agent requests without a verified client certificate are refused |

Helm:

```bash
helm upgrade --install kavach ./helm/kavach -n kavach-system \
  --set auth.token="$KAVACH_TOKEN" \
  --set mtls.mode=optional \
  --set mtls.secretName=kavach-agent-mtls
```

The Secret must hold `ca.crt`. Agents also need `tls.crt` and `tls.key`. The
controller mounts the CA only — never the agents' private key.

## Flags / env

| Side | Setting |
|---|---|
| Server | `-client-ca` (PEM CA); requires `-tls-cert` / `-tls-key` |
| Agent | `-agent-cert`, `-agent-key`, optional `-ca` |

Tokens remain mandatory. A certificate is a second factor, not a replacement.
This is not managed enrollment, TPM attestation, or automatic rotation —
certificates are provisioned out of band.

## Rollout

1. Issue CA + client cert; store in a Secret.
2. Set `mtls.mode=optional`, restart agents, confirm they present certs.
3. Flip to `mtls.mode=required` when every agent is covered.
