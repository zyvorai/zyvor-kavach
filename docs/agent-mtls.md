# Agent to controller mutual TLS

By default an agent authenticates with a bearer token (`KAVACH_TOKEN` or a
host-scoped enrollment token). Mutual TLS adds a second factor: the agent must
also present a client certificate signed by a CA you control.

**Off by default.** With `mtls.mode=off` (Helm default), nothing about an install
changes. Tokens remain mandatory in every mode: a certificate is a second factor,
not a replacement. This is not managed enrollment, TPM attestation or automatic
rotation; certificates are provisioned out of band.

## What the code actually does (read this first)

The behaviour is defined by two small functions in `internal/edr/secure_transport.go`:

- `ServerTLSConfig(caPath)`: TLS 1.2 minimum. When a client CA file is given it sets
  `ClientAuth = tls.RequireAndVerifyClientCert`. There is no code path that requests a
  certificate but accepts a connection without one.
- `NewMutualTLSClient(ca, cert, key)`: TLS 1.2 minimum, 5 second client timeout, the
  CA bundle is appended to the system roots, and the cert/key pair must be given
  together. It never sets `InsecureSkipVerify`.

Consequences, stated plainly:

- Passing `-client-ca` makes the **TLS handshake itself** require a verified client
  certificate from every client of that listener: agents, but also browsers,
  `kavachctl`, Prometheus and Kubernetes HTTPS probes, if they connect to the same port.
  The same listener serves the console and the API, so there is no separate agent port.
- The Helm chart passes `-client-ca` whenever `mtls.mode` is not `off`
  (`helm/kavach/templates/deployment.yaml`). `optional` and `required` therefore render
  the same controller arguments. **The "optional" behaviour described in the chart
  comments (agents without a certificate still work) is not confirmed in the code; the
  server code only implements require-and-verify.** Verify this on a throwaway install
  before relying on `optional` as a migration step, and note that the chart's own
  readiness and liveness probes are plain HTTPS `httpGet` probes without a client
  certificate. Not verified on a live cluster in this documentation pass.
- The agent binary does not read `KAVACH_TLS_INSECURE`. The chart exports it into the
  DaemonSet when `tls.agentInsecureSkipVerify=true`, but only `kavachctl` and `kavach-mcp`
  read that variable. An agent trusting the chart's self-signed certificate needs the CA
  passed with `-ca`.

## Modes (Helm)

| Mode | Chart behaviour | Verified controller behaviour |
|---|---|---|
| `off` (default) | No `-client-ca`; no client certificate requested | Confirmed |
| `optional` | Mounts the CA and passes `-client-ca` | Same as `required` (see above) |
| `required` | Mounts the CA and passes `-client-ca` | Every TLS connection needs a verified client certificate |

The chart refuses to render (`helm template` fails) if `mtls.mode` is not one of the three
values, if `tls.enabled=false` (a client certificate cannot be requested over plain HTTP)
or if `mtls.secretName` is empty.

```bash
helm upgrade --install kavach ./helm/kavach -n kavach-system \
  --set auth.token="$KAVACH_TOKEN" \
  --set mtls.mode=required \
  --set mtls.secretName=kavach-agent-mtls
```

The Secret must hold `ca.crt`. Agents also need `tls.crt` and `tls.key`; the DaemonSet
mounts all three read-only at `/run/mtls`. The controller mounts the CA only, never the
agents' private key.

## Flags

| Side | Flag | Meaning |
|---|---|---|
| Server | `-client-ca FILE` | PEM CA bundle for client certificates; requires `-tls-cert` and `-tls-key` (a listener without TLS on a non-loopback address is refused at start) |
| Agent | `-agent-cert FILE`, `-agent-key FILE` | Client certificate and key; give both or neither |
| Agent | `-ca FILE` | Extra trusted CA for the controller certificate |

There is no environment variable for any of these.

## Worked example (local, openssl)

```bash
mkdir -p /tmp/kavach-mtls && cd /tmp/kavach-mtls
# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=kavach-test-ca" -keyout ca.key -out ca.crt
# Server certificate (SAN for localhost)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=localhost" \
  -keyout server.key -out server.csr
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
  -extfile san.ext -out server.crt
# Agent certificate
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=agent-1" \
  -keyout agent.key -out agent.csr
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
  -extfile client.ext -out agent.crt

export KAVACH_TOKEN='a-long-random-lab-token-123456'
go run ./cmd/kavach -mode server -listen 127.0.0.1:8443 \
  -tls-cert server.crt -tls-key server.key -client-ca ca.crt &

# Without a client certificate the handshake fails:
curl --cacert ca.crt https://localhost:8443/healthz            # TLS alert, no HTTP response
# With one it works (the bearer token is still needed for /v1 routes):
curl --cacert ca.crt --cert agent.crt --key agent.key https://localhost:8443/healthz
curl --cacert ca.crt --cert agent.crt --key agent.key \
  -H "Authorization: Bearer $KAVACH_TOKEN" https://localhost:8443/v1/summary

go run ./cmd/kavach -mode agent -url https://localhost:8443 \
  -ca ca.crt -agent-cert agent.crt -agent-key agent.key
```

The agent refuses a plain `http://` URL for any non-loopback host ("remote server requires
HTTPS"), so a remote agent always needs TLS regardless of mTLS.

## Failure modes and troubleshooting

| Symptom | Cause |
|---|---|
| Agent log `remote error: tls: bad certificate` / `certificate required` | Client certificate missing, expired, not signed by the `-client-ca` bundle, or lacks the `clientAuth` extended key usage |
| Agent log `x509: certificate signed by unknown authority` | The agent does not trust the controller certificate: pass `-ca` |
| Pod never becomes Ready after enabling mTLS | The kubelet probes carry no client certificate; see "What the code actually does" |
| `kavachctl` or the browser cannot connect after enabling mTLS | They also lack a client certificate. `kavachctl` has no client-certificate option in this tree (not found in `cmd/kavachctl`); front the API with Envoy Gateway or a proxy that holds the certificate, or keep mTLS off |
| Server exits at start `invalid client CA bundle` | `-client-ca` file is not valid PEM |
| `client certificate and key must both be supplied` | Only one of `-agent-cert` / `-agent-key` was given |
| 401 despite a valid certificate | The bearer token is still checked; per-host enrollment tokens are host-scoped |

Nothing in this feature changes the observation-only contract: the certificate only
authenticates who may send telemetry; it never lets Kavach act on a host.

## Rollout

1. Issue a CA and per-agent client certificates; store them in a Secret
   (`ca.crt`, `tls.crt`, `tls.key`).
2. Test on a throwaway release first, including the probe behaviour above.
3. Roll agents and controller together; because the controller requires a certificate
   from every client, an agent without one is refused rather than degraded.
4. Rotation is manual: replace the Secret and restart the pods. Certificates are not
   hot-reloaded (no reload code was found; treat as unverified).

See also: [architecture.md](architecture.md), [envoy-gateway.md](envoy-gateway.md),
[deploy-remote.md](deploy-remote.md), [security-review.md](security-review.md).
