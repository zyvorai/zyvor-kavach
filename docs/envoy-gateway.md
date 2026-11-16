# Envoy Gateway in front of Kavach

Kavach uses **Envoy Gateway** as the preferred Kubernetes Gateway API front
door — deep observability, gRPC/HTTP3-capable Envoy data plane, and enterprise
traffic management. This is the recommended path for cloud-native deployments
as classic Ingress (including Ingress Nginx Controllers) is retiring in favor
of Gateway API.

Bearer tokens and agent mTLS are unchanged. Envoy adds TLS termination,
hostname routing, and edge policy. Node agents keep talking to the in-cluster
Service; only the API/UI goes through Envoy.

NodePort `:30899` remains available for direct lab access.

## Option A — Create a dedicated Envoy Gateway (recommended)

Requires GatewayClass `eg` (Envoy Gateway). The chart mints a **stable** TLS
Secret (`kavach-tls`), an `EnvoyProxy` (NodePort lab defaults `:30943` HTTPS),
a `Gateway`, `HTTPRoute`, `BackendTLSPolicy`, and `BackendTrafficPolicy`.

```bash
./k8s/bootstrap/ensure-envoy-gateway.sh

helm upgrade --install kavach ./helm/kavach -n kavach-system \
  --set auth.token="$KAVACH_TOKEN" \
  --set envoyGateway.enabled=true \
  --set envoyGateway.hostname=kavach.80.79.5.173.sslip.io \
  --set envoyGateway.addressHint=80.79.5.173 \
  --set agent.enabled=false
```

Or via remote deploy:

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
```

Then open `https://kavach.<node-ip>.sslip.io:30943/` (self-signed; `curl -sk`).

## Option B — Attach HTTPRoute to an existing Gateway

```bash
helm upgrade --install kavach ./helm/kavach -n kavach-system \
  --set auth.token="$KAVACH_TOKEN" \
  --set gateway.enabled=true \
  --set 'gateway.parentRefs[0].name=edge' \
  --set 'gateway.parentRefs[0].namespace=zyvora' \
  --set 'gateway.parentRefs[0].sectionName=auth' \
  --set 'gateway.hostnames[0]=kavach.example.com' \
  --set gateway.backendTLS.caCertificateRefs[0].name=kavach-ca \
  --set gateway.backendTLS.caCertificateRefs[0].kind=ConfigMap
```

## Backend TLS

The controller serves HTTPS by default, so Envoy must verify the pod
certificate. `envoyGateway.*` wires this automatically via `BackendTLSPolicy`
and ConfigMap `kavach-ca`. For long-lived streams,
`backendTrafficPolicy.useClientProtocol=true` (Envoy Gateway extension).

## Cilium Gateway (optional)

`gatewayApi.*` can still create a Cilium Gateway + cert-manager Certificate.
Prefer `envoyGateway.*` unless you explicitly want Cilium’s GatewayClass.

## Values reference (`envoyGateway.*`)

| Value | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Render the Envoy Gateway objects. Off unless you opt in (`--envoy-gateway` on deploy sets it) |
| `gatewayClassName` | `eg` | GatewayClass of Envoy Gateway; `k8s/bootstrap/ensure-envoy-gateway.sh` checks the Gateway API CRDs, the Envoy Gateway CRDs and this class, and exits non-zero if one is missing (`KAVACH_ENVOY_GATEWAY_CLASS` overrides the class) |
| `hostname` | empty | HTTPS listener hostname. When empty the chart builds `kavach.<addressHint with dots replaced by dashes>.sslip.io`. `deploy-remote.sh` passes `kavach.<node-ip>.sslip.io` explicitly |
| `addressHint` | `80.79.5.173` | Only used to build a default hostname and certificate SAN; set it to your node IP |
| `httpsPort` / `httpPort` | `8443` / `8080` | Envoy listener ports |
| `httpsNodePort` / `httpNodePort` | `30943` / `30980` | NodePorts of the Envoy service (`serviceType: NodePort`) |
| `httpRedirect` | `true` | Adds an HTTP to HTTPS redirect `HTTPRoute` |
| `requestTimeout` | `0s` | Route timeout; `0s` keeps `/v1/stream` (Server-Sent Events) from being cut |
| `tlsSecretName` / `caConfigMapName` | `kavach-tls` / `kavach-ca` | Stable edge TLS Secret and the CA ConfigMap Envoy uses to verify the pod |
| `backendTrafficPolicy.useClientProtocol` | `true` | Needed for long-lived streams when backend TLS is on |

Objects created: `Secret/kavach-tls`, `ConfigMap/kavach-ca`, `EnvoyProxy`, `Gateway`, the
app `HTTPRoute`, the redirect `HTTPRoute`, `BackendTLSPolicy` (SNI `kavach.<namespace>.svc`)
and `BackendTrafficPolicy`.

## Verify

```bash
kubectl get gatewayclass eg
kubectl -n kavach-system get gateway,httproute,backendtlspolicy
curl -sk https://kavach.80.79.5.173.sslip.io:30943/healthz
curl -sk -H "Authorization: Bearer $KAVACH_TOKEN" https://kavach.80.79.5.173.sslip.io:30943/v1/summary
# live stream through the gateway (should stay open):
curl -skN -H "Authorization: Bearer $KAVACH_TOKEN" https://kavach.80.79.5.173.sslip.io:30943/v1/stream
kavachctl doctor     # with KAVACH_URL pointing at the Envoy URL
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `ensure-envoy-gateway.sh` reports missing CRDs or class | Install Gateway API and Envoy Gateway first; Kavach does not install them. `deploy-remote.sh` logs a warning and continues, so Helm may then fail |
| `503` or upstream TLS errors from Envoy | `BackendTLSPolicy` must trust the pod certificate: confirm `kavach-ca` holds the CA of the Secret the pod serves (`tls.existingSecret=kavach-tls`, set by the deploy script) |
| `/v1/stream` closes after a minute | Route timeout: keep `requestTimeout: "0s"` and `backendTrafficPolicy.useClientProtocol=true` |
| Hostname not accepted by the Gateway | The listeners and routes match `envoyGateway.hostname` exactly; open the same name (the default form is `kavach.<ip>.sslip.io`) |
| Rate limits or throttling look shared | Kavach limits per `RemoteAddr`; behind a proxy every client shares Envoy's address and `X-Forwarded-For` is deliberately not trusted (see [security-review.md](security-review.md)) |
| Agent mTLS with `required` and Envoy in front | Envoy terminates edge TLS, so client certificates are not forwarded; node agents should keep using the in-cluster Service (see [agent-mtls.md](agent-mtls.md)) |

## Not covered

Envoy is the edge front door. Kavach does not ingest Envoy access logs through
this path (SIEM export is separate, see [siem-export.md](siem-export.md)). The cluster-level
prerequisites (Gateway API CRDs, Envoy Gateway controller, GatewayClass) are not installed
by the chart. The edge TLS certificate is self-signed in the lab defaults; bring your own
Secret for anything else. Not verified in this documentation pass: behaviour on a live
Envoy Gateway cluster.
