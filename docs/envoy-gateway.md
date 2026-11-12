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

## Not covered

Envoy is the edge front door. Kavach does not ingest Envoy access logs through
this path (SIEM export is separate).
