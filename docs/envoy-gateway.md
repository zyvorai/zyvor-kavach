# Envoy / Gateway API in front of Kavach

Kavach can sit behind Envoy through the Kubernetes Gateway API (Envoy Gateway
or any Gateway API implementation). It is **off by default** and does not change
how Kavach authenticates: bearer tokens and mTLS settings are the same with or
without the gateway. The gateway adds TLS termination, hostname routing, and
edge policy in front of the controller.

Node agents keep talking to the in-cluster Service; only the API/UI goes through
Envoy.

## Enable (HTTPRoute to an existing Gateway)

```bash
helm upgrade --install kavach ./helm/kavach -n kavach-system \
  --set auth.token="$KAVACH_TOKEN" \
  --set gateway.enabled=true \
  --set 'gateway.parentRefs[0].name=eg' \
  --set 'gateway.parentRefs[0].namespace=envoy-gateway-system' \
  --set 'gateway.hostnames[0]=kavach.example.com'
```

`gateway.parentRefs` is required when the gateway is enabled.

## Backend TLS

The controller serves HTTPS by default, so Envoy must verify the pod
certificate. Use a stable cert (`tls.existingSecret`) and give Envoy its CA via
`gateway.backendTLS.caCertificateRefs`. For long-lived streams, keep
`gateway.requestTimeout` at `"0s"`.

## Cilium Gateway (optional)

`gatewayApi.*` can create a Cilium Gateway + cert-manager Certificate. Off by
default; prefer NodePort `:30899` for lab access. See
`k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh` and
`./scripts/deploy-remote.sh … --cilium-gateway`.
