#!/usr/bin/env bash
# Optional: enable Cilium Gateway API + TLS for Kavach.
#
# Off by default — normal deploys use NodePort :30899 only.
# Do NOT run this unless you explicitly want Gateway; Cilium gatewayAPI
# stays disabled unless you opt in here or with deploy-remote.sh --cilium-gateway.
#
# This stub checks prerequisites and exits non-zero when GatewayClass is
# missing. A full bootstrap (CRDs, cert-manager, LB/L2, ClusterIssuer, Helm
# gatewayApi.enabled=true) can be filled in later, modeled on PacketWolf's
# k8s/bootstrap/ensure-packetwolf-cilium-gateway-tls.sh.
#
# Usage:
#   bash k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh
#   KAVACH_GATEWAY_HOST=kavach.example.com bash k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh
#
# After a full enable: https://$KAVACH_GATEWAY_HOST/
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAMESPACE="${KAVACH_NAMESPACE:-kavach-system}"
GATEWAY_HOST="${KAVACH_GATEWAY_HOST:-}"

echo "==> Kavach Cilium Gateway TLS (stub)"
echo "    namespace=${NAMESPACE}"
echo "    chart=${ROOT_DIR}/helm/kavach"
echo
echo "Prerequisites (all required before Gateway can terminate TLS for Kavach):"
echo "  1. Cilium installed with enable-gateway-api=true"
echo "  2. Gateway API CRDs (gatewayclasses, gateways, httproutes, …)"
echo "  3. GatewayClass/cilium present and Accepted"
echo "  4. cert-manager (+ --enable-gateway-api) and a ClusterIssuer (e.g. Let's Encrypt)"
echo "  5. Optional: Cilium LB IP pool + L2 announcement for a VIP"
echo "  6. Helm: gatewayApi.enabled=true on release kavach in ${NAMESPACE}"
echo "  7. DNS/hostname: \${KAVACH_GATEWAY_HOST:-<set me>} pointing at the Gateway VIP"
if [[ -n "$GATEWAY_HOST" ]]; then
  echo "    (KAVACH_GATEWAY_HOST=${GATEWAY_HOST})"
fi
echo

if ! command -v kubectl >/dev/null 2>&1; then
  echo "error: kubectl not found" >&2
  exit 1
fi

if ! kubectl get gatewayclass cilium &>/dev/null; then
  echo "GatewayClass/cilium missing — Gateway front door is optional."
  echo "Keep using NodePort :30899, or install Cilium Gateway API first, then re-run."
  echo "Full bootstrap not implemented in this stub; see PacketWolf's ensure script for the pattern."
  exit 1
fi

echo "GatewayClass/cilium found."
echo "Stub only — enable gatewayApi via Helm and finish cert-manager/LB wiring manually for now."
echo "  helm upgrade kavach ${ROOT_DIR}/helm/kavach -n ${NAMESPACE} --reuse-values --set gatewayApi.enabled=true"
exit 0
