#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
# Ensure Envoy Gateway (Gateway API) is ready for Kavach.
#
# Prerequisites (cluster-level — not installed by Kavach):
#   - Gateway API CRDs
#   - Envoy Gateway controller
#   - GatewayClass "eg" (gateway.envoyproxy.io/gatewayclass-controller)
#
# Usage:
#   ./k8s/bootstrap/ensure-envoy-gateway.sh
#   KAVACH_ENVOY_GATEWAY_CLASS=eg ./k8s/bootstrap/ensure-envoy-gateway.sh
set -euo pipefail

CLASS="${KAVACH_ENVOY_GATEWAY_CLASS:-eg}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl required" >&2
  exit 1
fi

if ! kubectl get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  echo "Gateway API CRDs missing — install Gateway API then Envoy Gateway" >&2
  echo "  https://gateway.envoyproxy.io/docs/install/" >&2
  exit 1
fi

if ! kubectl get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; then
  echo "Envoy Gateway CRDs missing — install Envoy Gateway" >&2
  echo "  https://gateway.envoyproxy.io/docs/install/" >&2
  exit 1
fi

if ! kubectl get gatewayclass "$CLASS" >/dev/null 2>&1; then
  echo "GatewayClass ${CLASS} not found. Expected Envoy Gateway class (controller gateway.envoyproxy.io/gatewayclass-controller)." >&2
  kubectl get gatewayclass 2>/dev/null || true
  exit 1
fi

ctrl="$(kubectl get gatewayclass "$CLASS" -o jsonpath='{.spec.controllerName}' 2>/dev/null || true)"
echo "GatewayClass ${CLASS} present (controller=${ctrl})"
echo "Envoy Gateway ready for Kavach envoyGateway.enabled=true"
