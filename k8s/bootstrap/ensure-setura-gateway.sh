#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Ensure Setura Gateway (Gateway API) is ready for Kavach.
#
# Prerequisites (cluster-level, not installed by Kavach):
#   - Gateway API CRDs
#   - The `setura` CLI (https://github.com/zyvorai/zyvor-setura-gateway)
#
# If the GatewayClass is missing this script installs the Setura controller:
#   setura gateway install --image ghcr.io/zyvorai/zyvor-setura-gateway:0.7.0 \
#     --namespace setura-system --expose-gateway-ports | kubectl apply -f -
#
# Usage:
#   ./k8s/bootstrap/ensure-setura-gateway.sh
#   KAVACH_SETURA_GATEWAY_CLASS=setura ./k8s/bootstrap/ensure-setura-gateway.sh
set -euo pipefail

CLASS="${KAVACH_SETURA_GATEWAY_CLASS:-setura}"
IMAGE="${KAVACH_SETURA_IMAGE:-ghcr.io/zyvorai/zyvor-setura-gateway:0.7.0}"
NAMESPACE="${KAVACH_SETURA_NAMESPACE:-setura-system}"
CONTROLLER="zyvor.dev/setura-gateway"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl required" >&2
  exit 1
fi

if ! kubectl get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  echo "Gateway API CRDs missing: install Gateway API first" >&2
  echo "  https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api" >&2
  exit 1
fi

if ! kubectl get gatewayclass "$CLASS" >/dev/null 2>&1; then
  if ! command -v setura >/dev/null 2>&1; then
    echo "GatewayClass ${CLASS} not found and the setura CLI is not installed" >&2
    echo "  https://github.com/zyvorai/zyvor-setura-gateway/blob/main/docs/install.md" >&2
    exit 1
  fi
  echo "Installing Setura Gateway (${IMAGE}) into ${NAMESPACE}"
  setura gateway install --image "$IMAGE" --namespace "$NAMESPACE" \
    --class "$CLASS" --expose-gateway-ports | kubectl apply -f -
  kubectl -n "$NAMESPACE" rollout status deploy/setura-gateway --timeout=120s || true
fi

ctrl="$(kubectl get gatewayclass "$CLASS" -o jsonpath='{.spec.controllerName}' 2>/dev/null || true)"
if [[ "$ctrl" != "$CONTROLLER" ]]; then
  echo "GatewayClass ${CLASS} is owned by '${ctrl}', expected ${CONTROLLER}" >&2
  kubectl get gatewayclass 2>/dev/null || true
  exit 1
fi
echo "GatewayClass ${CLASS} present (controller=${ctrl})"
echo "Setura Gateway ready for Kavach setura.enabled=true"
