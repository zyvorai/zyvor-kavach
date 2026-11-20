#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Kavach — Deploy remote + health verification
#
# Canonical lab path (kept for repeat deploys):
#   ./scripts/deploy-and-test.sh
#   ./scripts/deploy-and-test.sh 80.79.5.173 sus
#   ./scripts/deploy-and-test.sh sus@80.79.5.173
#
# Defaults to the shared demo host (same lab as PacketWolf/Netra).
# Extra flags are forwarded to deploy-remote.sh (--k8s, --quick, …).
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

HOST="${1:-80.79.5.173}"
USER="${2:-sus}"

if [[ "$HOST" == *@* ]]; then
  exec "${SCRIPT_DIR}/deploy-remote.sh" "$HOST" "${@:2}"
fi

# When only flags are passed (e.g. --quick), treat first arg as a flag and use defaults.
if [[ "$HOST" == -* ]]; then
  exec "${SCRIPT_DIR}/deploy-remote.sh" "sus@80.79.5.173" "$@"
fi

exec "${SCRIPT_DIR}/deploy-remote.sh" "$HOST" "$USER" "${@:3}"
