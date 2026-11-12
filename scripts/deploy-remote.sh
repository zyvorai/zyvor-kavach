#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Kavach — Remote deployment (SSH + rsync + optional K3s/Helm)
#
# Kavach runs as a Kubernetes workload (Helm). Default lab access is
# HTTPS NodePort :30899 (alongside PacketWolf :9443 and Netra :30870).
#
# Profiles (pick one):
#   default / --k3s   Sync + build + import image + Helm (expects K3s/kubeconfig)
#   --k8s             Helm on an existing kubeconfig (cluster already ready)
#   --quick           Sync + Helm only (image must already exist on the host)
#   --verify-only     curl healthz on the remote NodePort; no sync/build
#
# Opt-in:
#   --cilium-gateway  Sets KAVACH_GATEWAY_API=1 and notes Gateway is optional.
#                     Calls k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh when present.
#
# Usage:
#   ./scripts/deploy-remote.sh user@HOST
#   ./scripts/deploy-remote.sh user@HOST --k8s
#   ./scripts/deploy-remote.sh user@HOST --quick --verify-only
#   ./scripts/deploy-remote.sh HOST USER
#
# KAVACH_REMOTE_SUBDIR overrides where the remote checkout lives, relative to
# the target user's $HOME (default: .deployments/kavach). Use a path outside
# .deployments/ on hosts where sibling projects rsync --delete the shared parent.
#
# Auth: SSH keys / ssh-agent. Non-root users need passwordless sudo for k3s
# kubeconfig mirror and ctr image import.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="k3s"
VERIFY_ONLY=false
CILIUM_GATEWAY=false
DRY_RUN=false
TARGET=""
# shellcheck disable=SC2034
TARGET_USER=""
POSITIONAL=()
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

IMAGE_REF="ghcr.io/zyvorai/kavach:0.1.0"
IMAGE_REPO="ghcr.io/zyvorai/kavach"
IMAGE_TAG="0.1.0"
NODE_PORT="${KAVACH_NODE_PORT:-30899}"

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --k3s) PROFILE="k3s"; shift ;;
    --k8s) PROFILE="k8s"; shift ;;
    --quick) PROFILE="quick"; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    --cilium-gateway) CILIUM_GATEWAY=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -*)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  TARGET="${POSITIONAL[0]}"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  # ./scripts/deploy-remote.sh HOST USER
  if [[ "${POSITIONAL[0]}" == *@* ]]; then
    TARGET="${POSITIONAL[0]}"
  elif [[ "${POSITIONAL[1]}" == *@* ]]; then
    TARGET="${POSITIONAL[1]}"
  else
    TARGET="${POSITIONAL[1]}@${POSITIONAL[0]}"
  fi
elif [[ ${#POSITIONAL[@]} -gt 2 ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--quick]   or   $0 HOST USER [...]" >&2
  exit 2
fi

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--quick|--verify-only|--cilium-gateway]" >&2
  echo "   or: $0 HOST USER [...]" >&2
  exit 2
fi

if $CILIUM_GATEWAY; then
  export KAVACH_GATEWAY_API=1
fi

# Default matches lab demo login. Override with KAVACH_ADMIN_TOKEN for production.
ADMIN_TOKEN_LOCAL="${KAVACH_ADMIN_TOKEN:-Admin@321}"
if [[ -z "${ADMIN_TOKEN_LOCAL}" ]]; then
  ADMIN_TOKEN_LOCAL="$(openssl rand -hex 24)"
fi

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/${KAVACH_REMOTE_SUBDIR:-.deployments/kavach}"

log() { printf '[kavach-deploy] %s\n' "$*"; }

if $VERIFY_ONLY; then
  log "verify-only → ${TARGET} :${NODE_PORT}/healthz"
  ssh_host 'bash -s' <<EOF
set -euo pipefail
export KUBECONFIG="\${KUBECONFIG:-\$HOME/.kube/kavach-k3s.yaml}"
if [[ ! -r "\${KUBECONFIG}" ]]; then
  mkdir -p "\$HOME/.kube"
  if [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
    sudo cat /etc/rancher/k3s/k3s.yaml | sed "s/127.0.0.1/\$(hostname -I | awk '{print \$1}')/" > "\$HOME/.kube/kavach-k3s.yaml"
    chmod 600 "\$HOME/.kube/kavach-k3s.yaml"
    export KUBECONFIG="\$HOME/.kube/kavach-k3s.yaml"
  fi
fi
kubectl -n kavach-system get deploy,svc,pods 2>/dev/null || true
curl -skf https://127.0.0.1:${NODE_PORT}/healthz
echo
EOF
  exit 0
fi

log "sync → ${TARGET}:${REMOTE_DIR}"
if ! $DRY_RUN; then
  ssh_host "mkdir -p ${REMOTE_DIR}"
  rsync -az --delete \
    --exclude '.git' \
    --exclude 'bin' \
    --exclude 'data' \
    --exclude 'web/node_modules' --exclude 'web/dist' \
    --exclude 'website/node_modules' --exclude 'website/build' --exclude 'website/.docusaurus' \
    --exclude '.DS_Store' --exclude '.cursor' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
fi

GATEWAY_API_FLAG="${KAVACH_GATEWAY_API:-0}"
if $CILIUM_GATEWAY; then
  GATEWAY_API_FLAG=1
fi

remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/go/bin:/usr/local/bin:\$HOME/go/bin:/usr/bin:\$PATH"
export GOTOOLCHAIN=auto
PROFILE="${PROFILE}"
GATEWAY_API="${GATEWAY_API_FLAG}"
ADMIN_TOKEN="${ADMIN_TOKEN_LOCAL}"
IMAGE_REF="${IMAGE_REF}"
IMAGE_REPO="${IMAGE_REPO}"
IMAGE_TAG="${IMAGE_TAG}"
NODE_PORT="${NODE_PORT}"

log() { printf '[kavach-deploy] %s\n' "\$*"; }

mkdir -p "\$HOME/.kube"
if [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
  if [[ ! -r "\$HOME/.kube/kavach-k3s.yaml" ]] || [[ /etc/rancher/k3s/k3s.yaml -nt "\$HOME/.kube/kavach-k3s.yaml" ]]; then
    sudo cat /etc/rancher/k3s/k3s.yaml > "\$HOME/.kube/kavach-k3s.yaml"
    chmod 600 "\$HOME/.kube/kavach-k3s.yaml"
  fi
  export KUBECONFIG="\$HOME/.kube/kavach-k3s.yaml"
fi

if [[ "\$PROFILE" == "k3s" ]]; then
  if [[ -x scripts/lib/ensure-cilium-k3s.sh ]]; then
    bash scripts/lib/ensure-cilium-k3s.sh
  elif ! command -v k3s >/dev/null 2>&1 && [[ ! -r /etc/rancher/k3s/k3s.yaml ]]; then
    log "K3s not found — install K3s (or use --k8s with an existing kubeconfig)" >&2
    exit 1
  fi
fi

if ! command -v kubectl >/dev/null 2>&1; then
  log "kubectl required on remote host" >&2
  exit 1
fi
if ! command -v helm >/dev/null 2>&1; then
  log "helm required on remote host" >&2
  exit 1
fi

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    log "using \$(go version)"
    return 0
  fi
  log "installing Go toolchain..."
  local ver="1.23.4"
  local arch
  arch="\$(uname -m)"
  case "\$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) log "unsupported arch: \$arch" >&2; return 1 ;;
  esac
  local tgz="go\${ver}.linux-\${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/\${tgz}" -o "/tmp/\${tgz}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/\${tgz}"
  rm -f "/tmp/\${tgz}"
  export PATH="/usr/local/go/bin:\$PATH"
  log "installed \$(go version)"
}

resolve_cmd() {
  # Prefer cmd/kavach; fall back to cmd/zyvor-edr until rename lands.
  # Logs go to stderr so stdout stays a clean package path.
  local want="\$1"
  if [[ -d "cmd/\${want}" ]]; then
    echo "./cmd/\${want}"
    return 0
  fi
  if [[ "\$want" == "kavach" || "\$want" == "kavach-agent" ]] && [[ -d cmd/zyvor-edr ]]; then
    log "cmd/\${want} missing — falling back to ./cmd/zyvor-edr" >&2
    echo "./cmd/zyvor-edr"
    return 0
  fi
  return 1
}

build_binaries() {
  ensure_go
  mkdir -p bin
  local main_pkg agent_pkg bridge_pkg=""
  main_pkg="\$(resolve_cmd kavach)"
  if [[ -d cmd/netra-bridge ]]; then
    bridge_pkg="./cmd/netra-bridge"
  fi
  if [[ -d cmd/kavach-agent ]]; then
    agent_pkg="./cmd/kavach-agent"
  else
    agent_pkg="\$main_pkg"
    log "cmd/kavach-agent missing — agent binary will reuse controller package"
  fi

  log "GOOS=linux go build → bin/kavach (\${main_pkg})"
  CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o bin/kavach "\${main_pkg}"
  if [[ -n "\${bridge_pkg}" ]]; then
    log "GOOS=linux go build → bin/netra-bridge"
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o bin/netra-bridge "\${bridge_pkg}"
  fi
  log "GOOS=linux go build → bin/kavach-agent (\${agent_pkg})"
  CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o bin/kavach-agent "\${agent_pkg}"
}

pick_runtime() {
  if command -v podman >/dev/null 2>&1; then
    echo podman
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo docker
  else
    echo ""
  fi
}

build_image() {
  local runtime
  runtime="\$(pick_runtime)"
  if [[ -z "\$runtime" ]]; then
    log "podman or working docker required to build/import image" >&2
    exit 1
  fi

  if [[ -f Dockerfile.runtime ]]; then
    log "building \${IMAGE_REF} from Dockerfile.runtime (prebuilt binaries)"
    \$runtime build -f Dockerfile.runtime -t "\$IMAGE_REF" .
    return 0
  fi

  if [[ -f Dockerfile ]]; then
    log "building \${IMAGE_REF} from Dockerfile"
    \$runtime build -t "\$IMAGE_REF" .
    # Retag if Dockerfile used a different name (zyvor-edr:dev etc.)
    \$runtime tag "\$IMAGE_REF" "\$IMAGE_REF" 2>/dev/null || true
    return 0
  fi

  log "no Dockerfile — building thin runtime image from bin/kavach"
  local tmp
  tmp="\$(mktemp -d)"
  cat > "\$tmp/Dockerfile" <<'DF'
FROM alpine:3.20
RUN addgroup -S kavach && adduser -S -G kavach kavach
USER kavach
WORKDIR /app
COPY bin/kavach /usr/local/bin/kavach
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/kavach"]
CMD ["-mode", "server", "-listen", "0.0.0.0:8099", "-state", "/app/data/findings.jsonl", "-credentials", "/app/data/agents.json", "-tls-cert", "/run/tls/tls.crt", "-tls-key", "/run/tls/tls.key"]
DF
  mkdir -p "\$tmp/bin"
  cp bin/kavach "\$tmp/bin/kavach"
  \$runtime build -f "\$tmp/Dockerfile" -t "\$IMAGE_REF" "\$tmp"
  rm -rf "\$tmp"
}

import_image() {
  local runtime
  runtime="\$(pick_runtime)"
  if command -v k3s >/dev/null 2>&1 || [[ -S /run/k3s/containerd/containerd.sock ]]; then
    log "importing \${IMAGE_REF} into k3s containerd"
    if [[ "\$runtime" == "podman" ]]; then
      podman save "\$IMAGE_REF" | sudo k3s ctr images import -
    else
      docker save "\$IMAGE_REF" | sudo k3s ctr images import -
    fi
  else
    log "k3s ctr not available — skipping containerd import (image left in \${runtime})"
  fi
}

if [[ "\$PROFILE" != "quick" ]]; then
  build_binaries
  build_image
  import_image
fi

mkdir -p "\$HOME/.kavach"
printf '%s\n' "\$ADMIN_TOKEN" > "\$HOME/.kavach/admin-token"
HOST_IP="\$(hostname -I | awk '{print \$1}')"
cat > "\$HOME/.kavach/env" <<ENVEOF
# Written by deploy-remote.sh
KAVACH_URL=https://\${HOST_IP}:\${NODE_PORT}
KAVACH_TLS_INSECURE=true
KAVACH_ADMIN_TOKEN=\${ADMIN_TOKEN}
ENVEOF
chmod 600 "\$HOME/.kavach/"* || true

if [[ ! -d helm/kavach ]]; then
  log "helm/kavach chart missing — sync incomplete or chart not yet added" >&2
  exit 1
fi

HELM_SET=(
  --set "auth.token=\${ADMIN_TOKEN}"
  --set tls.enabled=true
  --set image.repository="\${IMAGE_REPO}"
  --set image.tag="\${IMAGE_TAG}"
  --set image.pullPolicy=IfNotPresent
  --set service.type=NodePort
  --set service.port="\${NODE_PORT}"
  --set service.nodePort="\${NODE_PORT}"
)

if [[ "\$GATEWAY_API" == "1" ]]; then
  log "Gateway API opt-in (KAVACH_GATEWAY_API=1) — Gateway remains optional; NodePort :\${NODE_PORT} stays the default path"
  HELM_SET+=(--set gatewayApi.enabled=true)
  if [[ -x k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh ]]; then
    bash k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh || log "ensure-kavach-cilium-gateway-tls.sh reported prerequisites missing (continuing with NodePort)"
  else
    log "k8s/bootstrap/ensure-kavach-cilium-gateway-tls.sh not executable — skipping Gateway bootstrap"
  fi
else
  HELM_SET+=(--set gatewayApi.enabled=false)
fi

log "helm upgrade --install kavach ./helm/kavach -n kavach-system"
helm upgrade --install kavach ./helm/kavach \
  --namespace kavach-system --create-namespace \
  "\${HELM_SET[@]}" \
  --wait --timeout 300s

# Fixed tag: force restart so freshly imported content is what runs.
if kubectl -n kavach-system get deploy kavach >/dev/null 2>&1; then
  kubectl -n kavach-system rollout restart deployment/kavach
  kubectl -n kavach-system rollout status deployment/kavach --timeout=180s || true
elif kubectl -n kavach-system get deploy -l app.kubernetes.io/name=kavach -o name 2>/dev/null | head -1 | grep -q .; then
  dep="\$(kubectl -n kavach-system get deploy -l app.kubernetes.io/name=kavach -o name | head -1)"
  kubectl -n kavach-system rollout restart "\$dep"
  kubectl -n kavach-system rollout status "\$dep" --timeout=180s || true
fi

log "ADMIN_TOKEN=\${ADMIN_TOKEN}"
log "KAVACH_URL=https://\${HOST_IP}:\${NODE_PORT}"
curl -skf "https://127.0.0.1:\${NODE_PORT}/healthz" \\
  || curl -skf "https://\${HOST_IP}:\${NODE_PORT}/healthz" \\
  || log "healthz not ready yet — retry with --verify-only"
echo
log "Kavach ready (HTTPS NodePort :\${NODE_PORT})"
EOF
)

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done — open https://<host>:${NODE_PORT}"
