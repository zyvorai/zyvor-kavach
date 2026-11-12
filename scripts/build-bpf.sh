#!/usr/bin/env bash
# Build all Kavach observation-only CO-RE eBPF objects (Linux + clang required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${KAVACH_BPF_OBJ:-$ROOT/bpf}"
mkdir -p "$OUT_DIR"
if ! command -v clang >/dev/null; then
  echo "clang required to build bpf/*.bpf.c" >&2
  exit 1
fi
ARCH_DEFINE="-D__TARGET_ARCH_x86"
case "$(uname -m)" in
  aarch64|arm64) ARCH_DEFINE="-D__TARGET_ARCH_arm64" ;;
esac

build_one() {
  local src="$1"
  local base
  base="$(basename "$src" .bpf.c)"
  local out="$OUT_DIR/${base}.o"
  clang -O2 -g -target bpf $ARCH_DEFINE -I"$ROOT/bpf" -c "$src" -o "$out"
  echo "wrote $out"
}

for src in "$ROOT"/bpf/kavach_*.bpf.c; do
  build_one "$src"
done

cat <<EOF
Pin examples (observe-only — never enforce):
  sudo mkdir -p /sys/fs/bpf/kavach
  sudo bpftool prog loadall $OUT_DIR/kavach_exec.o /sys/fs/bpf/kavach/exec
  sudo bpftool map pin name events /sys/fs/bpf/kavach/events
EOF
