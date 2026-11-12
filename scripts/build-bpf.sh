#!/usr/bin/env bash
# Build Kavach CO-RE eBPF object (Linux + clang required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${KAVACH_BPF_OBJ:-$ROOT/bpf}/kavach_exec.o"
mkdir -p "$(dirname "$OUT")"
if ! command -v clang >/dev/null; then
  echo "clang required to build bpf/kavach_exec.bpf.c" >&2
  exit 1
fi
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c "$ROOT/bpf/kavach_exec.bpf.c" -o "$OUT"
echo "wrote $OUT"
echo "Pin with: sudo bpftool prog load $OUT /sys/fs/bpf/kavach/exec type tracing"
echo "Map pin:  sudo bpftool map pin name events /sys/fs/bpf/kavach/events"
