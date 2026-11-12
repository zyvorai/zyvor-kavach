# Kavach eBPF sensors

Linux CO-RE programs for process exec (and optional file write) observation.

## Status

Scaffold for `sched_process_exec`. Production attach/loader lifecycle, ring-buffer
backpressure, and kernel compatibility matrix are lab-grade.

## Build (Linux)

```bash
./scripts/build-bpf.sh
# or:
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c kavach_exec.bpf.c -o kavach_exec.o
```

Set `KAVACH_BPF_OBJ` to the directory containing `kavach_exec.o`. Pin the ringbuf
to `/sys/fs/bpf/kavach/events` for `WatchEBPF`. The agent falls back to proc
connector / `/proc` polling when the object/pin is missing or `CAP_BPF` is
unavailable.

## Privilege

Loading requires `CAP_BPF` / `CAP_PERFMON` (or root). Review before enabling on
shared lab nodes that also run Netra/PacketWolf BPF programs.
