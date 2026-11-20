# Kavach eBPF sensors

Linux CO-RE programs for **observation-only** host telemetry (Falco / Tracee /
Tetragon-observe class). Kavach **never** kills, isolates, drops packets, or
LSM-denies. Network datapath enforce stays with Netra; Kavach mirrors Netra
observe APIs under `/v1/ebpf/netra/*`.

## Programs

| Object | Hooks | Events |
|--------|-------|--------|
| `kavach_exec.o` | `sched_process_exec` | exec + path/comm/cgroup |
| `kavach_process.o` | `sched_process_fork/exit` | lineage + exit codes |
| `kavach_file.o` | `sys_enter_openat` | path metadata (no content) |
| `kavach_priv.o` | setuid, memfd, ptrace, init_module, bpf | privilege / abuse signals |
| `kavach_net.o` | `sys_enter_connect` | host connect (never drop) |

Shared types: `kavach_common.h`. Ringbuf lost counters on exec map.

## Build (Linux)

```bash
./scripts/build-bpf.sh
```

Requires clang and kernel BTF headers suitable for your distro. Set
`KAVACH_BPF_OBJ` to the directory containing `*.o`. Pin ringbufs under
`/sys/fs/bpf/kavach/` for `WatchEBPF`. The agent falls back to proc connector /
`/proc` polling when objects/pins/`CAP_BPF` are unavailable.

## APIs

```text
GET  /v1/ebpf/status|health|coverage|capabilities|attachments|maps|census|summary|drops
GET  /v1/ebpf/events?type=exec|fork|exit|file|net|priv|memfd|ptrace|module|bpf
POST /v1/ebpf/events          # agent ingest {events, lost}
GET  /v1/ebpf/processes
GET  /v1/ebpf/features
POST /v1/ebpf/features/{id}   # mode=auto|on|off — load gate only
GET  /v1/ebpf/netra/status|drops|flows|attachments
```

```bash
kavachctl ebpf status
kavachctl ebpf events --type exec
kavachctl ebpf health
```

## Privilege

Loading requires `CAP_BPF` / `CAP_PERFMON` (or root). Review before enabling on
shared lab nodes that also run Netra/PacketWolf BPF programs.
