# eBPF observe platform

Kavach ships Falco / Tracee / Tetragon-**observe** class host telemetry.  
**Never** kill, isolate, LSM-deny, or drop packets. Network datapath enforce belongs to Netra.

---

## Programs (`bpf/`)

| Object | Hooks | Event types |
|--------|-------|-------------|
| `kavach_exec.o` | `sched_process_exec` | `exec` (+ path, cgroup, lost counter) |
| `kavach_process.o` | fork / exit | `fork`, `exit` |
| `kavach_file.o` | `sys_enter_openat` | `file` (path metadata only) |
| `kavach_priv.o` | setuid, memfd, ptrace, init_module, bpf | `priv`, `memfd`, `ptrace`, `module`, `bpf` |
| `kavach_net.o` | `sys_enter_connect` | `net` (observe connect) |

Shared header: `kavach_common.h`.

---

## Build & pin (Linux)

```bash
./scripts/build-bpf.sh
sudo mkdir -p /sys/fs/bpf/kavach
# example — exact bpftool flow depends on your kernel/BTF:
sudo bpftool prog loadall bpf/kavach_exec.o /sys/fs/bpf/kavach/exec
sudo bpftool map pin name events /sys/fs/bpf/kavach/events
```

Env:

| Variable | Meaning |
|----------|---------|
| `KAVACH_BPF_OBJ` | Directory with `*.o` |
| `KAVACH_BPF_PIN` | Exec ringbuf pin (default `/sys/fs/bpf/kavach/events`) |
| `KAVACH_BPF_PIN_ROOT` | Pin root for status/attachments |

Without pins or `CAP_BPF`, the agent falls back to proc connector → `/proc` poll. That is supported and expected on many labs.

Order the agent tries: the pin named by `KAVACH_BPF_PIN`, then `/sys/fs/bpf/kavach/events`, then
`/sys/fs/bpf/kavach_events`; if none opens it uses the proc connector, and finally `/proc` polling.
`scripts/build-bpf.sh` needs Linux and `clang`, writes `bpf/*.o` (or `$KAVACH_BPF_OBJ`) and only prints the
`bpftool` pin commands; it does not load anything. Objects are searched in `KAVACH_BPF_OBJ`, `bpf/` and
`/usr/lib/kavach/bpf`. The honest state of this repository: the programs and the ingest/status API exist and are
unit tested, but loading the objects into a kernel and the ringbuf reader are exercised only on Linux with
`bpftool`; nothing here was verified on a live kernel in this documentation pass. The kernel-side verifier
surface was not security reviewed ([security-review.md](security-review.md)).

---

## HTTP API

```text
GET  /v1/ebpf/status
GET  /v1/ebpf/health
GET  /v1/ebpf/coverage
GET  /v1/ebpf/capabilities
GET  /v1/ebpf/attachments
GET  /v1/ebpf/maps
GET  /v1/ebpf/census
GET  /v1/ebpf/summary
GET  /v1/ebpf/drops              # ringbuf lost samples — not packet drops
GET  /v1/ebpf/events?type=exec
POST /v1/ebpf/events             # { "events": [...], "lost": N }
GET  /v1/ebpf/processes
GET  /v1/ebpf/features
POST /v1/ebpf/features/{id}      # { "mode": "auto"|"on"|"off" } — load gate only
GET  /v1/ebpf/netra/status|drops|flows|attachments
```

All status payloads include `"enforce": false` (or equivalent note). All routes need the bearer token or a
console session. `POST /v1/ebpf/events` is capped at 4 MiB and `POST /v1/ebpf/features/{id}` at 4 KiB
(`bad json` on a malformed body). Feature ids: `exec`, `fork`, `exit`, `file`, `priv`, `memfd`, `ptrace`,
`module`, `bpf`, `net`, `netra-mirror`.

### Worked example (real output from a macOS lab, no kernel sensor)

```bash
export KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN='Admin@321'
H="Authorization: Bearer $KAVACH_TOKEN"

curl -s -H "$H" $KAVACH_URL/v1/ebpf/health
# {"backend":"proc-poll","level":"critical","lost_events":0,"missing":10,"score":15,
#  "summary":"critical · observation-only eBPF platform"}

# gate a sensor (a load gate only, never enforcement)
curl -s -X POST -H "$H" $KAVACH_URL/v1/ebpf/features/net -d '{"mode":"off"}'
# {"enforce":false,"id":"net","mode":"off","note":"Observation sensor gate only — never packet/process enforce"}

# push a decoded ringbuf batch plus the lost-sample counter
curl -s -X POST -H "$H" $KAVACH_URL/v1/ebpf/events \
  -d '{"events":[{"type":"exec","host":"web-01","pid":4242,"comm":"curl","path":"/usr/bin/curl"}],"lost":3}'
# {"ingested":1,"lost":3}

curl -s -H "$H" "$KAVACH_URL/v1/ebpf/events?type=exec"
curl -s -H "$H" $KAVACH_URL/v1/ebpf/drops
# {"kind":"ringbuf_lost","lost_events":3, ... "note":"Userspace/ringbuf sample loss — not packet drops. ..."}
```

A `critical` health level with `backend: proc-poll` is the expected result on hosts without a pinned eBPF
sensor (every feature reports `userspace-fallback`); it means "no kernel sensor", not a malfunction. Events
with `source: derived` (the `ebpf-seed-*` rows) are demo seed rows created by the platform so the console is never
empty; they are included in `event_count`. Rows with `source: ebpf` were ingested.

---

## CLI

```bash
kavachctl ebpf status
kavachctl ebpf health
kavachctl ebpf events --type memfd
kavachctl ebpf attachments
kavachctl ebpf features
kavachctl ebpf features set net off
kavachctl ebpf netra status
```

---

MCP (read-only): `kavach_ebpf_census`, `kavach_ebpf_coverage`, `kavach_ebpf_drops`, `kavach_ebpf_processes`,
`kavach_ebpf_summary`, `kavach_ebpf_netra_attachments`, `kavach_ebpf_netra_drops`, `kavach_ebpf_netra_flows`
(plus the earlier status and events tools). See [cli-reference.md](cli-reference.md).

## Troubleshooting

| Symptom | Cause and check |
|---|---|
| Health `critical`, backend `proc-poll` | No pin and no `CAP_BPF`; the supported fallback. Check `bpffs` and `btf` in `GET /v1/ebpf/status` |
| `attachments_ok: 0` after pinning | Status looks for pins under `KAVACH_BPF_PIN_ROOT` (default `/sys/fs/bpf/kavach`); set it if you pinned elsewhere |
| `lost_events` rising | Sample loss reported by the sensor (`lost` on `POST /v1/ebpf/events`); it is a counter of lost samples, not packet drops. Disable noisy features with `POST /v1/ebpf/features/{id}` |
| `/v1/ebpf/netra/*` empty | The Netra poller is not configured (`KAVACH_NETRA_POLLER_ENABLED`, `KAVACH_NETRA_URL`); status shows `configured: false` |
| Pins invisible inside a container | Not covered here: the chart's agent DaemonSet does not mount `/sys/fs/bpf` (not found in `daemonset-agent.yaml`), so a containerised agent will fall back to polling unless you add the mount yourself (untested) |

## Console

**Browse → eBPF** — health band, feature table, recent events.

---

## Netra boundary

| Kavach | Netra |
|--------|-------|
| Host process/file/priv/connect observe | TCX/XDP/cgroup datapath |
| `/v1/ebpf/netra/*` mirror | Canonical `/api/v1/ebpf/*` |
| Never writes Netra maps | May enforce under lease |

---

## See also

- [`bpf/README.md`](https://github.com/zyvorai/zyvor-kavach/blob/main/bpf/README.md)
- [Architecture](architecture.md)
- [Tutorial §7](tutorial.md)
- [Use case: eBPF host telemetry](use-cases.md)
