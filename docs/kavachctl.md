# kavachctl

Operator CLI for Zyvor Kavach — sister to [netractl](https://github.com/zyvorai/netra). Observation-only: it talks to the controller HTTP API and never instructs contain, kill, or isolate.

## Install

```bash
go install github.com/zyvorai/zyvor-kavach/cmd/kavachctl@latest
# or from a checkout:
go build -o bin/kavachctl ./cmd/kavachctl
```

## Config

| Variable / file | Purpose |
|-----------------|---------|
| `KAVACH_URL` | Controller base (default `https://127.0.0.1:30899`) |
| `KAVACH_TOKEN` | Bearer token (alias `ZYVOR_EDR_TOKEN`) |
| `KAVACH_TLS_INSECURE=true` | Skip TLS verify (auto on loopback) |
| `~/.kavach/api-key` | Token file if env unset |
| `~/.kavach/env` | Optional dotenv |

Demo login password `Admin@321` is the API token when deployed with that secret.

```bash
export KAVACH_URL=https://kavach.80.79.5.173.sslip.io:30943
export KAVACH_TOKEN='Admin@321'
export KAVACH_TLS_INSECURE=true
```

## Examples

```bash
kavachctl status
kavachctl status --json --wait
kavachctl findings --severity high
kavachctl fleet
kavachctl hunt query 'severity:high'
kavachctl ai briefing
kavachctl ai chat 'summarize critical findings'
kavachctl world modules
kavachctl ebpf status
kavachctl ebpf events --type exec
kavachctl ebpf health
kavachctl finance summary
kavachctl finance exchanges
kavachctl finance upi
kavachctl finance sebi
kavachctl finance insurance
kavachctl finance irdai
kavachctl finance motor-insurance
kavachctl sectors summary
kavachctl sectors railways
kavachctl sectors gov-vehicles
kavachctl sectors public-vehicles
kavachctl sectors city-buses
kavachctl sectors taxis-cabs
kavachctl sectors school-buses
kavachctl sectors ferries
kavachctl sectors automotive
kavachctl sectors manufacturing
kavachctl sectors isro-centers
kavachctl sectors space
kavachctl sectors gov-portals
kavachctl sectors power
kavachctl siem export
kavachctl get /v1/summary
```

Aliases: `finance`/`fin`/`banking`; `sectors`/`railways`/`govt`. Run `kavachctl --help` for the full command map.

## Observe, watch, diagnose

```bash
kavachctl watch --severity high        # live tail of /v1/stream, colored, auto-reconnect (backoff 1s..30s)
kavachctl attack                       # ATT&CK table: tactic, covered, hits  (--json for raw)
kavachctl compliance score             # grade table per framework          (--json for raw)
kavachctl findings -o table            # --output table|json|yaml (default json); also detections
kavachctl doctor                       # KAVACH_URL/TOKEN, /livez, /readyz, auth, TLS hint
source <(kavachctl completion zsh)     # also: bash, fish
```

`watch --severity` is a minimum (`high` shows high and critical); `--max-events N` exits after N events. A rejected token (401/403) stops `watch` instead of retrying. `doctor` exits non-zero if any check fails.
