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
| `KAVACH_ADMIN_TOKEN` | Token fallback (lowest precedence; written to `~/.kavach/env` by `deploy-remote.sh`) |
| `~/.kavach/api-key` | Token file if env unset |
| `~/.kavach/env` | Optional dotenv (`KEY=VALUE` lines; real environment variables win). Skipped when `KAVACH_SKIP_DOTENV=1` |
| `KAVACH_CLI_ACTOR` | Value sent as `X-Kavach-Actor` on requests (default `kavachctl`); shows up as the actor on notes, journal and ledger entries |
| `KAVACH_CLI_NO_BANNER` | Any value hides the TTY banner |
| `KAVACH_CLI_COLOR` | `true`/`false` (or `0`) forces colour on or off; `NO_COLOR` and `TERM=dumb` always turn it off; default is colour on a TTY |

Demo login password `Admin@321` is the API token when deployed with that secret. The console username is `admin`; the
password is the token itself.

Token resolution order: `KAVACH_TOKEN`, then `ZYVOR_EDR_TOKEN`, then `~/.kavach/env`, then `~/.kavach/api-key`. Note that
`KAVACH_ADMIN_TOKEN` (written by `deploy-remote.sh` into `~/.kavach/env` on the remote host) is **not** read by
`kavachctl`; export `KAVACH_TOKEN` as well. On a loopback URL TLS verification is skipped automatically; for a remote
self-signed certificate set `KAVACH_TLS_INSECURE=true`. There is no client-certificate option, so `kavachctl` cannot talk to
a listener that requires mTLS ([agent-mtls.md](agent-mtls.md)).

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

## Risk, trends, export, notes, alerts, journal

```bash
kavachctl risk hosts                   # ranked hosts: risk 0-100, band, findings, top rules (--json)
kavachctl risk summary                 # fleet risk index + host count per band
kavachctl trends --days 14 --bucket day   # --days 7|14|30, --bucket hour|day; sparkline of totals + per-day table

kavachctl export findings --format csv --severity high --since 2026-01-01T00:00:00Z --out findings.csv
kavachctl export findings --format ndjson > findings.ndjson   # csv|json|ndjson; filters: --severity --host --rule --since
kavachctl export report --format html --out report.html       # html|json

kavachctl notes list --finding F-123
kavachctl notes add --finding F-123 "isolated by the owner, benign"
kavachctl notes rm note-ab12

kavachctl saved-searches list
kavachctl saved-searches add --name "hot hosts" --scope findings --query "severity:high"
kavachctl saved-searches rm ss-ab12

kavachctl alerts rules list            # destination URLs are masked (path and query hidden)
kavachctl alerts rules add --url https://hooks.example.com/x --type webhook --min-severity high \
    --rule-contains ssh --host-contains prod
kavachctl alerts rules rm alr-ab12
kavachctl alerts deliveries            # recent delivery attempts and outcomes

kavachctl journal                      # tamper-evident activity journal
kavachctl journal verify               # checks the hash chain; exits non-zero if broken
```

`export` streams the response straight to the file or stdout. With `--out`, an existing file is never overwritten unless you pass `--force`, and no file is created if the server returns an error. Server error messages (for example `days must be 7, 14 or 30`) are shown verbatim with the HTTP status. Adding or removing an alert rule also records `alert_rule.create` / `alert_rule.delete` in the journal. Writes (`notes add|rm`, `saved-searches add|rm`, `alerts rules add|rm`) need an admin token.

## Intel feeds, detection lab, SOC, posture, compliance evidence

```bash
kavachctl intel feeds list                  # URL path and query are masked
kavachctl intel feeds add --name abuse --url https://feeds.example.com/ioc.csv --format csv \
    --interval 60 --ttl-days 7 --tlp green  # format: csv|plain|stix-lite-json
kavachctl intel feeds status
kavachctl intel feeds refresh abuse         # feed ID or name
kavachctl intel feeds rm abuse

kavachctl lab rules list
kavachctl lab rules add rule.json           # FILE, or - for stdin
kavachctl lab validate rule.json
kavachctl lab test rule.json --events events.json
cat rule.json | kavachctl lab backtest --rule -   # hits, noise/host/day, hits-per-day sparkline, sample hits
kavachctl lab backtest --id lab-1
kavachctl lab rules rm lab-1

kavachctl soc metrics --days 30             # MTTA/MTTR, backlog by age, SLA breaches, noisy rules
kavachctl soc shift-report --hours 12 --out shift.txt   # never overwrites without --force
kavachctl soc storyline web-01 --hours 24   # nested under soc: top-level `storyline` is the id/host endpoint

kavachctl posture summary
kavachctl posture vulns --limit 20 --explain   # --explain prints the per-factor score breakdown
kavachctl posture assets add --host db-01 --criticality 5 --owner dba --tags pci,db
kavachctl posture assets list
kavachctl posture baseline db-01            # omit HOST to baseline every observed host
kavachctl posture drift db-01
kavachctl posture assets rm db-01

kavachctl compliance controls --framework cis
kavachctl compliance evidence --framework cis --format html --out evidence.html   # refuses to overwrite without --force
kavachctl compliance cert-in-clock          # open high/critical findings with time remaining
```

All lab commands print a sandbox notice: lab rules never raise alerts or touch production detections. `compliance controls` and `evidence` are observe-only evidence, not a certification, and `cert-in-clock` is informational (Kavach files no reports). Existing `compliance` and `compliance score` are unchanged. Tables accept `--json` or `-o json|yaml`; server error messages are shown verbatim with the HTTP status. Writes need an admin token.

## Telemetry, cloud, exposure and coverage (read-only)

```bash
kavachctl events auth --host web-01 --limit 20       # also dns, module, registry; events summary
kavachctl cloudaudit sources                         # supported sources and the loaded cld- rule count
kavachctl exposure report --min_score 50             # exposed hosts from imported SBOMs and advisories
kavachctl exposure advisories                        # loaded advisory set (SAMPLE until you import data)
kavachctl exposure sboms web-01                      # SBOM inventory
kavachctl coverage blindspots                        # techniques with no telemetry / rules
kavachctl coverage telemetry                         # per-category: never_seen / stale / ok
kavachctl syslog status                              # listener state; syslog parse LINE is a dry run
kavachctl fleet health                               # also: fleet gaps, fleet stale, fleet host HOST
kavachctl fleet slo                                  # also: history, definitions, set --file slo.json (admin)
```

Ingest is not done through `kavachctl`: SBOMs, cloud audit records and telemetry are POSTed to the HTTP API with an admin
token or a per-host credential (see [exposure.md](exposure.md), [cloud-audit.md](cloud-audit.md),
[telemetry-types.md](telemetry-types.md)).

## Posture, reports and gates

```bash
kavachctl posture-trend --days 30                    # counts-only snapshots; every 6 h by default
kavachctl posture-trend diff --from 2026-11-01       # deltas between two dates (--to optional)
kavachctl digest --format md                         # executive digest (md|json|html via the API)
kavachctl auditor-bundle --out evidence.zip          # or --manifest to print the manifest only
kavachctl regulatory clocks                          # reporting-time clocks for your regimes (informational)
kavachctl regression gate --max-regressions 0 --max-false-positives 0
echo "exit=$?"                                       # non-zero when the server answers HTTP 412
```

## Output, errors and exit codes

* Tables are the default; `--json` prints the raw response; some commands accept `-o table|json|yaml`.
* Errors go to stderr as `kavachctl: <message>` and the process exits with status 1. Server error text is shown with the
  HTTP status (for example `days must be 7, 14 or 30`).
* Specific exits: `doctor` (any failed check), `journal verify` (broken hash chain) and `regression gate` (HTTP 412).
* Write commands need an admin token. Destructive or state-changing commands ask for `--yes` (for example
  `ml reset --yes`, `governance retention apply --yes`, `feedback record ... --yes`); without it the command refuses with `<name> is mutating; re-run with --yes to confirm` and sends nothing.
* Commands that write files (`export`, `soc shift-report`, `compliance evidence`, `auditor-bundle`, `reports archive get`)
  never overwrite an existing file without `--force`.
* `kavachctl get /v1/PATH` is a raw GET escape hatch. It does not count as CLI coverage in the parity test
  ([cli-reference.md](cli-reference.md)).
* `kavachctl completion bash|zsh|fish` prints a completion script; a test keeps the completion word list and `--help` in sync
  with the command catalog.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `kavachctl: set KAVACH_TOKEN (or ~/.kavach/api-key)` | Export the token, or write it to `~/.kavach/api-key` |
| `x509: certificate signed by unknown authority` | Self-signed server: `export KAVACH_TLS_INSECURE=true` (the error text includes this hint) |
| `connection refused` | Wrong `KAVACH_URL` (default `https://127.0.0.1:30899`; a local `go run` server is `http://127.0.0.1:8099`) |
| `HTTP 401` | Wrong token. Repeated failures are throttled per IP; wait a few seconds |
| `HTTP 403 admin token required` | The command writes; use the admin token, not a per-host agent credential |
| `unknown command` | `kavachctl --help` shows the full map; the usage line of a command group lists its subcommands |
| `watch` exits immediately | A 401/403 stops `watch` instead of retrying; fix the token |
| Run `kavachctl doctor` first | Checks URL, token, `/livez`, `/readyz`, auth and TLS in one go |

See also [cli-reference.md](cli-reference.md) for the read-only surface-parity commands and the MCP equivalents.
