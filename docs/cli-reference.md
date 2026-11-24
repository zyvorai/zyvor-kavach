# CLI and MCP surface reference

This page lists the read-only commands added for surface parity and explains
how parity between HTTP routes, `kavachctl` and `kavach-mcp` is enforced. For
the full operator CLI see [kavachctl.md](kavachctl.md); for MCP setup see
[mcp-integration.md](mcp-integration.md). The route contract is
[openapi.yaml](openapi.yaml).

All commands below are plain authenticated `GET` requests. They never change
state.

## Surface size

Measured at this commit by building `kavach-mcp` and calling `tools/list` over stdio: **425 tools in the default
read-only mode and 499 with `KAVACH_MCP_ALLOW_MUTATIONS=true`** (74 additional tools: POST/PUT/DELETE-backed ones such as
ledger writes, case and exception changes, sandbox lab runs and enroll/revoke; containment is only ever a request ledger). The registered `GET` routes are all covered by a `kavachctl` command or a listed
exemption. These numbers move with every release; re-measure with the command below rather than trusting this page.

```bash
go build -o bin/kavach-mcp ./cmd/kavach-mcp
(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
   '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'; sleep 1) \
 | KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN=xxxxxxxxxx ./bin/kavach-mcp 2>/dev/null | tail -1 \
 | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["result"]["tools"]))'
```

## Authentication and output

- Token: set `KAVACH_TOKEN` (or `ZYVOR_EDR_TOKEN`, or `~/.kavach/api-key`).
  `--token T` is accepted on these commands as a convenience, but it lands in
  shell history and `ps`; prefer the environment variable. The token is sent
  only as a bearer header and is never printed.
- Server: `KAVACH_URL` (default `https://127.0.0.1:30899`); for the chart's
  self-signed certificate set `KAVACH_TLS_INSECURE=true`.
- Output: a table by default (header fields, then the first list in the
  response as rows). `--json` prints the raw response unchanged.

## Commands

| Command | Route | Notes |
|---|---|---|
| `events auth\|dns\|module\|registry [--host H] [--limit N]` | `GET /v1/events/{type}` | Recent typed telemetry; limit 1-1000 |
| `events summary` | `GET /v1/events/summary` | Counts per type |
| `enrich geo --ip IP` | `GET /v1/enrich/geo` | Offline heuristic geo; approximate |
| `evidence cases [CASE_ID]` | `GET /v1/evidence/cases[/{id}]` | Imported evidence cases |
| `guidance [ID] [--kind K] [--q TEXT]` | `GET /v1/guidance[/{id}]` | Advisory catalog |
| `posture trend-config` | `GET /v1/posture/trend/config` | Read only; changing it needs the admin API |
| `queries library [ID] [--tactic T] [--tag T] [--q TEXT]` | `GET /v1/queries/library[/{id}]` | Does not save anything |
| `exposure report [--host H] [--min_score N]` | `GET /v1/exposure/report` | Exposed hosts from imported SBOMs and advisories (sample data until you import) |
| `exposure attack-paths [--host H] [--min_score N]` | `GET /v1/exposure/attack-paths` | Ranked toxic combinations (exposure + vulnerable software + excess privilege + data) per asset; see [attack-paths.md](attack-paths.md) |
| `exposure advisories` | `GET /v1/exposure/advisories` | Loaded advisory set |
| `exposure sboms [HOST]` | `GET /v1/exposure/sboms` | SBOM inventory per host |
| `regression status` | `GET /v1/regression/status` | Latest snapshot |
| `regression history [--limit N]` | `GET /v1/regression/history` | Newest first |
| `regression diff [--from REF] [--to REF]` | `GET /v1/regression/diff` | REF: `latest`, `previous` or a sequence number |
| `regression trend [--window 7d]` | `GET /v1/regression/trend` | |
| `regression config` | `GET /v1/regression/config` | |
| `regression gate [--min-detected N] [--max-regressions N] [--max-false-positives N]` | `GET /v1/regression/gate` | Prints the result and exits non-zero on HTTP 412, so CI can gate on it |
| `reports templates [ID]` | `GET /v1/reports/templates[/{id}/render]` | With an ID, renders markdown to stdout; nothing is stored or sent |
| `rollback [--id ID]` | `GET /v1/rollback` | Guidance only; never restores files |

Sector, finance, eBPF and similar routes that already had commands are
documented in [kavachctl.md](kavachctl.md).

### Worked examples

```bash
export KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN='Admin@321'
kavachctl events summary
kavachctl exposure report --min_score 50 --json
kavachctl regression gate --max-regressions 0 --max-false-positives 0; echo "exit=$?"   # 0 pass, non-zero on HTTP 412
kavachctl reports templates                 # list; with an ID it renders markdown to stdout
kavachctl rollback                          # guidance only; never restores anything
```

`regression gate` against a fresh install returned `pass: true` with `measured_detected_pct: 83.9` on Kavach's own
synthetic scenarios (one variant per technique); that number measures the software on its own corpus, not real-world
detection.

### Other command groups added since the first parity pass (read or dry-run)

| Command | Route | Notes |
|---|---|---|
| `cloudaudit sources` | `GET /v1/cloud/audit/sources` | Ingest is `POST /v1/cloud/audit/events` (admin), not a CLI command |
| `web sources` | `GET /v1/web/sources` | Formats, `web-` rule count, analytic rule ids, limits |
| `web analyze FILE [--openapi F] [--format F] [--host H] [--json]` | `POST /v1/web/analyze` (admin) | Offline access-log detection, API inventory, shadow-API check; see [web-detection.md](web-detection.md) |
| `authlog analyze FILE [--host H] [--json]` | `POST /v1/auth/logs` (admin) | Offline auth-log analytics |
| `netcfg analyze FILE [--format F] [--host H] [--json]`, `netcfg diff OLD NEW [--format F]`, `netcfg sources` | `POST /v1/netcfg/analyze` and `/v1/netcfg/diff` (admin), `GET /v1/netcfg/sources` | Offline network-device configuration posture review; see [netcfg-posture.md](netcfg-posture.md) |
| `zscaler logs FILE [--format F] [--host H] [--sanctioned FILE] [--work-start H] [--work-end H] [--json]`, `zscaler policy FILE`, `zscaler zdx FILE`, `zscaler sources` | `POST /v1/zscaler/logs`, `/v1/zscaler/policy` and `/v1/zscaler/zdx` (admin), `GET /v1/zscaler/sources` | Offline analytics over exported Zscaler logs, policy and probe metrics; see [zscaler-analytics.md](zscaler-analytics.md) |
| `netlog analyze FILE [--format F] [--host H] [--bad-nets F] [--fingerprints F] [--json]`, `netlog sources`, `netlog timeline [--ip A] [--host H]` | `POST /v1/net/logs` and `/v1/net/analyze` (admin), `GET /v1/net/sources`, `GET /v1/net/timeline` | Offline network-log analytics and evidence timeline; see [network-detection.md](network-detection.md) |
| `idplog analyze FILE [--host H] [--dormant-days N] [--json]`, `idplog sources` | `POST /v1/idp/logs` (admin), `GET /v1/idp/sources` | Offline Okta and Entra log analytics; see [identity-detection.md](identity-detection.md) |
| `ransomlog analyze FILE [--host H] [--json]`, `ransomlog sources` | `POST /v1/ransom/logs` (admin), `GET /v1/ransom/logs/sources` | Offline file-activity and backup-job log analytics; see [ransomware-logs.md](ransomware-logs.md) |
| `exploitintel import FILE [--kind K] [--source S] [--ttl-days N] [--min-epss X]`, `status`, `lookup CVE`, `withdraw kev\|epss` | `POST/GET /v1/intel/exploit-feeds[/lookup]`, `DELETE /v1/intel/exploit-feeds/{kind}` | Offline KEV and EPSS import (admin for changes); see [exploit-intel.md](exploit-intel.md) |
| `tripwire list\|add\|delete ID\|scan FILE` | `GET/POST /v1/deception/tripwires`, `DELETE .../{id}`, `POST .../scan` | Declared decoys matched against logs (admin for changes); see [tripwires.md](tripwires.md) |
| `content test FILE... [--pack P] [--json]`, `content selftest [--rules] [--json]`, `content fp-report --benign PATH... [--builtin] [--kind K] [--threshold N] [--fail-on-noisy] [--json]`, `content tested-coverage [--json]` | none (runs offline in the CLI process) | Detection-as-code harness; see [content-testing.md](content-testing.md) |
| `posture-trend [diff --from D]` | `GET /v1/posture/trend[/diff]` | Counts only |
| `digest`, `auditor-bundle` | `GET /v1/reports/digest`, `GET /v1/compliance/auditor-bundle` | `auditor-bundle` needs `--out FILE.zip` or `--manifest` |
| `fleet health\|gaps\|stale\|slo` | `GET /v1/fleet/*` | `fleet slo set --file F` is an admin write |
| `syslog status\|samples\|parse` | `GET /v1/syslog/*`, `POST /v1/syslog/parse` | `parse` is a dry run |
| `coverage blindspots\|telemetry` | `GET /v1/coverage/*` | Computed live |
| `siem status\|export` | `GET /v1/siem/*` | Push-sink status and the legacy ECS NDJSON dump |
| `export findings\|iocs\|layer` | `GET /v1/export/*` | SIEM formats with cursor paging ([siem-export.md](siem-export.md)) |

## MCP tools added

`kavach-mcp` registers these in read-only mode. Mutating or admin tools stay
behind the existing mutation flag and none were added to that set. Every tool
in this group is a `GET` with no request body, and its description says
"Read-only".

- `kavach_events_{auth,dns,module,registry,summary}`
- `kavach_ebpf_{census,coverage,drops,processes,summary}` and
  `kavach_ebpf_netra_{attachments,drops,flows}`
- `kavach_regression_{status,history,diff,trend,config,gate}`
- `kavach_queries_library`, `kavach_queries_library_get`
- `kavach_guidance`, `kavach_guidance_get`
- `kavach_evidence_cases`, `kavach_evidence_case`
- `kavach_report_templates`, `kavach_report_template_render`
- `kavach_enrich_geo`, `kavach_rollback_advice`
- `kavach_rule_history`, `kavach_rule_lifecycle`, `kavach_ransomware_host`
- `kavach_case_workflow_journal`, `kavach_posture_trend_config`,
  `kavach_vulns_feeds_status`
- `kavach_sectors_<view>` (42 views) and `kavach_finance_<view>` (16 views)

Gaps at this commit (found by comparing the tool list with the routes): no MCP tool exists for
`GET /v1/exposure/*` (only the older `kavach_exposure` world scorecard), `GET /v1/cloud/audit/sources`, `GET /v1/web/sources`,
or `POST /v1/inspect/email|url` (`kavach_email_threats` for the inventory view does exist). They are available over HTTP and
`kavachctl` (where listed above). Add them to `cmd/kavach-mcp/tools_surface.go` by hand if an agent needs them.

Not exposed over MCP on purpose: the console HTML and static assets, the
`/v1/stream` event stream, `/v1/export/report` and `/v1/reports/archive/{id}`
(raw stored report bytes; use `kavachctl reports archive get` or
`kavachctl export`), and every `POST`/`PUT`/`DELETE` route.

## Parity enforcement

`TestEveryGETRouteHasCLICommandOrExemption` in
`cmd/kavachctl/surface_parity_test.go` scans the `GET` routes registered in
`internal/edr` and fails when one has neither a `kavachctl` command (detected
by its path literal in the CLI sources, including a static prefix such as
`"/v1/vulns/"` that the code extends) nor an entry in `parityExempt`. The
generic `kavachctl get PATH` command does not count as coverage.

When the test fails for a new route: add a command (and a catalog entry in
`cmd/kavachctl/commands_catalog.go`), or add an exemption with a reason.
Stale exemptions also fail the test.

Current exemptions (all non-API):

| Route | Reason |
|---|---|
| `/` | Console HTML shell |
| `/c/{}` | Console deep-link redirect |
| `/zyvor-logomark.svg`, `/zyvor-mark.svg` | Static console assets |

Limits of the check: it is a source scan, so a command that builds its path
dynamically with a prefix counts as covering every route under that prefix, and
it checks that a command exists, not that it handles every query parameter.
The MCP side is covered by `cmd/kavach-mcp/tools_surface_test.go`, which checks
the added tools are read-only GETs; there is no automatic MCP parity test, so
new read-only routes should be added to `tools_surface.go` by hand.
