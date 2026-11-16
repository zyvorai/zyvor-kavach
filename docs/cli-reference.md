# CLI and MCP surface reference

This page lists the read-only commands added for surface parity and explains
how parity between HTTP routes, `kavachctl` and `kavach-mcp` is enforced. For
the full operator CLI see [kavachctl.md](kavachctl.md); for MCP setup see
[mcp-integration.md](mcp-integration.md). The route contract is
[openapi.yaml](openapi.yaml).

All commands below are plain authenticated `GET` requests. They never change
state.

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
