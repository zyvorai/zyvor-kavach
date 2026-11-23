# Architecture

Kavach is Zyvor’s unified endpoint security controller: host process and file observation, optional eBPF telemetry, Netra network-event correlation, cloud audit-log and software-exposure reporting, AI assist, and an investigation API/console. It is **observation-first** — no automatic containment.

Sister product: **Netra** (network XDR / eBPF datapath). Kavach owns host EDR; Netra owns network datapath. Together they form Zyvor XDR.

---

## Hard rule

```text
DETECT + REPORT  ✓
CONTAIN / KILL / ISOLATE / DROP  ✗
```

- Prevention policies and IOA/IOC drive `Detect()` only.  
- Containment APIs append a **request ledger**.  
- eBPF programs never return deny / drop.  
- AI recommends; it does not act.  
- Exceptions suppress *reporting* only (with mandatory expiry); nothing is blocked.  
- Optional outbound connections (SIEM push, alert and digest webhooks, intel/CERT/EPSS/vuln feeds, Netra poller) are operator opt-in and only send or fetch data; none of them can change a host.

---

## Component diagram

```text
  Browser / curl / kavachctl / MCP / SIEM
                    │
                    ▼
         ┌──────────────────────┐
         │   kavach (server)    │
         │   :8099 / :30899     │
         │                      │
         │  • HTTP /v1 API      │
         │  • dashboard.html    │
         │  • findings store    │
         │  • incident ledger   │
         │  • content engine    │
         │  • local models      │
         │  • AI platform       │
         │  • eBPF platform API │
         │  • world inventory   │
         │  • SIEM exporter     │
         │  • syslog listener   │
         └──────────┬───────────┘
                    │
         bearer token / session cookie / optional mTLS
                    │
      ┌─────────────┴──────────────┐
      ▼                            ▼
 ┌─────────────┐            ┌──────────────────┐
 │ kavach agent│            │ netra-bridge /   │
 │             │            │ Netra poller     │
 │ /proc poll  │            │ network events   │
 │ proc conn.  │            │ drops / flows    │
 │ eBPF pins   │            │ (never write     │
 │ collectors  │            │  Netra BPF maps) │
 └─────────────┘            └──────────────────┘
```

---

## Binaries

| Path | Role |
|------|------|
| `cmd/kavach` | Controller (`-mode server`) or agent (`-mode agent`) |
| `cmd/kavachctl` | Operator CLI (sister to `netractl`); [kavachctl.md](kavachctl.md), [cli-reference.md](cli-reference.md) |
| `cmd/kavach-mcp` | MCP stdio server for AI agents; [mcp-integration.md](mcp-integration.md) |
| `cmd/netra-bridge` | Stdin JSONL → `POST /v1/network-events`; each line needs `host`, `pid`, `time`, `destination`; a bad line or non-200 stops the run ("input may need replay"); HTTPS required except loopback |

### `kavach` flags

| Flag | Default | Mode | Meaning |
|------|---------|------|---------|
| `-mode` | `server` | both | `server` or `agent` |
| `-listen` | `127.0.0.1:8099` | server | API address. A non-loopback address without `-tls-cert`/`-tls-key` is refused at start |
| `-state` | `./data/findings.jsonl` | server | Findings store path; every other state file is `<state>` plus a suffix ([persistence-files.md](persistence-files.md)) |
| `-credentials` | `./data/agents.json` | server | Hashed per-host agent credential registry |
| `-tls-cert`, `-tls-key` | empty | server | Serve HTTPS (both or neither) |
| `-client-ca` | empty | server | Verify client certificates; `-client-auth require` (default) or `optional` ([agent-mtls.md](agent-mtls.md)) |
| `-url` | `http://127.0.0.1:8099` | agent | Server URL; `http://` is refused for any non-loopback host |
| `-queue` | `./data/outbox` | agent | Durable event queue directory (limit 10,000 queued events; when full the agent refuses to drop silently and returns an error) |
| `-ca`, `-agent-cert`, `-agent-key` | empty | agent | Trusted CA and client certificate pair |
| `-watch-files` | empty | agent | Opt-in file metadata watch root (otherwise `/etc` metadata is observed) |
| `-interval` | `3s` | agent | Process polling interval (minimum 1 s); heartbeat every 30 s |

The token comes from `KAVACH_TOKEN` (legacy alias `ZYVOR_EDR_TOKEN`): at least 8 characters or the process exits, with a warning under 16.

---

## Packages

| Package | Responsibility |
|---------|----------------|
| `internal/edr` | Store, Detect(), content engine, APIs, console, local models, world/AI/eBPF/finance platforms |
| `internal/mcpserver` | Minimal MCP framing for `kavach-mcp` |
| `bpf/` | CO-RE observation objects (exec, process, file, priv, net) |
| `helm/kavach` | Deployment, agent DaemonSet, Setura Gateway opts |

---

## Data path

1. **Discover** — agent uses eBPF pin (if present) → proc connector → `/proc` poll. Agents also push host inventories (persistence, firewall, browser, SBOM) and file metadata.  
2. **Ingest** — `POST /v1/events` (process), `/v1/network-events`, `/v1/file-events`, `/v1/events/{type}` (registry, dns, auth, module), `POST /v1/ebpf/events`, `POST /v1/cloud/audit/events` (admin), syslog listener (opt-in), SBOM upload (`PUT /v1/exposure/sboms/{host}`, admin).  
3. **Detect** — process/file/network/telemetry/cloud-audit signals evaluated by the content rule packs (JSON, validated at load), IOC/IOA, custom rules, Sigma imports, the built-in auth-burst counter and the local behaviour models.  
4. **Persist** — findings and recent events in append-only JSONL; the in-memory window is the newest 1000 findings. Inventory domains in `*.inventory.json`; all other state as listed in [persistence-files.md](persistence-files.md).  
5. **Correlate** — Netra-shaped network events join by host + PID; threat graph / storyline / provenance / attack-chain APIs.  
6. **Present** — console, `kavachctl`, MCP tools, SIEM pull endpoints (`/v1/export/*`) and the optional push sink ([siem-export.md](siem-export.md)).  
7. **Assist** — AI Hub scores, briefs, NL hunt (optional external LLM via `KAVACH_LLM_URL` / `KAVACH_LLM_API_KEY`).

Bootstrap on empty stores seeds live inventory so demos are never blank (`BootstrapLivePlatform`; the log line `live platform bootstrapped` appears at start).

### Detection content and models

| Layer | What | Docs |
|-------|------|------|
| Content packs | Embedded JSON detection, byte-pattern, adversary, scenario, hunt and compliance packs; custom rules; lifecycle (draft, testing, production, retired); exceptions | [content-framework.md](content-framework.md), [custom-content.md](custom-content.md), [rule-health.md](rule-health.md), [sigma-import.md](sigma-import.md) |
| Validation | Detection-as-code lab, validation scenarios, daily regression tracking and gate | [research-validation-lab.md](research-validation-lab.md), [regression-tracking.md](regression-tracking.md) |
| Local models | Lineage, command-vector, beacon, DNS, user, peer and fatigue models, learned on this install only | [local-models.md](local-models.md), [local-models-net.md](local-models-net.md) |
| Inspectors | Parse-only static analyzers for files, scripts, command lines, URLs, domains, e-mail, lockfiles and configs (never execute or fetch) | [artifact-analyzers.md](artifact-analyzers.md), [url-email-inspection.md](url-email-inspection.md) |

All corpora and scores are **synthetic or heuristic**; detection rates measured in the lab are not a guarantee of coverage on real attacks ([research-validation-lab.md](research-validation-lab.md)).

### Cloud, exposure and e-mail (overview)

- **Cloud and SaaS audit logs** — operators POST exported CloudTrail, Azure, GCP, Okta and M365 records; they are normalised and evaluated by `cld-` rules. Kavach never calls a cloud API ([cloud-audit.md](cloud-audit.md)). `GET /v1/cloud/posture` is the older inventory-domain view.  
- **Software exposure** — operators upload CycloneDX/SPDX SBOMs and import advisories; matching is local and offline, using a small SAMPLE advisory set until real data is imported ([exposure.md](exposure.md)). Optional `KAVACH_EXPOSURE_PRIORITY=1` adds an `exposure` factor to `GET /v1/ml/priority`.  
- **E-mail** — the parse-only e-mail and URL analyzers (`POST /v1/inspect/email`, `/url`) and the inventory view `GET /v1/email/threats`; no mail server is contacted ([url-email-inspection.md](url-email-inspection.md)).

---

## Trust & network boundaries

| Surface | Default |
|---------|---------|
| Local listen | Loopback HTTP `:8099` |
| Helm chart | In-pod HTTPS, NodePort **30899**, PVC at `/app/data` |
| Setura Gateway | Optional HTTPS NodePort **30943** (`kavach.<ip>.sslip.io`) |
| Auth | `KAVACH_TOKEN` bearer; console session cookie via `POST /v1/session` (body `{"token": ...}`; the console form sends username `admin` plus the token as password); cookie HttpOnly, SameSite=Strict, 1 hour |
| Public routes | `/healthz`, `/livez`, `/readyz`, `/`, two static SVGs, `POST /v1/session`, `POST /v1/logout`, canary beacon `/c/{id}` |
| Agent auth | Per-host credential (hashed at rest, host-scoped, revocable, ingest routes only) or the admin token; optional mTLS (`docs/agent-mtls.md`) |
| Roles | One shared admin token; `KAVACH_RBAC=1` roles via `X-Kavach-Role` / `KAVACH_ROLE` are advisory restrictions, not an authorisation boundary |
| TLS verify | Lab often uses self-signed → `KAVACH_TLS_INSECURE=true` for `kavachctl` and `kavach-mcp` (auto on loopback) |
| Limits | Request bodies capped per route; write rate limit `KAVACH_RATE_LIMIT` (default 100 per second per IP); login and failed-auth throttles always on |

Details and accepted risks: [security-review.md](security-review.md), [observability.md](observability.md).

---

## Lifecycle and shutdown

Background workers (SLO sampler, posture trend, schedulers, feed refreshers, model learners, syslog listener, Netra poller) register with a lifecycle registry (`internal/edr/lifecycle.go`). On SIGINT or SIGTERM the server flips `/readyz` to 503, drains HTTP for up to 7 s (long-lived `/v1/stream` connections fall through to a forced close), then stops registered workers within a 5 s budget (2 s per worker). Helm gives the pod a 20 s grace period. Workers that fail to stop in time are logged as `shutdown: <name>: timed_out=...`.

---

## eBPF placement

```text
  Host kernel                     Userspace
  ───────────                     ─────────
  kavach_*.o ──ringbuf──► pin ──► WatchEBPF / ingest
                                  │
                                  ▼
                           /v1/ebpf/events
                           Detect() / console
```

Netra’s TCX/XDP/cgroup programs are **out of process**. Kavach polls Netra observe APIs (`KAVACH_NETRA_POLLER_ENABLED`, `KAVACH_NETRA_URL`, `KAVACH_NETRA_API_KEY`) and exposes `/v1/ebpf/netra/*` mirrors. See [ebpf.md](ebpf.md).

---

## API map (high level)

The authoritative list is [openapi.yaml](https://github.com/zyvorai/zyvor-kavach/blob/main/docs/openapi.yaml); a test checks that every registered route is documented there.

| Prefix | Purpose |
|--------|---------|
| `/healthz`, `/livez`, `/readyz`, `/metrics` | Probes and Prometheus ([observability.md](observability.md)) |
| `/v1/summary`, `/v1/findings`, `/v1/detections`, `/v1/incidents`, `/v1/cases` | Core EDR and workflow |
| `/v1/fleet`, `/v1/hosts`, `/v1/agents` | Fleet, health, SLO |
| `/v1/events`, `/v1/network-events`, `/v1/file-events`, `/v1/events/{type}` | Ingest and typed telemetry ([telemetry-types.md](telemetry-types.md)) |
| `/v1/hunt/*`, `/v1/hunts/*`, `/v1/timeline`, `/v1/threat-graph`, `/v1/search` | Hunt and search |
| `/v1/content/*`, `/v1/rules/*`, `/v1/lab/*`, `/v1/validate/*`, `/v1/regression/*` | Detection engineering |
| `/v1/ml/*`, `/v1/ttp/*`, `/v1/prov/*`, `/v1/feedback/*` | Local models, resemblance, provenance, analyst verdicts |
| `/v1/ai/*` | AI Hub |
| `/v1/ebpf/*` | eBPF observe platform |
| `/v1/cloud/*`, `/v1/exposure/*`, `/v1/sbom/*`, `/v1/vulns/*`, `/v1/posture/*` | Cloud audit, software exposure, vulnerability and posture |
| `/v1/inspect/*` | Parse-only artifact inspector |
| `/v1/finance/*` | Banks / markets / payments (observe — never freezes money) |
| `/v1/sectors/*` | Railways / govt / energy / aviation / … (observe — never stops services) |
| `/v1/world/*` + inventory domains | Global catalog |
| `/v1/export/*`, `/v1/siem/*`, `/v1/reports/*` | Pull exports and reports |
| `/v1/regulatory/*`, `/v1/compliance/*` | Regional reporting clocks and control evidence (informational) |
| `/v1/syslog/*` | Agentless syslog listener |
| `/v1/governance/*` | Retention, redaction, subject lookup |
| `/v1/session`, `/v1/logout` | Console login |

---

## Operator surfaces and parity

`kavachctl` and `kavach-mcp` wrap the same HTTP API. A test (`TestEveryGETRouteHasCLICommandOrExemption`) fails when a `GET` route has no `kavachctl` command and no documented exemption. At this commit `kavach-mcp` registers 425 tools in the default read-only mode and 499 with `KAVACH_MCP_ALLOW_MUTATIONS=true` (counted with `tools/list`; the number changes as tools are added). Mutating MCP tools only write Kavach's own ledgers; containment is never enforced. See [cli-reference.md](cli-reference.md) and [mcp-integration.md](mcp-integration.md).

---

## Kubernetes layout

```text
kavach-system
  ├─ Deployment/kavach          controller (1 replica, Recreate strategy with a PVC)
  ├─ DaemonSet/kavach-agent     optional node agents
  ├─ PVC (2Gi, /app/data)       findings, models, ledgers
  ├─ Service NodePort 30899
  └─ (optional) Setura Gateway + HTTPRoute :30943
```

Chart: `helm/kavach`. Deploy script: `scripts/deploy-remote.sh`, gated by the test runs described in [deploy-remote.md](deploy-remote.md).

---

## Failure modes and limits

| Situation | Behaviour |
|-----------|-----------|
| Controller down | Agents queue events on disk (up to 10,000) and retry every 2 s; heartbeats stop, so fleet health shows them stale |
| Agent queue full | The agent returns an error instead of silently dropping events |
| No eBPF pin or no `CAP_BPF` | Agent falls back to proc connector, then `/proc` polling (`sensor_kind: proc-poll`) |
| Corrupt state file | Most files are ignored and treated as empty; a corrupt `.incidents` ledger or credential registry aborts startup ([persistence-files.md](persistence-files.md)) |
| Findings window | Only the newest 1000 findings are served from memory; exports and metrics reflect that window |
| Evaluation budget | Telemetry and cloud-audit batches are evaluated within a time budget (150 ms and 2 s); the rest are stored or counted as `not_evaluated` |
| Push sink failures | SIEM push is fire-and-forget with no retry; use pull export with a cursor for completeness |
| Several controller replicas | Not supported: state is file-backed by a single process |

---

## Related docs

- [Tutorial](tutorial.md)
- [Use cases](use-cases.md)
- [Deploy remote](deploy-remote.md)
- [Setura Gateway](setura-gateway.md)
- [Agent mTLS](agent-mtls.md)
- [Console](console.md)
- [Testing](testing.md)
- [Security review](security-review.md)
