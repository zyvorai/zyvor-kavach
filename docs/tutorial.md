# Tutorial — Your first hour with Kavach

This walkthrough takes you from zero to a working observation-only EDR console, CLI, hunt, AI briefing, and eBPF status check.

**Prerequisites:** Go 1.27+, git, curl. Optional: kubectl/Helm and SSH to a lab node for cluster deploy.

---

## 1. Clone and test

```bash
git clone https://github.com/zyvorai/zyvor-kavach.git
cd zyvor-kavach
export KAVACH_TOKEN='Admin@321'
go test ./...
```

All packages should pass. If something fails, see [testing.md](testing.md). The full suite is large; the
race-detector variant used by CI needs `go test -race -timeout 30m ./...` because the `internal/edr` package
exceeds Go's default 10 minute timeout. You can skip both for a first look and just run the server.

---

## 2. Run the controller locally

```bash
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
```

State is written under `./data/` (`findings.jsonl` plus derived files such as `findings.jsonl.exposure.json`,
see [persistence-files.md](persistence-files.md)). Use `-state /path/findings.jsonl` to move it. The token must be
at least 8 characters, otherwise the process exits; a warning is logged under 16.

Health check:

```bash
curl -s http://127.0.0.1:8099/healthz
# → ok
```

Open the console: http://127.0.0.1:8099/

- **Username:** `admin`
- **Password:** your `KAVACH_TOKEN` (`Admin@321` in this tutorial). The console posts the token to
  `POST /v1/session`; there is a single shared token and no separate user database.

You should see the Overview story hero, metric band, and Browse navigation.

---

## 3. Run an agent

In a second terminal:

```bash
export KAVACH_TOKEN='Admin@321'
go run ./cmd/kavach -mode agent \
  -url http://127.0.0.1:8099 \
  -interval 3s
```

Confirm fleet:

```bash
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" \
  http://127.0.0.1:8099/v1/fleet | head
```

Or in the console: **Fleet**.

---

## 4. Install kavachctl

```bash
go build -o bin/kavachctl ./cmd/kavachctl
export KAVACH_URL=http://127.0.0.1:8099
export KAVACH_TOKEN=Admin@321

./bin/kavachctl status
./bin/kavachctl findings
./bin/kavachctl modules | head
```

`status` prints a human board (banner on TTY). Add `--json` for automation.

---

## 5. Hunt and detections

```bash
./bin/kavachctl detections --severity high
./bin/kavachctl hunt query 'severity:high'
./bin/kavachctl timeline
./bin/kavachctl storyline
```

In the console: **Detect**, **Detections**, **Hunt**.

---

## 6. AI Hub

```bash
./bin/kavachctl ai capabilities
./bin/kavachctl ai briefing
./bin/kavachctl ai chat 'summarize open high severity findings'
```

Optional LLM: set `KAVACH_LLM_URL` to an OpenAI-compatible chat completions endpoint. Without it, heuristics still answer.

Console: **AI Hub**.

---

## 7. eBPF observe platform

```bash
./bin/kavachctl ebpf status
./bin/kavachctl ebpf health
./bin/kavachctl ebpf events --type exec
./bin/kavachctl ebpf capabilities
```

On Linux with clang you can build CO-RE objects:

```bash
./scripts/build-bpf.sh
# pin under /sys/fs/bpf/kavach/ — see docs/ebpf.md
```

Without pins, Kavach falls back to proc connector / `/proc` poll. That is expected on macOS and unprivileged hosts.

Console: **Browse → eBPF**.

---

## 8. Finance — banks & stock markets

```bash
./bin/kavachctl finance summary
./bin/kavachctl finance exchanges
./bin/kavachctl finance upi
./bin/kavachctl finance fraud
./bin/kavachctl finance sebi
./bin/kavachctl finance insurance
./bin/kavachctl finance irdai
./bin/kavachctl finance motor-insurance
./bin/kavachctl finance events --type claims_burst
```

Observation only: never freezes accounts, blocks trades, or drops payment messages.

Console: **Browse → Finance**. Full API map: [finance.md](finance.md).

---

## 9. Sectors — railways, government & more

```bash
./bin/kavachctl sectors summary
./bin/kavachctl sectors railways
./bin/kavachctl sectors gov-portals
./bin/kavachctl sectors power
./bin/kavachctl sectors airports
./bin/kavachctl sectors flights
./bin/kavachctl sectors defence
./bin/kavachctl sectors gov-vehicles
./bin/kavachctl sectors public-vehicles
./bin/kavachctl sectors city-buses
./bin/kavachctl sectors taxis-cabs
./bin/kavachctl sectors school-buses
./bin/kavachctl sectors ferries
./bin/kavachctl sectors automotive
./bin/kavachctl sectors manufacturing
./bin/kavachctl sectors isro-centers
./bin/kavachctl sectors space
./bin/kavachctl sectors critical-sites
./bin/kavachctl sectors events --sector city-buses
```

Observation only: never stops trains, cancels flights, controls ATC, trips breakers, or touches weapons/C2.

Console: **Browse → Sectors**. Full API map: [sectors.md](sectors.md).

---

## 10. World catalog & inventory

```bash
./bin/kavachctl world modules
./bin/kavachctl discover assets
./bin/kavachctl spotlight
./bin/kavachctl compliance
./bin/kavachctl zero-trust
```

Console: **World** domain loader.

---

## 11. Observe: ATT&CK, compliance, risk, live stream

```bash
./bin/kavachctl attack                 # ATT&CK coverage table (tactic, covered, hits)
./bin/kavachctl compliance score       # grade per framework (evidence counts, not a certification)
./bin/kavachctl risk summary           # fleet risk index and hosts per band
./bin/kavachctl watch --severity high --max-events 5
./bin/kavachctl doctor                 # URL, token, /livez, /readyz, auth, TLS hint
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/metrics | grep '^kavach_'
```

A freshly started install has few findings, so expect low compliance grades (the controls look for evidence such as
agents online, alert rules and audit entries) and zero ATT&CK hits. That is the honest state of an empty install,
not a fault. Details: [observability.md](observability.md).

---

## 12. Send your own data

Everything below is something *you* push; Kavach never fetches it and never changes a host.

**Typed telemetry** (registry, dns, auth, module):

```bash
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/events/auth \
  -d '{"host":"web-01","time":"2026-11-16T10:00:00Z","user":"root","source_ip":"203.0.113.9","method":"ssh","outcome":"failure"}'
# {"accepted":1,"findings":0,"not_evaluated":0}
./bin/kavachctl events auth --host web-01
```

Eight failures from one source inside 60 seconds raise a brute-force finding; see
[telemetry-types.md](telemetry-types.md).

**Software exposure from an SBOM** (offline, matched against a small SAMPLE advisory set until you import real data):

```bash
curl -s -X PUT -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/exposure/sboms/web-01 \
  --data-binary @sbom.cdx.json          # CycloneDX or SPDX 2.x JSON; admin token
./bin/kavachctl exposure report
```

An SBOM listing `log4j-core 2.14.1` scores `critical` against the sample CVE-2021-44228 entry. "Not exposed" only
ever means "not exposed to the advisories currently loaded". See [exposure.md](exposure.md).

**Cloud and SaaS audit logs** (CloudTrail, Azure, GCP, Okta, M365):

```bash
./bin/kavachctl cloudaudit sources
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" "$KAVACH_URL/v1/cloud/audit/events?source=aws" \
  --data-binary @cloudtrail-file.json   # a CloudTrail log file ({"Records":[...]}) works unchanged
# {"by_source":{"aws:cloudtrail":1},"findings":2,"normalized":1,"not_evaluated":0,"received":1,"rejected":0, ...}
```

The records become findings with `cld-` rule ids on a synthetic host named `cloud:aws` (and similar for the other
sources), so that host also appears in `kavachctl status`. See [cloud-audit.md](cloud-audit.md).

**E-mail and URLs**: the parse-only inspector (`POST /v1/inspect/email` and `/v1/inspect/url`, or the console Inspector; `kavachctl inspect` covers file, script, cmdline and domain)
never fetches a link or contacts a mail server. See [url-email-inspection.md](url-email-inspection.md).

**Syslog from network gear** is opt-in (`KAVACH_SYSLOG`, `KAVACH_SYSLOG_ALLOW`); see
[syslog-listener.md](syslog-listener.md).

---

## 13. Export to a SIEM

```bash
./bin/kavachctl export findings --format ocsf          # also ecs, cef, leef, splunk-hec
./bin/kavachctl export iocs                            # STIX 2.1 bundle
./bin/kavachctl export layer                           # ATT&CK Navigator layer
curl -s -D- -H "Authorization: Bearer $KAVACH_TOKEN" "$KAVACH_URL/v1/export/findings?format=ocsf&limit=100" | head
# X-Kavach-Count: 2
# X-Kavach-Next-Cursor: ...   pass as cursor= on the next call
```

Pull-based with checkpointing; format mappings were not validated against any vendor parser
([siem-export.md](siem-export.md)).

---

## 14. Deploy to the lab cluster (optional)

Run the test gates first ([deploy-remote.md](deploy-remote.md) explains the gated flow), then:

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
```

Then:

```bash
export KAVACH_URL=https://kavach.80.79.5.173.sslip.io:30943
export KAVACH_TOKEN=Admin@321
export KAVACH_TLS_INSECURE=true
./bin/kavachctl status --wait
```

The deploy script reads `KAVACH_ADMIN_TOKEN` (default `Admin@321`) for the chart token. Browser: same URL, accept the
self-signed cert, sign in as `admin` with that token as the password.

Full steps: [deploy-remote.md](deploy-remote.md), [envoy-gateway.md](envoy-gateway.md).

---

## 15. Lab demo script

With a running server:

```bash
export KAVACH_URL=http://127.0.0.1:8099
export KAVACH_TOKEN=Admin@321
./scripts/demo-lab.sh
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `set KAVACH_TOKEN to a secret of at least 8 characters` on start | Export `KAVACH_TOKEN` before `go run` |
| `non-loopback listener requires TLS` | `-listen 0.0.0.0:...` needs `-tls-cert` and `-tls-key`; use loopback for local runs |
| `kavachctl: set KAVACH_TOKEN` | Export the token or put it in `~/.kavach/api-key` |
| `x509: certificate signed by unknown authority` from `kavachctl` | Self-signed lab certificate: `export KAVACH_TLS_INSECURE=true` (automatic on loopback) |
| Console says wrong username or password | Username is `admin`; the password is the exact token the server was started with |
| `401 unauthorized` from curl | Missing or wrong `Authorization: Bearer ...` header; repeated failures are throttled per IP |
| Fleet shows 0 agents | Start `-mode agent` (it heartbeats every 30 s; remote servers need HTTPS) |
| Run `kavachctl doctor` | It checks URL, token, `/livez`, `/readyz`, auth and TLS and exits non-zero on failure |

---

## What you did not enable

Kavach will **not**:

- Kill processes  
- Isolate hosts  
- Quarantine files  
- Drop packets (Netra may, under its own lease model — Kavach only mirrors observe APIs)

Containment and RTR execute paths are ledgers / allowlists for investigation, not enforcement.

---

## Next reading

- [Architecture](architecture.md)
- [Use cases](use-cases.md)
- [Testing](testing.md)
- [Console](console.md)
- [kavachctl](kavachctl.md)
- [eBPF](ebpf.md)
- [Finance](finance.md)
- [Sectors](sectors.md)
- [MCP](mcp-integration.md)
- [Observability](observability.md), [Exposure](exposure.md), [Cloud audit](cloud-audit.md), [SIEM export](siem-export.md)
- [Persistence files](persistence-files.md), [Deploy remote](deploy-remote.md)
