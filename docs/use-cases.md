# Use cases

Practical ways teams use Kavach. Every scenario stays inside the observation-only contract.

---

## 1. SOC triage desk

**Goal:** Prioritize what’s noisy vs urgent without touching hosts.

1. Open Overview — metric band shows findings, fleet online, high severity, OverWatch, CVEs.  
2. **Detect** / **Detections** — filter by severity; open a finding drawer.  
3. `kavachctl ai briefing` or console **AI Hub → Daily briefing**.  
4. Transition incident state in **Incidents** (workflow ledger).  
5. Export for the SIEM: `kavachctl siem export` or Integrations download.

**APIs:** `/v1/findings`, `/v1/detections`, `/v1/incidents`, `/v1/ai/briefing`, `/v1/export/findings`, `/v1/siem/export`

Handy extras: `kavachctl watch --severity high` (live tail with auto-reconnect), `kavachctl soc metrics --days 30`
(MTTA/MTTR, backlog age, noisy rules), `kavachctl soc shift-report --hours 12 --out shift.txt` and
`kavachctl feedback record --finding ID --verdict false_positive` to feed per-rule precision (nothing is auto-applied).
Limits: SOC metrics need the incident ledger to contain transitions, so a new install reports `null` MTTA/MTTR.

---

## 2. Threat hunting

**Goal:** Answer “who ran what, where, with which network friends?”

```bash
kavachctl hunt query 'severity:high host:web'
kavachctl hunt kql 'DeviceProcessEvents | where ...'   # if KQL path enabled
kavachctl ai nl-hunt 'processes that look like living-off-the-land on prod'
kavachctl storyline --host web-01
kavachctl threat-graph
kavachctl timeline
```

Console: **Hunt**, **Timeline**, **World → storyline**.

---

## 3. Fleet & sensor hygiene

**Goal:** Know which nodes are reporting and how.

```bash
kavachctl fleet
kavachctl agents
kavachctl sensor
kavachctl sensor-health
kavachctl ebpf coverage
kavachctl ebpf health
```

Enroll from **Fleet** (console) or agent with bearer token. Revoke when decommissioning.

---

## 4. Vulnerability & asset posture

**Goal:** Spotlight-style CVE and Discover-style inventory views.

```bash
kavachctl discover assets
kavachctl discover apps
kavachctl spotlight --severity critical
kavachctl exposure
kavachctl compliance
kavachctl zero-trust
```

Agent collectors refresh FIM / SBOM / persistence / firewall / browser inventories.

---

## 5. Identity & UEBA

**Goal:** Surface spray / anomalous identity without AD write access.

```bash
kavachctl identity events
kavachctl identity entities
kavachctl ueba
kavachctl itdr
```

Console: **Identity**.

---

## 6. XDR with Netra

**Goal:** Join host process findings with network drops/flows.

1. Enable poller: `KAVACH_NETRA_POLLER_ENABLED=true`, `KAVACH_NETRA_URL=…`, API key.  
2. Or pipe events: `netra-bridge` → Kavach.  
3. Inspect:

```bash
kavachctl ebpf netra status
kavachctl ebpf netra drops
kavachctl get /v1/recent-events
```

Kavach **never** writes Netra BPF maps or flips Netra to enforce.

---

## 7. eBPF host telemetry

**Goal:** Falco/Tracee-class signals on Linux nodes.

```bash
./scripts/build-bpf.sh
# pin programs (see ebpf.md)
kavachctl ebpf events --type exec
kavachctl ebpf events --type memfd
kavachctl ebpf events --type priv
```

Agents can `POST /v1/ebpf/events` with decoded ringbuf batches + `lost` counts.

---

## 8. Bank / FI / stock-market observe

**Goal:** Surface market-desk, UPI, fraud, and regulatory posture without touching money rails.

```bash
kavachctl finance summary
kavachctl finance exchanges
kavachctl finance trading-desks
kavachctl finance upi
kavachctl finance cards
kavachctl finance fraud
kavachctl finance insider
kavachctl finance sebi
kavachctl finance rbi
kavachctl finance insurance
kavachctl finance irdai
kavachctl finance motor-insurance
kavachctl finance events --type claims_burst
```

Hard rule: never freeze accounts, block orders, pause algos, cancel policies, or rewrite SWIFT/UPI. See [finance.md](finance.md).

---

## 9. Railways / government / critical infra observe

**Goal:** Cover public-sector and critical infrastructure IT without touching OT control or citizen service availability.

```bash
kavachctl sectors summary
kavachctl sectors railways
kavachctl sectors stations
kavachctl sectors gov-portals
kavachctl sectors tax
kavachctl sectors power
kavachctl sectors scada
kavachctl sectors airports
kavachctl sectors flights
kavachctl sectors airlines
kavachctl sectors defence
kavachctl sectors border
kavachctl sectors gov-vehicles
kavachctl sectors public-vehicles
kavachctl sectors city-buses
kavachctl sectors taxis-cabs
kavachctl sectors school-buses
kavachctl sectors municipal-fleet
kavachctl sectors ferries
kavachctl sectors automotive
kavachctl sectors manufacturing
kavachctl sectors isro-centers
kavachctl sectors space
kavachctl sectors critical-sites
kavachctl sectors events --sector city-buses
```

Hard rule: never stop trains, cancel flights, control ATC, immobilize vehicles, command spacecraft, write plant OT, trip breakers, take portals offline, touch EVMs, or weapons/C2. See [sectors.md](sectors.md).

---

## 10. AI-assisted IR

**Goal:** Speed up narrative and next steps without autonomous response.

```bash
kavachctl ai narrative --id <finding-id>
kavachctl ai attack-path --id <finding-id>
kavachctl ai remediation --id <finding-id>
kavachctl ai report
kavachctl ai agents
kavachctl air
```

Optional: point `KAVACH_LLM_URL` at your gateway. Guardians and what-if stay advisory.

---

## 11. Compliance evidence pack

**Goal:** Snapshot posture for auditors (read-only).

```bash
kavachctl report
kavachctl audit
kavachctl compliance
kavachctl zero-trust
kavachctl rbac
kavachctl retention
```

Combine with SIEM NDJSON export for long-term retention outside Kavach.

---

## 12. Developer / platform lab

**Goal:** Validate chart + Gateway + console before production eval.

```bash
./scripts/deploy-remote.sh user@lab --k8s --setura-gateway
./scripts/demo-lab.sh
go test ./...
```

Follow [tutorial.md](tutorial.md) and [testing.md](testing.md).

---

## 13. Cloud and SaaS audit-log detection

**Goal:** Catch risky cloud activity (root console login, missing MFA, policy changes) from logs you already export.

```bash
kavachctl cloudaudit sources
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" "$KAVACH_URL/v1/cloud/audit/events?source=aws" \
  --data-binary @cloudtrail.json          # admin token; up to 4 MiB and 1000 records per request
kavachctl findings --rule cld-aws-root-console-login
```

Kavach reads what you send and never calls a cloud API. Findings carry `cld-` rule ids and appear on a synthetic
host such as `cloud:aws`. Coverage is only as good as the logs you export. See [cloud-audit.md](cloud-audit.md).

---

## 14. Software exposure from SBOMs

**Goal:** Which hosts carry a package with a known advisory, without scanning anything.

```bash
curl -s -X PUT -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/exposure/sboms/web-01 --data-binary @sbom.json
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" "$KAVACH_URL/v1/exposure/advisories/import?source=my-feed" \
  --data-binary @osv-or-kev.json
kavachctl exposure report --min_score 50
# with KAVACH_EXPOSURE_PRIORITY=1 set in the SERVER environment:
kavachctl ml priority --host web-01      # adds an `exposure` factor for hosts that have an SBOM
```

Until you import advisories the embedded SAMPLE set (five entries) is used, so an empty report proves nothing.
See [exposure.md](exposure.md), [vuln-feeds.md](vuln-feeds.md) and [lockfile-inspection.md](lockfile-inspection.md).

---

## 15. SIEM and data-lake integration

**Goal:** Feed an existing SIEM without giving Kavach any outbound reach.

```bash
curl -s -D hdr.txt -H "Authorization: Bearer $KAVACH_TOKEN" \
  "$KAVACH_URL/v1/export/findings?format=ocsf&limit=1000" > batch.ndjson
# store X-Kavach-Next-Cursor from hdr.txt, then call again with &cursor=<value>
```

A collector polls on a schedule and keeps the cursor; formats are OCSF, ECS, CEF, LEEF and Splunk HEC. An optional
fire-and-forget push sink (`KAVACH_SIEM_WEBHOOK`, `KAVACH_SIEM_SYSLOG`) exists for low-latency notification. Output was
validated by unit tests only, not by a live SIEM. See [siem-export.md](siem-export.md).

---

## 16. Agentless sources: network gear via syslog

**Goal:** See auth, DNS and flow signals from devices that cannot run an agent.

```bash
export KAVACH_SYSLOG=tls:10.0.0.5:6514 KAVACH_SYSLOG_ALLOW=10.1.0.0/16
export KAVACH_SYSLOG_TLS_CERT=/etc/kavach/syslog.crt KAVACH_SYSLOG_TLS_KEY=/etc/kavach/syslog.key
kavachctl syslog status
kavachctl syslog parse '<38>Nov 16 10:00:01 gw sshd[411]: Failed password for root from 203.0.113.9 port 4242 ssh2'
```

Off by default; plaintext UDP/TCP is spoofable. Events are namespaced `syslog:<name>` so a device can never write into an
enrolled agent's host. See [syslog-listener.md](syslog-listener.md).

---

## 17. Posture trend and executive reporting

**Goal:** Show direction of travel to management and auditors with counts only.

```bash
kavachctl posture-trend --days 30
kavachctl posture-trend diff --from 2026-11-01
kavachctl digest --format md
kavachctl auditor-bundle --out evidence.zip
kavachctl compliance evidence --framework cis --format html --out evidence.html
kavachctl regulatory clocks            # incident-reporting regimes and time remaining (informational; no filing)
```

Snapshots exist only while Kavach runs; gaps mean it was stopped. Scores are evidence counts, not a certification
or legal advice. See [posture-reports.md](posture-reports.md), [compliance-evidence.md](compliance-evidence.md) and
[regional-reporting.md](regional-reporting.md).

---

## 18. Detection engineering and CI gates

**Goal:** Change rules without silently losing coverage.

```bash
kavachctl lab backtest --rule rule.json      # sandbox: never raises alerts
kavachctl validate coverage
kavachctl regression gate --max-regressions 0 --max-false-positives 0 || echo "gate failed"
```

`regression gate` exits non-zero when the server answers HTTP 412, so a pipeline can stop. The corpus is synthetic
(one variant per technique) and the measured percentage is not a guarantee against real attacks. See
[regression-tracking.md](regression-tracking.md), [research-validation-lab.md](research-validation-lab.md) and
[content-framework.md](content-framework.md).

---

## 19. Fleet SLOs and sensor health

**Goal:** Know whether agents keep reporting, not just whether they enrolled.

```bash
kavachctl fleet health
kavachctl fleet gaps          # shadow hosts, agents without data, agents on the polling sensor
kavachctl fleet stale
kavachctl fleet slo
```

Only data agents already send is used (heartbeats, event timestamps); version, CPU and queue depth are reported as
"not reported by agent". See [observability.md](observability.md).

---

## Anti-use-cases (out of scope)

| Request | Kavach answer |
|---------|----------------|
| Freeze a bank account / block a trade / cancel a policy | No — finance observe only |
| Stop a train / cancel a flight / immobilize a vehicle / trip a breaker | No — sectors observe only |
| Command spacecraft / write plant OT / weapons / C2 / EVMs | No — sectors observe only |
| Auto-isolate a host | No — ledger only |
| Kill a PID from console | No |
| Quarantine a binary | No |
| Drop a 5-tuple in-kernel | Use Netra (leased) — not Kavach |
| Silent prevention | Detect-only policies |
| Scan or call out to a cloud tenant, mail server or link | No — only logs and files you send are read; analyzers never fetch |
| Patch a vulnerable package | No — exposure is reported, never remediated |
| Guarantee detection of a real attack | No — rates are measured on synthetic corpora |

If you need enforcement, use Netra’s leased datapath controls or an external SOAR that reads Kavach exports — never claim Kavach did the enforce.
