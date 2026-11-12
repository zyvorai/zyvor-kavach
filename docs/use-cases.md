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

**APIs:** `/v1/findings`, `/v1/detections`, `/v1/incidents`, `/v1/ai/briefing`, `/v1/siem/export`

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
kavachctl finance events --type market_data_lag
```

Hard rule: never freeze accounts, block orders, pause algos, or rewrite SWIFT/UPI. See [finance.md](finance.md).

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
kavachctl sectors critical-sites
kavachctl sectors events --sector aviation
```

Hard rule: never stop trains, cancel flights, control ATC, trip breakers, take portals offline, touch EVMs, or weapons/C2. See [sectors.md](sectors.md).

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
./scripts/deploy-remote.sh user@lab --k8s --envoy-gateway
./scripts/demo-lab.sh
go test ./...
```

Follow [tutorial.md](tutorial.md) and [testing.md](testing.md).

---

## Anti-use-cases (out of scope)

| Request | Kavach answer |
|---------|----------------|
| Freeze a bank account / block a trade | No — finance observe only |
| Stop a train / cancel a flight / control ATC / trip a breaker | No — sectors observe only |
| Touch weapons, C2, or EVMs | No — sectors observe only |
| Auto-isolate a host | No — ledger only |
| Kill a PID from console | No |
| Quarantine a binary | No |
| Drop a 5-tuple in-kernel | Use Netra (leased) — not Kavach |
| Silent prevention | Detect-only policies |

If you need enforcement, use Netra’s leased datapath controls or an external SOAR that reads Kavach exports — never claim Kavach did the enforce.
