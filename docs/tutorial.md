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

All packages should pass. If something fails, see [testing.md](testing.md).

---

## 2. Run the controller locally

```bash
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
```

Health check:

```bash
curl -s http://127.0.0.1:8099/healthz
# → ok
```

Open the console: http://127.0.0.1:8099/

- **Username:** `admin`
- **Password:** `Admin@321` (must match `KAVACH_TOKEN`)

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

## 11. Deploy to the lab cluster (optional)

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

Browser: same URL — accept the self-signed cert, sign in as `admin` / `Admin@321`.

Full steps: [deploy-remote.md](deploy-remote.md), [envoy-gateway.md](envoy-gateway.md).

---

## 12. Lab demo script

With a running server:

```bash
export KAVACH_URL=http://127.0.0.1:8099
export KAVACH_TOKEN=Admin@321
./scripts/demo-lab.sh
```

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
