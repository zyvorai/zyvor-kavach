# Kavach Roadmap

All work stays **observation-only**: detect, report, score, correlate, export. Nothing contains, kills, isolates, freezes money, immobilises assets, or commands systems.

Last updated: 2026-11-27.

## Status legend
- **Planned** — design + acceptance criteria ready; implementation not started
- **Partial** — some scaffolding or related capability already exists
- **Done** — shipped and documented

---

## 1. Multi-user auth / RBAC (or OIDC)

**Status:** Partial (advisory roles exist)

**Current state**
- Single shared `KAVACH_TOKEN` (or session cookie derived from it).
- `KAVACH_RBAC=1` + `X-Kavach-Role` / `KAVACH_ROLE` gives advisory restrictions (`internal/edr/authz.go`). Roles: admin, analyst, viewer, mssp. Not a hard authorisation boundary.
- Console login is username `admin` + token as password.

**Goal**
Proper multi-user identity so multiple analysts can work without sharing the admin token. Required for real Enterprise deployments.

**Acceptance criteria**
- [ ] User store (file-backed first, Postgres later) with hashed passwords or OIDC.
- [ ] Roles enforced as a real boundary (not advisory) when `KAVACH_RBAC=1`.
- [ ] Console login accepts real users; session cookie carries user id + role.
- [ ] Audit journal records actor (user id) on every mutating action (cases, exceptions, content, retention, etc.).
- [ ] Backward compatible: empty user store or missing `KAVACH_RBAC` falls back to current single-token behaviour.
- [ ] Optional OIDC (Dex or any OIDC provider) for SSO; offline-capable when IdP is unreachable.
- [ ] Docs: `docs/auth.md`, update `docs/security-review.md` and `docs/architecture.md`.

**Next steps**
1. Add `users.json` (or similar) persistence next to other state files.
2. Extend `requireAuth` / `requireRole` to check the real user store when enabled.
3. Console login form gains a username field that is not hard-coded to `admin`.

---

## 2. External state store option (Postgres)

**Status:** Planned

**Current state**
- Single-replica, file-backed (`-state` JSONL + dozens of `*.json` sidecars). See `docs/persistence-files.md`.
- Multi-replica explicitly unsupported.

**Goal**
Optional Postgres (or SQLite in WAL mode) backend so the controller can run multi-replica / HA. File backend remains the default for air-gapped and simple labs.

**Acceptance criteria**
- [ ] `KAVACH_STORE=file|postgres` (default `file`).
- [ ] All current state files have a Postgres equivalent (findings, incidents, cases, content versions, exposure, etc.).
- [ ] Schema migrations are versioned and automatic on start.
- [ ] Helm chart gains optional Postgres values (external or bundled).
- [ ] No behaviour change when `KAVACH_STORE=file`.
- [ ] Docs: `docs/ha.md`, update architecture and deploy docs.

**Next steps**
1. Introduce a `Store` interface that the current file implementation satisfies.
2. Add a Postgres implementation behind the same interface.
3. Prove one domain (findings) end-to-end, then expand.

---

## 3. Deeper Netra XDR correlation

**Status:** Partial (poller + some join already exist)

**Current state**
- Netra poller (`KAVACH_NETRA_POLLER_ENABLED`, etc.) and `/v1/ebpf/netra/*` mirrors.
- Network events can be joined by host + PID.
- Architecture doc already calls Netra the sister product.

**Goal**
First-class XDR: Netra findings, flows, drops and process attribution appear natively in the Kavach console, hunts, attack paths and AI assist.

**Acceptance criteria**
- [ ] Console “XDR” or “Netra” pane that shows correlated host + network timeline.
- [ ] Hunt queries can reference Netra fields without manual export.
- [ ] Attack-path scoring includes Netra-derived edges.
- [ ] MCP tools for Netra correlation.
- [ ] Still observation-only: Kavach never writes Netra BPF maps or issues drops.
- [ ] Docs: expand `docs/architecture.md` and add `docs/xdr.md`.

**Next steps**
1. Inventory every Netra field already ingested.
2. Add a unified “storyline” view that merges Kavach findings + Netra events by host/PID/time.
3. Surface it in the console and `kavachctl`.

---

## 4. GuestKit / offline VM inspection integration

**Status:** Planned

**Current state**
- Exposure scoring already accepts SBOMs (CycloneDX / SPDX).
- Parse-only artifact analyzers exist.
- GuestKit (sister project) can inspect QCOW2/VMDK/etc. offline and emit reports.

**Goal**
Ingest GuestKit reports (or raw disk metadata) so Kavach can score VM exposure, users, packages, SSH keys, services and persistence without ever booting the guest or installing an agent.

**Acceptance criteria**
- [ ] `POST /v1/guestkit/report` (admin) accepts a GuestKit JSON/PDF/HTML report or a structured summary.
- [ ] Findings and exposure scores are generated from the imported data.
- [ ] Console shows “offline VM” assets alongside live agents.
- [ ] Works fully air-gapped.
- [ ] Docs: `docs/guestkit.md`.

**Next steps**
1. Define a minimal GuestKit report schema (or reuse whatever GuestKit already emits).
2. Map it onto the existing exposure + inventory models.
3. Add the ingest route + `kavachctl guestkit` subcommand.

---

## 5. Richer Kubernetes / Cilium / KubeVirt observation

**Status:** Partial (some container/K8s rules already exist)

**Current state**
- Unix content pack includes container and Kubernetes depth.
- Agent can run as a DaemonSet.
- eBPF CO-RE programs exist for process, file, net, priv.

**Goal**
Deeper, still observation-only coverage of pods, network policies, Cilium flows, KubeVirt VMs and node-level activity.

**Acceptance criteria**
- [ ] Additional eBPF or log-based detectors for pod-to-pod, policy denials (observe only), and KubeVirt VM lifecycle.
- [ ] Optional Cilium Hubble export ingestion (offline, operator-supplied).
- [ ] Console fleet view distinguishes nodes, pods and VMs.
- [ ] Docs: `docs/kubernetes.md`.

**Next steps**
1. Inventory existing `ux2-*` and container rules.
2. Add a small set of high-value new rules + tests in the content harness.
3. Document how to point the agent at Cilium Hubble or KubeVirt logs.

---

## 6. India-specific / finance deepening

**Status:** Partial (finance packs already exist)

**Current state**
- Dedicated finance rule sets for banks, UPI, insurance, IRDAI (`docs/finance.md`).
- Explicitly never freezes money.

**Goal**
Richer observation rules and reports tailored to Indian banking, UPI, GST-adjacent systems, RBI guidelines and public-sector fleets.

**Acceptance criteria**
- [ ] Additional `fin-in-*` rules covering common UPI, IMPS, NEFT/RTGS and banking application patterns (from logs the operator supplies).
- [ ] Optional RBI / IRDAI control-evidence mapping (informational only).
- [ ] Console finance summary gains an “India” filter.
- [ ] All new rules have positive/negative examples in the content harness.
- [ ] Docs: expand `docs/finance.md`.

**Next steps**
1. Review existing finance rules.
2. Add a new content pack with 10–15 high-signal, offline rules.
3. Wire them into the existing finance summary endpoints.

---

## 7. Console AI assist improvements + better hunt/query power

**Status:** Partial (AI Hub + kavach-seq already exist)

**Current state**
- AI Hub with heuristic scores and optional external LLM (`KAVACH_LLM_URL`).
- `kavach-seq` (EQL-inspired) sequence queries.
- Command palette, saved searches, hunt packs.

**Goal**
Make the quiet console more useful for analysts: better AI briefs, richer (still bounded) hunt language, and clearer “what should I look at next” guidance.

**Acceptance criteria**
- [ ] AI briefs include correlated Netra + GuestKit + exposure context when available.
- [ ] Hunt language gains safe, bounded aggregations or simple joins (still time/scan budgeted).
- [ ] Console AI pane suggests next queries or related findings.
- [ ] Still fails soft when no LLM is configured.
- [ ] Docs: update `docs/console.md` and AI sections.

**Next steps**
1. Inventory current AI routes and `kavach-seq` grammar.
2. Add one high-value improvement (e.g. multi-finding brief or better sequence operators).
3. Surface it in the console.

---

## Cross-cutting principles (apply to every item above)

- Observation only. Containment, RTR, prevention and any “do something on the host” APIs remain request ledgers.
- Offline-first. Prefer operator-supplied logs, SBOMs, reports and exports over live API calls.
- Air-gap capable. Every new feature must work with no outbound network.
- Detection-as-code. New rules ship with positive and negative examples and are covered by `kavachctl content selftest`.
- Honest limits. Document what is synthetic, unverified or fixture-only.
- Backward compatible. New flags default to current behaviour.

## How to contribute

1. Pick an item above.
2. Open a short design note (or expand the relevant section here).
3. Implement behind a feature flag or new route so the default path is unchanged.
4. Add tests + docs + a CHANGELOG entry under Unreleased.
5. Keep the observation-only invariant.

Related docs: [architecture.md](architecture.md), [security-review.md](security-review.md), [persistence-files.md](persistence-files.md), [content-testing.md](content-testing.md).
