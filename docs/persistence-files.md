# On-disk state files

All files sit next to the findings store path (`<store>` below), are written atomically (temp file + rename) with mode 0600, and a missing or corrupt file is logged or ignored and treated as empty at startup.

| File | Holds |
|------|-------|
| `<store>.intel.json` | Threat-intel feed definitions, last-sync status, ETags, indicator expiries and the feed-sourced indicators (older files with a bare feed array still load) |
| `<store>.tuning.json` | Tuning history (applied and reverted exclusions are re-derived from it at startup) and digest definitions with schedule state |
| `<store>.alerts.json` | Alert rules (deliveries are in-memory and de-duplicated per finding) |
| `<store>.certfeeds.json` | Cache of the opt-in worldwide CERT advisory feeds (`KAVACH_CERT_FEEDS`): up to 300 normalised advisories and the last fetch time per feed. Served from cache; a feed that fails keeps its previous items. See `docs/cert-feeds.md` |
| `<store>.epss.json` | Cache of the opt-in FIRST EPSS feed (`KAVACH_EPSS_FEED=on`, default off): EPSS score and percentile only for CVEs matched on this install at the last refresh plus KEV CVEs (max 50,000), the model version, score date and fetch time. Served from cache; a failed refresh keeps the previous cache. See `docs/vuln-priority.md` |
| `<store>.workspace.json` | Saved searches, notes and the hash-chained analyst journal (alert-rule changes are journaled here) |
| `<store>.regulatory.json` | Regulatory profile: the regime ids the operator selected as applicable (`PUT /v1/regulatory/profile`), with update time and actor. Ids are validated against the embedded catalog on write; see `docs/regional-reporting.md` |
| `<store>.deception.json` | Deception canaries and trips |
| `<store>.customcontent.json` | Customer-authored detection content rules (full rule JSON including samples; see `docs/custom-content.md`). Every rule is re-validated at startup; rules that no longer pass are skipped |
| `<store>.rulelifecycle.json` | Rule lifecycle states (draft/testing/production/retired), the hash-chained rule change history (custom rule edits and lifecycle changes; capped at 5000 entries) and up to 500 shadow findings from rules in `testing`. Lifecycle only affects reporting and ordering, plus the shadow recording; see `docs/rule-health.md` |
| `<store>.mlbehaviour.json` | Fleet-learned local behaviour models (`docs/local-models.md`): process-lineage transition counts (basenames only, per host and fleet, capped at 64 hosts / 1,000 and 5,000 edges), per-host reservoirs of up to 128 hashed 3-5-gram command vectors (64 non-zero features each, 32 hosts; never raw command lines), per-host hour-of-week EWMA baselines with a bounded hashed destination set, and the ingest tail cursor. Typically under 5 MB. Reset with `POST /v1/ml/reset` or delete the file while stopped; rebuild with `POST /v1/ml/learn/replay` |
| `<store>.feedback.json` | Analyst feedback loop (`docs/research-feedback.md`): append-only, hash-chained verdicts (true_positive, false_positive, benign_expected, needs_more_data) with actor, time, finding id, rule and host; capped at 100,000 entries (oldest dropped). A retraction is a new verdict, never a rewrite. Per-rule precision is derived on read; nothing is auto-applied. Verify with `GET /v1/feedback/verify`. Delete only while stopped |
| `<store>.beacon_allowlist.json` | Optional, read-only: extra destinations the beacon detector (`GET /v1/ml/beacons`, `docs/local-models-net.md`) should ignore, on top of the built-in NTP, OS-update, CDN and OCSP list. Kavach never writes it; create it by hand to tune beacon noise |
| `<store>.reportschedules.json` | Scheduled report definitions (template, params, frequency, retention, format, next/last run; max 100). Rendered reports live in the directory `<store>.reports/` as `<run_id>.md|json|csv` plus `<run_id>.meta.json` (template, params, generated_at, bytes, sha256, status), capped per schedule by retention, and globally at 500 reports / 64 MB. Pull-only via `GET /v1/reports/archive/{run_id}`; Kavach never emails or pushes reports. Deleting a schedule deletes its reports |
| `<store>.fleetslo.json` | Fleet SLO targets and the bounded series (5-minute samples, max 72 h, 500 agents: heartbeat freshness flag and event count per sample), persisted at most every 10 minutes. Derived only from data agents already send |
| credential registry file | Agent enrollment and last heartbeat; fleet health is derived from it, so stale detection survives restarts |

Backup: copy these files while the server is stopped, or at any time (writes are atomic renames).
