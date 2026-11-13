# On-disk state files

All files sit next to the findings store path (`<store>` below), are written atomically (temp file + rename) with mode 0600, and a missing or corrupt file is logged or ignored and treated as empty at startup.

| File | Holds |
|------|-------|
| `<store>.intel.json` | Threat-intel feed definitions, last-sync status, ETags, indicator expiries and the feed-sourced indicators (older files with a bare feed array still load) |
| `<store>.tuning.json` | Tuning history (applied and reverted exclusions are re-derived from it at startup) and digest definitions with schedule state |
| `<store>.alerts.json` | Alert rules (deliveries are in-memory and de-duplicated per finding) |
| `<store>.workspace.json` | Saved searches, notes and the hash-chained analyst journal (alert-rule changes are journaled here) |
| `<store>.regulatory.json` | Regulatory profile: the regime ids the operator selected as applicable (`PUT /v1/regulatory/profile`), with update time and actor. Ids are validated against the embedded catalog on write; see `docs/regional-reporting.md` |
| `<store>.deception.json` | Deception canaries and trips |
| `<store>.customcontent.json` | Customer-authored detection content rules (full rule JSON including samples; see `docs/custom-content.md`). Every rule is re-validated at startup; rules that no longer pass are skipped |
| `<store>.rulelifecycle.json` | Rule lifecycle states (draft/testing/production/retired), the hash-chained rule change history (custom rule edits and lifecycle changes; capped at 5000 entries) and up to 500 shadow findings from rules in `testing`. Lifecycle only affects reporting and ordering, plus the shadow recording; see `docs/rule-health.md` |
| credential registry file | Agent enrollment and last heartbeat; fleet health is derived from it, so stale detection survives restarts |

Backup: copy these files while the server is stopped, or at any time (writes are atomic renames).
