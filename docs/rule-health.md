# Detection rule health and lifecycle

Kavach is observation-only. Rule health and lifecycle never block, kill or change anything on a host; they help you see which rules earn their keep and which ones to tune or retire.

## Research notes

Short notes from a brief look at detection-engineering practice, restated in my own words. Most sources are vendor or editorial pieces, not standards, and one statistic is cited secondhand, so treat them as practice, not proof.

- **Lifecycle.** A rule should move through intake, review, test, activation, monitoring and retirement; imported content stays disabled until someone has reviewed it and named an owner. Kavach models this as `draft`, `testing`, `production`, `retired`. ([NHIMG: should detections be treated like software](https://nhimg.org/faq/should-organisations-treat-detections-like-software-or-like-static-rules/), [NHIMG: detection content drift](https://nhimg.org/faq/what-should-soc-leaders-do-when-detection-content-keeps-drifting/))
- **Versioning and replay tests.** Version each detection artefact and its dependencies, and replay known-good and known-bad data against changes. Kavach already ships positive/negative samples and a benign baseline per rule; the change history adds a content hash and the changed fields per edit. ([NHIMG: governing detection rule changes](https://nhimg.org/faq/how-should-security-teams-govern-detection-rule-changes-without-creating-alert-f/))
- **Suppression.** Suppressions should be time-limited, scoped to one rule and documented, otherwise noise reduction quietly turns into lost coverage; too broad hides real abuse, too narrow keeps analysts drowning. Kavach's exclusions are in `docs/content-tuning.md`; this feature adds visibility (noisy score, trend) so you can judge them. ([Pebblous: exclusion ratchet](https://blog.pebblous.ai/blog/detection-rule-exclusion-ratchet/en/), a write-up of a SigmaHQ history study whose figures I did not verify)
- **Metrics.** Precision, recall and operational noise make tuning evidence-based; also alert fidelity and suppression rate. Kavach has no analyst verdicts per finding here, so it cannot compute precision; it reports volume-based noise only. ([Decryption Digest: maturity model](https://www.decryptiondigest.com/blog/detection-engineering-maturity-model))
- **Silent rules.** KPIs usually chase noisy rules, while rules that never fire (for example after a log format change) go unnoticed. Hence the explicit `silent` flag. ([Hunters: detection engineering checklist](https://www.hunters.security/hubfs/2025%20Research%20Paper/Detection%20Engineering%20Checklist%20for%20SOC%20Teams%20%20(3).pdf?hsLang=en))

## Health metrics

`GET /v1/rules/health` (`kavachctl rules health`) computes, on demand, per rule from the findings the store holds:

| Field | Meaning |
|-------|---------|
| `hits_24h`, `hits_7d`, `hits_30d`, `hits_total` | Finding counts in the window (relative to now) and in the whole retained store |
| `distinct_hosts_30d` | Distinct hosts with a hit in 30 days |
| `last_fired` | Newest finding time |
| `trend` | Last 7 days vs the 7 days before: `up` (>25% more), `down` (>25% fewer), `flat`, `new` (none before), `none` |
| `share_of_findings_30d` | Rule hits / all findings in 30 days |
| `noisy_score` | 0-100 = 50% volume (hits per day over 7d, saturating at 100/day) + 30% share (saturating at 50%) + 20% repetition (30d hits per host, saturating at 100). `noisy` is true at 60 or above |
| `silent` | Rule is in the content registry (embedded or custom) but has no finding and no shadow finding in the store |
| `shadow_hits` | Hits recorded while the rule was in `testing` |
| `source` | `custom`, `embedded`, or `builtin` (a rule seen in findings that is not in the content registry) |

Lists are ordered by lifecycle state (production, testing, draft, retired) then noisy score. Filters: `state`, `source`, `silent=1`, `noisy=1`, `limit`.

## Lifecycle

`GET/PUT /v1/rules/lifecycle/{id}`. A rule with no record is `production`. States:

- `production`, `draft`, `retired`: reporting and ordering only. A draft or retired rule still evaluates and still produces findings; use the content tooling to remove a custom rule.
- `testing`: the rule still evaluates, but its hits are stored as shadow findings in `<store>.rulelifecycle.json` (newest 500 kept) and are not appended to the main findings list, SIEM export or any list built from it. Health shows them as `shadow_hits`. This is the only behavioural effect and it is still observation-only.

Setting a state needs admin token or session, requires a known rule (registry, existing record, or one that has produced findings), and is written to the history.

## History

`GET /v1/rules/history/{id}` returns the entries for a rule and `chain_ok`. Entries are hash-chained like the analyst journal (sha256 over sequence, time, actor, rule, action, detail and the previous hash), across all rules in one chain. Recorded actions: `custom-rule.created|updated|deleted` (content hash, changed fields) and `lifecycle` (old to new state, note). Actor is `admin-token` or `session`.

## Limits

- Counts come from the retained store (default 1000 findings), so 30-day numbers are only as deep as retention; `silent` means "no hit in retained findings", not "never fired ever".
- Findings counted in the main list exclude `testing` hits; the ingest endpoints' returned counts still include them.
- No analyst verdicts, so no precision or recall; the noisy score is a volume heuristic, and its weights are a judgement call.
- Embedded rule edits arrive with new releases, so only custom rule edits and lifecycle changes are journaled.
- History is capped at 5000 entries; after trimming, the oldest retained entry is the chain anchor.
- Tamper evidence only: a writer of the file can rewrite the whole chain.
- Over MCP only the read tools are exposed; setting lifecycle is `PUT` or `kavachctl rules lifecycle ID --set STATE`.

## CLI and MCP

```
kavachctl rules health [ID] [--state S] [--source custom|embedded|builtin] [--silent] [--noisy] [--limit N] [--json]
kavachctl rules lifecycle ID [--set draft|testing|production|retired] [--note TEXT]
kavachctl rules history ID [--json]
```

MCP tools (read-only): `rules_health`, `rules_health_get`, `rules_lifecycle_get`, `rules_history`.
