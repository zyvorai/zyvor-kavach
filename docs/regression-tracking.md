# Continuous control validation (regression tracking)

Kavach re-runs its own validation-lab scenarios on a schedule and tells you when detection coverage
regresses, in the spirit of breach-and-attack-simulation re-runs and detection-as-code CI. Observation
only: it replays synthetic events in memory and never executes anything, never touches the host and never
writes to the live store except one informational finding (below). State: `<store>.regression.json`.

## What a run does

* Replays the whole embedded scenario set (`docs/research-validation-lab.md`) against the embedded
  content only (customer rules are excluded), with a bounded runtime (`max_runtime_sec`, default 60,
  range 5..300). If the bound is hit the snapshot is marked `truncated`, diffs are marked `incomplete`
  and no finding is raised from it.
* Records a result snapshot: content snapshot hash, per-scenario outcome, per-technique outcome,
  per-tactic measured coverage, benign false positives, rules that fired per scenario/technique, runtime.
  History is capped at 90 snapshots.
* Triggers: daily at `time` (HH:MM UTC, default 03:00), on demand (`POST /v1/regression/run`), and once at
  startup when the content hash differs from the last snapshot (or there is no snapshot). One bounded
  goroutine, no overlapping runs (a second run gets 409), stopped by `StopRegression()`.

## Regression diff

`GET /v1/regression/diff` (default previous vs latest) lists scenarios and techniques that moved
Detected to Partial/Missed or Partial to Missed (regressions) and the reverse (improvements), added and
removed scenarios, new and resolved benign false positives, per-tactic coverage deltas, and the embedded
rules added/removed/modified between the two snapshots (from the content-version hashes).

Each regression carries `likely_cause`, a HINT: the rules that fired for that scenario or technique in the
earlier snapshot are matched against the content diff (removed, or modified with severity and
match-affecting field names), against scenario definition changes, and against rule-health lifecycle
changes (e.g. retired, testing) recorded between the two snapshot times. Example:
`rule x modified (severity high -> medium; match changed)`. When nothing matches it says so (no content
change: consider engine code or environment; content changed but not in a rule that fired before).

## Alerting inside Kavach

When a run shows at least `alert_min_regressions` regressions (default 1) or a new benign false positive
(`alert_on_benign_fp`, default true) a finding `regression-detected` is recorded through the normal
finding path: severity low, or medium for a new false positive or at least `alert_medium_at` (default 3)
regressions; the diff summary is in `evidence.command` as JSON. Because it is a normal finding, existing
alert rules deliver it: create an alert rule with `rule_contains: "regression-detected"`. No new outbound
channel is added.

## Endpoints

All reads need auth (`requireAuth`); run-now and config writes need admin token or a session.

* `GET /v1/regression/status`: config, next run, running flag, latest snapshot, latest diff counts.
* `GET /v1/regression/history?limit=` (max 90, newest first).
* `GET /v1/regression/diff?from=&to=` (seq numbers, `previous`, `latest`; 404 when fewer than two snapshots).
* `GET /v1/regression/trend?window=` (`7d`, `30d` default, or a Go duration): measured coverage per tactic.
* `POST /v1/regression/run`: run now; returns the snapshot summary and diff.
* `GET|PUT /v1/regression/config`: `enabled`, `time`, `max_runtime_sec`, `alert_min_regressions`,
  `alert_medium_at`, `alert_on_benign_fp`.
* `GET /v1/regression/gate?min_detected=&max_regressions=&max_false_positives=`: evaluates the latest
  snapshot. `min_detected` is a percent (0..100) of claimed techniques measured Detected;
  `max_regressions` counts regressions in the latest diff; `max_false_positives` counts benign controls
  that fired. HTTP 200 and `pass: true`, or 412 and `pass: false` with per-check detail. No snapshot yet
  fails closed (412). Bad parameters give 400. The gate reads recorded results; it does not run anything.

## Honest limits

* The scenarios are Kavach's own synthetic events, mostly one variant per technique. A regression means
  that variant is no longer detected, not that the technique is; an improvement likewise.
* Synthetic replay is not a guarantee against real attacks, and passing the gate is not proof of coverage.
* Only embedded content is replayed. Custom rules, scheduled detections, ML models and live environment
  effects are not measured, so changes to them never show as regressions here.
* Built-in (Go) rule changes do not appear in the content diff; they surface as "no content change" causes.
* Cause attribution is a join on rule ids; indirect effects (a rule that suppresses or replaces another)
  are not modelled. The retained per-rule content detail is limited to the last 20 distinct content
  versions; older diffs say the detail is no longer retained. Severity before/after is known only for
  detection-pack rules.
* Lifecycle changes are listed for the time window between snapshots, not proven to affect the replay.
* The first run has nothing to compare with; trend and gate need at least one, diff at least two snapshots.
