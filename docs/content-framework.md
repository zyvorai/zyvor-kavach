# Detection content framework

Kavach ships detection content as JSON rule packs under `internal/edr/content/*.json`. They are embedded in the binary (`go:embed`), validated at load, and evaluated on the live ingest path. Observation only: a match raises a Finding, it never contains, kills or blocks.

## Pack format

```json
{ "pack": "seed", "rules": [ { ...rule... } ] }
```

Unknown fields are rejected. Any number of `*.json` files may be added; ids must be unique across all of them.

## Rule schema

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Unique kebab-case (`a-z0-9`, single dashes, max 64). Must not collide with a built-in rule id. This becomes `Finding.Rule`. |
| `name` | yes | Max 120 chars. |
| `description` | yes | Max 1000 chars. |
| `tactic` | yes | ATT&CK Enterprise tactic name exactly as in the matrix, e.g. `Persistence`, `Command and Control`. |
| `technique` | yes | ATT&CK id, `T1059` or `T1059.004`. |
| `technique_name` | no | Display name for the matrix and detections; falls back to the id. |
| `severity` | yes | `low`, `medium`, `high`, `critical`. |
| `os` | yes | `linux`, `macos`, `windows`, `any`. Metadata and filter only (events carry no OS field). |
| `event_type` | yes | `process`, `network`, `file` are evaluated live. `registry`, `dns`, `auth`, `module` are accepted and flagged `pending_telemetry`: they load, appear in the API and coverage, but never fire and are not counted in the ATT&CK matrix until a sensor emits them. |
| `match` | yes | Match tree, below. |
| `tags` | no | Up to 16, each up to 32 chars. |
| `batch` | no | Authoring batch label, e.g. `seed-v1`; used for filtering and coverage. |
| `tests` | yes | `{ "positive": [events], "negative": [events] }`, at least one each. |

### Match tree

Exactly one of a leaf, `all`, `any` or `not` per node (max depth 6, 50 nodes).

```json
{ "all": [
  { "field": "executable", "op": "suffix", "pattern": "/osascript" },
  { "field": "command", "op": "contains", "patterns": ["hidden answer", "password"] },
  { "not": { "field": "parent_exe", "op": "equals", "pattern": "/usr/bin/trusted" } }
] }
```

* `field`: `executable`, `command`, `parent_exe`, `host`, `uid`, `path`, `destination`, `operation`. Process events carry executable/parent_exe/command/uid/host, file events path/operation, network events destination. For pending types use `path` (registry key, module path), `destination` (dns name) or `command` (auth detail).
* `op`: `equals`, `contains`, `prefix`, `suffix`, `regex`, `in`.
* `pattern` is one string. `patterns` is a list: for `in` it is the set of allowed values; for other ops it is an any-of shorthand.
* Matching is case-insensitive unless `"case_sensitive": true`. Regexes are Go RE2 (linear time), max 256 chars, precompiled at load.

The matcher is the detection lab's (`LabNode` in `detection_lab.go`), so a content rule behaves identically in the lab and in production. `prefix`/`suffix` map to the lab's `startswith`/`endswith`.

### Sample events

Samples use the lab event shape (`executable`, `parent_exe`, `command`, `path`, `destination`, `operation`, `host`, `uid`). The harness fills the event kind from `event_type`.

## Adding a rule

1. Append a rule to an existing pack, or create `internal/edr/content/<name>.json`.
2. Write at least one realistic positive and one near-miss negative sample.
3. Run `go test ./internal/edr/ -run Content`. Failure messages name the rule id.
4. If the rule trips the benign baseline, tighten the pattern. Add everyday events to `benignBaseline` in `content_framework_test.go` when you spot a gap.

## How the harness gates

`TestContentHarness` (in `content_framework_test.go`) loads every embedded rule and, per rule id, checks:

* unique id, kebab-case id, valid ATT&CK id format, tactic/severity/os/event_type enums
* the match tree validates and every regex compiles
* every positive sample matches, every negative sample does not
* no rule matches any event in the built-in benign baseline (ls, cat, bash -c 'echo hi', systemd, curl https://example.com, ssh-agent, go build, python3 script.py, apt update, and more), tried under every event kind
* `pending_telemetry` is consistent with `event_type`

`TestContentValidationRejects` proves the loader refuses each class of bad rule, and `TestContentEvaluationScales` bounds per-event cost for a 300-rule set. CI runs these with the rest of `./internal/edr/...`, so a bad pack cannot merge.

At runtime an invalid rule is skipped (the others stay active); the gate above keeps that from shipping.

## Runtime behavior

* `LoadContentPacks()` is called by `RegisterContentFramework` (one line in `falcon_platform.go`). Until packs are loaded, evaluation is a no-op.
* Hook points: `Detect` (process events, `edr.go`), `Store.IngestNetwork` and `Store.IngestFile` (`ingest.go`). Each match creates a `Finding` with `Rule` = rule id, the rule severity, description `name: description`, and tags `content`, the technique id, rule tags and `batch:<batch>`.
* Cost bound: only live rules for the event's type are evaluated, regexes are precompiled, inputs are truncated to 4096 bytes, and one event raises at most 10 content findings.
* `MapDetection` and the incident/case technique lookup fall back to content rules (`mitreFor`), and `/v1/attack/matrix` includes live content rules in coverage.

## API (all require auth, read-only)

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/content/rules` | List rules without samples. Filters: `tactic`, `os` (also returns `any`), `batch`, `technique` (`T1059` matches `T1059.004`), `q` (id/name/description/tags substring). |
| `GET /v1/content/rules/{id}` | One rule with match tree and samples. |
| `GET /v1/content/coverage` | Counts by tactic, technique, os, batch, severity, event type; `techniques_covered`; `pending_telemetry` rule ids. |
