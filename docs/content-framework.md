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
| `event_type` | yes | `process`, `network`, `file`, `registry`, `dns`, `auth`, `module`: all are evaluated live. Telemetry types (`registry`, `dns`, `auth`, `module`) are evaluated after `POST /v1/events/{type}` accepts an event. The `pending_telemetry` field remains in the API for compatibility and is always `false`. |
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

* `field`: `executable`, `command`, `parent_exe`, `host`, `uid`, `path`, `destination`, `operation`. Process events carry executable/parent_exe/command/uid/host, file events path/operation, network events destination.
* Telemetry event types add fields named exactly like the `TelemetryMatchView` keys (see `docs/telemetry-types.md`): registry `key`, `value_name`, `value_data`, `operation`; dns `query`, `qtype`, `answers`, `resolver`; auth `user`, `source_ip`, `method`, `outcome`; module `module_path`, `hash`, `signed` (`"true"`/`"false"`), `signer`, `module_kind` (the view's `kind`, renamed because `kind` is the event kind). `user` and `pid` are valid for all four. For convenience `path` is also filled with the registry key or module path and `destination` with the dns query, so rules written against the generic fields keep working. A field the event does not carry is absent and never matches, so write telemetry rules with at least one positive condition.
* `op`: `equals`, `contains`, `prefix`, `suffix`, `regex`, `in`.
* `pattern` is one string. `patterns` is a list: for `in` it is the set of allowed values; for other ops it is an any-of shorthand.
* Matching is case-insensitive unless `"case_sensitive": true`. Regexes are Go RE2 (linear time), max 256 chars, precompiled at load.

The matcher is the detection lab's (`LabNode` in `detection_lab.go`), so a content rule behaves identically in the lab and in production. `prefix`/`suffix` map to the lab's `startswith`/`endswith`.

### Sample events

Samples use the lab event shape (`executable`, `parent_exe`, `command`, `path`, `destination`, `operation`, `host`, `uid`). Telemetry fields go in an `attrs` object, for example `{ "attrs": { "key": "HKCU\\...\\Run", "value_data": "powershell -enc ...", "operation": "set" } }`. The harness fills the event kind from `event_type`.

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
* `pending_telemetry` is consistent with `event_type` (false for every known type)

`TestContentValidationRejects` proves the loader refuses each class of bad rule, and `TestContentEvaluationScales` bounds per-event cost for a 300-rule set. CI runs these with the rest of `./internal/edr/...`, so a bad pack cannot merge.

At runtime an invalid rule is skipped (the others stay active); the gate above keeps that from shipping.

## Runtime behavior

* `LoadContentPacks()` is called by `RegisterContentFramework` (one line in `falcon_platform.go`). Until packs are loaded, evaluation is a no-op.
* Hook points: `Detect` (process events, `edr.go`), `Store.IngestNetwork` and `Store.IngestFile` (`ingest.go`), and `Store.IngestTelemetry` (telemetry events, called by the `POST /v1/events/{registry,dns,auth,module}` handlers after the batch is validated and persisted). Each match creates a `Finding` with `Rule` = rule id, the rule severity, description `name: description`, and tags `content`, the technique id, rule tags and `batch:<batch>`.
* Cost bound: only live rules for the event's type are evaluated, regexes are precompiled, inputs are truncated to 4096 bytes, and one event raises at most 10 content findings.
* `MapDetection` and the incident/case technique lookup fall back to content rules (`mitreFor`), and `/v1/attack/matrix` includes live content rules in coverage.

## API (all require auth, read-only)

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/content/rules` | List rules without samples. Filters: `tactic`, `os` (also returns `any`), `batch`, `technique` (`T1059` matches `T1059.004`), `q` (id/name/description/tags substring). |
| `GET /v1/content/rules/{id}` | One rule with match tree and samples. |
| `GET /v1/content/coverage` | Counts by tactic, technique, os, batch, severity, event type; `techniques_covered`; `pending_telemetry` rule ids. |
* Telemetry detection: after a telemetry batch is stored, each event is flattened with `TelemetryMatchView` and evaluated against the live rules of its type, with the same 10-findings-per-event cap and 4096-byte truncation. Findings are stored like process/network/file findings (`Evidence.Command` carries a one-line summary, dns findings set `Destination` to the query). The response is `{"accepted":N,"findings":M,"not_evaluated":K}`. Evaluation is a no-op when no rules target the type.
* Time budget: one POST spends at most 150 ms evaluating rules. Events past the budget are still accepted and stored but not evaluated; this is logged (`content: <type> telemetry batch exceeded ...`) and counted in `kavach_telemetry_eval_skipped_total`, and reported as `not_evaluated` in the response.
* Persistence: if the telemetry ledger (`<events ledger>.telemetry`) is corrupt at startup, a log line names the file and line, the file is moved aside to `<ledger>.corrupt-<timestamp>`, and persistence restarts empty. If it cannot be moved aside, a log line says persistence is disabled for the run.

## Literal prefilter

Evaluating a thousand regexes against a 3 KB command used to cost about 30 to 60 ms. At load time each rule is reduced to the literals it provably requires: `contains`, `prefix`, `suffix`, `equals` and `in` leaves require their value (any-of lists require one of the values); regex leaves contribute literal runs found by walking the parsed regex (concatenations, captures, `+`, `{n,}` with n >= 1; alternations of literals require one branch's literal); `all` combines requirements, `any` requires one of its branches' requirements, `not` and everything else contribute nothing. Before running a rule, the engine checks that each required literal occurs in the event field (the field is looked up, truncated and lowercased once per event, shared by all rules). A missing literal means the rule cannot match, so its full evaluation is skipped.

The filter is a necessary condition only, so results are identical to unfiltered evaluation. Soundness details: case-insensitive non-regex literals use the matcher's own lowercase comparison; case-folded regex literals are used only when ASCII and only against ASCII fields (RE2 folds U+212A and U+017F to `k` and `s`); literals containing U+FFFD are ignored; the same 4096-byte truncation applies. `TestContentPrefilterEquivalence` runs the shipped rules plus 500 generated rules over about 1700 events, including Unicode folding, invalid UTF-8 and truncation edge cases, with and without the prefilter and requires identical results. `BenchmarkContentEvaluate1000Regex3KB` reports roughly 29 ms without and 0.48 ms with the prefilter (about 60x) for 1000 non-matching regexes on a 3 KB command (Apple M4).

## The T-telemetry pack

`internal/edr/content/telemetry.json` (batch `T-telemetry`) ships original per-event rules for the four telemetry types: registry (Run keys to user-writable paths or interpreters, IFEO and SilentProcessExit, AppInit/AppCert DLLs, service ImagePath, Defender exclusions and disable values, UAC, LSA/RunAsPPL, LSA packages, WDigest, RDP enabling and NLA, Winlogon, COM hijack, script block logging), dns (DGA-like labels, long TXT and NULL queries, hex-encoded labels, dynamic-DNS, paste-site and file-drop domain classes, onion gateways), auth (root ssh from a public address, sudo or ssh by service accounts, RDP from public addresses or default accounts, NTLM from public addresses or as Administrator, krbtgt Kerberos use, OAuth to privileged accounts) and module (unsigned modules from temp and user directories, injection-prone paths, LD_PRELOAD-style shared objects, unsigned drivers and kexts from user directories, kexts outside the Extensions directories, vulnerable drivers, credential-theft modules, amsi.dll outside system directories). Rules that need counting over time (failure bursts) are out of scope: content rules are per-event.
