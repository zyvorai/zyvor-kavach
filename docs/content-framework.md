# Detection content framework

Kavach ships detection content as JSON rule packs under `internal/edr/content/*.json`. They are embedded in the binary (`go:embed`), validated at load, and evaluated on the live ingest path. Observation only: a match raises a Finding, it never contains, kills or blocks.

## Pack format

```json
{ "pack": "seed", "rules": [ { ...rule... } ] }
```

Unknown fields are rejected. Any number of `*.json` files may be added; ids must be unique across all of them. Limits: 5000 rules in the registry, 4 MiB per pack file, at most 20 positive and 20 negative samples per rule.

## Shipped packs

Counts below were read from `internal/edr/content/*.json` on 2026-11-16 (1,475 rules in 12 packs). The generated "Detection rules" row in [index.md](index.md#feature-inventory) is the authoritative total; recount with the snippet under "Recounting" if you add rules.

| File | Pack / batch | Id prefix | Rules | Event types | Notes |
|------|--------------|-----------|-------|-------------|-------|
| `seed.json` | `seed` / `seed-v1` | mixed (`linux-`, `windows-`, `macos-`, `unix-`, ...) | 10 | process, file, network, registry | first rules, written to prove the framework |
| `linux.json` | `linux` / `a1-linux` | `lx-` | 170 | process, file, network | Linux host tradecraft |
| `macos.json` | `macos` / `a2-macos` | `macos-` | 135 | process, file, network | 15 rules are `os: any` |
| `windows.json` | `windows` / `a3-windows` | `win-` | 201 | process, file, network | |
| `behavioural.json` | `behavioural` / `b-behavioural` | `ioa-` | 153 | process, file, network | behaviour-shaped (indicator-of-attack) rules |
| `cloud.json` | `cloud` / `cloud-v1` | `cloud-` | 195 | process, file, network, dns, auth | host-side cloud and Kubernetes tooling on Linux (kubectl, cloud CLIs, metadata access); not audit-log rules, all `os: linux` |
| `telemetry.json` | `telemetry` / `T-telemetry` | `reg-`, `auth-`, `dns-`, `module-` | 47 | registry, dns, auth, module | per-event telemetry rules, see below |
| `gaps.json` | `gaps` / `gaps-v1` | `gap-` | 46 | process, dns, file, registry | closed the first validation-lab misses |
| `gap2.json` | `gap2` / `gap2-v1` | `gp2-` | 105 | process, registry, file, module, network, auth | untested ATT&CK techniques, see below |
| `unix2.json` | `unix2` / `unix2-v1` | `ux2-` | 134 | process, file, network, dns | Linux, macOS, container, Kubernetes depth |
| `regional.json` | `regional` / `regional-v1` | `rgn-` | 120 | process, file, registry, module, network | region-specific threats, see [regional-threats.md](regional-threats.md) |
| `cloud_audit.json` | `cloud-audit` / `cloud-audit-v1` | `cld-` | 159 | process (normalised audit records) | see [cloud-audit.md](cloud-audit.md) |

Severity mix across all packs is read from the same files: `GET /v1/content/coverage` reports the live split by tactic, technique, OS, batch, severity and event type.

### Recounting

```sh
python3 - <<'EOF'
import json, glob
total = 0
for f in sorted(glob.glob('internal/edr/content/*.json')):
    n = len(json.load(open(f))['rules']); total += n
    print(f, n)
print('total', total)
EOF
```

### Lifecycle and shadow mode

Embedded rules have no lifecycle record, so they are `production` until an admin sets another state with `PUT /v1/rules/lifecycle/{id}` (see [rule-health.md](rule-health.md)). `testing` is the only state that changes behaviour: hits are stored as shadow findings and do not reach the findings list or SIEM export. Rules imported from Sigma without derivable samples start in `testing` ([sigma-import.md](sigma-import.md)).

### Content versions

`GET /v1/content/versions` lists snapshots of the embedded content (recorded at startup only when content differs from the last snapshot, newest first, cap 50). `GET /v1/content/changes?from=&to=` diffs two snapshots (added, removed, modified, with `highlights` when severity or match-affecting fields changed). `GET /v1/content/changelog` gives one summary entry per snapshot. The regression tracker uses the same hashes to explain regressions ([regression-tracking.md](regression-tracking.md)).

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
* Telemetry event types add fields named exactly like the `TelemetryMatchView` keys (see [telemetry-types.md](telemetry-types.md)): registry `key`, `value_name`, `value_data`, `operation`; dns `query`, `qtype`, `answers`, `resolver`; auth `user`, `source_ip`, `method`, `outcome`; module `module_path`, `hash`, `signed` (`"true"`/`"false"`), `signer`, `module_kind` (the view's `kind`, renamed because `kind` is the event kind). `user` and `pid` are valid for all four. For convenience `path` is also filled with the registry key or module path and `destination` with the dns query, so rules written against the generic fields keep working. A field the event does not carry is absent and never matches, so write telemetry rules with at least one positive condition.
* `op`: `equals`, `contains`, `prefix`, `suffix`, `regex`, `in`.
* `pattern` is one string. `patterns` is a list: for `in` it is the set of allowed values; for other ops it is an any-of shorthand.
* Matching is case-insensitive unless `"case_sensitive": true`. Regexes are Go RE2 (linear time), max 256 chars, precompiled at load.

The matcher is the detection lab's (`LabNode` in `detection_lab.go`), so a content rule behaves identically in the lab and in production. `prefix`/`suffix` map to the lab's `startswith`/`endswith`.

### Sample events

Samples use the lab event shape (`executable`, `parent_exe`, `command`, `path`, `destination`, `operation`, `host`, `uid`). Telemetry fields go in an `attrs` object, for example `{ "attrs": { "key": "HKCU\\...\\Run", "value_data": "powershell -enc ...", "operation": "set" } }`. The harness fills the event kind from `event_type`.

## Authoring a rule, step by step

Worked example: detect a base64-decoded payload piped straight into a shell. The example is illustrative and is not shipped; it was run against the real validator, the benign corpus and the scenario loader while writing this page (0 corpus hits).

1. Choose the pack. Append to the pack that matches the OS or theme, or create `internal/edr/content/<name>.json` (any `*.json` there is embedded automatically). Pick an id prefix that is unique to the pack. Check the technique first: `kavachctl content list --technique T1140` shows what already covers it, so you tighten or extend rather than duplicate.
2. Write the rule. Only fields the live path supplies are usable: process events carry `executable`, `parent_exe`, `command`, `uid`, `host`; file events only `path` and `operation` (no writer process); network events only `destination`; telemetry events the fields listed above.

```json
{ "id": "lx-example-base64-decode-to-shell",
  "name": "Base64 payload decoded straight into a shell",
  "description": "A base64 -d output is piped into sh or bash, a common way to run an encoded payload without writing it to disk.",
  "tactic": "Defense Evasion", "technique": "T1140",
  "technique_name": "Deobfuscate/Decode Files or Information",
  "severity": "high", "os": "linux", "event_type": "process",
  "match": { "all": [
    { "field": "command", "op": "regex",
      "pattern": "base64\\s+(-d|--decode)\\b[^|]*\\|\\s*(/bin/|/usr/bin/)?(ba|da|z)?sh\\b" },
    { "not": { "field": "parent_exe", "op": "suffix", "pattern": "/dpkg" } }
  ] },
  "tags": ["example"], "batch": "example-v1",
  "tests": {
    "positive": [ { "executable": "/bin/bash", "command": "echo ZWNobyBoaQ== | base64 -d | sh", "parent_exe": "/usr/sbin/sshd" } ],
    "negative": [
      { "executable": "/usr/bin/base64", "command": "base64 -d token.b64 > token.bin" },
      { "executable": "/bin/bash", "command": "base64 -d <<< aGk= | wc -c" } ] } }
```

3. Make the negatives near misses, not unrelated events: the same tool with a harmless argument (decode to a file, decode into `wc`). An unrelated negative proves nothing.
4. Run the gate. The failure message names the rule id and the failing check:

```sh
go test ./internal/edr/ -run 'TestContentHarness|TestContentValidationRejects|TestContentBenignCorpus|TestCloudAuditBenignCorpus'
```

5. If `TestContentBenignCorpus` reports your rule, read the three offending events it prints, then tighten the pattern, add a `not` clause or lower severity to `low` (the accepted resolution for activity that is routine for admins; see [content-tuning.md](content-tuning.md)). Do not edit the corpus to hide a hit. Add a corpus event only when you find a realistic everyday event the rule family should be checked against.
6. Add an independent scenario so the rule is measured, not just self-tested. Write it from the public ATT&CK procedure description, not from your own positive sample, in `internal/edr/scenarios/<file>.json` (full walk-through in [research-validation-lab.md](research-validation-lab.md), section "Authoring a scenario"). Then run `go test ./internal/edr/ -run 'TestVal'`.
7. Commit the pack, the scenario and any corpus event together, and run `go test ./internal/edr/ -run 'Docs|OpenAPI|Content|Lab'` before pushing. The rule-count row in `index.md` is generated; do not hand-edit it.

Rules you author at run time (without rebuilding) use the same schema and harness through the custom-content API; see [custom-content.md](custom-content.md).

## How the harness gates

`TestContentHarness` (in `content_framework_test.go`) loads every embedded rule and, per rule id, checks:

* unique id, kebab-case id, valid ATT&CK id format, tactic/severity/os/event_type enums
* the match tree validates and every regex compiles
* every positive sample matches, every negative sample does not
* no rule matches any event in the built-in benign baseline (ls, cat, bash -c 'echo hi', systemd, curl https://example.com, ssh-agent, go build, python3 script.py, apt update, and more), tried under every event kind (this small in-code baseline is separate from the 1,719-event corpus below)
* `pending_telemetry` is consistent with `event_type` (false for every known type)

`TestContentValidationRejects` proves the loader refuses each class of bad rule, and `TestContentEvaluationScales` bounds per-event cost for a 300-rule set. CI runs these with the rest of `./internal/edr/...`, so a bad pack cannot merge.

Three further guards look at the shipped packs as a whole:

| Guard | What it enforces | Command |
|-------|------------------|---------|
| `TestContentBenignCorpus` | every embedded rule against `testdata/benign_corpus.json` (1,719 events: 703 process, 320 file, 199 network, 165 registry, 144 module, 128 dns, 60 auth; 692 linux, 681 windows, 346 macos). Any hit by a medium, high or critical rule fails; `low` rules may fire and are logged | `go test ./internal/edr/ -run TestContentBenignCorpus -v` |
| `TestCloudAuditBenignCorpus` | every non-low process-type rule against `testdata/benign_corpus_cloud.json` (71 normalised audit events) | `go test ./internal/edr/ -run TestCloudAuditBenignCorpus -v` |
| `TestValDetectedRateFloor` | scenario detect rate at or above 0.93 and zero benign controls firing at medium or above | `go test ./internal/edr/ -run TestVal -v` |

Details of the corpus, tuning decisions and the low-severity worklist are in [content-tuning.md](content-tuning.md).

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
| `GET /v1/content/versions`, `/changes`, `/changelog` | Snapshot history and diffs of embedded content (see Content versions above). |

CLI: `kavachctl content list [--tactic T] [--os O] [--event-type E] [--severity S] [--batch B] [--technique ID] [--q TEXT] [--json]`, `kavachctl content show RULE_ID`, `kavachctl content coverage`.
* Telemetry detection: after a telemetry batch is stored, each event is flattened with `TelemetryMatchView` and evaluated against the live rules of its type, with the same 10-findings-per-event cap and 4096-byte truncation. Findings are stored like process/network/file findings (`Evidence.Command` carries a one-line summary, dns findings set `Destination` to the query). The response is `{"accepted":N,"findings":M,"not_evaluated":K}`. Evaluation is a no-op when no rules target the type.
* Time budget: one POST spends at most 150 ms evaluating rules. Events past the budget are still accepted and stored but not evaluated; this is logged (`content: <type> telemetry batch exceeded ...`) and counted in `kavach_telemetry_eval_skipped_total`, and reported as `not_evaluated` in the response.
* Persistence: if the telemetry ledger (`<events ledger>.telemetry`) is corrupt at startup, a log line names the file and line, the file is moved aside to `<ledger>.corrupt-<timestamp>`, and persistence restarts empty. If it cannot be moved aside, a log line says persistence is disabled for the run.

## Literal prefilter

Evaluating a thousand regexes against a 3 KB command used to cost about 30 to 60 ms. At load time each rule is reduced to the literals it provably requires: `contains`, `prefix`, `suffix`, `equals` and `in` leaves require their value (any-of lists require one of the values); regex leaves contribute literal runs found by walking the parsed regex (concatenations, captures, `+`, `{n,}` with n >= 1; alternations of literals require one branch's literal); `all` combines requirements, `any` requires one of its branches' requirements, `not` and everything else contribute nothing. Before running a rule, the engine checks that each required literal occurs in the event field (the field is looked up, truncated and lowercased once per event, shared by all rules). A missing literal means the rule cannot match, so its full evaluation is skipped.

The filter is a necessary condition only, so results are identical to unfiltered evaluation. Soundness details: case-insensitive non-regex literals use the matcher's own lowercase comparison; case-folded regex literals are used only when ASCII and only against ASCII fields (RE2 folds U+212A and U+017F to `k` and `s`); literals containing U+FFFD are ignored; the same 4096-byte truncation applies. `TestContentPrefilterEquivalence` runs the shipped rules plus 500 generated rules over about 1700 events, including Unicode folding, invalid UTF-8 and truncation edge cases, with and without the prefilter and requires identical results. `BenchmarkContentEvaluate1000Regex3KB` reports roughly 29 ms without and 0.48 ms with the prefilter (about 60x) for 1000 non-matching regexes on a 3 KB command (Apple M4).

## The T-telemetry pack

`internal/edr/content/telemetry.json` (batch `T-telemetry`) ships original per-event rules for the four telemetry types: registry (Run keys to user-writable paths or interpreters, IFEO and SilentProcessExit, AppInit/AppCert DLLs, service ImagePath, Defender exclusions and disable values, UAC, LSA/RunAsPPL, LSA packages, WDigest, RDP enabling and NLA, Winlogon, COM hijack, script block logging), dns (DGA-like labels, long TXT and NULL queries, hex-encoded labels, dynamic-DNS, paste-site and file-drop domain classes, onion gateways), auth (root ssh from a public address, sudo or ssh by service accounts, RDP from public addresses or default accounts, NTLM from public addresses or as Administrator, krbtgt Kerberos use, OAuth to privileged accounts) and module (unsigned modules from temp and user directories, injection-prone paths, LD_PRELOAD-style shared objects, unsigned drivers and kexts from user directories, kexts outside the Extensions directories, vulnerable drivers, credential-theft modules, amsi.dll outside system directories). Rules that need counting over time (failure bursts) are out of scope: content rules are per-event.

## The gap2 pack

`internal/edr/content/gap2.json` (batch `gap2-v1`, ids `gp2-*`) ships 105 original rules (97 at first, later extended by the fixes recorded in section 9) for ATT&CK techniques the validation lab originally reported as untested; see sections 8 and 9 of [research-validation-lab.md](research-validation-lab.md) for scope, the independent scenarios (`val2-*`) and caveats.

## The unix2 pack

`internal/edr/content/unix2.json` (batch `unix2-v1`, ids `ux2-*`) deepens Linux, macOS, container and Kubernetes coverage: systemd/cron/ld.so.preload/rc.local/PAM/udev/XDG/authorized_keys persistence, shadow and key and cloud-credential theft, macOS keychain/dscl/osascript abuse, history/log/audit tampering and timestomping, hidden directories, TCC/Gatekeeper/quarantine/profile abuse, launchd persistence, and container escape and abuse (docker.sock, privileged runs, nsenter, cgroup release_agent, core_pattern, kubectl secret and exec use, kubelet and etcd access, cloud metadata, miner pools). Every rule carries an ATT&CK technique and has positive and near-miss negative samples. Count and per-OS and per-tactic split: `GET /v1/content/coverage` (filter `batch=unix2-v1` on `GET /v1/content/rules`). Validation: `scenarios/unix2.json` (ids `val3-*`) and `scenarios/benign3.json`, see section 10 of [research-validation-lab.md](research-validation-lab.md).

## Honest limits

* Rule and sample authors are the same team. A rule's own positive and negative samples prove the rule matches what its author imagined, not that it detects real tooling. Of the 1,475 rules, 666 fire in at least one non-benign validation-lab scenario (measured 2026-11-16 by replaying every scenario against the embedded packs); the other 809 are exercised only by their own samples. Per pack (rules / fired in a scenario): `cld` 159/115, `ux2` 134/100, `gap` 46/45, `gp2` 105/70, `ioa` 153/70, `win` 201/63, `lx` 170/77, `macos` 137/55, `cloud` 195/40, `rgn` 120/11, telemetry `reg` 19/8, `auth` 10/3, `module` 9/3, `dns` 9/0. The regional pack is the least measured.
* Per-event only. Rules cannot count or correlate over time; bursts are handled by `auth_burst.go`, ransomware by its own detector, sequences by hunting (`kavach-seq`).
* File events carry no writing process and network events carry only a destination, so file and network rules are path or port heuristics.
* Events carry no container context and the content `os` field is metadata only (OS is not enforced at evaluation), so an OS-labelled rule can fire on another OS's paths.
* Most rules are string or name heuristics; a renamed binary or reordered flags can evade them.
* Overlapping rules are not deduplicated, so one behaviour can raise several findings (up to 10 per event).
* Valid does not mean accurate: the loader skips an invalid rule at runtime and keeps the others active, so rely on the CI gate, not on runtime behaviour.
