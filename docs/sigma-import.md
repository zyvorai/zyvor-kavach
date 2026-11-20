# Sigma import and export (detection as code)

An offline importer converts a subset of [Sigma](https://github.com/SigmaHQ/sigma) rules into Kavach custom rules, and an exporter writes Kavach custom rules back to Sigma where that is lossless. Everything is observation-only: an imported rule raises Findings like any other custom rule and never blocks or contains anything. There are no network calls, no rule downloads and no third-party YAML library (a small built-in YAML subset parser is used).

This is a subset converter, not a Sigma backend. Anything it does not understand is reported rule by rule and is not imported. It never guesses.

## Routes, CLI, MCP

| Interface | Purpose |
|-----------|---------|
| `POST /v1/content/import/sigma[?dry_run=false]` | Admin token. **Dry run by default**; nothing is stored unless `dry_run=false`. Body: Sigma YAML (documents separated by `---`), a JSON rule or array, or `{"sigma":"<yaml>","dry_run":false}`. The query string wins over the body |
| `POST /v1/content/export/sigma` | Any authenticated caller. Optional `{"ids":[...]}`. Returns `{yaml, exported[], skipped[{id,reason}]}` |
| `POST /v1/content/import?format=sigma` | The older entry point (same converter and guards; per-rule `imported`/`valid`/`rejected`/`unsupported` results) |
| `kavachctl content import-sigma FILE\|DIR [--apply] [--json]` | One request per `.yml`, `.yaml` or `.json` file. Dry run unless `--apply` |
| `kavachctl content export-sigma [--ids a,b] [--out FILE]` | Writes the YAML; skipped rules and reasons go to stderr |
| MCP `content_import_sigma_dryrun` | Read-only. `dry_run=true` is fixed in the request path, so it cannot store anything (available without `--allow-mutations`) |

Limits (echoed in every report): 1 MiB per file or body (413 above that), 200 rules per import, regex at most 256 characters, at most 64 expanded values per field (after `windash` or `base64offset`).

## What the report says

```json
{"mode":"observe-only","dry_run":true,
 "summary":{"rules":13,"converted":9,"imported":0,"skipped":3,"noisy":1,"rejected":0,"starts_in_testing":1,"samples_derived":8},
 "gap_summary":{"field":{"Hashes":1},"modifier":{"cidr":1,"fieldref":1},"category":{"create_remote_thread":1},"regex":{"(a+)+$":1}},
 "results":[{"id":"ex-sigma-unsupported","status":"skipped","gaps":[{"kind":"field","name":"Hashes","detail":"selection selection: field \"Hashes\" has no Kavach mapping ..."}]}]}
```

Per-rule `status`:

* `converted` (dry run) or `imported` (applied): converted and passed the harness and both benign guards.
* `skipped`: uses something outside the subset. `gaps` lists every unsupported field, modifier, category, product, logsource key, condition construct, value or regex (`kind`, `name`, `detail`); all selections are checked, not only the first failure.
* `noisy`: matched the built-in benign baseline or at least one event of the embedded benign corpus (`benign_hits`, `benign_hit_examples`). A noisy rule is **never imported and never enabled**, with or without `dry_run=false`; tighten it and re-run.
* `rejected`: malformed (missing title, level, ATT&CK tags) or failed the harness (for example a supplied sample disagrees with the rule, or the id collides with an embedded rule).

## Validation pipeline

1. Parse (size and rule-count limits) and convert.
2. Samples: if the rule carries the Kavach `tests:` extension they are used (`samples: provided`). Otherwise positive and negative samples are **derived from the match tree** and each is verified against the compiled rule (`samples: derived`): positives are synthesised from the leaf patterns, negatives are near-misses (one constrained field replaced) plus an unrelated event. If no verified positive and negative can be derived (for example contradictory constraints on one field, or a regex the generator cannot satisfy), the rule is stored with `unverified: true` and **starts in the `testing` lifecycle**, so its hits become shadow findings (see `rule-health.md`) until an admin promotes it with `PUT /v1/rules/lifecycle/{id}`.
3. The same harness as embedded content (`custom-content.md`): schema, regex compilation, samples, benign baseline.
4. The embedded benign corpus (the same events the embedded-rule false-positive test uses). Any hit makes the rule `noisy`.
5. Only then, and only with `dry_run=false`, is the rule stored (max 500 custom rules, id collisions with embedded rules rejected, change history recorded).

Derived samples show that the conversion is self-consistent. They do not show that the rule detects the real attack in your telemetry. Review imported rules and watch `rule-health` before promoting.

## Supported Sigma subset

* **Logsource category**: `process_creation` (process), `network_connection` (network), `file_event` (file), `registry_set` (registry), `dns_query` (dns), `authentication` (auth). `product` windows, linux or macos sets `os`; no product means `any`. Other keys (`service`, `definition`) are reported as gaps.
* **Condition**: selection names with `and`, `or`, `not`, parentheses, `1 of X`, `all of X`, `N of X` (N from 2, expanded to subsets, at most 50 combinations), where `X` is `them` or a glob like `sel_*`. Selections as a map (fields ANDed) or a list of maps (ORed). Filters are simply selections used with `not`.
* **Value modifiers**: `contains`, `startswith`, `endswith`, `re`, `all`, `cased`, `windash`, `base64`, `base64offset`. No modifier means equals.
  * Wildcards in plain equals values: `*x*` becomes contains, `x*` prefix, `*x` suffix, anything else an anchored regex (`*` is any run, `?` one character). `\*` and `\?` are literal. A bare `*` is refused (it matches everything). Wildcards combined with another modifier are refused.
  * `windash` expands arguments that start with `-` into `-`, `/`, en dash, em dash and horizontal bar variants (uniform replacement, not every mix).
  * `base64offset` uses the pySigma algorithm (three alignments) and matches as contains.
* **Regex**: RE2 only (no lookaround or backreferences). Rejected: longer than 256 characters, nested unbounded quantifiers such as `(a+)+`, huge repetition counts, or a probe match slower than 250 ms. Go's regex engine is linear time, so these checks are defence in depth, not the only protection.
* **Fields** (case-insensitive names):

| Event type | Sigma field to Kavach field |
|------------|------------------------------|
| process | `Image` to executable, `CommandLine` to command, `ParentImage` to parent_exe |
| network | `DestinationHostname`, `DestinationIp` to destination |
| file | `TargetFilename` to path |
| registry | `TargetObject` to key, `Details` to value_data |
| dns | `QueryName` to query, `QueryResults` to answers |
| auth | `TargetUserName`/`User` to user, `IpAddress`/`SourceIp` to source_ip, `AuthenticationPackageName` to method |

* **Metadata**: `level` (informational becomes low), exactly one `attack.tNNNN[.NNN]` technique tag and one `attack.<tactic>` tag, `title`, `description`. The id is `kavach_id` or `sigma-<slug of title>`; batch is `sigma` unless `kavach_batch` is given. Other tags (up to 16, max 32 characters) are kept as rule tags. Kavach extensions: `kavach_id`, `kavach_batch`, `kavach_technique_name`, `tests`.

## Known gaps (reported, not converted)

* Fields with no Kavach equivalent: for example `ParentCommandLine`, `OriginalFileName`, `Hashes`, `User` on process events, `ProcessId`, `CurrentDirectory`, `Initiated`, `SourceIp` on network events. Kavach events do not carry them, so the rule would silently never match; the importer refuses instead.
* Modifiers: `cidr`, `exists`, `fieldref`, `gt`/`lt`/`gte`/`lte`, `expand`, `utf16le`, `utf16`, `wide`, `re` flags (`re|i`, `re|m`, `re|s`), combining `windash` with `base64`, and combining two match modifiers (for example `contains|startswith`).
* Conditions: aggregations (`| count() > N`), `timeframe`, `near`, keyword (field-less) selections, multiple conditions.
* Categories and services outside the list above (`create_remote_thread`, `image_load`, `process_access`, `service`-only sources, ...), correlation rules and `action: global` rule collections.
* Null and empty values, and non-scalar values.
* Several technique or tactic tags on one rule (Kavach rules carry one of each).
* Sigma's case rules are approximated: values match case-insensitively unless `cased`, like Kavach custom rules; regexes get `(?i)` unless `cased`.
* Field normalisation differs between Sigma backends. A Windows path rule assumes Kavach events carry the same path spelling as the Sysmon-style field; verify against your own telemetry.

## Export (Kavach to Sigma)

`POST /v1/content/export/sigma` writes a rule only when it converts back to an equivalent rule (the round-trip test imports the exported YAML and compares metadata, the canonicalised match tree and the samples). Exported rules carry the `kavach_*` extensions and the `tests:` block so the samples travel with the rule. Skipped, with the reason in `skipped[]`:

* a pattern containing `*` or `?` under a non-regex operator (Sigma would read them as wildcards),
* the `in` operator, fields without a Sigma mapping (for example `host`), the `module` event type,
* samples carrying time, uid, rule or severity, multi-line names or values, tags with upper-case letters or an `attack.` prefix.

The output uses Sigma syntax Kavach itself can re-import; it is not guaranteed to be accepted by every Sigma toolchain (the `tests` and `kavach_*` keys are extensions, and the generated `condition` uses one selection per leaf).

## Worked example: from a Sigma rule to a watched custom rule

The first rule in `internal/edr/testdata/sigma/examples_ok.yml` (original, not from SigmaHQ), condensed here to flow style:

```yaml
title: Kavach Example Encoded PowerShell Launcher
kavach_id: ex-sigma-encoded-pwsh
level: high
tags: [attack.execution, attack.t1059.001]
logsource: { category: process_creation, product: windows }
detection:
  selection_img:    { Image|endswith: ['\powershell.exe', '\pwsh.exe'] }
  selection_arg:    { CommandLine|contains|windash: ' -encodedcommand ' }
  selection_parent: { ParentImage|endswith: ['\winword.exe', '\excel.exe'] }
  condition: selection_img and selection_arg and selection_parent
```

1. Dry run (default, stores nothing): `kavachctl content import-sigma rule.yml --json`. Read `results[].status`: `converted` is good. `skipped` lists `gaps`; `noisy` lists `benign_hits` and `benign_hit_examples`; `rejected` gives the harness error.
2. Look at `samples`: `provided` means your `tests:` block was used, `derived` means Kavach generated and verified samples from the match tree. A rule with `unverified: true` will start in `testing`.
3. Fix gaps by rewriting the rule inside the subset (drop the unsupported field, split a rule with two techniques into two rules, replace a `|cidr` match with explicit prefixes). Fix `noisy` by adding a filter selection used with `not`.
4. Apply with an admin token: `kavachctl content import-sigma rule.yml --apply`. The rule is stored as a custom rule (`source: custom`, batch `sigma`).
5. Watch it: `kavachctl rules health ex-sigma-encoded-pwsh`, and set `testing` first if you want shadow findings (`kavachctl rules lifecycle ex-sigma-encoded-pwsh --set testing`).
6. Replay the whole directory of rules you maintain in CI with the dry run (no `--apply`); a non-converted rule is visible in the JSON, so a pipeline can fail on `skipped`, `noisy` or `rejected`. (Whether `kavachctl` exits non-zero on those statuses is unverified; check the exit code in your version before relying on it.)

Dry-run counts for the two fixture files: `examples_ok.yml` holds nine rules that convert; `examples_skipped.yml` holds the rejected shapes (a noisy rule, unsupported fields and modifiers, an unsupported category, an unsafe regex). The summary block in "What the report says" is the combined shape.

## Honest limits of the importer

* A converted rule is self-consistent, not proven against real telemetry. Field normalisation differs between Sigma backends and Kavach events carry far fewer fields than Sysmon (no hashes, no original file name, no integrity level), so many public Sigma rules will be skipped rather than imported; that is the intended behaviour.
* The noisy guard uses the same hand-written corpus as the embedded rules (1,719 events). A rule that does not hit it can still be noisy on your fleet.
* The benign corpus and derived samples were authored by the same team that wrote the importer.

## Fixtures

`internal/edr/testdata/sigma/examples_ok.yml` (nine original rules covering windash, base64offset, quantifiers, wildcards, regex, network, file, registry, dns and a rule that starts in testing) and `examples_skipped.yml` (a noisy rule, unsupported fields and modifiers, an unsupported category and an unsafe regex). All are original and not copied from SigmaHQ.
