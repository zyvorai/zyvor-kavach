# Custom detection content

Customers can author their own detection rules on top of the embedded packs described in [content-framework.md](content-framework.md). Custom rules use the same JSON schema, run on the same live ingest path, appear in the ATT&CK matrix, and stay observation-only: a match raises a Finding, nothing is contained or blocked.

* Rules are marked `source: "custom"`; in `/v1/attack/matrix` each technique lists them under `custom_rules` (also included in `rules`).
* A custom rule can never override an embedded or built-in rule id (rejected with 409).
* Persistence: `<store>.customcontent.json` (see [persistence-files.md](persistence-files.md)). Rules are re-validated on startup. Max 500 custom rules.
* All endpoints require authentication.

## Validation (same harness as embedded content)

Every create, update and import runs: schema and enum checks, match-tree and regex compilation, at least one positive and one negative sample, every positive matches, every negative does not, and the benign-baseline guard (the rule must not match common everyday events such as `ls`, `git status`, `curl https://example.com`, ordinary file paths and destinations, tried under every event kind). Errors name the rule and the failing check, for example `negative sample #0 matches the rule but must not` or `matches benign baseline event #1 (cat /etc/hostname) as kind process; tighten the pattern`.

## Endpoints

| Method and path | Purpose |
|-----------------|---------|
| `POST /v1/content/custom` | Create or update (upsert by id) one rule. 200 saved, 400 validation, 409 embedded id clash |
| `GET /v1/content/custom` | List custom rules (`?tests=1` includes samples) |
| `DELETE /v1/content/custom/{id}` | Delete a custom rule (404 unknown, 400 embedded) |
| `POST /v1/content/custom/{id}/dryrun` | Body `{"events":[...]}` (1..1000 lab events). Returns `matches` with indexes; no findings are recorded |
| `POST /v1/content/export` | Optional filter `{source: custom\|embedded\|all (default custom), ids, tactic, technique, os, batch, q, event_type}`. Returns `{"pack":"export","rules":[...]}` |
| `POST /v1/content/import[?validate_only=true]` | Body is a pack `{"pack":..,"rules":[..]}`. Per-rule results; valid rules are imported even if others are rejected. `validate_only` runs every check and stores nothing |
| `POST /v1/content/import?format=sigma` | Sigma-subset importer (below) |

Importing an export of embedded rules is rejected per rule with the id-collision error, by design.

## Example

```sh
curl -H "Authorization: Bearer $KAVACH_TOKEN" -X POST localhost:8080/v1/content/custom -d '{
 "id":"acme-evil-tool","name":"Evil tool","description":"internal evil tool run","tactic":"Execution","technique":"T1059",
 "severity":"high","os":"any","event_type":"process",
 "match":{"field":"command","op":"contains","pattern":"acme-evil-tool --pwn"},
 "tests":{"positive":[{"command":"/opt/acme-evil-tool --pwn now"}],"negative":[{"command":"/opt/acme-good-tool --run"}]}}'
```

## Sigma-subset importer

`POST /v1/content/import?format=sigma` accepts one rule or several: YAML documents separated by `---`, a JSON object, or a JSON array. YAML is parsed with a small built-in subset parser (block mappings and lists, flow lists, quoted and plain scalars, `|` and `>` block scalars, comments); anchors, flow maps and other YAML features are rejected.

Supported:

* `logsource.category`: `process_creation` (process), `network_connection` (network), `file_event` (file), `registry_set` (registry), `dns_query` (dns), `authentication` (auth). `logsource.product` windows, linux or macos sets `os`; otherwise `any`.
* Fields: process `Image`, `CommandLine`, `ParentImage`; network `DestinationHostname`, `DestinationIp` (destination); file `TargetFilename`; registry `TargetObject` (key), `Details` (value_data); dns `QueryName`, `QueryResults` (answers); auth `TargetUserName`/`User`, `IpAddress`/`SourceIp`, `AuthenticationPackageName`.
* Modifiers (the older summary; [sigma-import.md](sigma-import.md) is authoritative): `contains`, `startswith`, `endswith`, `re`, `all`, `cased`, `windash`, `base64`, `base64offset`, and `*`/`?` wildcards in equals values; no modifier means equals. Value lists are any-of (all-of with `|all`).
* Selections as a map (fields ANDed) or a list of maps (ORed); `condition` of selection names with `and`, `or`, `not`, parentheses, `1 of`, `all of` and `N of`.
* `level` maps to severity (informational becomes low); `tags` must contain one `attack.tNNNN[.NNN]` technique and one `attack.<tactic>` tag. The rule id is `kavach_id` if given, else `sigma-<slug of title>`; batch is `sigma`.

Sigma rules carry no test samples, so the importer derives verified positive and negative samples from the match tree, or uses the Kavach extension `tests:` when present. If samples cannot be derived the rule is stored with `unverified: true` and starts in the `testing` lifecycle. Rules that match the benign corpus are never imported.

Anything outside the subset is reported per rule instead of guessed, and that rule is not imported: it appears under `unsupported` with status `unsupported` and the exact field, modifier or category named. The full supported list, known gaps, limits, the admin-only dry-run-by-default route `POST /v1/content/import/sigma`, and the Sigma export are in [sigma-import.md](sigma-import.md).

```json
{"imported":1,"valid":0,"rejected":0,"unsupported":1,"results":[
 {"id":"sigma-acme-suspicious-whoami","status":"imported"},
 {"id":"sigma-bad-one","status":"unsupported","unsupported":["quantifier condition ... is not supported"]}]}
```

## Authoring workflow (end to end)

Worked example: flag an internal tool that is only legitimate when run by a named service account's launcher.

1. Write the rule JSON with at least one positive and one near-miss negative sample. Use only fields the live path supplies (process: `executable`, `parent_exe`, `command`, `uid`, `host`; file: `path`, `operation`; network: `destination`; telemetry types add their own, see [content-framework.md](content-framework.md)).

```json
{ "id": "acme-backup-tool-from-shell",
  "name": "Backup tool started from an interactive shell",
  "description": "The backup tool is only launched by its scheduler; an interactive shell parent is unexpected.",
  "tactic": "Collection", "technique": "T1560", "severity": "medium", "os": "linux", "event_type": "process",
  "match": { "all": [
    { "field": "executable", "op": "suffix", "pattern": "/acme-backup" },
    { "field": "parent_exe", "op": "in", "patterns": ["/bin/bash", "/bin/zsh", "/bin/sh"] } ] },
  "tests": {
    "positive": [ { "executable": "/opt/acme/acme-backup", "command": "acme-backup --all", "parent_exe": "/bin/bash" } ],
    "negative": [ { "executable": "/opt/acme/acme-backup", "command": "acme-backup --all", "parent_exe": "/usr/sbin/cron" } ] } }
```

2. Validate without storing anything: `kavachctl content custom import pack.json --validate-only` (wrap the rule as `{"pack":"mine","rules":[...]}`), or `POST /v1/content/import?validate_only=true`. Fix any error; it names the rule and the failing check.
3. Replay real events you already have: `kavachctl content custom dryrun acme-backup-tool-from-shell events.json` (after the rule is stored) returns `matches` with event indexes and `findings_recorded: 0`.
4. Store it with `kavachctl content custom put rule.json` (`POST /v1/content/custom`).
5. Start in shadow mode if you are unsure: `kavachctl rules lifecycle acme-backup-tool-from-shell --set testing --note "week 1 watch"`. Hits become shadow findings (not in the findings list or SIEM export) and show as `shadow_hits` in `kavachctl rules health`. Promote with `--set production` when the shadow hits look right. Sigma-imported rules without derivable samples start in `testing` automatically.
6. Review noise later with `kavachctl rules health --source custom --noisy`. Every create, update and delete is journaled in the rule history (`kavachctl rules history ID`).

The example reuses the rule shape the tests exercise; it was not stored in any tenant. Custom rules are checked only against the small built-in benign baseline, not the 1,719-event embedded corpus, so a custom rule can still be noisy on your fleet: use dryrun and `testing` rather than assuming the guard covers you.

## Honest limits

* Custom rules are validated for consistency (samples agree with the match) and against everyday events, not for real-world detection quality; a rule you write and test yourself shares your blind spots.
* Custom rules are never replayed by the regression tracker or the validation lab unless you pass `include_custom` to `POST /v1/validate/run` ([regression-tracking.md](regression-tracking.md)).
* The 500-rule cap and the 1,000-event dryrun cap are hard limits; matching fields are the same limited set the embedded packs use, so file rules cannot see the writing process.

## CLI and MCP

```sh
kavachctl content custom list
kavachctl content custom put rule.json
kavachctl content custom dryrun acme-evil-tool events.json
kavachctl content custom export --source all --out pack.json
kavachctl content custom import pack.json --validate-only
kavachctl content custom import sigma.yml --format sigma
kavachctl content custom rm acme-evil-tool
```

`kavach-mcp` exposes read-only `content_custom_list`, `content_custom_export` and `content_import_sigma_dryrun` (available without `--allow-mutations`). `kavachctl content import-sigma FILE|DIR [--apply]` and `export-sigma` are described in sigma-import.md.
