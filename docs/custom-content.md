# Custom detection content

Customers can author their own detection rules on top of the embedded packs described in `content-framework.md`. Custom rules use the same JSON schema, run on the same live ingest path, appear in the ATT&CK matrix, and stay observation-only: a match raises a Finding, nothing is contained or blocked.

* Rules are marked `source: "custom"`; in `/v1/attack/matrix` each technique lists them under `custom_rules` (also included in `rules`).
* A custom rule can never override an embedded or built-in rule id (rejected with 409).
* Persistence: `<store>.customcontent.json` (see `persistence-files.md`). Rules are re-validated on startup. Max 500 custom rules.
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

* `logsource.category`: `process_creation` (process), `network_connection` (network), `file_event` (file), `registry_set` (registry), `dns_query` (dns). `logsource.product` windows, linux or macos sets `os`; otherwise `any`.
* Fields: process `Image`, `CommandLine`, `ParentImage`; network `DestinationHostname`, `DestinationIp` (destination); file `TargetFilename`; registry `TargetObject` (key), `Details` (value_data); dns `QueryName`, `QueryResults`.
* Modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `cased`; no modifier means equals. Value lists are any-of (all-of with `|all`).
* Selections as a map (fields ANDed) or a list of maps (ORed); `condition` of selection names with `and`, `or`, `not` and parentheses.
* `level` maps to severity (informational becomes low); `tags` must contain one `attack.tNNNN[.NNN]` technique and one `attack.<tactic>` tag. The rule id is `kavach_id` if given, else `sigma-<slug of title>`; batch is `sigma`.

Sigma rules carry no test samples, so add the Kavach extension `tests:` with `positive` and `negative` lists of lab events (`executable`, `command`, `parent_exe`, `path`, `destination`, `operation`, `attrs`). Without it the harness rejects the rule.

Anything outside the subset is reported per rule instead of guessed, and that rule is not imported: other categories or products, `N of` / `all of` quantifiers, wildcard values (`*`, `?`), other modifiers (`base64`, `windash`, `cidr`, ...), null values, keyword lists, `timeframe`, aggregations (`| count`), unknown fields, multiple technique or tactic tags. The response lists them under `unsupported` with status `unsupported`.

```json
{"imported":1,"valid":0,"rejected":0,"unsupported":1,"results":[
 {"id":"sigma-acme-suspicious-whoami","status":"imported"},
 {"id":"sigma-bad-one","status":"unsupported","unsupported":["quantifier condition ... is not supported"]}]}
```

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

`kavach-mcp` exposes read-only `content_custom_list` and `content_custom_export` (available without `--allow-mutations`).
