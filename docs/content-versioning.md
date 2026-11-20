# Content versioning (detection as code)

Embedded rule packs ([content-framework.md](content-framework.md)) can be inventoried, snapshotted and diffed at rule level. Observation only: nothing here changes what fires.

This sits beside the older startup history (`GET /v1/content/versions`, `/changes`, `/changelog`), which hashes every embedded content kind. The manifest below is rule-level and covers detection packs only. Custom (customer-authored) rules are not included.

## Manifest

`GET /v1/content/manifest` (authenticated) is generated from the embedded packs on each call:

* per pack file: `pack` name, `batches` (the distinct `batch` labels of its rules, e.g. `a1-linux`), `rule_count`, and the SHA-256 of the file bytes;
* per rule: `id`, pack, a hash of the whole rule, and short hashes of four fields (severity, match patterns, ATT&CK tactic+technique, lifecycle state);
* `manifest_sha256`: SHA-256 of the compact JSON of the `manifest` object as served.

The "enabled" field is the rule lifecycle state ([rule-health.md](rule-health.md)); embedded rules are `production` until an admin changes it.

## Optional signature

If `KAVACH_CONTENT_SIGN_KEY` is set on the server, the response also carries `signature` = hex HMAC-SHA256 (keyed with that value) of the `manifest_sha256` hex string. A holder of the same key can recompute it and detect a manifest altered in transit or at rest. This is a shared-secret integrity check, not a PKI: anyone with the key can sign, there is no key distribution, rotation, revocation or identity, and it does not prove who built the binary. Without the key set, `signed` is `false`.

## Snapshots

`POST /v1/content/snapshots` (admin token only; sessions and other roles are refused; body max 4 KiB, optional `{"label": "..."}`) stores the current manifest in `<store>.contentsnaps.json` (mode 0600, capped at 20, oldest dropped). A snapshot holds counts and hashes only, never rule bodies. `GET /v1/content/snapshots` lists them. With no store path the snapshots live in memory only.

## Diff

`GET /v1/content/diff?from=&to=` where each side is a snapshot `seq`, `latest` or `embedded` (defaults: `from=latest`, `to=embedded`). The result lists `added`, `removed` and `changed` rules. For a changed rule `fields_changed` names what differs: `severity`, `patterns`, `attack_mapping`, `enabled_state`, or `other` (name, description, tags, tests and similar). Field hashes are 12 hex characters, so the diff says which field changed, not the old and new values.

## Tooling

```sh
kavachctl content manifest
kavachctl content snapshot create --label before-upgrade
kavachctl content snapshot list
kavachctl content diff --from 1 --to embedded
```

Read-only MCP tools: `content_manifest`, `content_snapshots`, `content_diff`. Creating a snapshot is not exposed over MCP.

## Limits

* No upstream Sigma version tracking and no custom-rule coverage.
* Lifecycle state is read at request time, so an `enabled_state` difference reflects the state when each snapshot was taken.
