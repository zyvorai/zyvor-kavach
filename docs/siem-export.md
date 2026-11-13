# SIEM and standards export

Pull-based and read-only. A SIEM, collector or script polls Kavach; Kavach opens no new outbound
connection. All endpoints need the bearer token (or a console session).

| Endpoint | Output |
|---|---|
| `GET /v1/export/findings?format=ocsf\|ecs\|cef\|leef\|splunk-hec&since=&limit=&cursor=&kind=` | one record per line |
| `GET /v1/export/iocs?format=stix` | STIX 2.1 bundle (`application/stix+json;version=2.1`) |
| `GET /v1/export/attack-layer` | ATT&CK Navigator layer v4.5 |

CLI: `kavachctl export findings --format ocsf`, `kavachctl export iocs`, `kavachctl export layer`.
MCP (read-only): `export_findings_siem`, `export_iocs_stix`, `export_attack_layer`.

## Parameters

- `kind=findings` (default) or `events` (raw process events from the recent-events buffer; no detection context).
- `severity`, `host`, `rule`: exact-match filters. `since`: RFC3339 lower bound. `limit`: 1..10000 (default 1000).
- Existing `format=csv|json|ndjson` on the same endpoint is unchanged.

## Checkpointed polling (no duplicates)

Records are ordered by (time, id). Every response carries `X-Kavach-Count` and
`X-Kavach-Next-Cursor`. Pass that value as `cursor=` on the next call; the export resumes strictly
after that record. An empty page echoes the same cursor, so a poller can store it unconditionally.
`cursor` overrides `since`. Limit: ordering is by event time, so a finding ingested late with a time
older than your cursor is not re-delivered; use an overlap (`since`) and de-duplicate on the id if
that matters. Findings are held in a bounded store, so very old records can age out between polls.

## Mapping table (Kavach field to target field)

| Kavach | OCSF 1.3 (Detection Finding 2004) | ECS 8.11 | CEF:0 ext | LEEF 2.0 |
|---|---|---|---|---|
| id | `finding_info.uid`, `metadata.uid` | `event.id` | `externalId` | `eventId` |
| time | `time` (epoch ms) | `@timestamp` | `rt` (epoch ms) | `devTime` (+`devTimeFormat`) |
| host | `device.hostname`, `device.name` | `host.name` | `dvchost` | `identHostName` |
| pid | `evidences[].process.pid` | `process.pid` | `dvcpid` | `pid` |
| rule | `finding_info.title` | `rule.name`, `event.action` | header SignatureID + Name | header EventID |
| severity | `severity_id` 1..5 + `severity` | `event.severity` 1/21/47/73/99, `labels.kavach_severity` | header Severity 1/3/5/8/10 | `sev` |
| description | `finding_info.desc`, `message` | `message`, `rule.description` | `msg` | `msg` |
| evidence.executable | `evidences[].process.file.path/name` | `process.executable/name` | `sproc` | `exe` |
| evidence.command | `evidences[].process.cmd_line` | `process.command_line` | `cs1` (`cs1Label=command`) | `cmd` |
| evidence.uid | `evidences[].process.user.uid` | `process.user.id` | `suid` | `usrName` |
| evidence.parent_exe / ppid | `process.parent_process.file.path/pid` | `process.parent.executable/pid` | (events: `cs2` parentExecutable) | not mapped |
| tags | `finding_info.tags` | `tags` | `cs2` (`cs2Label=tags`) | not mapped |
| destination | `evidences[].dst_endpoint.name` | `destination.address` | `dst` (IP) or `dhost` | `dst` / `dstName` |
| MITRE (from rule) | `finding_info.attacks[]` tactic/technique | `threat.framework/tactic/technique` | `cs3` (`mitreTechnique`) | `mitre` |

Constants: OCSF `class_uid 2004`, `category_uid 2`, `activity_id 1` (Create), `type_uid 200401`,
`status_id 1` (New), `action_id 1` (Allowed, because Kavach is observe-only and blocks nothing),
`disposition_id 15` (Detected), `metadata.version 1.3.0`. Events use Process Activity `1007`/`100701`
(Launch). ECS: `event.kind alert`, `category [intrusion_detection]` (events: `event`/`process`/`start`),
`dataset kavach.findings|kavach.events`. CEF/LEEF vendor `Zyvor AI Labs`, product `Kavach`, version `1.0`.
LEEF uses the explicit `^` delimiter; `^`, tabs and newlines in values become spaces.

Splunk HEC: each line is a HEC event envelope `{time (epoch s), host, source "kavach", sourcetype
"kavach:finding"|"kavach:event", event: <native Kavach JSON>, fields: {severity, rule}}`. Kavach does not
push; a forwarder reads these lines and posts them to the collector.

STIX: one `identity` (Kavach) plus one `indicator` per enabled IOC of type sha256, sha1, md5, domain,
ipv4, ipv6 or url (others skipped). Patterns: `[file:hashes.'SHA-256' = '...']`, `[domain-name:value = '...']`,
`[ipv4-addr:value = '...']`, etc. Indicator ids are UUIDv5 of type+value, so they are stable across
exports; `created`/`modified`/`valid_from` come from the IOC creation time, millisecond UTC.

Navigator layer: `domain enterprise-attack`, `versions {attack 16, navigator 5.1.0, layer 4.5}`; one
technique entry per covered technique per tactic, `score` = observed finding count, green when covered
only and red when hits were observed.

## Research notes (specs, own words)

- OCSF Detection Finding (class 2004, category Findings): requires `class_uid`, `category_uid`,
  `activity_id`, `type_uid` (= class_uid x 100 + activity_id), `severity_id` (0 unknown, 1 informational,
  2 low, 3 medium, 4 high, 5 critical, 6 fatal), `action_id`, `time`, `finding_info`, `metadata`.
  Recommended: `device`, `evidences`, `observables`, `message`. https://schema.ocsf.io/1.3.0/classes/detection_finding
- ECS `event.*`: `kind` (alert, event, ...), `category` array (intrusion_detection, process, ...), `type`
  array (info, start, ...), numeric `severity`, `id`, `module`, `dataset`, `action`.
  https://www.elastic.co/guide/en/ecs/current/ecs-event.html
- CEF: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`.
  Header escapes `\|` and `\\`; extension values escape `\=`, `\\` and newlines as `\n`; extension is
  space-separated `key=value`. Custom strings use `csN` with `csNLabel`. Severity 0..10. (ArcSight CEF
  implementation standard; the vendor PDF was not fetchable here, so this follows the widely published
  rules.)
- LEEF 2.0 (IBM QRadar): `LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>|` then delimiter-separated
  `key=value`; the header must end in a pipe; delimiter may be given explicitly. https://docs.nxlog.co/integrations/format/leef.html
- STIX 2.1: ids are `<type>--<RFC 4122 UUID>` (v4 recommended for SDOs; v5 for SCOs), timestamps RFC 3339
  UTC with `Z`; Indicator requires `type`, `spec_version`, `id`, `created`, `modified`, `pattern`,
  `pattern_type`, `valid_from`. https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- ATT&CK Navigator layer 4.5: `name`, `versions{attack,navigator,layer}`, `domain`, `techniques[]` with
  `techniqueID`, `tactic` (lowercase hyphenated shortname), `score`, `color`, `comment`, `enabled`.
  https://github.com/mitre-attack/attack-navigator/tree/master/layers (page not fetchable from this
  environment; written from the published v4.5 format).

## Honest limits

- No live SIEM (Splunk, Elastic, QRadar, ArcSight, Sentinel) was used. Output is validated by unit tests with
  golden files and structural checks only; field choices follow the public specs but are not
  certified by any vendor parser or schema validator (no OCSF/ECS/STIX validator was run).
- CEF/LEEF key choices (`cs1..cs3`, `dvchost`, `sproc`) are conventional, not tied to a vendor parser.
- Events are process events only, unredacted by data-governance rules (findings are redacted when enabled).
- ATT&CK version in the layer (16) is an assumption about the Navigator in use; adjust in your tool if it warns.
