# SIEM and standards export

Pull-based and read-only. A SIEM, collector or script polls Kavach; the endpoints below open no
outbound connection. All of them need the bearer token (or a console session). Kavach also has an
optional, separate push sink configured by the operator with environment variables; see
[Optional push sink](#optional-push-sink-operator-configured) at the end. The two are independent.

| Endpoint | Output |
|---|---|
| `GET /v1/export/findings?format=ocsf\|ecs\|cef\|leef\|splunk-hec&since=&limit=&cursor=&kind=` | one record per line |
| `GET /v1/export/iocs?format=stix` | STIX 2.1 bundle (`application/stix+json;version=2.1`) |
| `GET /v1/export/attack-layer` | ATT&CK Navigator layer v4.5 |

CLI: `kavachctl export findings --format ocsf`, `kavachctl export iocs`, `kavachctl export layer`.
MCP (read-only): `export_findings_siem`, `export_iocs_stix`, `export_attack_layer`.
Related: `GET /v1/siem/status` (push sink state) and `GET /v1/siem/export` (every stored finding as
one ECS-flavoured JSON document per line, `application/x-ndjson`, no filters or cursor; prefer
`/v1/export/findings?format=ecs` for polling). `kavachctl siem status|export` wraps these two.

## Examples

```bash
export KAVACH_URL=http://127.0.0.1:8099 KAVACH_TOKEN='Admin@321'
H="Authorization: Bearer $KAVACH_TOKEN"

# First page, OCSF, and keep the response headers to read the cursor
curl -s -D hdr.txt -H "$H" "$KAVACH_URL/v1/export/findings?format=ocsf&limit=500" > page1.ndjson
grep -i '^X-Kavach-' hdr.txt            # X-Kavach-Count, X-Kavach-Next-Cursor

# Resume strictly after the last record you stored
CUR=$(grep -i '^X-Kavach-Next-Cursor:' hdr.txt | cut -d' ' -f2 | tr -d '\r')
curl -s -H "$H" "$KAVACH_URL/v1/export/findings?format=ocsf&limit=500&cursor=$CUR" > page2.ndjson

# Only high severity from one host since a date, as Splunk HEC envelopes
curl -s -H "$H" "$KAVACH_URL/v1/export/findings?format=splunk-hec&severity=high&host=web-01&since=2026-11-01T00:00:00Z"

# Raw process events instead of findings
curl -s -H "$H" "$KAVACH_URL/v1/export/findings?format=ecs&kind=events&limit=100"

# STIX 2.1 bundle and an ATT&CK Navigator layer
curl -s -H "$H" "$KAVACH_URL/v1/export/iocs?format=stix" > iocs.stix.json
curl -s -H "$H" "$KAVACH_URL/v1/export/attack-layer" > layer.json

# CLI equivalents
kavachctl export findings --format ocsf
kavachctl export iocs
kavachctl export layer
```

Errors are plain text with a 400: `kind must be findings or events`, `limit must be 1..10000`,
`since must be RFC3339`, an invalid `cursor`, and `format must be stix` on the IOC export.
The first call without `cursor` returns the oldest records first (ordering is by time, then id),
so a new poller backfills the whole retained window before reaching the present.

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

## Optional push sink (operator configured)

Separate from the pull endpoints, the controller can push each **newly ingested** finding to a
webhook and/or a UDP syslog target. It is off unless a target is configured, and the settings come
only from the server environment (or the Helm `siem.*` values), never from request data.

| Variable | Meaning |
|---|---|
| `KAVACH_SIEM_WEBHOOK` (alias `KAVACH_SIEM_WEBHOOK_URL`) | HTTP endpoint that receives one JSON POST per finding (5 s client timeout) |
| `KAVACH_SIEM_SYSLOG` (alias `KAVACH_SIEM_SYSLOG_ADDR`) | `host:port` of a UDP syslog receiver; one RFC 5424-style datagram per finding (`<134>1 <time> kavach - - - <json>`) |
| `KAVACH_SIEM_ALLOW_PRIVATE` | `1` allows RFC1918/ULA webhook targets (internal collectors). Loopback, link-local (including `169.254.169.254`), unspecified and multicast stay refused |
| `KAVACH_SIEM_HEADERS` | Extra webhook headers as `k=v,k2=v2` |
| `KAVACH_SIEM_SINK` | `webhook`, `syslog`, `both` (default) or `none` |
| `KAVACH_SIEM_FORMAT` | `json`, `ecs` or `syslog`; default `ecs` |
| `KAVACH_SIEM_ENABLED` | `false` or `0` forces it off; otherwise it is on exactly when a target is set and the sink is not `none` |

Behaviour read from `internal/edr/siem.go`: the payload is always the ECS-flavoured document
(`@timestamp`, `message`, `event.kind=alert`, `rule.id`, `host.name`, `kavach.finding_id`, tags) whatever
`KAVACH_SIEM_FORMAT` says; that variable is only echoed in the status. Delivery is fire and forget:
each finding is sent in its own goroutine; the webhook is tried up to 3 times (backoff 0.5 s doubling, capped at 5 s; retried on network errors, 5xx and 429, not on other 4xx; retries stop at shutdown), there is no queue, signature or TLS pinning, and
a final failure increments `err_count` and sets `last_error`. UDP can drop silently. The webhook URL is
checked at start: only http/https, and a host that resolves to a loopback, link-local/metadata, unspecified, multicast or (without `KAVACH_SIEM_ALLOW_PRIVATE=1`) private address is refused and the webhook is disabled with the reason in `last_error`. The IP is checked again when connecting (DNS rebinding) and redirects to blocked addresses fail; proxy environment variables are ignored. The syslog address is not filtered. Check it with
`kavachctl siem status` or `GET /v1/siem/status`:

```json
{"enabled":false,"err_count":0,"format":"ecs","last_error":"","ok_count":0,"sink":"both","syslog_set":false,"webhook_set":false}
```

Use the pull endpoints with a cursor when you need completeness; use the push sink only for low-latency
notification. Neither can change anything on a host.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Poller sees the same records | The cursor was not stored, or `since` was used instead of `cursor` (`cursor` overrides `since`) |
| Poller misses a late finding | Ordering is by event time; a finding ingested with a time older than your cursor is not re-delivered. Poll with an overlap and de-duplicate on the id |
| Records disappear | The findings store is bounded (1000 findings in memory); export between polls or use the push sink as well |
| `X-Kavach-Count: 0` and an unchanged cursor | No new records; store the cursor anyway. On a first call that returns nothing the `X-Kavach-Next-Cursor` header is absent |
| Push sink status `enabled: false` | No webhook or syslog target is set, `KAVACH_SIEM_SINK=none`, or `KAVACH_SIEM_ENABLED=false` |
| `ok_count` stays 0 with a webhook set | Webhook returned HTTP 300 or above, timed out (5 s) or refused; read `last_error` |
| Fields look redacted | Data-governance redaction is on (`GET /v1/governance/redaction`); it applies to finding exports |

## Honest limits

- No live SIEM (Splunk, Elastic, QRadar, ArcSight, Sentinel) was used. Output is validated by unit tests with
  golden files and structural checks only; field choices follow the public specs but are not
  certified by any vendor parser or schema validator (no OCSF/ECS/STIX validator was run).
- CEF/LEEF key choices (`cs1..cs3`, `dvchost`, `sproc`) are conventional, not tied to a vendor parser.
- Events are process events only, unredacted by data-governance rules (findings are redacted when enabled).
- ATT&CK version in the layer (16) is an assumption about the Navigator in use; adjust in your tool if it warns.
