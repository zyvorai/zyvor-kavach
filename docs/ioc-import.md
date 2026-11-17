# Offline IOC import and lifecycle

Kavach can load threat-intel indicators from files you already have. It never fetches anything from the network for this (the opt-in feeds in [cert-feeds.md](cert-feeds.md) are separate). Everything is observation only: a matching indicator raises a finding or enrichment, nothing is blocked.

## Import

`POST /v1/ioc/import` needs the admin token. The body is the file. It is a **dry run unless `dry_run=false`**.

| Query | Meaning |
|-------|---------|
| `format` | `auto` (default), `stix`, `misp`, `csv`, `txt` |
| `source` | label for the indicators (1-64 of letters, digits, `.`, `_`, `-`); default `import-<format>` |
| `dry_run` | `false` stores the valid items |

CLI: `kavachctl ioc import FILE [--format F] [--source NAME] [--apply] [--json]`.

Limits: 5 MiB body, 5000 items (objects, attributes or lines) per import, 1000 items echoed in the report (`items_truncated`), 20,000 indicators in total. Over a limit the request fails with 400 or 413; nothing is partly imported.

### Formats

* **STIX 2.1 bundle.** `indicator` objects with `pattern_type: stix`. Other object types are counted in `ignored_objects`. Revoked indicators are rejected. `valid_from` and `valid_until` are kept. TLP comes from `object_marking_refs` (the four well-known TLP marking ids, or `marking-definition` objects in the bundle with `definition_type: tlp`); the most restrictive wins. `confidence` maps to severity (>=80 high, <40 low, otherwise medium).
* **MISP.** An event, `{"Event": ...}`, or `{"response": [{"Event": ...}]}`. Event attributes and object attributes with `to_ids` true are imported; deleted attributes and `to_ids` false are rejected. Types: `md5`, `sha1`, `sha256`, `filename|<hash>`, `domain`, `hostname`, `ip-src`, `ip-dst`, `url`, `email`, `email-src`, `email-dst`. TLP comes from `tlp:*` tags on the event and the attribute (most restrictive wins). MISP has no expiry field that is used here, so the per-source expiry applies.
* **CSV.** With a header row containing `value` (or `indicator`/`ioc`); optional columns `type`, `tlp`, `valid_from`, `valid_until` (or `expires`), `severity`, `description`. Without a header a row is `value` or `type,value`.
* **TXT.** One indicator per line (the whole line is the value, so URLs with commas work). `#` starts a comment line. The type is detected from the exact shape: hash length, IP, URL, email, otherwise domain.

Types: `sha256`, `sha1`, `md5`, `ipv4`, `ipv6`, `domain`, `url`, `email`. Values are validated and normalised (hashes, domains and emails lower-cased). Nothing is repaired: defanged values (`hxxp://`, `[.]`), CIDR ranges, bare labels and values with whitespace are rejected with a reason.

### STIX pattern subset

The parser is a small hand-written tokenizer (no regular expressions, no recursion, no evaluation; pattern length capped at 4096 bytes and 512 tokens). Supported:

```
[file:hashes.'SHA-256' = '<hex>']        (also SHA-1, MD5)
[ipv4-addr:value = '203.0.113.9']        [ipv6-addr:value = '2001:db8::1']
[domain-name:value = 'evil.example']     [url:value = 'http://evil.example/x']
[email-addr:value = 'a@evil.example']
[domain-name:value = 'a.example' OR domain-name:value = 'b.example']   one indicator per comparison
```

Rejected with a reason: `AND`, `NOT`, `LIKE`, `MATCHES`, `IN`, `ISSUBSET`, `!=`, `<`/`>`, parentheses, several bracketed observations, `FOLLOWEDBY`, `WITHIN`/`REPEATS`/`START`/`STOP`, other object types or properties, other hash algorithms, and `pattern_type` other than `stix` (Sigma, YARA, Snort and so on). Unsupported patterns are never approximated.

### Report

Per item: `status` is `valid` (dry run), `imported`, `updated` (an earlier import of the same value had its validity and TLP refreshed), `duplicate` (repeated in the file, or already present from another source; left unchanged) or `rejected` with a `reason`. An indicator whose `valid_until` is already past is rejected.

## Aging

Each imported indicator without its own `valid_until` expires after the source's default:

* `KAVACH_IOC_DEFAULT_TTL_DAYS` (default 90; `0` means never expire)
* `KAVACH_IOC_SOURCE_TTL_DAYS` per source, e.g. `misp-prod=30,partner=0`

An indicator outside `valid_from`..`valid_until` does not match. Expired indicators are **kept** (visible in `GET /v1/ioc` and counted by the stats) so there is an audit trail; remove one explicitly with `DELETE /v1/ioc?id=`. Indicators that predate this feature, or are added with `POST /v1/ioc` or by an intel feed, have no expiry unless the feed manages one.

Each match increments the indicator's `sightings` counter and `last_seen`. Only counts are stored, never event content.

Matching is the existing case-insensitive substring match against command lines, URLs and similar text, so a short indicator can match inside a longer string.

## Statistics

`GET /v1/ioc/stats` (any valid token; CLI `kavachctl ioc stats`; MCP tool `kavach_ioc_stats`, read-only) returns totals, `active`, `expired`, `not_yet_valid`, `by_type`, `by_source` (with expired and sightings per source), `by_tlp` (`unmarked` when no marking) and `sightings_total`.

## State

Imported indicators and their counters are stored in `<store>.iocimport.json` (see [persistence-files.md](persistence-files.md)). Importing over MCP is deliberately not available.

## TLP

TLP is a label carried through for your own handling. Kavach does not share indicators, so the marking does not change behaviour. Unknown markings are rejected rather than ignored.
