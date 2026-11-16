# Global search

`GET /v1/search?q=&types=&limit=` looks across findings, hosts, content rules,
hunt packs, library queries, guidance, ATT&CK techniques, CVEs, IOCs, cases
and saved searches. Read-only, bearer or session auth.

## Research notes (own words)

A brief look at how other consoles do cross-entity search and pivoting. The
first broad search returned mostly vendor press releases, so these notes rest
on two vendor-documentation pages and are deliberately modest.

- Elastic Security treats a host name or similar field as a pivot key: from an
  alert or entity view you open Timeline pre-filtered on that value, and any
  field:value can be dragged in to widen the hunt. Search is therefore
  "pick an entity, then pivot", not one box that returns everything.
  https://www.elastic.co/docs/solutions/security/investigate/timeline
- Microsoft Defender XDR offers "go hunt": from an incident, entity or
  timeline event it generates an advanced hunting query for that entity.
  Hunting itself is query-based (KQL) with row and time quotas, so a typed
  global box is a lighter complement. https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-go-hunt
  and https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview
- Not verified: CrowdStrike Falcon's own search UI (the search only surfaced
  marketing material). Its indicator management correlates IOCs with endpoint
  telemetry, which matches the IOC-as-entity idea used here.

Takeaways applied: typed results so the user sees what kind of thing matched;
every result carries a route so it is a pivot, not a dead end; IDs rank above
free-text matches because analysts paste identifiers (T1059, CVE-..., case ids,
hostnames) far more often than prose.

## Behaviour

- Matching is case-insensitive substring. User input is never compiled into a
  regex, so there is nothing to escape and no backtracking risk.
- Score: exact id 100, id prefix 80, id substring 60, title exact 55, title
  prefix 50, title substring 40, other field 20, multi-word all-present 10.
  Ties break by type order, then id.
- Caps: query 2-128 chars, limit default 20 / max 100, at most 5000 items
  examined per type per request (findings newest first).
- Cases are read from the case store's JSON file (size capped at 8 MB) because
  the case manager is private to its registration.
- `types` values: finding, host, rule, huntpack, query, guidance, technique,
  cve, ioc, case, saved. Unknown types return 400.

Clients: `kavachctl search QUERY [--type T,...] [--limit N] [--json]`, MCP tool
`global_search`, console Search page (`g /`, or Ctrl/Cmd+K then pick "Search
everything").

## Result shape and routes

Each hit has `type`, `id`, `title`, an optional `subtitle`, `score` and a console `route` hash. The route is where the console sends you when you open the hit:

| type | route |
|------|-------|
| finding, saved | `#/detections` |
| host | `#/hosts` |
| rule, query, guidance, technique | `#/content` |
| huntpack | `#/huntpacks` |
| cve | `#/vulns` |
| ioc | `#/intel` |
| case | `#/cases` |

## Console Search page

Open it with `g /`, from the Browse menu (`#/search`), or from the command palette.

- Controls: a search box (2 to 128 characters), a result type select (All types plus the eleven types above, with the labels Findings, Hosts, Rules, Hunt packs, Queries, Guidance, Techniques, CVEs, IOCs, Cases, Saved searches), arrow keys to move through results and Enter to open the highlighted one.
- Empty state: "Type at least 2 characters. Use the arrow keys to move through results, Enter to open."
- Palette lookups: in the command palette `host web01`, `cve CVE-2024-1234`, `ioc <value>`, `rule`, `case`, `finding`, `technique` and `huntpack` followed by text run this page with the type preset. A bare CVE id, IPv4 address, 32 to 64 character hex hash or dotted domain is treated as a lookup too (CVE ids preset `cve`, the others `ioc`). "Search everything for ..." runs it with all types.
- Saved views (a per-page bar) store the query and type in this browser only; see [console](console.md).
- Known limit: in the palette the `/` key opens the palette, and `g` then `/` opens this page; the two are different shortcuts.

## Limits and honesty

- Substring matching only: no stemming, typo tolerance or field syntax. `T1059` finds `T1059.001` by prefix, but `1059` finds it only as a substring and ranks lower.
- At most 5000 items per type are examined, newest first for findings, so an old finding in a very large store may not be reachable by search; use the Export page or the API listing for those.
- Case search reads the case store file directly, with its size capped at 8 MB.
- The matched fields for each type are chosen in code (`internal/edr/global_search.go`), so not every field of every record is searched.
- Dark mode and phone width of the Search page are unverified in a browser (see [console-qa](console-qa.md)).
