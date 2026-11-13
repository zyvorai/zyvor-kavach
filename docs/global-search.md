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
