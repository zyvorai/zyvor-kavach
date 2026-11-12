# Vulnerability feeds

Kavach is observation-only: it matches the software inventory against advisories and gives advice; it never patches.

## Sources

| Source | Enabled by | Notes |
|---|---|---|
| Embedded SAMPLE set (5 entries) | default | Demo only, labelled `embedded-sample` |
| `KAVACH_CVE_FILE` | env path to JSON array of advisories | Offline source. Parse/read failures are logged and reported in `feed_errors`; the sample set is used only as a visible fallback |
| CISA KEV | `KAVACH_VULN_FEED=kev` | Matched CVEs get `known_exploited: true`; exposure score +20 |
| OSV.dev | `KAVACH_VULN_FEED=osv` | Per package name+ecosystem+version |

`KAVACH_VULN_FEED` is a comma list (`kev,osv`). Default off: no network traffic.

## What is sent

- osv.dev (`POST /v1/querybatch`, `GET /v1/vulns/{id}`): package name, ecosystem, version and OSV ids only. No hostnames, IPs, or other inventory fields.
- cisa.gov: plain GET of the KEV catalog; nothing is sent.
- Only `www.cisa.gov`/`cisa.gov` and `api.osv.dev` over https; max 3 redirects (re-checked against the allowlist); no user-controlled URLs; request timeout 30s; response size limits (KEV 16 MiB, OSV 8 MiB); OSV batches of 500, at most 200 detail fetches per refresh.

Ecosystem mapping: dpkg/apt->Debian, ubuntu->Ubuntu, apk->Alpine, rpm->Rocky Linux, pip->PyPI, npm, go->Go, cargo->crates.io, gem->RubyGems, maven, nuget. Rows may carry `ecosystem` or `manager`; otherwise Linux hosts are assumed dpkg (Debian). Unsupported rows are skipped.

## Cache and refresh

Results are cached at `<store path>.vulncache.json` (OSV per-package TTL 24h). When enabled, a background refresh runs at start and every 6h. Findings are served from cache; requests never block on the network.

## API

- `GET /v1/vulns/feeds/status` (auth): enabled feeds, last refresh, KEV/OSV counts, `feed_errors`, source.
- `POST /v1/vulns/feeds/refresh` (auth): refresh now; 409 if feeds are disabled.
- `/v1/vulns/{advisories,findings,exposure,top}` include `source_status` and `feed_errors`.
