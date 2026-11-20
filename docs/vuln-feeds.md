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

## Worked examples

```sh
# opt in (server environment), then:
KAVACH_VULN_FEED=kev,osv go run ./cmd/kavach -mode server -listen 127.0.0.1:8099
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" http://127.0.0.1:8099/v1/vulns/feeds/status
# {"enabled":["kev","osv"],"source":"feeds:kev,osv","last_refresh":"...","kev_count":1200,
#  "osv_cached_packages":87,"osv_cached_vulns":143,"feed_errors":[],"offline_file":"","note":"osv.dev receives package name, ecosystem and version only; cisa.gov receives a plain GET"}
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" http://127.0.0.1:8099/v1/vulns/feeds/refresh
# 200 with the same status object; 409 {"error":"network feeds disabled; set KAVACH_VULN_FEED=kev,osv","status":{...}} when disabled
```

With no feed enabled, status reports `source: "embedded-sample"` and a note saying so (`offline_file` shows `KAVACH_CVE_FILE` when set). The `source_status` block on `/v1/vulns/{advisories,findings,exposure,top}` carries `advisory_source`, `source`, `enabled_feeds`, `last_refresh`, `kev_count`, `feed_errors` and `note`. Values above are illustrative.

## Details and limits

- Exposure score per host (`vmExposure`): `min(100, int(8 x highest CVSS) + 2 x findings)`, plus 20 when any finding is KEV-listed. OSV records with no severity label get a neutral CVSS of 5.0; labels map LOW 3.5, MODERATE/MEDIUM 5.5, HIGH 8.0, CRITICAL 9.5. Advisory summaries are cut at 200 characters.
- Refresh: at start and every 6 h in a background goroutine (10 min budget per run); manual refresh has a 5 min budget. An HTTP client timeout of 30 s applies per request. A failed refresh keeps the previous cache and is listed in `feed_errors`.
- Cache: `<store path>.vulncache.json` (KEV map with date added, OSV per-package results with a 24 h TTL, OSV vulnerability details), written atomically with mode 0600.
- Allowed hosts are fixed in code (`www.cisa.gov`, `cisa.gov`, `api.osv.dev`); a redirect to anything else fails. The data is only as complete as these two feeds and the inventory rows that carry ecosystem and version; a package whose ecosystem cannot be mapped is skipped and therefore never reported, which is not the same as clean.
- Relationship to other features: priority ranking on top of these matches is in [vuln-priority.md](vuln-priority.md); SBOM-based exposure (offline, operator-imported advisories) is in [exposure.md](exposure.md).
