# Software exposure reporting

Kavach is observation-only. This feature reports which assets carry software that matches a known advisory. It never scans, patches, updates or blocks anything.

**Everything is local and offline.** SBOMs are pushed to Kavach by the operator, advisories are loaded from files by the operator, and matching runs inside the controller. No network request is made. The embedded advisory dataset is a small labelled SAMPLE (five well-known entries) and is **not a complete or current vulnerability feed**. "Not exposed" only ever means "not exposed to the advisories currently loaded". For real coverage import your own KEV/OSV data (below). The opt-in online feeds in [vuln-feeds.md](vuln-feeds.md) and the lockfile analyzer in [lockfile-inspection.md](lockfile-inspection.md) are separate features.

## Ingesting SBOMs

`PUT /v1/exposure/sboms/{host}` (also `POST`) with the SBOM JSON as the body. Requires the admin token (a browser session is refused with 403); body capped at 8 MiB, 20000 components per SBOM, 2000 hosts. Accepted: CycloneDX JSON (`bomFormat`, nested components are walked) and SPDX 2.x JSON (`spdxVersion`; the purl is taken from `externalRefs` of type `purl`). SPDX 3 and XML/tag-value forms are rejected with 400.

Only counts and component metadata are retained: name, version, purl, type. Hashes, licences, dependency graphs, supplier data and everything else are dropped. A re-ingest replaces the host's SBOM. Reads (`GET /v1/exposure/sboms`, `GET /v1/exposure/sboms/{host}`) need normal auth; `DELETE` needs the admin token.

## Advisory dataset

`GET /v1/exposure/advisories` shows the active set and whether it is the sample. Until an operator imports data, the embedded SAMPLE is used; once an operator set is present it replaces the sample entirely.

`POST /v1/exposure/advisories/import` (admin token, 8 MiB) accepts, auto-detected:

1. **Kavach format** `kavach-advisories/1`:

```json
{"format":"kavach-advisories/1","source":"my-feed","advisories":[
 {"id":"CVE-2099-1000","aliases":["GHSA-xxxx"],"purl":"pkg:npm/lodash",
  "ranges":[{"introduced":"4.17.0","fixed":"4.17.21"}],
  "versions":["1.0.0"],"severity":"high","cvss":8.1,"kev":false,"summary":"text"}]}
```

`purl` is the package without version, qualifiers or subpath. A range matches when `introduced <= v` (empty or `0` means from the start) and `v < fixed` (or `v <= last_affected`). `versions` lists exact affected versions. `severity` is low, medium, high or critical. Each advisory needs `id`, a valid `purl`, and `ranges` or `versions`.

2. **OSV records**: one object, an array, or `{"vulns":[...]}`. `affected[].package.purl` is used, otherwise ecosystem and name are mapped for npm, PyPI, Go, Maven (`group:artifact`), RubyGems, crates.io and NuGet. Other ecosystems (for example Debian) and GIT ranges are skipped, not guessed. `database_specific.severity` is used when present.
3. **CISA KEV catalogue** (`{"vulnerabilities":[{"cveID":...}]}`): flags already-imported advisories whose id or alias is listed as `known-exploited`. Import advisories first, then the KEV file.

Query parameters: `mode=merge` (default, upsert by id and purl) or `mode=replace`; `source=label` is shown in reports. `DELETE /v1/exposure/advisories` returns to the sample.

## Matching

Components are matched by purl (type, namespace and name, case-insensitive; PyPI names normalised) and compared with the ecosystem version rules already used by the lockfile analyzer (semver, PEP 440, Maven, deb, rpm, apk, gem). Components without a purl or version are not matched and are counted (`components` versus `components_with_purl`). If a version cannot be compared under its scheme the check is counted in `indeterminate_version_checks` and is never reported as exposed.

## Report

`GET /v1/exposure/report?host=&min_score=` lists only hosts with at least one match, ranked by score. Each asset carries `matches` (advisory id, package, version, `fixed_in`, severity, CVSS, KEV flag) and `factors`:

| Factor | Weight | Meaning |
|---|---:|---|
| `known_exploited` | 0.45 | 1 if any match is flagged KEV in the loaded dataset |
| `max_severity` | 0.35 | highest CVSS (or severity-derived value) / 10 |
| `breadth` | 0.20 | exposed package versions / 10, saturating |

The score is the weighted sum scaled to 0-100; `level` is none, low, medium, high or critical using the same bands as `/v1/ml/priority`. Asset criticality from `/v1/posture/assets` is shown as a zero-weight context factor. The response states `advisory_sample` and carries the disclaimer.

## Optional priority factor

With `KAVACH_EXPOSURE_PRIORITY=1`, `GET /v1/ml/priority` gains an `exposure` factor (weight 0.10) for findings on hosts that have an SBOM: the host's exposure score / 100. Hosts without an SBOM list the factor under `omitted`. It is off by default and advisory only; `/v1/ai/score` is unchanged.

## State and limits

State is persisted in `<store>.exposure.json` (see [persistence-files.md](persistence-files.md)). No background goroutine is used; the only lifecycle registration is the stopper that detaches the optional priority hook. Limits: 8 MiB bodies, 20000 components per SBOM, 2000 hosts, 50000 advisories.
