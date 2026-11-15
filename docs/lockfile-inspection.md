# Dependency file (lockfile) inspection

Kavach's artifact inspector has a `lockfile` kind. An analyst submits a dependency file; Kavach parses it, builds a CycloneDX 1.5 SBOM, matches the components against advisory data it already holds locally, and reports hygiene problems. It is observation only.

What it never does:

- execute anything or follow includes (`-r other.txt`, parent POMs, workspace paths); only the submitted bytes are read
- open a network connection or call out to any service; component names are never sent anywhere
- store the submitted bytes (the inspector keeps only the report and the sha256)

Code: `internal/edr/inspect_lockfile_*.go`. A structure test fails if those files import `net`/`net/http` or call `os.ReadFile`/`exec`.

## Formats parsed

| Format | Direct/transitive | Integrity hash | Notes |
|---|---|---|---|
| `package-lock.json` v1, v2, v3 | v2/v3 yes (root deps); v1 unknown | `integrity` | v2/v3 use `packages`; v1 walks nested `dependencies` (depth 64) |
| `yarn.lock` v1 | unknown | `integrity`, or sha1 from the `resolved` fragment | Yarn Berry (v2+) is detected and reported, not parsed |
| `pnpm-lock.yaml` | yes (importers / top-level deps) | `resolution.integrity` | via `miniYAMLParse`, see below |
| `requirements.txt` | all direct (manifest) | `--hash` presence only | only `==` / `===` is a pin |
| `Pipfile.lock` | unknown | `hashes[0]` | |
| `poetry.lock` | unknown | first file hash | TOML subset |
| `Cargo.lock` | unknown | `checksum` | TOML subset; sourceless (first-party) packages skipped |
| `go.mod` | yes (`// indirect`) | none | `replace` is counted, not applied |
| `go.sum` | unknown | `h1:` | `/go.mod` lines ignored |
| `Gemfile.lock` | yes (`DEPENDENCIES`) | `CHECKSUMS` section if present | platform suffix stripped from versions |
| `composer.lock` | unknown | dist `shasum` (SHA-1, often empty) | |
| `pom.xml` | direct only | none | literal versions only |
| Gradle lockfile (`gradle.lockfile`, `*.lockfile`) | unknown | none | `group:artifact:version=configs` |
| NuGet `packages.lock.json` | yes (`type`) | `contentHash` | `Project` entries skipped |
| `dpkg -l`, `rpm -qa`, `apk info -v` | n/a | none | sniffed by content when the name does not say |

The format is chosen from the submitted name first, then by content sniffing.

### Unsupported or partial, reported in the finding `sca-limits` and Meta `lockfile.summary.notes`

- **pnpm**: `miniYAMLParse` has no flow mappings, anchors/aliases, tags or multiple documents. `resolution: {integrity: ..}` lines are rewritten to block form, other flow mappings (`engines: {node: ..}`) are dropped, and anything else it rejects makes the file a `sca-parse-error`. Peer-suffix variants of one version are collapsed.
- **Yarn Berry**: not parsed.
- **poetry.lock / Cargo.lock**: the TOML reader is a small hand parser for `[[package]]` tables, `key = "string"` pairs, `[package.source]`, and the first `hash = "..."` in a `files = [...]` array. It is not a general TOML parser and never errors on unknown syntax.
- **pom.xml**: `${property}` substitution, parent POM inheritance, `dependencyManagement`, BOM imports and profiles are out of scope. Such dependencies are listed without a version, reported as unpinned, and never matched. Version ranges (`[1,2)`, `LATEST`) are range findings.
- **requirements.txt**: `-r`/`-c` includes are not followed; environment markers are ignored; URL / VCS requirements are not registry pins.
- **go.mod**: `replace` directives are not applied.
- Package-list formats carry no direct/transitive data and no hashes. `rpm -qa` output has no epoch (assumed 0).
- Each file is capped at 50,000 components (`limits_hit: lockfile:components`); the embedded SBOM at 10,000.

## Version comparison: exactly what is supported

Matching reuses Kavach's inventory matcher (`vmMatch`) and the cached OSV/KEV feeds, then re-checks each match with an ecosystem-aware comparison. Where the comparison is outside the supported subset, the result is **unknown**, reported as a low-severity, weight-5 finding titled "version comparison unknown" and marked `UNVERIFIED`. Kavach does not guess.

| Scheme | Ecosystems | Supported | Not supported (-> unknown) |
|---|---|---|---|
| semver | npm, cargo, go, nuget, composer | optional `v`/`=`, 1-4 numeric core parts, `-prerelease` with SemVer 2.0 precedence, `+build` ignored (incl. Go `+incompatible`), arbitrary-length numbers | ranges, `dev-*` branches, non-numeric cores |
| PEP 440 | pypi | epoch, release, a/b/rc (and alpha/beta/c/pre/preview), `.postN`, `-N`, `.devN`, local `+x` ignored | legacy non-PEP-440 versions |
| Maven | maven | numeric and qualifier items; alpha < beta < milestone < rc/snapshot < release < sp | unknown qualifiers; the `1-1` vs `1.1` distinction; snapshot is ranked equal to rc |
| Debian | deb | full dpkg algorithm with epoch, upstream, revision, `~` | malformed epoch |
| RPM | rpm | `rpmvercmp` with epoch, `~` and `^`; release compared only when both sides have one | malformed epoch |
| Alpine | apk | numeric core, one letter, `_alpha/_beta/_pre/_rc` before and `_cvs/_svn/_git/_hg/_p` after release, `-rN` | other suffixes |
| RubyGems | gem | numeric and alphabetic segments; alphabetic = prerelease | non-alphanumeric characters |

OSV-derived matches (`source: osv`) are exact-version hits from the cache and are not re-compared.

Advisory names must equal the component name in its ecosystem form: Maven `group:artifact`, Go full module path, npm scoped `@scope/name`, PyPI normalised lowercase with `-`. The embedded sample advisories (openssl, curl, openssh, sudo, zlib) are demonstration data only. The data source is whatever is loaded locally: the embedded sample, `KAVACH_CVE_FILE`, cached KEV/OSV feeds. If none cover a package, nothing matches; a clean result is not proof of safety.

## Findings and weights

| ID | Severity | Weight |
|---|---|---|
| `sca-<cve>` critical / high / medium / low (from advisory CVSS 9+/7+/4+/>0; no score = medium) | as shown | 40 / 25 / 12 / 5, total capped at 60 across all SCA matches |
| `sca-unpinned` (no version constraint) | low | 4 |
| `sca-range` (range or wildcard specifier) | low | 3 |
| `sca-no-integrity` (format normally carries a hash, entry has none) | low | 2 |
| `sca-git-dependency` | medium | 6 |
| `sca-insecure-registry` (resolved/index over `http://`) | medium | 6 |
| `sca-typosquat` | low | 3 |
| `sca-known-malicious` (name, `name@ver` or purl equals an enabled IOC-store value) | high | 50 |
| `sca-limits`, `sca-parse-error`, `sca-format-unknown` | info | 0 |

Hygiene findings are aggregated per category (up to 8 example names). Typosquat findings are individual, capped at 20.

Each `sca-<cve>` evidence line carries package and version, the fixed version when the advisory states one, CVSS, KEV status, source, and the SSVC outcome. SSVC comes from `vpBuildFactors` + `ssvcEvaluate` (the vuln-priority code). Kavach has no EPSS/asset context for a submitted file, so unknown decision points use the documented defaults and the evidence shows the best-to-worst outcome range (for example `Attend [range Track..Act]`). It is a prioritisation hint, not a verdict.

The inspector's score is the sum of the top 10 finding weights, so hygiene findings alone cannot reach the "suspicious" line (40).

### Typosquat list

Edit distance 1 (insertion, deletion, substitution or adjacent swap) from an embedded list, names of 5+ characters, not flagged when the name is itself in the list. The list is NOT a reputation database. npm and PyPI carry about 100 names each; Go, Cargo, RubyGems, Composer, Maven and NuGet carry 12-35. Legitimate packages one edit from a popular name will be flagged low. Known-malicious names are matched only against the IOC store; Kavach ships no package-malware list.

## SBOM

Report `Meta["lockfile.sbom"]` is a CycloneDX 1.5 JSON document: `bomFormat`, `specVersion: "1.5"`, a deterministic `serialNumber` (derived from the input hash), `metadata`, `components` (type `library`, `bom-ref`, `purl`, `version`, `hashes` when the recorded integrity is an SRI or hex digest; Go `h1:` hashes are not CycloneDX hashes and are omitted) and `vulnerabilities` that point at component `bom-ref`s. No `dependencies` graph is emitted: the formats parsed here mostly do not provide one in a form Kavach reads. It is produced by a small separate emitter because `vmCycloneDX` works on the live host inventory and cannot take parsed components.

## Tests

`inspect_lockfile_test.go`: a golden fixture per format (by name and by sniffing), hostile inputs (deep JSON, XML entity bombs, tabs in YAML, NULs, 10k-package TOML), version tables per scheme including antisymmetry, matching against a synthetic advisory set, the weight cap, unknown-comparison fallback, CycloneDX structural validity, the no-network structure test, and a short fuzz target per parser.
