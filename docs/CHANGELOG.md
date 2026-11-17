# Changelog

Kavach is an observation-only security platform: every change below detects, reports or stores records. Nothing here contains, kills or blocks.

This file was written from `git log` and the docs on 2026-11-16, grouped by area. It is a summary, not a release process: the repository has tags `v0.1.0`, `v0.2.0`, `v0.2.1`, `v0.2.2` and `v0.2.3`; each section describes the commits since the previous tag. Changes after `v0.2.3` are under Unreleased. Counts such as rule totals come from the commit messages and the linked docs and were not recounted.

There was no changelog file before this one, and no version string in the source tree, so the tag is the only version marker.

## Unreleased

- Compliance framework verification pass (2026-11-17): Singapore CCoP ids now follow the official 2026 edition section numbers, Canada CCCS ids follow baseline controls 3.1-3.13 (two non-baseline controls removed), South Korea ISMS-P breach control moved to 2.11, FedRAMP CA family title corrected. Australia ISM, Japan METI/NISC, UAE IA, HKMA/PCPD, `ae-pdpl` and `hk-pdpo` stay UNVERIFIED (official sources unreachable). See [verification-log](verification-log.md).

## v0.2.3 (2026-11-17)

### Security and robustness
- Server flag `-client-auth require|optional` (default `require`); `optional` verifies a client certificate only when one is presented. The Helm chart passes it from `mtls.mode`. With `mtls.mode=required` kubelet plain-HTTPS probes still fail the handshake (documented). Not tested on live Kubernetes.
- A corrupt `<store>.incidents` file is moved to `.incidents.corrupt-<unixtime>` instead of blocking start; a corrupt credentials file still fails closed with a clear error and never prints its contents.
- Removed `KAVACH_TLS_INSECURE` and `tls.agentInsecureSkipVerify` from the chart.
- `kavachctl` accepts `KAVACH_ADMIN_TOKEN` (environment or `~/.kavach/env`) as the lowest-precedence token source.

### Content
- Content versioning: `GET /v1/content/manifest`, admin `POST /v1/content/snapshots` (cap 20), `GET /v1/content/snapshots`, `GET /v1/content/diff`, optional HMAC with `KAVACH_CONTENT_SIGN_KEY`; `kavachctl content`, MCP tools. See [content-versioning](content-versioning.md).
- Validation lab fix: pack `labfix.json` (14 `lab-` rules). Scenarios passing 486/504 to 501/504; benign controls firing 0/63; three scenarios still fail. The earlier shortfall was scenarios that never passed, not a regression.
- IOC import: admin `POST /v1/ioc/import` (dry-run by default; STIX 2.1, MISP, CSV, text), IOC aging, `GET /v1/ioc/stats`, `kavachctl ioc`. See [ioc-import](ioc-import.md).

### Console
- Theme follows the OS (system, light, dark); Browse menu moved out of the scrolling strip; phone navigation wraps; contrast and table fixes. Checked in headless Chrome on synthetic data only.

## v0.2.2 (2026-11-16)

- Competitive matrix: backlog items 21 (cloud audit logs) and 24 (offline vulnerability matching) moved from open to partial, with evidence and limits.
- Changelog: v0.2.1 section corrected.

## v0.2.1 (2026-11-16)

### Fixes
- `/v1/ml/priority`: the optional factors `dns_anomaly`, `user_behaviour`, `peer_outlier` and `rule_fatigue` now influence score, coverage and the factor list (they were computed after the weighted sum and dropped). Regression test `TestMLExtFactorsReachPriorityScore`.
- CI: race job timeout raised from 15 to 30 minutes.
- Docs: full accuracy pass (see `docs/verification-log.md`).

## v0.2.0 (2026-11-16)

Twelve commits after `v0.1.0`, plus the merge of the `feat/observability-attack-compliance` branch.

### Content

- Unix content pack `ux2-*` for Linux, macOS, container and Kubernetes depth, with new validation scenarios (`val3`) and an extended benign corpus.
- Sigma importer v2: quantifiers, wildcards, `windash` and `base64offset` modifiers, authentication fields, regex safety, derived test samples, a noisy-rule guard, an admin dry-run route and Sigma export with a round trip. See [sigma-import](sigma-import.md).
- Cloud and SaaS audit-log rule pack `cld-` (batch `cloud-audit-v1`, 159 rules); see Cloud below.

### Inspector

- New analyzers: .NET, OneNote and extension or package files.
- Email-extra analyzer: ATT&CK T1566 tags, hidden links, QR hints, defanged-link restoration and a basic `.msg` detector.
- Report clustering and SARIF export (API only; no console control). See [artifact-analyzers](artifact-analyzers.md) and [url-email-inspection](url-email-inspection.md).

### Models

- No new model code after `v0.1.0`. The Models page gained four tabs, listed under Console.

### Reporting

- No new reporting features after `v0.1.0`; see Exposure for the new exposed-assets report.

### Exposure

- Offline software exposure reporting: CycloneDX and SPDX 2.x SBOM ingestion, operator advisory import (Kavach format, OSV, CISA KEV) and a ranked exposed-assets report. Nothing is fetched from the network; the built-in advisory set is a five-entry labelled sample. Optional exposure factor in `/v1/ml/priority` behind `KAVACH_EXPOSURE_PRIORITY=1`. See [exposure](exposure.md).
- `kavachctl` commands for the exposure report, advisories and SBOMs, with a parity test.

### Cloud

- Cloud and SaaS audit-log detection: `POST /v1/cloud/audit/events` (admin token) normalises AWS CloudTrail, Azure (Activity Log, Entra sign-in and audit), GCP Cloud Audit Logs, Okta System Log and Microsoft 365 records into events the existing rule engine evaluates; `GET /v1/cloud/audit/sources`; `kavachctl cloudaudit sources`. Push-only: Kavach calls no cloud API. Field shapes come from public provider documentation and were not replayed against real tenant exports. See [cloud-audit](cloud-audit.md).

### Console

- Command palette lookups (`host`, `cve`, `ioc`, `rule`, `case`, `finding`, `technique`, `huntpack`) and actions; sortable tables with column toggle and CSV/JSON export; per-page saved views kept in browser `localStorage`.
- Models page: four new tabs (DNS tunneling, Users, Peers, Alert fatigue) and a Priority factor reference; per-type learned events render correctly instead of `[object Object]`.
- Inspector page: URL, Email and Lockfile modes (the server already supported them).
- Light-theme contrast fixes (`--text-tertiary`, tags) and a `--danger-text` token.
- Static dashboard tests: every page resolves, inline script parses, Models and Inspector tabs have panes, text-token contrast, usability safety rules.
- Console QA notes added. Dark theme and phone width of the new features are unverified in a browser. See [console](console.md) and [console-qa](console-qa.md).

### CLI and MCP

- Surface parity work: `kavachctl` commands and read-only MCP tools for routes that lacked them, a GET-route parity test, and a CLI reference. See [cli-reference](cli-reference.md).
- `kavachctl` exposure, Sigma and cloud-audit commands; MCP tools for Sigma import and export.

### Security

- Security review hardening: route-walk authentication tests, request body caps, bounded in-memory state and new fuzz targets. See [security-review](security-review.md).

### CI

- Race-detector job timeout raised to 30 minutes because the `edr` test suite exceeds the 10-minute default; the non-race job runs `go test ./...`. See [testing](testing.md).

## v0.1.0

First tagged release. About 310 commits between 2026-11-12 and 2026-11-16. Summarised by area; follow the linked docs for detail and limits.

### Content

- Data-driven detection content framework with a seed pack and validation harness, then packs: macOS (136 rules), behavioural IOA (153), Windows, Linux A1 (170), cloud-v1 (195) with 33 cloud and container hunt packs, regional threat landscape, gap closers (`gaps-v1`, gap2 with 97 `gp2-*` rules), plus a telemetry pack. Registry, DNS, auth and module event types were wired into the rules, with a literal prefilter.
- Extended ATT&CK hunt pack library, curated query library, advisory guidance catalogue and report templates.
- Customer-authored content lifecycle with a Sigma-subset importer; detection rule health and lifecycle (metrics, testing shadow mode, hash-chained history).
- Benign false-positive corpus guard (51 rules tuned); ATT&CK mapping fixes.
- Content versioning and a telemetry blind-spot report; 60 public adversary profiles with a coverage API; adversary-technique similarity.
- Detection validation lab (synthetic scenario replay, per-technique scoring) and continuous control validation with regression diffs. See [content-framework](content-framework.md), [rule-health](rule-health.md), [research-validation-lab](research-validation-lab.md).

### Inspector

- Artifact inspector contract, analyzer registry and limits; file analyzers (PE, ELF, Mach-O, OOXML, PDF, OLE2, archives, LNK, ISO, VBA macros), script and command-line deobfuscation, byte-pattern rule engine (151 rules), domain inspector (offline DGA scorer), configuration assessment (150 embedded policies), lockfile SCA analyzer, URL and email inspectors, obfuscation statistics, similarity hashing (kavach-ctph, kavach-lsh) with a Similar submissions view. See [artifact-analyzers](artifact-analyzers.md).

### Models

- Fleet-learned local models: process lineage, command similarity, hour-of-week baselines, beaconing, draft-rule synthesis and priority fusion; later DNS tunneling and DGA, user baseline, peer outliers and alert fatigue. Provenance-graph stories, metadata-only ransomware behaviour scoring, TTP similarity and next-technique hints, each with synthetic evaluation and stated limits. See [local-models](local-models.md), [research-provenance](research-provenance.md), [research-ransomware](research-ransomware.md), [research-ttp](research-ttp.md).
- Analyst feedback loop: hash-chained verdicts and per-rule precision.

### Reporting

- Executive posture report, findings export, SIEM and standards export (OCSF, ECS, CEF, LEEF, Splunk HEC, STIX 2.1, ATT&CK layer).
- Compliance evidence: 18 framework catalogs and 230 controls scored per control with an honest "not observable" state, CERT-In clock, regional incident-reporting clocks, posture trend, executive digest and auditor evidence bundle.
- Scheduled pull-only reports, fleet SLO views, scheduled detections with hunt quotas and expiring exceptions, attack chains, case workflow with templates and SLAs, offline evidence import. See [compliance-evidence](compliance-evidence.md), [posture-reports](posture-reports.md), [regional-reporting](regional-reporting.md), [siem-export](siem-export.md).

### Exposure

- Software inventory, vulnerability management and CycloneDX SBOM export; opt-in CISA KEV and OSV feeds; SSVC prioritisation with an opt-in EPSS feed; worldwide CERT advisory feeds with inventory correlation; Spotlight-style posture (asset criticality, drift). See [vuln-feeds](vuln-feeds.md), [vuln-priority](vuln-priority.md), [cert-feeds](cert-feeds.md).

### Cloud

- Cloud-v1 content pack and cloud and container hunt packs, container visibility, and cloud posture ledgers. No native cloud audit-log ingestion yet (added in v0.2.0).

### Console

- Initial Netra-sister console, then pages for every area above: Search, Models, Inspector, Provenance, Ransomware behaviour, TTP similarity, Regulatory clocks, CERT advisories, Adversaries, Rule health, Export, Content library, Coverage, Sequence hunt, Vulnerability priority, Feedback, Attack chains, Automation, Reports and SLO, Content versions, Syslog, Competitive, Posture trend, Executive digest and Auditor bundle. Command palette, `g` shortcuts and hash routing. Finance, Sectors and eBPF pages. See [console](console.md).

### CLI and MCP

- `kavachctl` (grouped commands, watch, doctor, completion, table views) and the `kavach-mcp` stdio server, with read-only MCP tools for most areas above. See [kavachctl](kavachctl.md), [mcp-integration](mcp-integration.md), [cli-reference](cli-reference.md).

### Security

- Metadata-only collection by design, HttpOnly session cookie, signed alert webhooks, hash-chained journal and verdict logs, data governance (inventory, retention, redaction, subject lookup), opt-in agentless syslog listener, agent mTLS. See [agent-mtls](agent-mtls.md), [security-review](security-review.md).

### CI

- Go test and vet workflows, a Docker build, an Envoy Gateway front door, a persistent TLS cert Secret for redeploys, GitHub Pages docs site, route-coverage and docs-index tests, and a docs count and index guard. See [testing](testing.md), [deploy-remote](deploy-remote.md).

## Not covered here

Observation boundary: response, containment and blocking are out of scope by design and are not planned; see [competitive-analysis](competitive-analysis.md).
