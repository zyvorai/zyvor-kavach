# Changelog

Kavach is an observation-only security platform: every change below detects, reports or stores records. Nothing here contains, kills or blocks.

This file was written from `git log` and the docs on 2026-11-16, grouped by area. It is a summary, not a release process: the repository has tags `v0.1.0`, `v0.2.0`, `v0.2.1`, `v0.2.2`, `v0.2.3`, `v0.2.4` and `v0.2.5`; each section describes the commits since the previous tag. Changes after `v0.2.5` are under Unreleased. Counts such as rule totals come from the commit messages and the linked docs and were not recounted.

There was no changelog file before this one, and no version string in the source tree, so the tag is the only version marker.

## Unreleased

- Network-device configuration posture review (docs: [netcfg-posture.md](netcfg-posture.md), [RESEARCH-network-posture.md](RESEARCH-network-posture.md)): offline parsers for documented subsets of PAN-OS XML, FortiGate `show` text, Cisco ASA running-config, `iptables-save` and `nft list ruleset` feed one rule-base model with 20 `netcfg-*` rules (shadowed and redundant rules with explicit cost caps, any-any and any-service permits, risky services from untrusted sources, logging off, disabled and temporary rules, missing descriptions, unused and duplicate objects, management exposure and weak administrative protocols, weak crypto, default SNMP communities, cleartext and empty credential patterns, default-accept chains, logging off), a posture score and a diff of two exports. Routes `POST /v1/netcfg/analyze`, `POST /v1/netcfg/diff` (admin token), `GET /v1/netcfg/sources`; `kavachctl netcfg analyze|diff|sources`; test kind `netcfg` and 40 examples for the detection-as-code harness. ATT&CK guidance gained T1600, T1078.001 and T1040. Observation only and offline; credential values are never shown; parsers were not run against real device exports and fields marked [U] in the docs are unverified.
- Network-log analytics (docs: [network-detection.md](network-detection.md), [RESEARCH-vendors-network.md](RESEARCH-vendors-network.md)): offline Zeek (TSV and JSON), Suricata EVE, DNS query-log, AWS VPC and Azure NSG flow-log, NetFlow CSV and PAN-OS, FortiGate and Cisco ASA log subsets with 32 rules (`net-an-*`, `net-eve-*`: beaconing, long connections, scans, brute force, SMB and east-west fan-out, certificate and JA3/JA4 list checks, DGA, DNS tunnelling, NXDOMAIN storms, fast flux, exfiltration outliers, address-list contact, alert grouping, firewall deny and admin events) and an evidence timeline joining stored findings. Routes `POST /v1/net/logs`, `POST /v1/net/analyze` (admin token), `GET /v1/net/sources`, `GET /v1/net/timeline`; `kavachctl netlog analyze|sources|timeline`. ATT&CK guidance gained T1568, T1568.001, T1568.002 and T1562.004. Observation only and offline: nothing is captured, fetched, looked up or blocked; thresholds are fixed heuristics for summarising a supplied log.
- Posture, cloud and configuration analysis (observation-only, offline): F5 BIG-IP configuration format with 12 policies, 7 nginx proxy and logging policies, a versioned and operator-replaceable advisory table for BIG-IP and nginx versions (`config-advisory`, `KAVACH_CONFIG_ADVISORIES`; embedded sample entries are unverified against vendor pages), Terraform plan JSON and CloudFormation (JSON and YAML) exposure checks with 17 policies, a generic firewall and WAF rule export review (`config-firewall`, `fw-*` findings), and attack-path scoring that ranks internet exposure, vulnerable software, excess privilege and sensitive-data signals per asset (`GET /v1/exposure/attack-paths`, `POST /v1/exposure/attack-paths/evaluate`, `kavachctl exposure attack-paths`, MCP `kavach_attack_paths`). Config policies are now 186. Research and rationale in `docs/RESEARCH-vendors-posture.md`.
- Detection content and analytics (docs: [web-detection.md](web-detection.md), [RESEARCH-vendors-detection.md](RESEARCH-vendors-detection.md)): offline web access-log detection with a new `web-` content pack (49 rules, batch `web-access-v1`: injection, traversal and inclusion, command injection, framework and edge-appliance exploit probes, SSRF and metadata, scanner User-Agents, secret-file and admin-interface probes, web shell footprints); API discovery and a shadow-API check against an OpenAPI JSON you send (inventory, shadow and undocumented-but-protected endpoints, verb and query-parameter drift); built-in HTTP flood, login brute-force, credential-stuffing, path-enumeration and User-Agent-rotation detectors (`web-an-*`); authentication-log analytics (`auth-an-*`: credential stuffing, many sources against one account, velocity, success after a failure storm, impossible travel from geo fields in the log). Routes `POST /v1/web/logs`, `POST /v1/web/analyze`, `POST /v1/auth/logs` (admin token) and `GET /v1/web/sources`; `kavachctl web analyze|sources` and `kavachctl authlog analyze`. Observation only, offline: no log is fetched, no server contacted, no geo lookup, secret-looking query values redacted from evidence. Vendor and open-content research in `docs/RESEARCH-vendors-detection.md`.
- Identity, ransomware-log, exploit-intelligence and deception analytics (docs: [identity-detection.md](identity-detection.md), [ransomware-logs.md](ransomware-logs.md), [exploit-intel.md](exploit-intel.md), [tripwires.md](tripwires.md), [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md)): offline Okta and Microsoft Entra sign-in and audit log analytics (`idp-an-*`: MFA push fatigue then success, password spray, impossible travel, new device then privilege change, admin role grants, MFA removal, password reset then MFA enrolment, legacy authentication, dormant account use, session reuse from two places, authentication policy weakened, application credential or consent, provider risk) on `POST /v1/idp/logs`; ransomware indicators from file-activity and backup-job logs (`rwlog-an-*`: mass rename, extension churn, entropy flags, ransom-note spread, mass delete, recovery-inhibiting commands, backup deletion and weakening, vendor malware flags, backup size spikes, backup tampering near encryption) on `POST /v1/ransom/logs`; offline import of CISA KEV (JSON or CSV) and FIRST EPSS (CSV, gzip or API JSON) files with versions and expiry on `/v1/intel/exploit-feeds`, used to mark SBOM matches, feed SSVC and weight attack-path scores with every adjustment listed; a declared tripwire registry (honey accounts, decoy values, hosts, IPs and paths) matched against uploaded logs on `/v1/deception/tripwires`. New `kavachctl idplog|ransomlog|exploitintel|tripwire` commands and seven ATT&CK techniques with guidance (T1621, T1098.001, T1098.003, T1098.005, T1556, T1556.006, T1550.004). Observation only and offline: no provider, feed or decoy is contacted, no account is locked or reset, no file content is read, and allow-listed fields only.
- Detection as code (docs: [content-testing.md](content-testing.md)): `kavachctl content test` runs fixture-driven rule tests in the new `kavach-content-tests/1` JSON-lines format (raw log lines, records, events or a generator, expected and forbidden rule ids, line-numbered diffs, JSON output, non-zero exit); `content selftest` requires every `web-*` content rule and every built-in analytic rule to fire on its own positive example and stay quiet on its own negative one (examples in `internal/edr/content_examples/`, enforced on every `go test`); `content fp-report` replays benign logs you supply (or a built-in synthetic corpus) and reports per-rule hit counts and rates with redacted samples and noisy-rule flags; `content tested-coverage` reports ATT&CK techniques covered by rules that pass their own examples. CLI only, offline, no new routes. The first self-test run found one rule that missed its own attack: `web-recon-iot-router-probe` required a literal `+` in `/shell?cd+/tmp`, but the access-log normaliser turns `+` into a space before matching, so the real probe line never fired; the pattern now accepts either.
- Gateway API front door: Setura Gateway (`zyvor.dev/setura-gateway`, GatewayClass `setura`) replaces Envoy Gateway. Helm values `envoyGateway.*` are now `seturaGateway.*`, `--envoy-gateway` is `--setura-gateway`, `ensure-envoy-gateway.sh` is `ensure-setura-gateway.sh` and `docs/envoy-gateway.md` is `docs/setura-gateway.md`. The EnvoyProxy and BackendTrafficPolicy objects are gone. Not run on a live cluster.

## v0.2.5 (2026-11-17)

Docs only; no code changes since v0.2.4.

- Docs: `-client-auth optional` and `require` verified end to end against a local server with a throwaway CA; recorded in `docs/agent-mtls.md` and `docs/verification-log.md`. Still not run on a live cluster.

## v0.2.4 (2026-11-17)

### Security
- SIEM push webhook: URL validation (http/https, blocks loopback, link-local/metadata, unspecified, multicast, and private ranges unless `KAVACH_SIEM_ALLOW_PRIVATE=1`), dial-time IP re-check against DNS rebinding, redirect checks, and 3 attempts with capped backoff that stop at shutdown.
- `scripts/deploy-remote.sh` no longer prints the admin token; it logs only that one is set and whether the lab default is in use. Behaviour otherwise unchanged.

### Content and compliance
- Validation lab: investigated the 3 remaining failing scenarios (Normal.dotm persistence, fast-flux DNS, revoked-signer module). None is detectable from the telemetry as modelled without overfitting, so no rule was added; reasons documented. Refreshed the stale top-table numbers in `docs/research-validation-lab.md` to the measured 501/504 pass, 231 detected, 0 partial, 2 missed, 0/63 benign false positives.
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
