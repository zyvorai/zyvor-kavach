# Kavach documentation

Start here if you cloned the repo and want the full story. Kavach is observation-only: it detects, scores and
explains, and never contains, kills, isolates or blocks. Measured detection rates and scores in these docs come
from synthetic corpora and heuristics; treat them as evidence about this software, not a guarantee about your
environment.

[index.md](index.md) lists every document by area and carries the generated feature inventory (counts are read
from the files). This page is the short reading order. The HTTP contract is
[openapi.yaml](https://github.com/zyvorai/zyvor-kavach/blob/main/docs/openapi.yaml); a Go test checks that every
registered route is listed in it, and another test checks that every file in `docs/` is linked from this page or
from the index.

Published site (synced from these files): https://zyvorai.github.io/zyvor-kavach/

## Read in this order

| Doc | Audience |
|-----|----------|
| [README](https://github.com/zyvorai/zyvor-kavach/blob/main/README.md) | Everyone: overview and quickstart |
| [tutorial.md](tutorial.md) | First-time operators: first hour, local run, CLI, hunt, eBPF |
| [architecture.md](architecture.md) | Engineers and reviewers: components, flags, data path, limits |
| [use-cases.md](use-cases.md) | SOC / IR / platform scenarios with commands |
| [testing.md](testing.md) | Contributors and CI: race and full suites, fixtures |

## Operate

| Doc | Audience |
|-----|----------|
| [console.md](console.md), [console-qa.md](console-qa.md) | UI login, layout, how the console was checked |
| [kavachctl.md](kavachctl.md), [cli-reference.md](cli-reference.md) | CLI operators; surface parity between HTTP, CLI and MCP |
| [mcp-integration.md](mcp-integration.md) | MCP / AI agents (read-only by default) |
| [observability.md](observability.md) | Probes, Prometheus metrics, ATT&CK, compliance score, SLOs, alerts, governance |
| [posture-reports.md](posture-reports.md) | Posture trend, executive digest, auditor bundle |
| [persistence-files.md](persistence-files.md) | Every on-disk state file, reset and backup |
| [deploy-remote.md](deploy-remote.md) | Lab / Kubernetes deploy and the gated deploy flow |
| [setura-gateway.md](setura-gateway.md) | Gateway API front door |
| [agent-mtls.md](agent-mtls.md) | Mutual TLS for agents |

## Data sources and integrations

| Doc | Audience |
|-----|----------|
| [ebpf.md](ebpf.md) | Sensor / kernel observe |
| [telemetry-types.md](telemetry-types.md) | Registry, DNS, auth and module telemetry |
| [syslog-listener.md](syslog-listener.md) | Agentless syslog from network gear |
| [cloud-audit.md](cloud-audit.md) | CloudTrail, Azure, GCP, Okta and M365 audit-log detection |
| [web-detection.md](web-detection.md) | Web access-log and auth-log detection, API discovery, flood and credential-stuffing summaries |
| [RESEARCH-vendors-detection.md](RESEARCH-vendors-detection.md) | Vendor and open-content detection survey with ranked ideas |
| [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md) | Identity, e-mail, threat-intel, SIEM, deception, ransomware and DSPM vendor survey with ranked ideas |
| [network-detection.md](network-detection.md) | Zeek, Suricata, DNS, flow and firewall log analytics; research in [RESEARCH-vendors-network.md](RESEARCH-vendors-network.md) |
| [identity-detection.md](identity-detection.md) | Okta and Entra sign-in and audit log analytics |
| [ransomware-logs.md](ransomware-logs.md) | Ransomware indicators from file-activity and backup-job logs |
| [content-testing.md](content-testing.md) | Detection as code: rule test files, self-test examples, benign-corpus false-positive report, ATT&CK coverage by tested rule |
| [exploit-intel.md](exploit-intel.md) | Offline KEV and EPSS import, weighting of SBOM findings and attack paths |
| [tripwires.md](tripwires.md) | Declared decoys matched against uploaded logs |
| [exposure.md](exposure.md) | SBOM-based software exposure (offline, sample advisory set until you import data) |
| [siem-export.md](siem-export.md) | OCSF, ECS, CEF, LEEF, Splunk HEC, STIX and Navigator export; optional push sink |
| [evidence-import.md](evidence-import.md) | Offline evidence import |
| [finance.md](finance.md), [sectors.md](sectors.md) | Banks, markets, insurance; rail, aviation, industry, space and government fleets (observe only) |

## Detection engineering

| Doc | Audience |
|-----|----------|
| [content-framework.md](content-framework.md) | JSON rule packs and the harness gate |
| [custom-content.md](custom-content.md), [content-tuning.md](content-tuning.md), [rule-health.md](rule-health.md) | Custom rules, benign guard, lifecycle and health |
| [sigma-import.md](sigma-import.md) | Sigma import and export |
| [research-validation-lab.md](research-validation-lab.md), [regression-tracking.md](regression-tracking.md) | Validation scenarios and continuous control validation |
| [local-models.md](local-models.md), [local-models-net.md](local-models-net.md) | Learned local behaviour, DNS, user, peer and beacon models |
| [research-hunt-language.md](research-hunt-language.md), [research-ttp.md](research-ttp.md), [research-provenance.md](research-provenance.md), [research-ransomware.md](research-ransomware.md), [research-obfuscation.md](research-obfuscation.md), [research-similarity.md](research-similarity.md), [research-feedback.md](research-feedback.md), [research-vuln-priority.md](research-vuln-priority.md) | Research notes with evaluation and honest limits |
| [adversary-profiles.md](adversary-profiles.md), [regional-threats.md](regional-threats.md) | Public adversary profiles and regional content (resemblance, not attribution) |

## Inspectors and search

| Doc | Audience |
|-----|----------|
| [artifact-analyzers.md](artifact-analyzers.md), [domain-inspector.md](domain-inspector.md), [url-email-inspection.md](url-email-inspection.md), [lockfile-inspection.md](lockfile-inspection.md), [config-assessment.md](config-assessment.md) | Parse-only static analyzers |
| [global-search.md](global-search.md) | Search across findings, hosts, rules, CVEs and more |

## Vulnerability, compliance and reporting

| Doc | Audience |
|-----|----------|
| [vuln-feeds.md](vuln-feeds.md), [vuln-priority.md](vuln-priority.md), [cert-feeds.md](cert-feeds.md) | Opt-in feeds and evidence-based prioritisation |
| [compliance-evidence.md](compliance-evidence.md), [regional-frameworks.md](regional-frameworks.md), [regional-reporting.md](regional-reporting.md) | Control evidence, framework catalogs, incident-reporting clocks (informational, not legal advice) |

## Assurance

| Doc | Audience |
|-----|----------|
| [security-review.md](security-review.md) | Security review of Kavach itself, accepted risks and what was not reviewed |
| [verification-log.md](verification-log.md) | Which research claims were verified against sources, and which are still unverified |
| [competitive-analysis.md](competitive-analysis.md) | Capability comparison from public documentation (may be out of date) |

## Reference material

| Doc | What |
|-----|------|
| [design/APPLE-UX-CONTRACT.md](design/APPLE-UX-CONTRACT.md) | Console design contract |
| [social/README.md](social/README.md) | Social hero image build notes |
