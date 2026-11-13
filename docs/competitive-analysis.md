# Competitive analysis

Last researched: 2026-11-13. Research-only; no engine behaviour changed. Data is also served at `GET /v1/world/competitive`.

> Competitor cells come from public vendor documentation and may be out of date or incomplete. Pages were read on the access date; SentinelOne and the Cortex XDR admin guide were blocked or unavailable. **Not doc.** means not found on the pages read, not that the capability is absent. Cells marked `(U)` are UNVERIFIED. Kavach cells come from this repository, with evidence below.

Products: CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender XDR, Elastic Security, Wazuh, Velociraptor, osquery + Fleet, Sysmon, Cortex XDR, Trend Vision One. Response and containment are out of scope for Kavach by design: it observes and reports and never contains, kills, or blocks.

## Capability matrix

| Capability | CrowdStrike Falcon | SentinelOne Singularity | Microsoft Defender XDR | Elastic Security | Wazuh | Velociraptor | osquery + Fleet | Sysmon / Sysinternals | Cortex XDR | Trend Vision One | Kavach |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Telemetry collection | Has | Partial (U) | Has | Has | Has | Has | Partial | Has | Has | Not doc. (U) | Partial |
| Detection engineering | Has | Partial (U) | Has | Has | Has | Has | Not doc. (U) | Not doc. | Has | Has | Has |
| Hunting / query languages | Partial | Partial (U) | Has | Partial | Partial | Has | Has | Not doc. | Not doc. (U) | Partial | Partial |
| Response / containment | Has | Partial (U) | Has | Has | Has | Has | Not doc. (U) | Partial | Has | Has | Out of scope |
| Vulnerability / exposure | Has | Has (U) | Has | Not doc. (U) | Has | Not doc. (U) | Partial | Not doc. | Not doc. (U) | Has | Partial |
| Identity | Has | Not doc. (U) | Has | Not doc. (U) | Not doc. (U) | Not doc. (U) | Not doc. (U) | Not doc. | Partial | Has | Partial |
| Cloud | Has | Not doc. (U) | Has | Partial | Has | Not doc. (U) | Not doc. (U) | Not doc. | Has | Has | Partial |
| Data lake / SIEM integration | Has | Not doc. (U) | Has | Has | Partial | Partial | Not doc. (U) | Partial | Has | Partial | Has |
| Case management | Partial | Not doc. (U) | Has | Not doc. (U) | Not doc. (U) | Not doc. (U) | Not doc. (U) | Not doc. | Not doc. (U) | Not doc. (U) | Has |
| Reporting | Partial | Not doc. (U) | Not doc. (U) | Not doc. (U) | Partial | Not doc. (U) | Partial | Not doc. | Partial | Not doc. (U) | Has |
| APIs and automation | Partial | Not doc. (U) | Has | Not doc. (U) | Partial | Has | Has | Not doc. | Has | Partial | Has |
| Deployment and agent footprint | Has | Not doc. (U) | Not doc. (U) | Has | Has | Has | Not doc. (U) | Has | Has | Not doc. (U) | Partial |
| Licensing model | Has | Not doc. (U) | Partial (U) | Has | Partial (U) | Has | Has | Partial | Not doc. (U) | Has | Has |

UNVERIFIED cells: 44 of 143. A Has/Partial cell marked (U) rests on secondary or partially read evidence only.

## Kavach evidence (read from repo)

- **Telemetry collection** (Partial): Process exec (internal/edr/edr.go Event: pid, ppid, uid, executable, parent_exe, command; no hashes/user name/cwd), network (ingest.go NetworkEvent: pid + destination only), file (file_events.go: path, operation, size; writer not attributable), registry/dns/auth/module via POST /v1/events/{type} (docs/telemetry-types.md), eBPF /v1/ebpf/events.
- **Detection engineering** (Has): Content rules + Sigma (/v1/content/rules, /v1/sigma, /v1/yara), custom content, lab validate/test/backtest (/v1/lab/rules/*), rule lifecycle and health (/v1/rules/lifecycle, /v1/rules/health), ATT&CK matrix (/v1/attack/matrix), ML behaviour/beacon.
- **Hunting / query languages** (Partial): Hunt packs, schedules, saved searches, query library, global search (/v1/hunts/*, /v1/queries/library, /v1/search); fixed filter queries, no general-purpose query language.
- **Response / containment** (Out of scope by design): By design. /v1/containment, /v1/rtr/sessions, /v1/prevention/policies only record requests (host_rtr.go ContainmentRequest.Status 'recorded (never enforced)', Enforced field).
- **Vulnerability / exposure** (Partial): /v1/vulns/feeds, /v1/spotlight/vulnerabilities, /v1/sbom/{host}, /v1/exposure (vuln_mgmt.go, vuln_feeds.go); inventory depth depends on collected software data.
- **Identity** (Partial): /v1/identity/events (ingest) and /v1/identity/entities, /v1/ueba, /v1/itdr/*, /v1/lateral (identity_ueba_fusion.go, itdr.go); no native directory collector.
- **Cloud** (Partial): /v1/cloud/posture, /v1/cnapp/*, /v1/containers are ledger/derived endpoints (mergeLive in world_platform.go, hunt_cases_audit.go); no native cloud-API collector evidenced.
- **Data lake / SIEM integration** (Has): /v1/siem/export (findings or events; CEF, LEEF, OCSF, ECS, STIX, Navigator layer per docs/siem-export.md), checkpointed polling, /v1/export; no own data lake.
- **Case management** (Has): /v1/cases, /v1/notes, /v1/journal, /v1/itsm/tickets, /v1/incidents (cases.go, analyst_workspace.go).
- **Reporting** (Has): /v1/reports/templates and render, /v1/digests, /v1/compliance/*, /v1/regulatory/*, /v1/trends (report_templates.go, compliance_*.go).
- **APIs and automation** (Has): REST under /v1/* with docs/openapi.yaml, kavachctl CLI (cmd/kavachctl), MCP server (cmd/kavach-mcp), webhooks/connectors (/v1/connectors), playbooks (/v1/fusion/playbooks, /v1/hyperautomation).
- **Deployment and agent footprint** (Partial): Go controller plus agent collectors (agent_collectors.go), eBPF on Linux (ebpf_linux.go, docs/ebpf.md), per-host credentials and mTLS (docs/agent-mtls.md); no measured footprint numbers in repo.
- **Licensing model** (Has): Source header LicenseRef-Zyvor-Production-1.0 (commercial/proprietary reference, not an open-source licence).

## Per-product notes with sources

### CrowdStrike Falcon
- Telemetry collection: **Has** - Single lightweight sensor collecting cross-domain telemetry. [S1]
- Detection engineering: **Has** - AI-driven real-time detection documented; rule-authoring surface not described on pages read. [S1]
- Hunting / query languages: **Partial** - Threat hunting and intelligence documented; query language not named on pages read. [S1] [S2]
- Response / containment: **Has** - SOAR, managed response, and agent-driven actions documented. [S1]
- Vulnerability / exposure: **Has** - Exposure Management and AI-assisted vulnerability management listed. [S1]
- Identity: **Has** - Identity security module listed. [S1]
- Cloud: **Has** - CNAPP, agent and agentless, listed. [S1]
- Data lake / SIEM integration: **Has** - Next-Gen SIEM with data pipeline and federated search listed. [S1] [S2]
- Case management: **Partial** - Incident management listed without workflow detail. [S2]
- Reporting: **Partial** - Live dashboards documented; dedicated reporting not described. [S2]
- APIs and automation: **Partial** - No-code workflow automation and agentic SOAR listed; public API not described on pages read. [S1] [S2]
- Deployment and agent footprint: **Has** - One agent for security and IT; footprint figures not documented on pages read. [S1]
- Licensing model: **Has** - Commercial; per-endpoint tiers (Go, Pro, Enterprise) and a Flex model listed. [S1]

### SentinelOne Singularity
- Telemetry collection: **Partial** (UNVERIFIED) - Datasheet snippets mention EDR visibility of benign and malicious data; primary page not readable. [S3]
- Detection engineering: **Partial** (UNVERIFIED) - Storyline event-chain grouping described in secondary snippets. [S3]
- Hunting / query languages: **Partial** (UNVERIFIED) - Deep Visibility hunting with a 14-day retention tier appears on one datasheet snippet. [S3]
- Response / containment: **Partial** (UNVERIFIED) - RemoteOps remote investigation, forensics and scripted response described in snippets. [S3]
- Vulnerability / exposure: **Has** (UNVERIFIED) - Vulnerability management using existing agents, with exploitability signals such as EPSS and KEV, per its Ranger Insights page snippet. [S3]
- Identity: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Cloud: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Data lake / SIEM integration: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Case management: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Reporting: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- APIs and automation: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Deployment and agent footprint: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 
- Licensing model: **Not documented** (UNVERIFIED) - UNVERIFIED: primary pages blocked (HTTP 429); not confirmed. 

### Microsoft Defender XDR
- Telemetry collection: **Has** - Signals from endpoint, identity, email, cloud apps and more, joined in one suite. [S4]
- Detection engineering: **Has** - Custom detection rules built from hunting queries; correlated multi-workload alerts. [S4] [S5]
- Hunting / query languages: **Has** - Advanced hunting with KQL, guided and advanced modes; 30 days native data, 100k-row result cap. [S5]
- Response / containment: **Has** - Automatic attack disruption, automated investigation and remediation. [S4]
- Vulnerability / exposure: **Has** - Vulnerability Management and Security Exposure Management in the suite. [S4]
- Identity: **Has** - Defender for Identity and Entra ID Protection. [S4]
- Cloud: **Has** - Defender for Cloud and Defender for Cloud Apps. [S4]
- Data lake / SIEM integration: **Has** - Microsoft Sentinel onboarding extends hunting and retention; streaming APIs for export. [S5]
- Case management: **Has** - Combined incidents queue grouping alerts, assets and actions. [S4]
- Reporting: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- APIs and automation: **Has** - Advanced hunting API and streaming API referenced. [S5]
- Deployment and agent footprint: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Licensing model: **Partial** (UNVERIFIED) - Commercial; licensing prerequisites page exists but was not read. [S4]

### Elastic Security
- Telemetry collection: **Has** - Elastic Agent collects OS events, network activity and user behaviour in ECS; 400+ integrations. [S6] [S8]
- Detection engineering: **Has** - Over 1,300 open detection rules; rule types incl. correlation, ML anomaly, ES|QL; exceptions and suppression; MITRE coverage view. [S6] [S7]
- Hunting / query languages: **Partial** - ES|QL rule type and a piped query language referenced; hunting languages not enumerated on pages read. [S6] [S7]
- Response / containment: **Has** - Kill, suspend, isolate response actions and workflow orchestration documented. [S6] [S8]
- Vulnerability / exposure: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Identity: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Cloud: **Partial** - Cloud deployment options documented; cloud-workload protection not described on pages read. [S6]
- Data lake / SIEM integration: **Has** - SIEM with ECS and OCSF support; self-managed, air-gapped and cloud. [S6]
- Case management: **Not documented** (UNVERIFIED) - Cases not covered on the detection-engine page read; not confirmed either way. 
- Reporting: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- APIs and automation: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Deployment and agent footprint: **Has** - Cloud serverless, hosted, self-managed, on-prem and air-gapped options. [S6]
- Licensing model: **Has** - Open detection rules and a free tier for core endpoint protection; subscriptions add XDR and automated response. [S6] [S8]

### Wazuh
- Telemetry collection: **Has** - Agent plus syslog log collection, FIM, agentless monitoring, cloud event monitoring. [S9]
- Detection engineering: **Has** - Decoders and rules with threat-intel matching on the server. [S9]
- Hunting / query languages: **Partial** - Dashboards for threat hunting over indexed alerts; no dedicated query language described. [S9]
- Response / containment: **Has** - Active Response runs scripts on rule match, stateless or stateful. [S10]
- Vulnerability / exposure: **Has** - Inventory-based vulnerability detection against a CTI repository, online or offline copy. [S11]
- Identity: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Cloud: **Has** - AWS, Azure, Google Cloud, GitHub and Office 365 monitoring listed in docs navigation. [S9]
- Data lake / SIEM integration: **Partial** - Own indexer and dashboard; third-party SIEM export not described on page read. [S9]
- Case management: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Reporting: **Partial** - Prebuilt compliance and SCA dashboards documented. [S9]
- APIs and automation: **Partial** - Server API referenced; no detail on page read. [S9]
- Deployment and agent footprint: **Has** - Agent for Linux, Windows, macOS, Solaris, AIX, HP-UX; clustered server; footprint figures not documented. [S9]
- Licensing model: **Partial** (UNVERIFIED) - Presented as open source; exact license not stated on page read. [S9]

### Velociraptor
- Telemetry collection: **Has** - Volatile and event data via ETW and eBPF event sources; offline collectors. [S12]
- Detection engineering: **Has** - Real-time event queries with Sigma rules. [S12]
- Hunting / query languages: **Has** - VQL with artifacts and fleet-wide hunts. [S12] [S13]
- Response / containment: **Has** - Remediation and quarantine of endpoints mentioned. [S12]
- Vulnerability / exposure: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Identity: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Cloud: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Data lake / SIEM integration: **Partial** - Exports to Splunk, Elastic, Timesketch and archives; no own SIEM. [S12]
- Case management: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Reporting: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- APIs and automation: **Has** - gRPC API usable from Python, Go, Java and shell. [S12]
- Deployment and agent footprint: **Has** - Client/server or offline collector; CPU limits to restrain footprint. [S12]
- Licensing model: **Has** - Described as an open-source platform. [S12]

### osquery + Fleet
- Telemetry collection: **Partial** - SQL view of OS state (processes, sockets, etc.) on Linux, macOS, Windows; event tables not covered on page read. [S16]
- Detection engineering: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Hunting / query languages: **Has** - SQL queries, interactive and scheduled via daemon. [S16]
- Response / containment: **Not documented** (UNVERIFIED) - Not documented on pages read (Fleet MDM/patching exists; no endpoint containment documented). 
- Vulnerability / exposure: **Partial** - Fleet monitors high-impact vulnerabilities via policies; no full feature described on page read. [S15]
- Identity: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Cloud: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Data lake / SIEM integration: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Case management: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Reporting: **Partial** - Built-in report and 400+ CIS policy library in Fleet. [S15]
- APIs and automation: **Has** - Fleet REST API, webhooks, MCP server, fleetctl, YAML GitOps. [S14]
- Deployment and agent footprint: **Not documented** (UNVERIFIED) - Footprint not documented on pages read. 
- Licensing model: **Has** - Fleet mostly MIT with paid license-key features (Premium); osquery license not named on README read. [S15] [S16]

### Sysmon / Sysinternals
- Telemetry collection: **Has** - Event IDs 1-29 incl. process create with hashes, network, image/driver load, remote thread, process access, file create/delete, registry, pipes, WMI, DNS, clipboard, process tampering (Windows; Linux port exists). [S17]
- Detection engineering: **Not documented** - States it does not analyse events; no detection content. [S17]
- Hunting / query languages: **Not documented** - None; relies on downstream tools. [S17]
- Response / containment: **Partial** - Blocks executable creation and file shredding (IDs 27, 28); no general response. [S17]
- Vulnerability / exposure: **Not documented** - Not a documented function of Sysmon. [S17]
- Identity: **Not documented** - Not a documented function of Sysmon. [S17]
- Cloud: **Not documented** - Not a documented function of Sysmon. [S17]
- Data lake / SIEM integration: **Partial** - Writes to Windows event log for collection by WEC or SIEM agents. [S17]
- Case management: **Not documented** - Not a documented function of Sysmon. [S17]
- Reporting: **Not documented** - Not a documented function of Sysmon. [S17]
- APIs and automation: **Not documented** - Command-line install/config only. [S17]
- Deployment and agent footprint: **Has** - Service plus boot-start driver, XML config with include/exclude filtering; Windows 11 and Server 2019+. [S17]
- Licensing model: **Partial** - Free Sysinternals download with accepted EULA; no source license stated. [S17]

### Cortex XDR
- Telemetry collection: **Has** - Endpoint, network, cloud, identity and email via one sensor. [S18]
- Detection engineering: **Has** - Behavioural analytics, customisable BIOCs, IOCs and correlation rules. [S18]
- Hunting / query languages: **Not documented** (UNVERIFIED) - XQL not covered on page read; UNVERIFIED. 
- Response / containment: **Has** - Root-cause mapping and AI-agent response; managed response services. [S18]
- Vulnerability / exposure: **Not documented** (UNVERIFIED) - Exposure Management mentioned only as separate; UNVERIFIED. 
- Identity: **Partial** - Identity listed as a data source only. [S18]
- Cloud: **Has** - Cloud security in same sensor. [S18]
- Data lake / SIEM integration: **Has** - Unified data lake; forwarding to Google SecOps. [S18]
- Case management: **Not documented** (UNVERIFIED) - Admin guide fetch failed (S20); UNVERIFIED. 
- Reporting: **Partial** - Managed-service reports only on page read. [S18]
- APIs and automation: **Has** - REST API returning alerts and incidents as JSON. [S18]
- Deployment and agent footprint: **Has** - Single lightweight sensor (no footprint figures). [S18]
- Licensing model: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 

### Trend Vision One
- Telemetry collection: **Not documented** (UNVERIFIED) - Telemetry sources not described on page read. 
- Detection engineering: **Has** - AI-driven detection, endpoint correlation, network intrusion detection. [S19]
- Hunting / query languages: **Partial** - AI-driven hunting mentioned; no query language described. [S19]
- Response / containment: **Has** - Endpoint response, identity-risk mitigation, automated workflows. [S19]
- Vulnerability / exposure: **Has** - Cyber Risk Exposure Management. [S19]
- Identity: **Has** - Identity Security module. [S19]
- Cloud: **Has** - Cloud Security module. [S19]
- Data lake / SIEM integration: **Partial** - Agentic SIEM listed; data lake not mentioned. [S19]
- Case management: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Reporting: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- APIs and automation: **Partial** - Integrations marketplace and automated workflows; no API described. [S19]
- Deployment and agent footprint: **Not documented** (UNVERIFIED) - Not found in the public pages fetched for this study; not confirmed either way. 
- Licensing model: **Has** - Commercial; Flex credit licence across 30+ solutions. [S19]

## Prioritised backlog (observation-only)

Every item except the last is compatible with the observation-only boundary. 'Telemetry sufficient?' states whether today's data (process exec, network destination only, file path/op/size only) can support it.

| # | Feature | What | Competitors | Why it matters | Data needed | Telemetry sufficient? | Effort | Risk | Conflicts with observation-only? |
|---|---|---|---|---|---|---|---|---|---|
| 1 | File hashing on exec and file events | Record SHA-256/MD5 of executed images and written files in events. | Sysmon (S17) | Hash pivots enable IOC matching and prevalence without relying on paths. | Agent-side hashing of image and file content | Insufficient: exec has path only, file has path/op/size only | M | Hash cost on busy hosts; privacy of file reads | No |
| 2 | Process GUID / start-time keyed lineage | Stable process identity across all event types for reliable trees. | Sysmon (S17) | Pid reuse breaks storylines and joins. | Process start time on every event; network has optional process_start | Partial: process_start exists but is optional | S | Low | No |
| 3 | Process terminate events | Capture exits with exit time. | Sysmon ID 5 (S17) | Gives lifetime of short-lived processes; supports burst detection. | Exit hook (netlink/eBPF) | Insufficient: exec only | S | Event volume | No |
| 4 | Image/DLL/module load coverage across platforms | Native module load collection with signer and hash (ingest endpoint exists). | Sysmon ID 6/7 (S17) | Detects sideloading and rogue drivers. | Native collector emitting module events; hash and signature | Partial: /v1/events/module accepts events but no native collector evidenced | M | High volume | No |
| 5 | Process-to-process access and remote thread events | Cross-process memory access and injection telemetry. | Sysmon ID 8/10 (S17) | Credential dumping and injection visibility. | Kernel/ETW/eBPF source | Insufficient: no such event type | L | High volume, platform-specific | No |
| 6 | Named pipe and WMI subscription events | Pipe create/connect and WMI filter/consumer events. | Sysmon IDs 17-21 (S17) | Lateral-movement and persistence tradecraft. | Windows ETW collector | Insufficient | L | Windows-only effort | No |
| 7 | Network events with ports, protocol, direction, bytes | Enrich network events beyond destination string with ports, protocol, bytes, resolved name. | Sysmon ID 3 (S17) | Needed for beaconing, exfil volume and service identification. | Socket-level collector | Insufficient: destination only | M | Moderate volume | No |
| 8 | File writer attribution | Attach the writing process to file events. | Sysmon ID 11 (S17) | File changes without an actor are hard to triage. | fanotify/eBPF/ETW file hook; the current scanner cannot identify the writer | Insufficient: file path/op/size only | L | Overhead, privileges | No |
| 9 | Alternate data stream / mark-of-the-web events | Detect downloaded-file provenance streams on Windows. | Sysmon ID 15 (S17) | Phishing-delivery triage. | Windows collector | Insufficient | M | Windows-only | No |
| 10 | File-create-time tampering detection | Report timestomping. | Sysmon ID 2 (S17) | Anti-forensics indicator. | File metadata hook | Insufficient | M | Noisy | No |
| 11 | Clipboard and process-tampering events | Hollowing/herpaderp and clipboard-change events. | Sysmon IDs 24/25 (S17) | Evasion visibility. | Kernel collector | Insufficient | L | Privacy (clipboard), noise | No |
| 12 | General query language over events | KQL/ES|QL/VQL-style expression language with joins and time windows for hunts. | Defender XDR KQL (S5), Elastic ES|QL (S6, S7), Velociraptor VQL (S12, S13), osquery SQL (S16) | Analysts can pivot without new code releases. | Existing event store; parser and limits | Yes | L | Resource exhaustion; needs quotas | No |
| 13 | Fleet-wide read-only live query | On-demand collection of OS state (processes, sockets, users) across hosts. | osquery/Fleet (S16), Velociraptor hunts (S12) | Answers 'is X present' quickly during incidents. | Agent read-only collector set; allow-list of tables | Insufficient: no remote read channel beyond recorded RTR | L | Remote execution surface is sensitive | Partially: remote collection resembles RTR; must be fixed read-only tables |
| 14 | Promote saved hunt to scheduled detection | Turn a saved hunt into an automatically running rule. | Defender custom detections (S4, S5) | Closes the hunt-to-detection loop. | Saved searches (exist) plus rule scheduler | Yes | M | Low | No |
| 15 | Hunt retention and quota controls | Documented retention window, row and time quotas on hunts. | Defender XDR (S5) | Predictable analyst experience and DoS protection. | Config and counters | Yes | S | Low | No |
| 16 | Offline evidence collector package | Portable read-only triage collector producing an archive for later ingest. | Velociraptor offline collectors (S12) | Covers hosts without a live agent. | New collector binary; archive importer | Insufficient: new collector | L | Collection depth must stay observational | No |
| 17 | Sigma coverage and rule-pack versioning | Report which Sigma rules map to available telemetry and track upstream versions. | Velociraptor Sigma (S12), Elastic open rules (S6) | Defenders trust content they can audit. | Existing content framework | Yes | S | Low | No |
| 18 | ATT&CK coverage gaps caused by missing telemetry | Show technique gaps due to absent telemetry, not only absent rules. | Elastic MITRE coverage page (S7) | Directs collector investment. | /v1/attack/matrix plus telemetry inventory | Yes | S | Low | No |
| 19 | Rule exceptions with expiry and alert suppression | Time-boxed exceptions and snooze with audit. | Elastic (S7) | Reduces fatigue without losing history. | Exclusions (exist) plus expiry fields | Yes | S | Hidden blind spots if expiry ignored | No |
| 20 | Alert grouping into attack chains | Cluster related alerts into one attack narrative. | Elastic Attack Discovery (S6, S8), Defender incidents (S4), SentinelOne Storyline (S3, secondary) | Fewer, richer cases. | Findings plus provenance graph (exists) | Yes | M | Mis-grouping | No |
| 21 | Native cloud audit-log collectors | Pull AWS, Azure, GCP, GitHub and M365 audit logs. | Wazuh (S9), Defender for Cloud (S4), CrowdStrike (S1) | Cloud attacks leave no host telemetry. | Read-only API credentials and poller | Insufficient: cloud endpoints are ledgers | L | Credential handling, cost | No |
| 22 | Agentless syslog device monitoring | Receive syslog from network gear and appliances. | Wazuh (S9) | Covers devices that cannot run agents. | Syslog listener and parsers | Insufficient: no listener | M | Parser maintenance | No |
| 23 | Security configuration assessment policies | Benchmark checks with pass/fail evidence. | Wazuh SCA (S9), Fleet CIS policies (S15) | Hardening drift is a common root cause. | Read-only config collection; policy format | Insufficient | M | Content licensing | No |
| 24 | Offline vulnerability repository matching | Match installed packages to a local copy of a vulnerability repository. | Wazuh (S11) | Air-gapped customers get exposure data. | Package inventory from agents; local feed copy | Partial: SBOM and feeds exist | M | Feed freshness | No |
| 25 | Exploit-likelihood prioritisation (EPSS, KEV) | Rank vulnerabilities by exploit signals. | SentinelOne Ranger Insights (S3, secondary) | Better prioritisation than CVSS alone. | Public EPSS/KEV feeds | Yes | S | Low | No |
| 26 | Directory and identity provider log ingestion | Ingest AD and Entra sign-in and directory logs. | Defender for Identity/Entra (S4), Trend Identity (S19) | Identity is a main attack path. | Connectors for directory logs | Partial: identity events accepted, no native collector | L | PII | No |
| 27 | Measured agent footprint and coverage SLOs | Publish measured CPU/memory per agent and coverage. | Velociraptor CPU limits (S12) | Defenders need evidence of low impact. | Agent self-metrics | Yes | S | Low | No |
| 28 | Continuous raw event streaming to customer lake | Extend SIEM export to a continuous raw event stream. | Defender streaming API (S5), Elastic ECS/OCSF (S6) | Longer retention in the customer's own lake. | Existing exporter; streaming sink | Yes | M | Volume, redaction | No |
| 29 | Case templates, SLA timers and assignment | Case workflow beyond notes and tickets. | Defender incidents (S4), CrowdStrike incident management (S2) | SOC process consistency. | Case schema extension | Yes | M | Low | No |
| 30 | Scheduled report exports | PDF/CSV scheduled reports to stakeholders. | Wazuh dashboards (S9), Fleet reports (S15) | Evidence for auditors. | Existing templates; scheduler | Yes | S | Low | No |
| 31 | Automatic attack disruption / host isolation | Auto-containment of hosts, accounts or mail. | Defender (S4), CrowdStrike (S1), Elastic (S8), Wazuh AR (S10), Velociraptor (S12) | Speeds containment. | Enforcement channel to hosts | n/a | L | Not applicable | YES: contradicts the product boundary; listed only to document the deliberate gap |

## Sources

All accessed 2026-11-13. Summaries are in our own words; no vendor text, rules or screenshots were copied.

- S1: CrowdStrike Falcon platform page - https://www.crowdstrike.com/en-us/platform/
- S2: CrowdStrike Next-Gen SIEM page - https://www.crowdstrike.com/en-us/platform/next-gen-siem/
- S3: SentinelOne: official platform pages returned HTTP 429 on fetch; web-search snippets of Ranger Insights, RemoteOps and datasheets used (secondary) - https://www.sentinelone.com/platform/singularity-ranger-insights
- S4: Microsoft Defender XDR overview (Microsoft Learn) - https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender
- S5: Microsoft Defender advanced hunting overview - https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview
- S6: Elastic Security page - https://www.elastic.co/security
- S7: Elastic Security detection engine overview - https://www.elastic.co/guide/en/security/current/detection-engine-overview.html
- S8: Elastic endpoint security page - https://www.elastic.co/security/endpoint-security
- S9: Wazuh components (docs) - https://documentation.wazuh.com/current/getting-started/components/index.html
- S10: Wazuh Active Response (docs) - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- S11: Wazuh vulnerability detection (docs) - https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html
- S12: Velociraptor overview (docs) - https://docs.velociraptor.app/docs/overview/
- S13: Velociraptor VQL (docs) - https://docs.velociraptor.app/docs/vql/
- S14: Fleet: why Fleet (docs) - https://fleetdm.com/docs/get-started/why-fleet
- S15: Fleet FAQ (docs) - https://fleetdm.com/docs/get-started/faq
- S16: osquery README - https://raw.githubusercontent.com/osquery/osquery/master/README.md
- S17: Sysmon (Microsoft Learn, Sysinternals) - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- S18: Cortex XDR product page (Palo Alto Networks) - https://www.paloaltonetworks.com/cortex/cortex-xdr
- S19: Trend Vision One platform page (redirected from trendmicro.com to trendaisecurity.com) - https://www.trendaisecurity.com/en-us/platform
- S20: Cortex XDR admin guide URL: returned Page Not Found on fetch (no evidence gained) - https://cortex-docs.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Cortex-XDR-Pro-Administrator-Guide

## Limits

- Public marketing and docs pages only; no product was tested. SentinelOne primary pages returned HTTP 429 and the Cortex XDR admin guide URL was Page Not Found, so those columns are mostly UNVERIFIED.
- Much vendor documentation is login-gated and could not be checked.
- No numbers are quoted except those printed on the cited pages.
