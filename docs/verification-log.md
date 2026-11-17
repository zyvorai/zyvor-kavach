# Verification log

Verification pass of 2026-11-16 over every item previously marked UNVERIFIED in Kavach reporting regimes, framework controls and configuration defaults. Statuses: **confirmed** (read in the cited source), **corrected** (source differs from what was written; data changed), **partial**, **unverified** (reason given). "Read directly" means the page or document text was fetched; "search excerpt" means the official page was only seen as a search-result excerpt because the direct fetch failed (EUR-Lex, legislation.gov.uk, cyber.gov.au, oaic.gov.au, sdaia.gov.sa, PCPD, UAE portal blocked, empty or timed out), so wording should be re-checked on that site before external use. Informational, not legal advice.

## Summary counts

| Group | Items | Confirmed | Corrected | Partial | Still unverified |
|---|---:|---:|---:|---:|---:|
| Reporting regimes (previously unverified) | 21 | 16 | 3 | 0 | 2 |
| Framework catalogs (previously UNVERIFIED rows) | 15 | 3 | 4 | 4 | 4 |
| Config absence defaults | 16 | 16 | 0 | 0 | 0 |
| Config Kubernetes NSA/CISA reference (24 policies) | 24 | 5 | 0 | 0 | 19 |
| Pod Security Standards Restricted items | 4 | 4 | 0 | 0 | 0 |
| **Total** | **80** | **44** | **7** | **4** | **25** |

Regimes: the 21 are the 24 catalog entries minus uk-gdpr, us-sec-8k-1-05 and us-circia, which were already verified on 2026-11-13. The two still-unverified regimes are ae-pdpl and hk-pdpo. Of the 19 regimes confirmed or corrected, 12 were read directly and 7 only through search excerpts (see the kind column). Config clarifications: sudo use_pty (on only from sudo 1.9.14) and login UMASK (022 per the man page but distro/PAM overrides) were confirmed with sharper wording; neither changed an outcome.

## 1. Reporting regimes

Catalog: `internal/edr/regulatory_regimes.json` (`verified`, `last_verified` = verified-on date, `source_url`, `source_kind`, optional `sources`). Rendered in `docs/regional-reporting.md`.

| Regime id | Status | Claim checked / result | Source | Kind | Date |
|---|---|---|---|---|---|
| eu-gdpr-art33 | confirmed | 72 hours from awareness, reasons if late | https://www.edpb.europa.eu/system/files/2023-04/edpb_guidelines_202209_personal_data_breach_notification_v2.0_en.pdf | official_fetched | 2026-11-16 |
| eu-nis2-art23 | confirmed | 24h early warning, 72h notification, final report one month after notification | https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng | official_excerpt | 2026-11-16 |
| eu-dora-major-ict | confirmed | 4h from classification / 24h from awareness; intermediate 72h; final one month after last intermediate | https://eur-lex.europa.eu/eli/reg_del/2025/301/oj/eng ; https://www.esma.europa.eu/sites/default/files/2026-09/DORA_Incident_reporting_-_Operational_instructions.pdf | official_excerpt | 2026-11-16 |
| uk-nis | confirmed | 72 hours from awareness | https://www.legislation.gov.uk/uksi/2018/506/regulation/11/made?view=plain | official_excerpt | 2026-11-16 |
| us-hipaa-breach | confirmed | 60 calendar days (individuals); HHS at same time for 500+, annual for fewer than 500 | https://www.ecfr.gov/current/title-45/section-164.404 ; https://www.law.cornell.edu/cfr/text/45/164.408 | official_fetched | 2026-11-16 |
| sg-cybersecurity-act | corrected | 2h; supplementary 72h (14 days NOT supported); final 30 days after supplementary submission (not from awareness) | https://www.csa.gov.sg/legislation/forms/ | official_fetched | 2026-11-16 |
| sg-pdpa | confirmed | 3 calendar days after assessment; 30-day assessment | https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/guide-on-managing-and-notifying-data-breaches-under-the-pdpa-15-mar-2021.pdf | official_fetched | 2026-11-16 |
| au-soci-critical | confirmed | 12h; written within 84h if verbal | https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident | official_excerpt | 2026-11-16 |
| au-soci-other | confirmed | 72h; written within 48h if verbal | https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident | official_excerpt | 2026-11-16 |
| au-ndb | confirmed | 30-day assessment; notify as soon as practicable | https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme | official_excerpt | 2026-11-16 |
| jp-appi | confirmed | preliminary 3-5 days; final 30 days, 60 days if improper purpose | https://www.ppc.go.jp/personalinfo/legal/leakAction/ | official_fetched | 2026-11-16 |
| in-certin-2022 | confirmed | 6 hours from noticing | https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf | official_fetched | 2026-11-16 |
| in-dpdp | corrected | 72h detailed report confirmed; Rule 7 only in force 18 months after 13 Nov 2025 gazette (about 13 May 2027) | https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf | official_fetched | 2026-11-16 |
| br-lgpd | confirmed | 3 business days from knowing personal data affected; 20 business days to supplement | https://bibliotecadigital.mj.gov.br/bitstream/1/12879/2/RES_ANPD_2024_15.html | official_fetched | 2026-11-16 |
| sa-nca-ecc | confirmed | ECC contains no numeric reporting limit (control 2-13-3-3 only) | https://cdn.nca.gov.sa/ar/ecc-en.pdf | official_fetched | 2026-11-16 |
| sa-pdpl | confirmed | 72 hours (Implementing Regulation Art. 24) | https://sdaia.gov.sa/en/SDAIA/about/Documents/ImplementingRegulation.pdf | official_excerpt | 2026-11-16 |
| ae-pdpl | UNVERIFIED | Art. 9 defers the period to Executive Regulations; whether a deadline exists could not be confirmed | https://uaelegislation.gov.ae/en/legislations/1972 | official_excerpt | 2026-11-16 |
| za-popia | confirmed | as soon as reasonably possible after discovery (s22(2)); no hour limit | https://inforegulator.org.za/wp-content/uploads/2025/08/PROTECTION-OF-PERSONAL-INFORMATION-ACT-4-OF-2013.pdf | official_fetched | 2026-11-16 |
| ca-pipeda | confirmed | as soon as feasible after determination; records kept 24 months (OPC page) | https://laws-lois.justice.gc.ca/eng/acts/p-8.6/page-3.html ; https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/ | official_fetched | 2026-11-16 |
| kr-pipa | corrected | 72h in Enforcement Decree Art. 39 (individuals) and Art. 40 (report, only 1,000+ subjects / sensitive or unique IDs / illegal external access) | https://elaw.klri.re.kr/eng_mobile/viewer.do?hseq=69668&type=part&key=4 | official_fetched | 2026-11-16 |
| hk-pdpo | UNVERIFIED | guidance only, as soon as practicable; no source newer than Aug 2024 | https://www.pcpd.org.hk/english/resources_centre/publications/files/guidance_note_dbn_e.pdf | official_excerpt | 2026-11-16 |

Already verified before this pass (unchanged): uk-gdpr, us-sec-8k-1-05, us-circia (2026-11-13).

2026-11-17 retry on the two regimes: **ae-pdpl** - uaelegislation.gov.ae returned HTTP 403 again; no new primary evidence. **hk-pdpo** - only secondary reports found (SCMP, Feb 2026, says PCPD plans to consult on mandatory breach reporting; commentary says reporting is still voluntary); no PCPD or gazette text. Both stay UNVERIFIED.

Why the two stay unverified (2026-11-16): **ae-pdpl** - the Decree-Law 45/2021 Art. 9 text (search excerpt of https://uaelegislation.gov.ae/en/legislations/1972) leaves the period to Executive Regulations and the portal returned HTTP 403, so the claim "no fixed time limit published" could not be confirmed. **hk-pdpo** - PCPD guidance (https://www.pcpd.org.hk/english/resources_centre/publications/files/guidance_note_dbn_e.pdf) and an August 2024 PCPD slide deck, both seen only as search excerpts, call notification non-statutory, but nothing from 2025 to 2026 was found and a later amendment cannot be excluded.

Not modelled / caveats found: DORA weekend and bank-holiday relief (noon next working day, exceptions garbled in the excerpt); HIPAA media notice (164.406) not read; Singapore third-party-owned CII and systems of temporary cybersecurity concern regulations not read; Korea 2026 amendment not checked.

## 2. Framework catalogs

Source: `internal/edr/compliance_controls_regional.go`, table in `docs/regional-frameworks.md`.

| Framework | Status | Result | Source | Kind |
|---|---|---|---|---|
| EU NIS2 Art.21 | partial | Art. 21(2) measures list exists; items (a),(d),(e),(g)-(j) described, (b),(c),(f) headings only | https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng | search excerpt |
| EU DORA | partial | Art. 5, 8, 9, 11, 12, 13, 17, 18, 19, 24, 26, 28 topics consistent with control titles; Art. 6 and 10 not confirmed | https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng | search excerpt |
| EU GDPR Art.32 | confirmed | four listed measures | https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=celex:32016R0679 | search excerpt |
| Australia Essential Eight | partial | eight strategies confirmed; maturity entries remain themes; ASD now publishes a principles-based "Transitioning from the Essential Eight" with no target maturity level | https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-explained | search excerpt |
| Australia ISM | UNVERIFIED | 2026-11-17 retry: cyber.gov.au ISM page, guidelines page and ISM PDF (https://www.cyber.gov.au/sites/default/files/2026-10/Information%20security%20manual%20%28September%202026%29.pdf) timed out or were refused for direct fetch; only search snippets seen, which show a September 2026 edition and suggest chapter names may have changed (for example supply chain / managed services versus "procurement and outsourcing"). Guideline names not confirmed, not changed | https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines | none (accessed 2026-11-17) |
| Singapore CCoP | corrected | Official CSA PDF read directly (2026-11-17): Cybersecurity Code of Practice for CII, 2026 edition (Release 1, effective 29 July 2026; supersedes 2.0 of 2022). Section titles confirmed: 3.1 Board-Level Accountability, 3.10 Outsourcing Management, 4.1 Asset Management, 5.1 Access Control, 5.9 System Hardening, 5.14 Vulnerability Assessment, 5.15 Penetration Testing, 6.1 Logging, 6.2 Monitoring and Detection, 7.1 Incident Management, 7.3 Cybersecurity Exercise, 8.2 BCP and DRP, 9.2 Cybersecurity Training and Skills. Kavach ids changed from labels to these section numbers; the file-integrity control had no counterpart section (no file-integrity requirement found) and was replaced by 5.9 System Hardening (not observable). Titles for 3.10 and 9.2 aligned | https://www.csa.gov.sg/docs/default-source/legislation/ccop---second-edition_revision-one.pdf | read directly (accessed 2026-11-17) |
| Japan METI/NISC | UNVERIFIED | 2026-11-17: METI Cybersecurity Management Guidelines v3.0 PDF (https://www.meti.go.jp/policy/netsecurity/downloadfiles/CSM_Guideline_v3.0_en.pdf) and mng_guide page returned HTTP 403; NISC standard not found. Search snippet only: v3.0 (24 Mar 2023) keeps the three principles and ten important items. Kavach ids (JP-CSMG-1..8) are labels and were not compared to the ten items | https://www.meti.go.jp/policy/netsecurity/mng_guide.html | none (accessed 2026-11-17) |
| Saudi NCA ECC | corrected | ECC-2-7 was labelled Cryptography; the PDF has 2-7 Data and Information Protection and 2-8 Cryptography, so the id is now ECC-2-8; ECC-4-1 title shortened to "Third-party cybersecurity" (4-2 is cloud); all other ids match | https://cdn.nca.gov.sa/ar/ecc-en.pdf | read directly |
| UAE IA | UNVERIFIED | 2026-11-17: official regulation PDF (https://www.tdra.gov.ae/-/media/guidelines/Guidelines-2020/UAE-IA-Regulation-v11-1.pdf) returned an HTML challenge page, u.ae page 404, government.ae host failed TLS. Only secondary vendor pages seen (management families M1-M6, regulation v1.1 of March 2020); not an official read. Ids not changed | https://u.ae | none (accessed 2026-11-17) |
| Brazil LGPD | confirmed | arts. 37, 41, 46, 47, 48, 49, 50 topics match | https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm | search excerpt |
| South Africa POPIA | confirmed | s19(1), 19(2)(a)-(d), 20, 21, 22 match control titles | https://inforegulator.org.za/wp-content/uploads/2025/08/PROTECTION-OF-PERSONAL-INFORMATION-ACT-4-OF-2013.pdf | read directly |
| FedRAMP Moderate | partial | Official FedRAMP control reference read (2026-11-17): based on NIST SP 800-53 Rev 5 (catalog 5.2.0), 20 families including AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR; every family id Kavach cites exists. CA is titled Assessment, Authorization, and Monitoring (Kavach title corrected). Not confirmed: which families and the CA-7 control are in the Moderate baseline (page does not name the baseline; baseline spreadsheet not read). FedRAMP RFC-0027 page also read, only says Rev5 baselines include Moderate | https://fedramp.gov/2026/reference/controls/ ; https://www.fedramp.gov/rfcs/0027 | read directly (accessed 2026-11-17) |
| Canada CCCS / PIPEDA | corrected | PIPEDA s10.1-10.3 read earlier. CCCS Baseline Cyber Security Controls for Small and Medium Organizations v1.2 read directly 2026-11-17 (page date modified 2020-02-18): 13 controls numbered 3.1-3.13 (incident response plan, patching, security software, secure configuration, strong authentication, awareness training, backup and encryption, secure mobility, perimeter defences, cloud and outsourced IT, secure websites, access control and authorization, portable media). Kavach ids rewritten to 3.x numbers with official titles; two Kavach controls (asset inventory, logging and monitoring) are not baseline controls and were removed | https://www.cyber.gc.ca/en/guidance/baseline-cyber-security-controls-small-and-medium-organizations | read directly (accessed 2026-11-17) |
| South Korea ISMS-P | corrected | PIPC English certification page read directly 2026-11-17 (official government page; KISA site itself not read): 3 parts (1 management system, 16 items; 2 protection measures, 64 items; 3 personal information processing, 22 items) with domains 1.1-1.4, 2.1-2.12, 3.1-3.5. Domain-level ids match. Corrected: ISMSP-3.4-breach was wrong (3.4 is destruction of personal information), now ISMSP-2.11-breach (2.11 Incident prevention and response); titles of 2.1, 2.2, 2.5 aligned to the page. Sub-item numbers (for example log management inside 2.9) not read | https://www.pipc.go.kr/eng/user/lgp/bnp/certification.do | read directly (accessed 2026-11-17) |
| Hong Kong HKMA / PCPD | UNVERIFIED | 2026-11-17: HKMA press release of 3 Nov 2020 read (https://www.hkma.gov.hk/eng/news-and-media/press-releases/2020/11/20201103-4/): confirms CFI 2.0 and iCAST exist. C-RAF 2.0 annex PDF (https://brdr.hkma.gov.hk/eng/doc-ldg/docId/getPdf/20201103-2-EN/20201103-2-EN.pdf) is only about tester qualifications; the domain structure was not read (a secondary snippet says seven domains, Kavach uses five function-style labels HKMA-governance..respond, so labels may not match). PDPO DPP4 text (elegislation.gov.hk) did not load. Ids not changed | https://www.hkma.gov.hk | partial (iCAST and CFI 2.0 only) (accessed 2026-11-17) |

Not in scope of the 15 rows (unchanged): the rows already verified or partial on 2026-11-13 (UK Cyber Essentials, NIST SP 800-171, Singapore MAS TRM).

## 3. Configuration defaults (`absence_note`)

Policies: `internal/edr/configpolicies/*.json`. New optional fields `absence_source` and `default_verified_on`. All pages were read directly on 2026-11-16 and describe current releases; older versions were not checked.

| Policy id | Status | Default confirmed | Source |
|---|---|---|---|
| ssh-ignore-rhosts | confirmed | IgnoreRhosts yes | https://man.openbsd.org/sshd_config |
| ssh-login-grace-time | confirmed | LoginGraceTime 120 seconds | https://man.openbsd.org/sshd_config |
| ssh-weak-kex | confirmed | default KexAlgorithms has no SHA-1 variants (older OpenSSH not checked) | https://man.openbsd.org/sshd_config |
| ssh-strict-modes | confirmed | StrictModes yes | https://man.openbsd.org/sshd_config |
| ssh-legacy-protocol | confirmed | manual documents no Protocol keyword | https://man.openbsd.org/sshd_config |
| sudo-env-reset | confirmed | env_reset on by default | https://www.sudo.ws/docs/man/sudoers.man/ |
| sudo-use-pty | confirmed (sharpened) | use_pty on by default only for sudo 1.9.14 and above; absent therefore still treated as failure | https://www.sudo.ws/docs/man/sudoers.man/ |
| sudo-timestamp-timeout | confirmed | 5 minutes | https://www.sudo.ws/docs/man/sudoers.man/ |
| login-pass-min-days | confirmed | 0 if not specified (disables restriction) | https://man7.org/linux/man-pages/man5/login.defs.5.html |
| login-umask | confirmed (sharpened) | 022 if UMASK not set; distros/PAM often override so result stays unknown | https://man7.org/linux/man-pages/man5/login.defs.5.html |
| web-apache-tls-protocols | confirmed (sharpened) | default "all -SSLv3" from 2.4.17, "all" alone before; "all" includes TLSv1 and TLSv1.1 when OpenSSL allows | https://httpd.apache.org/docs/2.4/mod/mod_ssl.html |
| web-apache-server-tokens | confirmed | ServerTokens Full | https://httpd.apache.org/docs/2.4/mod/core.html |
| web-apache-indexes | confirmed | Options FollowSymlinks (no Indexes) | https://httpd.apache.org/docs/2.4/mod/core.html |
| web-apache-trace | confirmed | TraceEnable on | https://httpd.apache.org/docs/2.4/mod/core.html |
| terraform-azure-storage-public | confirmed (current provider) | allow_nested_items_to_be_public defaults false in the azurerm main-branch docs; older provider versions not checked | https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/main/website/docs/r/storage_account.html.markdown |
| terraform-azure-storage-transport | confirmed (current provider) | https_traffic_only_enabled true; min_tls_version TLS1_2 for new accounts; older versions and existing accounts not checked | https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/main/website/docs/r/storage_account.html.markdown |

### Kubernetes policy references and Pod Security Standards

- Pod Security Standards Restricted items (runAsNonRoot true, allowPrivilegeEscalation false, drop ALL with only NET_BIND_SERVICE allowed back, seccomp explicitly set): **confirmed**, page read directly, https://kubernetes.io/docs/concepts/security/pod-security-standards/ (the earlier read had truncated before the Restricted section).
- NSA/CISA Kubernetes Hardening Guidance v1.2 (Aug 2022) reference on 24 policies: PDF https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF returned HTTP 403 to the fetcher. A search excerpt of it confirms the topics for k8s-run-as-non-root, k8s-read-only-rootfs, k8s-memory-limit, k8s-cpu-limit and k8s-sa-token (**confirmed**, reference text updated). The other 19 (privileged, privilege-escalation, host-network/pid/ipc, hostpath, runtime-socket, run-as-user-zero, dangerous-capabilities, drop-all-capabilities, image-tag, image-digest, seccomp, host-port, proc-mount, env-secret, rbac-wildcard-verbs, rbac-wildcard-resources, rbac-cluster-admin) are **still UNVERIFIED** against this guidance; the reference text now says so and why. These are citations only; no check depends on them.

## 4. Other UNVERIFIED markers in the repository (not part of this task, untouched)

- `internal/edr/competitive_matrix.json` (11 notes, vendor pages blocked with HTTP 429), `docs/competitive-analysis.md`.
- `docs/regional-threats.md` "Unverified or heuristic items" (detection-rule artefact names).
- Syslog format notes (`internal/edr/syslog_parse.go`, `docs/syslog-listener.md`: RFC 3164 rsyslog timestamps, LEEF, PAN-OS field positions), `docs/url-email-inspection.md`, `docs/lockfile-inspection.md`, `docs/evidence-import.md`, the runtime `UNVERIFIED` evidence string in `internal/edr/inspect_lockfile_analyzer.go` (a behaviour marker, not a research claim).
- `docs/config-assessment.md` frameworks hints (NIST 800-53 CM-6 on every policy, ATT&CK ids) were not checked against NIST or MITRE.
- Config checks whose thresholds are project choices (MaxAuthTries 4 and similar) are not facts to verify.

## 5. Documentation accuracy pass (code versus docs)

A separate pass compared operational documentation with the code and a locally running server (built from this tree, loopback only, throwaway data directory, synthetic requests). It checks what the software does, not external standards, so it complements sections 1 to 4. Statuses use the same words as above.

| Doc | Claim checked | Status | Evidence |
|---|---|---|---|
| `siem-export.md` | "Kavach opens no new outbound connection" | corrected | True for the pull endpoints only; `internal/edr/siem.go` has an optional webhook and UDP syslog push sink (`KAVACH_SIEM_*`). Doc now separates the two |
| `siem-export.md` | Cursor paging headers | confirmed | `X-Kavach-Count` and `X-Kavach-Next-Cursor` seen on a live `format=ocsf` request; header absent when the first page is empty (code) |
| `syslog-listener.md` | "the `kavach` binary has no graceful-shutdown hook" | corrected | `cmd/kavach/main.go` drains HTTP and calls the lifecycle registry, where the listener is registered as stopper `syslog`. A live shutdown was not exercised |
| `deploy-remote.md` | Token variable | corrected | The script reads `KAVACH_ADMIN_TOKEN` (default `Admin@321`), not `KAVACH_TOKEN`; its random-token fallback is unreachable because of `${...:-Admin@321}` |
| `deploy-remote.md` | Tests gate the deploy | not implemented in the script | `deploy-remote.sh` runs no tests; the gate is a process, documented with the CI commands |
| `deploy-remote.md`, `tutorial.md` | Console login | confirmed | `POST /v1/session` accepts `{"token": ...}` and returns 401 for any other body; the login form's username must be `admin` and the password is the token (`dashboard.html`) |
| `agent-mtls.md` | `optional` mode lets agents without certificates connect | fixed (was contradicted by code) | Added `-client-auth optional` (`VerifyClientCertIfGiven`); chart passes it for `optional`. Unit-tested on the `tls.Config` and rendered with `helm template`; not tried on a live cluster |
| `agent-mtls.md` | Certificate hot reload | unverified | No reload code found; documented as manual restart |
| `persistence-files.md` | "a missing or corrupt file is ignored" | fixed for incidents; registry fail-closed by design | `<store>.incidents` is now moved aside to `.corrupt-<unixtime>`; the credential registry still refuses to start on invalid JSON, with a clear error; documented. Real files seen after a short run: `.contentversions.json`, `.events.telemetry`, `.exposure.json`, `.inventory.json`, `.posturetrend.json`, `.regression.json` |
| `observability.md` | Write rate limiting | corrected | PUT and PATCH are limited too; failed-auth throttle (burst 20, then 1 per 5 s) applies to every route; login limiter stays on with `KAVACH_RATE_LIMIT=0` |
| `observability.md` | Metric names | confirmed | Listed from `/metrics` output of a running server |
| `ebpf.md` | Pin lookup order and API shapes | confirmed | `ebpf_watch_linux.go`, live responses for status, health, features, events and drops. Kernel loading was not tested (macOS host) |
| `cli-reference.md`, `mcp-integration.md` | MCP tool count | measured | `tools/list` against the built `kavach-mcp`: 425 tools read-only, 499 with `KAVACH_MCP_ALLOW_MUTATIONS=true` |
| `testing.md` | Race run needs `-timeout 30m` | confirmed by CI config | `.github/workflows/ci.yml` job `go`; the timeout itself was not re-measured here |

Still unverified from this pass: behaviour on a live Kubernetes cluster (Helm install, Envoy Gateway, probes with mTLS, persistence across pod restarts), kernel-side eBPF loading, any real SIEM or syslog device, and the mTLS "optional" behaviour described above.

Addendum: `deploy-remote.sh` writes `KAVACH_ADMIN_TOKEN` to the remote `~/.kavach/env`, which `kavachctl` now reads as the lowest-precedence token fallback (after `KAVACH_TOKEN` and `ZYVOR_EDR_TOKEN`, before `~/.kavach/api-key`); fixed, `TestAPITokenAdminFallbackLowestPrecedence`. The chart no longer sets `KAVACH_TLS_INSECURE` on agents (the agent never read it); `tls.agentInsecureSkipVerify` was removed.
