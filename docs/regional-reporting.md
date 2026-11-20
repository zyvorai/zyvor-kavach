# Regional incident-reporting clocks

Informational, not legal advice. Kavach does not file reports, notify regulators or contain anything; it only shows how long is left on each clock.

## How it works

- `GET /v1/regulatory/regimes` lists the embedded catalog (`internal/edr/regulatory_regimes.json`). Filters: `jurisdiction`, `verified`.
- `PUT /v1/regulatory/profile` (admin or session) saves the regimes that apply to you in `<store>.regulatory.json` (see `persistence-files.md`); `GET` reads it back.
- `GET /v1/regulatory/clocks[?regime=a,b]` computes, for every open high/critical finding that is not resolved or marked false positive, the deadline, time remaining and overdue flag per stage. This reuses the CERT-In clock logic, so the clock starts at the finding's first detection. Real regimes start at awareness, classification, assessment or a materiality determination, so first detection is a conservative proxy and each response says so.
- Stages that depend on another stage (for example "one month after the final intermediate report") or on a legal determination Kavach cannot see (SEC materiality) are listed with `computable: false` and rule text only. Business-day stages skip weekends only, with no holiday calendar.
- CLI: `kavachctl regulatory regimes|clocks|profile [set ID,...]`. MCP (read-only): `kavach_regulatory_regimes`, `kavach_regulatory_clocks`, `kavach_regulatory_profile`.

## Verification status

`verified: true` means the rule was read on an official regulator or legislator page on the date in `last_verified` (the verified-on date). `source_kind` says how: `official_fetched` means the page or document was read directly; `official_excerpt` means official text was seen only through a search-result excerpt because the direct fetch failed (EUR-Lex, legislation.gov.uk, cyber.gov.au, oaic.gov.au and sdaia.gov.sa blocked or timed out), so the exact wording should still be checked there. `sources` lists any further pages read. Everything else is **UNVERIFIED** and must be checked before anyone relies on it. Research date for the original entries: 2026-11-13; verification pass: 2026-11-16 (see `verification-log.md`). Items corrected in that pass: Singapore Cybersecurity Act (final report runs 30 days from the supplementary submission; 14-day figure not on the CSA page), India DPDP Rule 7 (applies from about 13 May 2027), South Korea PIPA (72 hours is in the Enforcement Decree; the PIPC/KISA report only applies in listed cases).

## Rules, sources and access dates

### GDPR Art. 33 personal data breach (`eu-gdpr-art33`) - VERIFIED

- Jurisdiction / regulator: EU / National supervisory authorities (EDPB coordinates)
- Trigger: Personal data breach likely to result in a risk to individuals' rights and freedoms
- Clock starts at: awareness
- Applies to: Controllers (processors must alert the controller without undue delay)
- Stage: Notify supervisory authority - 72h (computed by Kavach). Without undue delay and, where feasible, within 72 hours of becoming aware; reasons required if later
- Source: https://www.edpb.europa.eu/system/files/2023-04/edpb_guidelines_202209_personal_data_breach_notification_v2.0_en.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: EDPB Guidelines 9/2022 (read directly) restate Art. 33(1): notify "not later than 72 hours after having become aware of it", with reasons for any delay. EUR-Lex pages returned empty to the research tool, so the statute itself was read only through the EDPB quotation. National transposition and supervisory-authority portals were not checked.

### NIS2 Art. 23 significant incident (`eu-nis2-art23`) - VERIFIED

- Jurisdiction / regulator: EU / National competent authorities / CSIRTs
- Trigger: Significant incident affecting an essential or important entity
- Clock starts at: awareness
- Applies to: Essential and important entities under NIS2 (as transposed nationally)
- Stage: Early warning - 24h (computed by Kavach). Within 24 hours of becoming aware of a significant incident
- Stage: Incident notification - 72h (computed by Kavach). Within 72 hours of becoming aware
- Stage: Final report - no fixed hour limit (rule text only). No later than one month after the incident notification (progress report first if the incident is still ongoing)
- Source: https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from a search-result excerpt of the EUR-Lex text of Art. 23(4) (direct fetch of EUR-Lex returned empty): early warning within 24 hours of awareness, incident notification within 72 hours, intermediate report only on request, final report not later than one month after the incident notification (progress report if still ongoing). Trust service providers: 24 hours instead of 72. National transposition differences were not checked.

### DORA major ICT-related incident (`eu-dora-major-ict`) - VERIFIED

- Jurisdiction / regulator: EU / Competent financial supervisors (ESAs oversee)
- Trigger: Incident classified as major under the DORA classification RTS
- Clock starts at: classification
- Applies to: Financial entities in scope of DORA
- Stage: Initial notification - 24h (computed by Kavach). Within 4 hours of classifying as major and no later than 24 hours after awareness
- Stage: Intermediate report - no fixed hour limit (rule text only). Within 72 hours of the initial notification
- Stage: Final report - no fixed hour limit (rule text only). No later than one month after the latest intermediate report
- Source: https://eur-lex.europa.eu/eli/reg_del/2025/301/oj/eng (source kind: official_excerpt; verified on 2026-11-16)
- Further source: https://www.esma.europa.eu/sites/default/files/2026-09/DORA_Incident_reporting_-_Operational_instructions.pdf
- Notes: Confirmed 2026-11-16: Delegated Regulation 2025/301 Art. 5 per a search-result excerpt of the EUR-Lex text (initial notification within 4 hours of classification and no later than 24 hours from awareness; intermediate report within 72 hours of the initial notification; final report within one month of the latest intermediate report). The final-report wording was also read directly in an ESMA operational-instructions document (https://www.esma.europa.eu/sites/default/files/2026-09/DORA_Incident_reporting_-_Operational_instructions.pdf). The excerpt also mentions a noon-next-working-day relief for weekends and bank holidays whose exceptions were garbled; it is not modelled. Kavach computes only the 24-hour outer limit from first detection.

### UK GDPR personal data breach (`uk-gdpr`) - VERIFIED

- Jurisdiction / regulator: United Kingdom / Information Commissioner's Office (ICO)
- Trigger: Breach likely to risk individuals' rights and freedoms
- Clock starts at: awareness
- Applies to: UK controllers
- Stage: Report to ICO - 72h (computed by Kavach). Within 72 hours of becoming aware; phased reporting allowed; explain any delay
- Source: https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/ (source kind: official_fetched; verified on 2026-11-13)
- Notes: 

### NIS Regulations 2018 incident notification (`uk-nis`) - VERIFIED

- Jurisdiction / regulator: United Kingdom / Sectoral competent authorities (e.g. Ofcom, Ofgem, DWI, ICO for digital service providers)
- Trigger: Incident with significant impact on continuity of an essential service
- Clock starts at: awareness
- Applies to: Operators of essential services and relevant digital service providers
- Stage: Notify competent authority - 72h (computed by Kavach). Without undue delay and no later than 72 hours
- Source: https://www.legislation.gov.uk/uksi/2018/506/regulation/11/made?view=plain (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from a search-result excerpt of regulation 11 (operator of essential services notifies its competent authority without undue delay and in any event no later than 72 hours after becoming aware). Direct fetch of legislation.gov.uk returned empty; the site shows differing versions of reg. 11 (the 2021 version also mentions digital service providers), so check the version in force. The government second post-implementation review asked whether 72 hours suffices; no change was found.

### Form 8-K Item 1.05 material cybersecurity incident (`us-sec-8k-1-05`) - VERIFIED

- Jurisdiction / regulator: United States / Securities and Exchange Commission
- Trigger: Registrant determines a cybersecurity incident is material
- Clock starts at: materiality_determination
- Applies to: SEC registrants (US-listed issuers)
- Stage: File Form 8-K Item 1.05 - 4 business days (rule text only). Four business days after determining materiality; materiality must be determined without unreasonable delay; the US Attorney General may authorise delay for national security or public safety
- Source: https://www.sec.gov/newsroom/press-releases/2023-139 (source kind: official_fetched; verified on 2026-11-13)
- Notes: Kavach cannot know when materiality is determined, so no deadline is computed from findings (the clock starts at the determination, not detection).

### HIPAA Breach Notification Rule (`us-hipaa-breach`) - VERIFIED

- Jurisdiction / regulator: United States / HHS Office for Civil Rights
- Trigger: Discovery of a breach of unsecured protected health information
- Clock starts at: discovery
- Applies to: HIPAA covered entities (business associates notify the covered entity)
- Stage: Notify individuals and HHS (500 or more) - 1440h (computed by Kavach). Without unreasonable delay and no later than 60 calendar days after discovery
- Stage: Annual HHS log (fewer than 500) - no fixed hour limit (rule text only). Within 60 days after the end of the calendar year in which the breach was discovered
- Source: https://www.ecfr.gov/current/title-45/section-164.404 (source kind: official_fetched; verified on 2026-11-16)
- Further source: https://www.law.cornell.edu/cfr/text/45/164.408
- Notes: Confirmed 2026-11-16: 45 CFR 164.404 read on eCFR (individuals: "without unreasonable delay and in no case later than 60 calendar days after discovery"). 164.408 read via the Cornell LII reproduction (https://www.law.cornell.edu/cfr/text/45/164.408): 500 or more individuals, notify the Secretary at the same time as individuals; fewer than 500, within 60 days after the end of each calendar year. The media-notice rule (164.406) was not read.

### CIRCIA covered cyber incident and ransom payment reporting (`us-circia`) - VERIFIED

- Jurisdiction / regulator: United States / CISA
- Trigger: Covered entity reasonably believes a covered cyber incident occurred; or pays a ransom
- Clock starts at: reasonable_belief
- Applies to: Critical infrastructure covered entities (proposed rule)
- Stage: Covered cyber incident report - 72h (computed by Kavach). Proposed: within 72 hours of reasonable belief the incident occurred
- Stage: Ransom payment report - no fixed hour limit (rule text only). Proposed: within 24 hours of making a ransom payment
- Source: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia (source kind: official_fetched; verified on 2026-11-13)
- Notes: NOT YET IN EFFECT: the NPRM was published 2024-04-04 and the final rule has no stated effective date; reporting is not required until the final rule takes effect. Informational only until then.

### Cybersecurity Act incident reporting (`sg-cybersecurity-act`) - VERIFIED

- Jurisdiction / regulator: Singapore / Cyber Security Agency of Singapore (CSA)
- Trigger: Prescribed cybersecurity incident affecting a CII or covered system
- Clock starts at: awareness
- Applies to: CII owners (and entities covered by the 2025 amendments)
- Stage: Initial notification (verbal) - 2h (computed by Kavach). Within 2 hours of becoming aware
- Stage: Supplementary details - 72h (computed by Kavach). Written supplementary details within 72 hours after becoming aware (CSA forms page, section 3.3)
- Stage: Final report - 720h (rule text only). Within 30 days after submission of the supplementary details (CSA forms page, section 3.4)
- Source: https://www.csa.gov.sg/legislation/forms/ (source kind: official_fetched; verified on 2026-11-16)
- Notes: Corrected 2026-11-16: the CSA forms page (read directly, section 3.2-3.4) gives 2 hours from awareness (phone/text), supplementary details within 72 hours of becoming aware, and a final report within 30 days after submission of the supplementary details. The earlier 14-day figure does not appear there (a search excerpt indicates it belonged to the 2018 rules, amended from 31 Oct 2025). The final report is now measured from the supplementary submission, not from awareness. Applies to owners of provider-owned CII; other owner types (third-party-owned, systems of temporary concern) have separate regulations not checked.

### PDPA data breach notification (`sg-pdpa`) - VERIFIED

- Jurisdiction / regulator: Singapore / Personal Data Protection Commission (PDPC)
- Trigger: Breach assessed to be notifiable (significant harm or 500 or more individuals)
- Clock starts at: assessment
- Applies to: Organisations under the PDPA
- Stage: Notify PDPC - 72h (computed by Kavach). Within 3 calendar days of assessing the breach as notifiable (measured here from first detection as a conservative proxy)
- Source: https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/guide-on-managing-and-notifying-data-breaches-under-the-pdpa-15-mar-2021.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: PDPC guide (read directly; dated 15 Mar 2021) shows assessment within 30 calendar days and notification to the PDPC within 3 calendar days after the assessment that the breach is notifiable. The statute text (PDPA s26D) was seen only via a search excerpt. Kavach measures the 3 days from first detection as a conservative outer bound. Check the PDPC site for guide revisions after 2021.

### SOCI Act critical cyber security incident (`au-soci-critical`) - VERIFIED

- Jurisdiction / regulator: Australia / Australian Signals Directorate (ASD / ACSC)
- Trigger: Incident with significant impact on availability of a critical infrastructure asset
- Clock starts at: awareness
- Applies to: Responsible entities of critical infrastructure assets
- Stage: Report to ASD - 12h (computed by Kavach). Within 12 hours of becoming aware; written record within 84 hours if reported verbally
- Source: https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from a search-result excerpt of the ASD page: critical incident reported within 12 hours of becoming aware; if reported verbally, a written record within 84 hours. Direct fetch of the page timed out. A statutory cite (s30BC) comes from a Home Affairs exposure-draft explanatory statement, not read directly.

### SOCI Act other cyber security incident (`au-soci-other`) - VERIFIED

- Jurisdiction / regulator: Australia / Australian Signals Directorate (ASD / ACSC)
- Trigger: Incident with relevant impact on a critical infrastructure asset
- Clock starts at: awareness
- Applies to: Responsible entities of critical infrastructure assets
- Stage: Report to ASD - 72h (computed by Kavach). Within 72 hours of becoming aware; written record within 48 hours if reported verbally
- Source: https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from a search-result excerpt of the ASD page: other (relevant-impact) incident within 72 hours of becoming aware; written record within 48 hours if reported verbally. Direct fetch timed out. A submission recommending a single 72-hour window is a recommendation only.

### Notifiable Data Breaches scheme (`au-ndb`) - VERIFIED

- Jurisdiction / regulator: Australia / Office of the Australian Information Commissioner (OAIC)
- Trigger: Eligible data breach likely to result in serious harm
- Clock starts at: awareness
- Applies to: Organisations covered by the Privacy Act 1988
- Stage: Complete assessment - 720h (computed by Kavach). Reasonable steps to assess within 30 days of suspicion; notify OAIC and individuals as soon as practicable once an eligible breach is confirmed
- Source: https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from search-result excerpts of OAIC guidance: reasonable steps to complete the assessment within 30 days of suspicion (OAIC treats 30 days as a ceiling); notify OAIC and individuals as soon as practicable once an eligible breach is believed. Direct fetch of oaic.gov.au returned 403. Privacy Act amendments after 2024 were not checked.

### APPI leakage report (`jp-appi`) - VERIFIED

- Jurisdiction / regulator: Japan / Personal Information Protection Commission (PPC)
- Trigger: Leak, loss or damage of personal data likely to harm individuals' rights (e.g. sensitive data, unauthorised access, 1,000+ people)
- Clock starts at: awareness
- Applies to: Business operators handling personal information
- Stage: Preliminary report - no fixed hour limit (rule text only). Promptly, commonly described as about 3 to 5 days
- Stage: Final report (wrongful-purpose cases) - 1440h (computed by Kavach). Within 60 days where wrongful acts are involved; otherwise 30 days
- Source: https://www.ppc.go.jp/personalinfo/legal/leakAction/ (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: PPC page (read directly) gives a preliminary report within 3 to 5 days of discovery, a final report within 30 days, and 60 days where the incident may have been committed for an improper purpose. Whether any exemption from the preliminary report has since been adopted was not checked.

### CERT-In Directions of 28 April 2022 (`in-certin-2022`) - VERIFIED

- Jurisdiction / regulator: India / CERT-In (MeitY)
- Trigger: Occurrence of a listed cyber security incident (Annexure I)
- Clock starts at: awareness
- Applies to: Service providers, intermediaries, data centres, body corporates, government organisations
- Stage: Report to CERT-In - 6h (computed by Kavach). Within 6 hours of noticing or being notified of the incident
- Source: https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: the Directions PDF (read directly) requires listed cyber incidents (Annexure I) to be reported "within 6 hours of noticing such" an incident. Later amendments or FAQ changes were not checked. This is the clock Kavach already shows at /v1/compliance/cert-in-clock.

### DPDP Rules 2025 personal data breach (Rule 7) (`in-dpdp`) - VERIFIED

- Jurisdiction / regulator: India / Data Protection Board of India
- Trigger: Personal data breach
- Clock starts at: awareness
- Applies to: Data fiduciaries
- Stage: Detailed report to the Board - 72h (computed by Kavach). Intimate the Board without delay; detailed report within 72 hours (Board may extend). Rule 7 applies from about 13 May 2027 (18 months after gazette publication)
- Source: https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Corrected 2026-11-16: Rule 7(2) (read in the gazetted Rules, dated 13 Nov 2025) requires intimation to the Board without delay and detailed information within 72 hours of becoming aware (or longer if the Board allows on written request). Rule 1(4): rules 5 to 16 (including Rule 7) come into force eighteen months after gazette publication, so about 13 May 2027; the clock is not yet legally binding. Some PIB pages give 14 Nov as the notification date; the gazette itself is dated 13 Nov.

### LGPD security incident (Resolution CD/ANPD 15/2024) (`br-lgpd`) - VERIFIED

- Jurisdiction / regulator: Brazil / Autoridade Nacional de Protecao de Dados (ANPD)
- Trigger: Incident that may cause relevant risk or damage to data subjects
- Clock starts at: awareness
- Applies to: Controllers under LGPD
- Stage: Notify ANPD and data subjects - 3 business days (computed by Kavach). Within 3 business days of knowing the incident affected personal data; supplementary information within 20 business days; small agents get double time
- Source: https://bibliotecadigital.mj.gov.br/bitstream/1/12879/2/RES_ANPD_2024_15.html (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: Resolution CD/ANPD 15/2024 art. 6 (read on a Ministry of Justice digital-library copy): three business days, counted from the controller knowing the incident affected personal data; supplementary information within 20 business days of the communication. Specific legislation with its own deadline prevails. The official Diario Oficial copy was not read.

### NCA Essential Cybersecurity Controls incident reporting (`sa-nca-ecc`) - VERIFIED

- Jurisdiction / regulator: Saudi Arabia / National Cybersecurity Authority (NCA)
- Trigger: Cybersecurity incident at an entity subject to NCA controls
- Clock starts at: awareness
- Applies to: Government and critical national infrastructure entities
- Stage: Notify NCA - no fixed hour limit (rule text only). Timeline not found
- Source: https://cdn.nca.gov.sa/ar/ecc-en.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: ECC-1:2018 (PDF text read directly) lists control 2-13-3-3 "Cybersecurity incidents reporting to NCA" and no numeric time limit anywhere in the document. NCA may set timelines in other instruments, which were not checked.

### PDPL breach notification (`sa-pdpl`) - VERIFIED

- Jurisdiction / regulator: Saudi Arabia / Saudi Data and AI Authority (SDAIA)
- Trigger: Breach likely to harm data subjects or conflict with their rights (draft amendments would remove the harm test)
- Clock starts at: awareness
- Applies to: Controllers under the PDPL
- Stage: Notify SDAIA - 72h (computed by Kavach). Within 72 hours of awareness; written justification if later
- Source: https://sdaia.gov.sa/en/SDAIA/about/Documents/ImplementingRegulation.pdf (source kind: official_excerpt; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16 from search-result excerpts of the SDAIA Implementing Regulation (Art. 24: notify the competent authority within 72 hours of becoming aware; missing details later with justification) and SDAIA breach guide. Direct fetch of sdaia.gov.sa was rejected. Amendments after the excerpted versions were not checked.

### Federal PDPL breach notification (`ae-pdpl`) - UNVERIFIED

- Jurisdiction / regulator: United Arab Emirates / UAE Data Office
- Trigger: Breach affecting data subjects' privacy, confidentiality or security
- Clock starts at: awareness
- Applies to: Controllers under Federal Decree-Law 45 of 2021 (DIFC and ADGM have separate regimes)
- Stage: Notify Data Office - no fixed hour limit (rule text only). Immediate notification expected; no fixed time limit published
- Source: https://uaelegislation.gov.ae/en/legislations/1972 (source kind: official_excerpt; accessed 2026-11-13)
- Notes: UNVERIFIED. 2026-11-16: a search excerpt of the UAE Legislation portal text of Decree-Law 45/2021 Art. 9 says the controller notifies the regulator when it becomes aware of a breach, "in accordance with the period and measures" set by the Executive Regulations. Whether Executive Regulations fixing a deadline are in force could not be confirmed (portal fetch returned HTTP 403), so the "no fixed time limit" claim stays unverified.

### POPIA section 22 security compromise (`za-popia`) - VERIFIED

- Jurisdiction / regulator: South Africa / Information Regulator
- Trigger: Reasonable grounds to believe personal information was accessed or acquired by an unauthorised person
- Clock starts at: awareness
- Applies to: Responsible parties under POPIA
- Stage: Notify Regulator and data subjects - no fixed hour limit (rule text only). As soon as reasonably possible after discovery; no fixed hour limit
- Source: https://inforegulator.org.za/wp-content/uploads/2025/08/PROTECTION-OF-PERSONAL-INFORMATION-ACT-4-OF-2013.pdf (source kind: official_fetched; verified on 2026-11-16)
- Notes: Confirmed 2026-11-16: POPIA s22(2) (read in the Regulator-hosted Act) requires notification "as soon as reasonably possible after the discovery of the compromise", allowing for law enforcement needs and scoping. No fixed hour limit. The Regulator says reporting is through its eServices portal from 1 April 2025 (search excerpt).

### PIPEDA breach of security safeguards (`ca-pipeda`) - VERIFIED

- Jurisdiction / regulator: Canada / Office of the Privacy Commissioner of Canada (OPC)
- Trigger: Breach creating a real risk of significant harm
- Clock starts at: awareness
- Applies to: Private-sector organisations under PIPEDA
- Stage: Report to OPC and notify individuals - no fixed hour limit (rule text only). As soon as feasible after determining the breach meets the threshold; keep records for 24 months
- Source: https://laws-lois.justice.gc.ca/eng/acts/p-8.6/page-3.html (source kind: official_fetched; verified on 2026-11-16)
- Further source: https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/
- Notes: Confirmed 2026-11-16: PIPEDA s10.1 (read on Justice Laws) requires reporting to the Commissioner "as soon as feasible after the organization determines that the breach has occurred" when there is a real risk of significant harm; s10.3 requires records of every breach. The OPC page https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/ (read) states two years (24 months) retention.

### PIPA breach notification (Art. 34) (`kr-pipa`) - VERIFIED

- Jurisdiction / regulator: South Korea / Personal Information Protection Commission (PIPC) / KISA
- Trigger: Leak of personal information (thresholds apply for regulator reporting, e.g. 1,000+ data subjects)
- Clock starts at: awareness
- Applies to: Personal information controllers
- Stage: Notify data subjects; report to PIPC/KISA in listed cases - 72h (computed by Kavach). Within 72 hours of becoming aware (Decree Art. 39 for individuals; Art. 40 for the report, only for 1,000+ data subjects, sensitive or unique identifiers, or illegal external access)
- Source: https://elaw.klri.re.kr/eng_mobile/viewer.do?hseq=69668&type=part&key=4 (source kind: official_fetched; verified on 2026-11-16)
- Notes: Corrected 2026-11-16: the 72-hour limits are in the Enforcement Decree, not the Act (KLRI English translation, text amended through Presidential Decree 35343 of 25 Feb 2025; read directly). Art. 39: notify data subjects within 72 hours (later once the cause ceases in listed cases). Art. 40: report to the PIPC or KISA within 72 hours only where 1,000 or more data subjects are affected, sensitive or unique identifiers are involved, or illegal external access occurred. KLRI is a government translation, not the Korean original; a 2026 amendment was not checked (a search excerpt showed a consolidated text effective 2026-09-11).

### PDPO data breach notification (`hk-pdpo`) - UNVERIFIED

- Jurisdiction / regulator: Hong Kong / Office of the Privacy Commissioner for Personal Data (PCPD)
- Trigger: Data breach with real risk of harm (notification currently guidance, not mandatory; reform proposed)
- Clock starts at: awareness
- Applies to: Data users under the PDPO
- Stage: Notify PCPD (guidance) - no fixed hour limit (rule text only). As soon as practicable; no statutory hour limit
- Source: https://www.pcpd.org.hk/english/resources_centre/publications/files/guidance_note_dbn_e.pdf (source kind: official_excerpt; accessed 2026-11-13)
- Notes: UNVERIFIED. 2026-11-16: search excerpts of the PCPD June 2023 guidance say notify "as soon as practicable" and an August 2024 PCPD presentation lists notification as not a statutory requirement. The PCPD PDF fetch returned empty and nothing from 2025-2026 was found, so a later statutory change cannot be ruled out.

## Summary

Verified (22): eu-gdpr-art33, eu-nis2-art23, eu-dora-major-ict, uk-gdpr, uk-nis, us-sec-8k-1-05, us-hipaa-breach, us-circia, sg-cybersecurity-act, sg-pdpa, au-soci-critical, au-soci-other, au-ndb, jp-appi, in-certin-2022, in-dpdp, br-lgpd, sa-nca-ecc, sa-pdpl, za-popia, ca-pipeda, kr-pipa.

UNVERIFIED (2): ae-pdpl, hk-pdpo.

Regimes without a published fixed deadline (rule text only): HIPAA annual log, UAE PDPL, South Africa POPIA, Canada PIPEDA, Hong Kong PDPO, Saudi NCA ECC.

## API reference and worked examples

| Endpoint | Auth | Details |
|---|---|---|
| `GET /v1/regulatory/regimes` | bearer or session | optional `jurisdiction` (case-insensitive exact match) and `verified=true|false`; returns `{count, regimes, informational, disclaimer}` with every catalog field (`id`, `jurisdiction`, `regulator`, `name`, `trigger`, `start_event`, `applies_to`, `stages`, `source_url`, `source_kind`, `sources`, `last_verified`, `last_researched`, `verified`, `notes`) |
| `GET /v1/regulatory/profile` | bearer or session | `{profile: {regimes, updated_at, updated_by}, ...}` |
| `PUT /v1/regulatory/profile` | admin token or console session | body `{"regimes": ["eu-nis2-art23", ...]}` (max 16 KiB, `regimes` must be present); duplicates are collapsed; an unknown id is 400 `unknown regime id X`; saved atomically to `<store>.regulatory.json` (mode 0600); `updated_by` is `admin` or `session` |
| `GET /v1/regulatory/clocks` | bearer or session | `regime=a,b` (comma list) overrides the saved profile; unknown id 400. With no profile and no parameter the result list is empty |

A stage carries `hours` or `business_days` (business days skip weekends only, no holidays) and a `description`. In the clocks response, a stage is `computable: true` only when it has its own hour or business-day limit measured from the start; each open high/critical finding (not resolved, not a false positive) then gets `deadline`, `remaining_seconds` (negative when late) and `overdue`, sorted most urgent first. Stages that depend on another stage or on a legal determination are `computable: false` with an empty `incidents` list. Every regime entry in the clocks output has `start_event` (the legal start) and `start_proxy`, which states that Kavach measures from first detection of the finding as a conservative proxy.

```sh
curl -s -X PUT -H "Authorization: Bearer $KAVACH_ADMIN_TOKEN" -d '{"regimes":["eu-nis2-art23","in-certin-2022"]}' \
  http://127.0.0.1:8099/v1/regulatory/profile
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/regulatory/clocks?regime=eu-nis2-art23"
# {"generated_at":"...","regimes":[{"regime":"eu-nis2-art23","name":"...","jurisdiction":"EU","verified":true,
#   "start_event":"awareness","start_proxy":"first detection of the finding (conservative proxy; ...)",
#   "stages":[{"name":"Early warning","hours":24,"business_days":0,"description":"...","computable":true,
#              "incidents":[{"finding_id":"...","rule":"...","host":"...","severity":"high","status":"open",
#                            "first_detected":"...","deadline":"...","remaining_seconds":41230,"overdue":false}]},
#             {"name":"Final report","computable":false,"incidents":[]}],
#   "notes":"...","source_url":"..."}],
#  "informational":true,"disclaimer":"...","note":"Kavach does not file reports; ..."}
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/regulatory/regimes?verified=false"
# lists ae-pdpl and hk-pdpo at this revision
```

Values in the example are illustrative.

## Limits

- 24 regimes: 22 verified, 2 `UNVERIFIED` (`ae-pdpl`, `hk-pdpo`), counted from `regulatory_regimes.json`. No status was changed in this revision of the document; see [verification-log.md](verification-log.md) for the evidence behind each.
- Clocks run from the first detection of an open high/critical finding, not from the legal start event (awareness, classification, materiality, reasonable belief or assessment). A late-detected incident therefore looks later than the regulator would measure, and an incident detected before the legal start looks earlier. Choose the conservative reading only as a reminder.
- The catalog is embedded in the binary: a rule change at a regulator is not reflected until the catalog is updated and Kavach rebuilt. Several regimes carry `source_kind: official_excerpt` (official text seen through a search-result excerpt), not a directly read page.
- Not modelled (from the verification log): DORA weekend and bank-holiday relief, HIPAA media notice, and other conditions listed in the per-regime notes above. `us-circia` is a proposed rule and informational only until it takes effect; `in-dpdp` Rule 7 is only in force about 18 months after the 13 Nov 2025 gazette.
- Kavach never files a report, notifies an authority or sends mail.
