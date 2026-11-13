# Regional incident-reporting clocks

Informational, not legal advice. Kavach does not file reports, notify regulators or contain anything; it only shows how long is left on each clock.

## How it works

- `GET /v1/regulatory/regimes` lists the embedded catalog (`internal/edr/regulatory_regimes.json`). Filters: `jurisdiction`, `verified`.
- `PUT /v1/regulatory/profile` (admin or session) saves the regimes that apply to you in `<store>.regulatory.json` (see `persistence-files.md`); `GET` reads it back.
- `GET /v1/regulatory/clocks[?regime=a,b]` computes, for every open high/critical finding that is not resolved or marked false positive, the deadline, time remaining and overdue flag per stage. This reuses the CERT-In clock logic, so the clock starts at the finding's first detection. Real regimes start at awareness, classification, assessment or a materiality determination, so first detection is a conservative proxy and each response says so.
- Stages that depend on another stage (for example "one month after the final intermediate report") or on a legal determination Kavach cannot see (SEC materiality) are listed with `computable: false` and rule text only. Business-day stages skip weekends only, with no holiday calendar.
- CLI: `kavachctl regulatory regimes|clocks|profile [set ID,...]`. MCP (read-only): `kavach_regulatory_regimes`, `kavach_regulatory_clocks`, `kavach_regulatory_profile`.

## Verification status

`verified: true` means the rule was read on an official regulator or legislator page (fetched, `source_kind: official_fetched`) on the date in `last_verified`. Everything else is **UNVERIFIED**: it was taken from law-firm summaries, an unofficial reproduction, or recalled without a successful fetch, and must be checked before anyone relies on it. Research date for all entries: 2026-11-13.

## Rules, sources and access dates


### GDPR Art. 33 personal data breach (`eu-gdpr-art33`) - UNVERIFIED

- Jurisdiction / regulator: EU / National supervisory authorities (EDPB coordinates)
- Trigger: Personal data breach likely to result in a risk to individuals' rights and freedoms
- Clock starts at: awareness
- Applies to: Controllers (processors must alert the controller without undue delay)
- Stage: Notify supervisory authority - 72h (computed by Kavach). Without undue delay and, where feasible, within 72 hours of becoming aware; reasons required if later
- Source: https://gdpr-info.eu/art-33-gdpr/ (source kind: secondary; accessed 2026-11-13)
- Notes: Content read from gdpr-info.eu (unofficial reproduction of the Regulation); official EUR-Lex text not read. UNVERIFIED against the official source.

### NIS2 Art. 23 significant incident (`eu-nis2-art23`) - UNVERIFIED

- Jurisdiction / regulator: EU / National competent authorities / CSIRTs
- Trigger: Significant incident affecting an essential or important entity
- Clock starts at: awareness
- Applies to: Essential and important entities under NIS2 (as transposed nationally)
- Stage: Early warning - 24h (computed by Kavach). Within 24 hours of becoming aware of a significant incident
- Stage: Incident notification - 72h (computed by Kavach). Within 72 hours of becoming aware
- Stage: Final report - no fixed hour limit (rule text only). No later than one month after the incident notification
- Source: https://eur-lex.europa.eu/eli/dir/2022/2555/oj (source kind: official_fetched; accessed 2026-11-13)
- Notes: 24h/72h/one-month figures confirmed on the EUR-Lex page; the start trigger wording and national transposition differences were NOT confirmed. UNVERIFIED.

### DORA major ICT-related incident (`eu-dora-major-ict`) - UNVERIFIED

- Jurisdiction / regulator: EU / Competent financial supervisors (ESAs oversee)
- Trigger: Incident classified as major under the DORA classification RTS
- Clock starts at: classification
- Applies to: Financial entities in scope of DORA
- Stage: Initial notification - 24h (computed by Kavach). Within 4 hours of classifying as major and no later than 24 hours after awareness
- Stage: Intermediate report - no fixed hour limit (rule text only). Within 72 hours of the initial notification
- Stage: Final report - no fixed hour limit (rule text only). No later than one month after the latest intermediate report
- Source: https://www.springlex.eu/en/packages/dora/rts-ir-regulation/article-5/ (source kind: secondary; accessed 2026-11-13)
- Notes: Taken from a secondary copy of RTS Art. 5 (OJ L 2025/301) surfaced by search; sources disagree on clock starts and weekend relief. Official EUR-Lex text not read. UNVERIFIED. Kavach computes only the 24-hour outer limit from first detection.

### UK GDPR personal data breach (`uk-gdpr`) - VERIFIED

- Jurisdiction / regulator: United Kingdom / Information Commissioner's Office (ICO)
- Trigger: Breach likely to risk individuals' rights and freedoms
- Clock starts at: awareness
- Applies to: UK controllers
- Stage: Report to ICO - 72h (computed by Kavach). Within 72 hours of becoming aware; phased reporting allowed; explain any delay
- Source: https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/ (source kind: official_fetched; accessed 2026-11-13)

### NIS Regulations 2018 incident notification (`uk-nis`) - UNVERIFIED

- Jurisdiction / regulator: United Kingdom / Sectoral competent authorities (e.g. Ofcom, Ofgem, DWI, ICO for digital service providers)
- Trigger: Incident with significant impact on continuity of an essential service
- Clock starts at: awareness
- Applies to: Operators of essential services and relevant digital service providers
- Stage: Notify competent authority - 72h (computed by Kavach). Without undue delay and no later than 72 hours
- Source: https://www.ncsc.gov.uk/collection/nis-directive (source kind: official_unfetched; accessed 2026-11-13)
- Notes: 72 hours recalled from general knowledge; page not read. UNVERIFIED. UK cyber resilience reforms may change this.

### Form 8-K Item 1.05 material cybersecurity incident (`us-sec-8k-1-05`) - VERIFIED

- Jurisdiction / regulator: United States / Securities and Exchange Commission
- Trigger: Registrant determines a cybersecurity incident is material
- Clock starts at: materiality_determination
- Applies to: SEC registrants (US-listed issuers)
- Stage: File Form 8-K Item 1.05 - 4 business days (rule text only). Four business days after determining materiality; materiality must be determined without unreasonable delay; the US Attorney General may authorise delay for national security or public safety
- Source: https://www.sec.gov/newsroom/press-releases/2023-139 (source kind: official_fetched; accessed 2026-11-13)
- Notes: Kavach cannot know when materiality is determined, so no deadline is computed from findings (the clock starts at the determination, not detection).

### HIPAA Breach Notification Rule (`us-hipaa-breach`) - UNVERIFIED

- Jurisdiction / regulator: United States / HHS Office for Civil Rights
- Trigger: Discovery of a breach of unsecured protected health information
- Clock starts at: discovery
- Applies to: HIPAA covered entities (business associates notify the covered entity)
- Stage: Notify individuals and HHS (500 or more) - 1440h (computed by Kavach). Without unreasonable delay and no later than 60 calendar days after discovery
- Stage: Annual HHS log (fewer than 500) - no fixed hour limit (rule text only). Within 60 days after the end of the calendar year in which the breach was discovered
- Source: https://www.hhs.gov/hipaa/for-professionals/breach-notification/breach-reporting/index.html (source kind: official_unfetched; accessed 2026-11-13)
- Notes: HHS page returned HTTP 403 to the research tool; values recalled from general knowledge. UNVERIFIED. Media notice also applies for breaches over 500 residents of a state.

### CIRCIA covered cyber incident and ransom payment reporting (`us-circia`) - VERIFIED

- Jurisdiction / regulator: United States / CISA
- Trigger: Covered entity reasonably believes a covered cyber incident occurred; or pays a ransom
- Clock starts at: reasonable_belief
- Applies to: Critical infrastructure covered entities (proposed rule)
- Stage: Covered cyber incident report - 72h (computed by Kavach). Proposed: within 72 hours of reasonable belief the incident occurred
- Stage: Ransom payment report - no fixed hour limit (rule text only). Proposed: within 24 hours of making a ransom payment
- Source: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia (source kind: official_fetched; accessed 2026-11-13)
- Notes: NOT YET IN EFFECT: the NPRM was published 2024-04-04 and the final rule has no stated effective date; reporting is not required until the final rule takes effect. Informational only until then.

### Cybersecurity Act incident reporting (`sg-cybersecurity-act`) - UNVERIFIED

- Jurisdiction / regulator: Singapore / Cyber Security Agency of Singapore (CSA)
- Trigger: Prescribed cybersecurity incident affecting a CII or covered system
- Clock starts at: awareness
- Applies to: CII owners (and entities covered by the 2025 amendments)
- Stage: Initial notification (verbal) - 2h (computed by Kavach). Within 2 hours of becoming aware
- Stage: Supplementary details - 72h (computed by Kavach). Written details within 72 hours per CSA form; secondary sources cite 14 days, conflicting
- Stage: Final report - 720h (computed by Kavach). Within 30 days per CSA form
- Source: https://www.csa.gov.sg/legislation/forms/ (source kind: secondary; accessed 2026-11-13)
- Notes: Figures surfaced via search summary of the CSA form page; the Act page fetched did not state them and sources conflict. UNVERIFIED.

### PDPA data breach notification (`sg-pdpa`) - UNVERIFIED

- Jurisdiction / regulator: Singapore / Personal Data Protection Commission (PDPC)
- Trigger: Breach assessed to be notifiable (significant harm or 500 or more individuals)
- Clock starts at: assessment
- Applies to: Organisations under the PDPA
- Stage: Notify PDPC - 72h (computed by Kavach). Within 3 calendar days of assessing the breach as notifiable (measured here from first detection as a conservative proxy)
- Source: https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act/data-protection-obligations (source kind: official_unfetched; accessed 2026-11-13)
- Notes: Secondary sources only; PDPC page not read. UNVERIFIED.

### SOCI Act critical cyber security incident (`au-soci-critical`) - UNVERIFIED

- Jurisdiction / regulator: Australia / Australian Signals Directorate (ASD / ACSC)
- Trigger: Incident with significant impact on availability of a critical infrastructure asset
- Clock starts at: awareness
- Applies to: Responsible entities of critical infrastructure assets
- Stage: Report to ASD - 12h (computed by Kavach). Within 12 hours of becoming aware; written follow-up within 84 hours if reported verbally (sources differ)
- Source: https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries; ASD page not read. UNVERIFIED.

### SOCI Act other cyber security incident (`au-soci-other`) - UNVERIFIED

- Jurisdiction / regulator: Australia / Australian Signals Directorate (ASD / ACSC)
- Trigger: Incident with relevant impact on a critical infrastructure asset
- Clock starts at: awareness
- Applies to: Responsible entities of critical infrastructure assets
- Stage: Report to ASD - 72h (computed by Kavach). Within 72 hours of becoming aware
- Source: https://www.cyber.gov.au/report-and-recover/report/report-a-cyber-security-incident (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries. UNVERIFIED.

### Notifiable Data Breaches scheme (`au-ndb`) - UNVERIFIED

- Jurisdiction / regulator: Australia / Office of the Australian Information Commissioner (OAIC)
- Trigger: Eligible data breach likely to result in serious harm
- Clock starts at: awareness
- Applies to: Organisations covered by the Privacy Act 1988
- Stage: Complete assessment - 720h (computed by Kavach). Reasonable steps to assess within 30 days of suspicion; notify OAIC and individuals as soon as practicable once an eligible breach is confirmed
- Source: https://www.oaic.gov.au/privacy/notifiable-data-breaches (source kind: official_unfetched; accessed 2026-11-13)
- Notes: Secondary summaries only; OAIC page not read. UNVERIFIED.

### APPI leakage report (`jp-appi`) - UNVERIFIED

- Jurisdiction / regulator: Japan / Personal Information Protection Commission (PPC)
- Trigger: Leak, loss or damage of personal data likely to harm individuals' rights (e.g. sensitive data, unauthorised access, 1,000+ people)
- Clock starts at: awareness
- Applies to: Business operators handling personal information
- Stage: Preliminary report - no fixed hour limit (rule text only). Promptly, commonly described as about 3 to 5 days
- Stage: Final report (wrongful-purpose cases) - 1440h (computed by Kavach). Within 60 days where wrongful acts are involved; otherwise 30 days
- Source: https://www.ppc.go.jp/en/ (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries (Nishimura, Baker McKenzie); PPC guideline not read; a proposed exemption from the preliminary report was not confirmed. UNVERIFIED.

### CERT-In Directions of 28 April 2022 (`in-certin-2022`) - UNVERIFIED

- Jurisdiction / regulator: India / CERT-In (MeitY)
- Trigger: Occurrence of a listed cyber security incident (Annexure I)
- Clock starts at: awareness
- Applies to: Service providers, intermediaries, data centres, body corporates, government organisations
- Stage: Report to CERT-In - 6h (computed by Kavach). Within 6 hours of noticing or being notified of the incident
- Source: https://www.cert-in.org.in/ (source kind: secondary; accessed 2026-11-13)
- Notes: Six hours corroborated by several law-firm summaries; the official Directions PDF was not read, and sources differ on the exact trigger. This is the clock Kavach already shows at /v1/compliance/cert-in-clock. UNVERIFIED.

### DPDP Rules 2025 personal data breach (Rule 7) (`in-dpdp`) - UNVERIFIED

- Jurisdiction / regulator: India / Data Protection Board of India
- Trigger: Personal data breach
- Clock starts at: awareness
- Applies to: Data fiduciaries
- Stage: Detailed report to the Board - 72h (computed by Kavach). Intimate the Board and affected individuals without delay; detailed report within 72 hours (Board may extend)
- Source: https://www.dpdpa.com/dpdparules/rule7.html (source kind: secondary; accessed 2026-11-13)
- Notes: Secondary page reproducing Rule 7; breach obligations may only apply from a later compliance date (one source says 13 May 2027). UNVERIFIED.

### LGPD security incident (Resolution CD/ANPD 15/2024) (`br-lgpd`) - UNVERIFIED

- Jurisdiction / regulator: Brazil / Autoridade Nacional de Protecao de Dados (ANPD)
- Trigger: Incident that may cause relevant risk or damage to data subjects
- Clock starts at: awareness
- Applies to: Controllers under LGPD
- Stage: Notify ANPD and data subjects - 3 business days (computed by Kavach). Within 3 business days of knowing the incident affected personal data; supplementary information within 20 business days; small agents get double time
- Source: https://www.gov.br/anpd/pt-br (source kind: secondary; accessed 2026-11-13)
- Notes: Several Brazilian law-firm summaries agree on 3 business days; the Resolution text was not read. UNVERIFIED.

### NCA Essential Cybersecurity Controls incident reporting (`sa-nca-ecc`) - UNVERIFIED

- Jurisdiction / regulator: Saudi Arabia / National Cybersecurity Authority (NCA)
- Trigger: Cybersecurity incident at an entity subject to NCA controls
- Clock starts at: awareness
- Applies to: Government and critical national infrastructure entities
- Stage: Notify NCA - no fixed hour limit (rule text only). Timeline not found
- Source: https://nca.gov.sa/en/ (source kind: official_unfetched; accessed 2026-11-13)
- Notes: No reporting timeline found in research. UNVERIFIED (rule text unknown).

### PDPL breach notification (`sa-pdpl`) - UNVERIFIED

- Jurisdiction / regulator: Saudi Arabia / Saudi Data and AI Authority (SDAIA)
- Trigger: Breach likely to harm data subjects or conflict with their rights (draft amendments would remove the harm test)
- Clock starts at: awareness
- Applies to: Controllers under the PDPL
- Stage: Notify SDAIA - 72h (computed by Kavach). Within 72 hours of awareness; written justification if later
- Source: https://sdaia.gov.sa/en/ (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries; draft amendments are proposals. UNVERIFIED.

### Federal PDPL breach notification (`ae-pdpl`) - UNVERIFIED

- Jurisdiction / regulator: United Arab Emirates / UAE Data Office
- Trigger: Breach affecting data subjects' privacy, confidentiality or security
- Clock starts at: awareness
- Applies to: Controllers under Federal Decree-Law 45 of 2021 (DIFC and ADGM have separate regimes)
- Stage: Notify Data Office - no fixed hour limit (rule text only). Immediate notification expected; no fixed time limit published
- Source: https://uaelegislation.gov.ae/ (source kind: secondary; accessed 2026-11-13)
- Notes: Secondary summaries say the Executive Regulations had not fixed a deadline. UNVERIFIED.

### POPIA section 22 security compromise (`za-popia`) - UNVERIFIED

- Jurisdiction / regulator: South Africa / Information Regulator
- Trigger: Reasonable grounds to believe personal information was accessed or acquired by an unauthorised person
- Clock starts at: awareness
- Applies to: Responsible parties under POPIA
- Stage: Notify Regulator and data subjects - no fixed hour limit (rule text only). As soon as reasonably possible after discovery; no fixed hour limit
- Source: https://inforegulator.org.za/ (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries; form SCN1. UNVERIFIED.

### PIPEDA breach of security safeguards (`ca-pipeda`) - UNVERIFIED

- Jurisdiction / regulator: Canada / Office of the Privacy Commissioner of Canada (OPC)
- Trigger: Breach creating a real risk of significant harm
- Clock starts at: awareness
- Applies to: Private-sector organisations under PIPEDA
- Stage: Report to OPC and notify individuals - no fixed hour limit (rule text only). As soon as feasible after determining the breach meets the threshold; keep records for 24 months
- Source: https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/pipeda-compliance-help/pipeda-breach-of-security-safeguards/ (source kind: official_unfetched; accessed 2026-11-13)
- Notes: The OPC page tried returned HTTP 404; wording from general knowledge. UNVERIFIED.

### PIPA breach notification (Art. 34) (`kr-pipa`) - UNVERIFIED

- Jurisdiction / regulator: South Korea / Personal Information Protection Commission (PIPC) / KISA
- Trigger: Leak of personal information (thresholds apply for regulator reporting, e.g. 1,000+ data subjects)
- Clock starts at: awareness
- Applies to: Personal information controllers
- Stage: Notify data subjects and report to PIPC/KISA - 72h (computed by Kavach). Within 72 hours of becoming aware
- Source: https://www.pipc.go.kr/eng/ (source kind: secondary; accessed 2026-11-13)
- Notes: Law-firm summaries; a 2026 amendment extending triggers could not be confirmed. UNVERIFIED.

### PDPO data breach notification (`hk-pdpo`) - UNVERIFIED

- Jurisdiction / regulator: Hong Kong / Office of the Privacy Commissioner for Personal Data (PCPD)
- Trigger: Data breach with real risk of harm (notification currently guidance, not mandatory; reform proposed)
- Clock starts at: awareness
- Applies to: Data users under the PDPO
- Stage: Notify PCPD (guidance) - no fixed hour limit (rule text only). As soon as practicable; no statutory hour limit
- Source: https://www.pcpd.org.hk/english/index.html (source kind: official_unfetched; accessed 2026-11-13)
- Notes: PCPD page fetch returned no content; recalled from general knowledge. UNVERIFIED.

## Summary

Verified: uk-gdpr, us-sec-8k-1-05, us-circia.

UNVERIFIED: eu-gdpr-art33, eu-nis2-art23, eu-dora-major-ict, uk-nis, us-hipaa-breach, sg-cybersecurity-act, sg-pdpa, au-soci-critical, au-soci-other, au-ndb, jp-appi, in-certin-2022, in-dpdp, br-lgpd, sa-nca-ecc, sa-pdpl, ae-pdpl, za-popia, ca-pipeda, kr-pipa, hk-pdpo.

Regimes without a published fixed deadline (rule text only): HIPAA annual log, UAE PDPL, South Africa POPIA, Canada PIPEDA, Hong Kong PDPO, Saudi NCA ECC.
