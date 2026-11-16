# Worldwide compliance framework catalogs

Kavach supports evidence for these frameworks. It does not certify or assess compliance, and a
control is only scored when at least one Kavach signal supports it. Everything else is reported as
`not_observable` with a reason and excluded from scores.

Select a framework with `GET /v1/compliance/score?framework=ID`, `GET /v1/compliance/evidence?framework=ID`,
`kavachctl compliance score --framework ID`, or the console framework selector (populated from the API).

Catalog source: `internal/edr/compliance_controls_regional.go` (230 controls across 18 frameworks).
Titles are original summaries of public control themes, not quotations.

| id | Framework | Controls |
|----|-----------|---------:|
| nis2 | EU NIS2 Art.21 measures | 14 |
| dora | EU DORA (2022/2554) | 15 |
| gdpr-32 | EU GDPR Art.32 | 8 |
| uk-cyber-essentials | UK Cyber Essentials | 6 |
| au-essential-eight | Australia Essential Eight + maturity themes | 13 |
| au-ism | Australia ISM (selected) | 12 |
| sg-ccop | Singapore CCoP | 12 |
| sg-mas-trm | Singapore MAS TRM | 13 |
| jp-meti-nisc | Japan METI/NISC | 12 |
| sa-nca-ecc | Saudi NCA ECC | 19 |
| ae-ia | UAE IA standard | 16 |
| br-lgpd | Brazil LGPD | 9 |
| za-popia | South Africa POPIA s19-22 | 9 |
| us-cmmc-l2 | US CMMC 2.0 L2 / NIST SP 800-171 | 16 |
| us-fedramp-moderate | US FedRAMP Moderate | 19 |
| ca-cccs | Canada CCCS + PIPEDA | 12 |
| kr-ismsp | South Korea ISMS-P | 15 |
| hk-hkma | Hong Kong HKMA C-RAF / PCPD | 10 |

## Sources and verification (first pass 2026-11-13, verification pass 2026-11-16)

Web access is unreliable (EUR-Lex, legislation.gov.uk and several regulator sites returned empty, 403 or timed out for direct fetches). Status values: `verified` = the point was read in the source on 2026-11-16 (directly, or as a search-result excerpt where noted); `partial` = some control themes confirmed, others not; `UNVERIFIED` = not confirmed, with the reason. Full per-item evidence is in `verification-log.md`. Control ids marked "Kavach label" are stable local identifiers, not official clause numbers.

| Framework | Source | Status |
|-----------|--------|--------|
| UK Cyber Essentials | https://www.ncsc.gov.uk/cyberessentials/overview | verified (five controls) |
| US NIST SP 800-171 | https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final | partially verified (page reachable, family list truncated); CMMC mapping to families not checked against DoD CMMC text |
| Singapore MAS TRM | https://www.mas.gov.sg/regulation/guidelines/technology-risk-management-guidelines | page reachable; section topics unverified (PDF not read) |
| EU NIS2 Art.21 | https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng | partial (2026-11-16): Art. 21(2) measures confirmed to exist; items (a), (d), (e), (g)-(j) described in search excerpts; (b), (c), (f) only as headings; direct EUR-Lex fetch empty |
| EU DORA | https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng | partial (2026-11-16, search excerpts): topics of Art. 5, 8, 9, 11, 12, 13, 17, 18, 19, 24, 26, 28 consistent with the control titles; Art. 6 and 10 not confirmed (Art. 10 only a fragment) |
| EU GDPR Art.32 | https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=celex:32016R0679 | verified (2026-11-16, search excerpt): four listed measures (pseudonymisation/encryption, CIA and resilience, restoration, regular testing) |
| Australia Essential Eight | https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-explained | partial (2026-11-16, search excerpt): the eight strategies are confirmed; maturity entries remain themes, not exact ML text. Note: ASD now publishes "Transitioning from the Essential Eight" describing a principles-based model with no target maturity level; the catalog still follows the maturity-model layout |
| Australia ISM | https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism | UNVERIFIED; guideline names approximate; not checked in the 2026-11-16 pass beyond reachability |
| Singapore CCoP | https://www.csa.gov.sg | UNVERIFIED; control ids are Kavach labels |
| Japan | https://www.meti.go.jp / https://www.nisc.go.jp | UNVERIFIED; ids are Kavach labels |
| Saudi NCA ECC | https://cdn.nca.gov.sa/ar/ecc-en.pdf | verified (2026-11-16, PDF read directly) and corrected: Cryptography is 2-8 (2-7 is Data and Information Protection), so the id `ECC-2-7` became `ECC-2-8`; domain 4 is "Third-Party and Cloud Computing Cybersecurity" but 4-1 is Third-Party Cybersecurity (4-2 is cloud), so the `ECC-4-1` title was shortened. Other subdomain numbers used (1-1, 1-3, 1-5, 1-9, 1-10, 2-1 to 2-3, 2-5, 2-9 to 2-14, 3-1) match |
| UAE IA | https://www.tdra.gov.ae / https://u.ae | UNVERIFIED; ids are Kavach labels |
| Brazil LGPD | https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm | verified (2026-11-16, search excerpts of Planalto and government copies): art. 37 records, 41 encarregado, 46 security measures, 47 duty after processing, 48 incident communication, 49 systems, 50 good practice and governance |
| South Africa POPIA | https://inforegulator.org.za/wp-content/uploads/2025/08/PROTECTION-OF-PERSONAL-INFORMATION-ACT-4-OF-2013.pdf | verified (2026-11-16, Act read directly): s19(1), 19(2)(a)-(d), s20, s21 and s22 match the control titles |
| FedRAMP Moderate | https://www.fedramp.gov | UNVERIFIED; family-level only |
| Canada CCCS / PIPEDA | https://www.cyber.gc.ca / https://www.priv.gc.ca | partial: PIPEDA s10.1-10.3 breach provisions read (see regional-reporting.md); CCCS baseline controls UNVERIFIED |
| South Korea ISMS-P | https://isms.kisa.or.kr | UNVERIFIED; ids are Kavach labels |
| Hong Kong | https://www.hkma.gov.hk / https://www.pcpd.org.hk | UNVERIFIED (HKMA C-RAF not checked; PCPD breach guidance see regional-reporting.md) |

Where an id is described as a "Kavach label" it is a stable local identifier, not an official clause number.

## Evidence versus manual controls per framework

Counted from `compliance_controls_regional.go` (`ev(...)` = evidence-based, backed by at least one Kavach signal; `mn(...)` = manual, reported as `not_observable` in `/v1/compliance/score`):

| Framework id | Evidence-based | Manual | Total |
|---|---:|---:|---:|
| nis2 | 5 | 9 | 14 |
| dora | 6 | 9 | 15 |
| gdpr-32 | 4 | 4 | 8 |
| uk-cyber-essentials | 4 | 2 | 6 |
| au-essential-eight | 7 | 6 | 13 |
| au-ism | 5 | 7 | 12 |
| sg-ccop | 5 | 7 | 12 |
| sg-mas-trm | 5 | 8 | 13 |
| jp-meti-nisc | 5 | 7 | 12 |
| sa-nca-ecc | 4 | 15 | 19 |
| ae-ia | 6 | 10 | 16 |
| br-lgpd | 4 | 5 | 9 |
| za-popia | 6 | 3 | 9 |
| us-cmmc-l2 | 6 | 10 | 16 |
| us-fedramp-moderate | 6 | 13 | 19 |
| ca-cccs | 7 | 5 | 12 |
| kr-ismsp | 5 | 10 | 15 |
| hk-hkma | 6 | 4 | 10 |
| **Total** | **96** | **134** | **230** |

The seven original frameworks (`cis-v8`, `nist-csf-2`, `soc2`, `iso27001`, `rbi`, `cert-in`, `dpdp`) are documented in [compliance-evidence.md](compliance-evidence.md); together with the 18 above there are 25 selectable frameworks. Signals and the pass/partial/fail derivation are the same for all of them.

## Worked examples

```sh
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" "http://127.0.0.1:8099/v1/compliance/score?framework=nis2"
# {"overall":..,"grade":"..","framework":"nis2","mode":"observe-only","certification":false,
#  "frameworks":[{"id":"nis2","controls_total":14,"observable":5,"met":..,"partial":..,"unmet":..,"not_observable":9,"score":..,"grade":".."}],
#  "controls":[{"id":"...","framework":"nis2","title":"...","status":"not_observable","score":null,"reason":"..."}],
#  "evidence":{...},"note":"Scores cover observable controls only; ..."}
kavachctl compliance score --framework dora
```

## Status of verification: items still UNVERIFIED

As of the 2026-11-16 pass (see [verification-log.md](verification-log.md) for per-item evidence; nothing here was upgraded without it):

- `UNVERIFIED`: Australia ISM (guideline names approximate), Singapore CCoP (ids are Kavach labels), Japan METI/NISC (ids are Kavach labels), UAE IA (ids are Kavach labels), FedRAMP Moderate (family-level only), South Korea ISMS-P (ids are Kavach labels), Hong Kong HKMA C-RAF / PCPD (HKMA not checked), and the CCCS baseline controls of Canada CCCS / PIPEDA.
- `partial`: EU NIS2 Art.21 (items (b), (c), (f) headings only), EU DORA (Art. 6 and 10 not confirmed), Australia Essential Eight (maturity entries are themes; ASD now describes a principles-based model), US CMMC / NIST SP 800-171 (CMMC family mapping not checked against DoD text), Singapore MAS TRM (page reachable, section topics unverified).
- `verified` or `verified and corrected`: UK Cyber Essentials, EU GDPR Art.32, Brazil LGPD, South Africa POPIA, Saudi NCA ECC (one id and one title corrected).

Consequence for users: control titles for the UNVERIFIED and partial rows are original summaries of public themes and may not match the current official wording or numbering; use them as orientation, not as a citation. A control marked `not_observable` is a statement about what Kavach can see, not about the organisation.
