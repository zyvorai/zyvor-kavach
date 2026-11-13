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

## Sources and verification (accessed 2026-11-13)

Web access during research was unreliable (timeouts, 429s, empty EUR-Lex pages). Only the items marked
verified were confirmed by reading the page during this work; the rest were written from prior
knowledge of the public texts and must be checked against the source before external use.

| Framework | Source | Status |
|-----------|--------|--------|
| UK Cyber Essentials | https://www.ncsc.gov.uk/cyberessentials/overview | verified (five controls) |
| US NIST SP 800-171 | https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final | partially verified (page reachable, family list truncated); CMMC mapping to families not checked against DoD CMMC text |
| Singapore MAS TRM | https://www.mas.gov.sg/regulation/guidelines/technology-risk-management-guidelines | page reachable; section topics unverified (PDF not read) |
| EU NIS2 Art.21 | https://eur-lex.europa.eu/eli/dir/2022/2555/oj | UNVERIFIED (fetch returned empty) |
| EU DORA | https://eur-lex.europa.eu/eli/reg/2022/2554/oj | UNVERIFIED (fetch returned empty); article numbers from memory |
| EU GDPR Art.32 | https://eur-lex.europa.eu/eli/reg/2016/679/oj | UNVERIFIED |
| Australia Essential Eight | https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight | UNVERIFIED (timeout); maturity entries are themes, not exact ML text |
| Australia ISM | https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism | UNVERIFIED; guideline names approximate |
| Singapore CCoP | https://www.csa.gov.sg | UNVERIFIED; control ids are Kavach labels |
| Japan | https://www.meti.go.jp / https://www.nisc.go.jp | UNVERIFIED; ids are Kavach labels |
| Saudi NCA ECC | https://nca.gov.sa | UNVERIFIED; subdomain numbers approximate |
| UAE IA | https://www.tdra.gov.ae / https://u.ae | UNVERIFIED; ids are Kavach labels |
| Brazil LGPD | https://www.planalto.gov.br (Lei 13.709/2018) | UNVERIFIED; articles 37, 41, 46-50 from memory |
| South Africa POPIA | https://inforegulator.org.za | UNVERIFIED; s19-22 from memory |
| FedRAMP Moderate | https://www.fedramp.gov | UNVERIFIED; family-level only |
| Canada CCCS / PIPEDA | https://www.cyber.gc.ca / https://www.priv.gc.ca | UNVERIFIED |
| South Korea ISMS-P | https://isms.kisa.or.kr | UNVERIFIED; ids are Kavach labels |
| Hong Kong | https://www.hkma.gov.hk / https://www.pcpd.org.hk | UNVERIFIED |

Where an id is described as a "Kavach label" it is a stable local identifier, not an official clause number.
