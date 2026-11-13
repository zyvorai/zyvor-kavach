// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Regional and worldwide framework catalogs. Observation only: Kavach supports
// evidence for these frameworks; it does not certify or assess compliance.
// Control ids are short public references (prefixed per framework so they stay
// globally unique); titles and notes are original summaries. A control is
// evidence-based only when at least one Kavach signal supports it; everything
// else is manual with a reason. See docs/regional-frameworks.md for sources.

const (
	rProc   = "Organisational or procedural; not observable from Kavach telemetry."
	rConfig = "Configuration or architecture decision; Kavach does not read it."
	rCrypto = "Kavach does not inspect cryptographic configuration or key handling."
	rPhys   = "Physical or environmental; out of scope for endpoint telemetry."
	rIAM    = "Identity and access administration is handled by the identity provider, not observed by Kavach."
	rLegal  = "Legal, contractual or regulatory decision for the organisation; Kavach only supplies supporting records."
	rBCP    = "Backup, recovery and continuity are not observed by Kavach."
	rVuln   = "Kavach is not a vulnerability or patch scanner; SBOM only lists components."
	rVendor = "Third-party and supplier management is contractual; not observed by Kavach."
)

func mn(fw, id, title, why string) evControl { return ctl(fw, id, title, "manual", why) }
func ev(fw, id, title, note string, sig ...string) evControl {
	return ctl(fw, id, title, "", note, sig...)
}

func init() {
	evidenceFrameworks = append(evidenceFrameworks, regionalFrameworks...)
	evidenceCatalog = append(evidenceCatalog, regionalControls...)
}

var regionalFrameworks = []evidenceFramework{
	{"nis2", "EU NIS2 Directive Art.21 measures", "Cybersecurity risk-management measures; Kavach supports monitoring and incident-handling evidence only."},
	{"dora", "EU DORA (Regulation 2022/2554)", "ICT risk, incident, testing and third-party pillars; observation evidence only."},
	{"gdpr-32", "EU GDPR Art.32 security of processing", "Technical and organisational security evidence; no legal determination."},
	{"uk-cyber-essentials", "UK Cyber Essentials (five controls)", "Technical control themes; Kavach does not assess or certify."},
	{"au-essential-eight", "Australia Essential Eight (with maturity levels)", "Mitigation strategies and maturity-level themes; evidence support only."},
	{"au-ism", "Australia ISM (selected guidelines)", "Information Security Manual guideline themes with observable evidence."},
	{"sg-ccop", "Singapore Cybersecurity Code of Practice (CCoP)", "CII owner code themes; evidence support only."},
	{"sg-mas-trm", "Singapore MAS Technology Risk Management", "MAS TRM guideline themes; evidence support only."},
	{"jp-meti-nisc", "Japan METI/NISC cybersecurity guidelines", "Management guideline and NISC standard themes; evidence support only."},
	{"sa-nca-ecc", "Saudi NCA Essential Cybersecurity Controls", "ECC domains; evidence support only."},
	{"ae-ia", "UAE Information Assurance standard", "UAE IA control families; evidence support only."},
	{"br-lgpd", "Brazil LGPD security and incident provisions", "Security, prevention and incident communication themes; no legal determination."},
	{"za-popia", "South Africa POPIA s19 security safeguards", "Section 19-22 themes; no legal determination."},
	{"us-cmmc-l2", "US CMMC 2.0 Level 2 (NIST SP 800-171 families)", "The families of NIST SP 800-171; evidence support only."},
	{"us-fedramp-moderate", "US FedRAMP Moderate (NIST 800-53 families)", "Moderate-baseline control families; evidence support only."},
	{"ca-cccs", "Canada CCCS baseline controls and PIPEDA safeguards", "Baseline cyber security control themes and privacy safeguards."},
	{"kr-ismsp", "South Korea ISMS-P", "Management system and protection measure themes; evidence support only."},
	{"hk-hkma", "Hong Kong HKMA C-RAF / PCPD security", "Cyber resilience and data-security themes; evidence support only."},
}

var regionalControls = []evControl{
	// EU NIS2 Art.21(2)
	mn("nis2", "NIS2 21(2)(a)", "Risk analysis and information system security policies", rProc),
	ev("nis2", "NIS2 21(2)(b)", "Incident handling", "Incident workflow and alert routing record handling activity.", sigWorkflow, sigAlerts),
	mn("nis2", "NIS2 21(2)(c)", "Business continuity, backup and crisis management", rBCP),
	mn("nis2", "NIS2 21(2)(d)", "Supply chain security", rVendor),
	ev("nis2", "NIS2 21(2)(e)", "Security in acquisition, development and maintenance incl. vulnerability handling", "SBOM supplies the component inventory for vulnerability matching; disclosure handling is manual.", sigSBOM),
	mn("nis2", "NIS2 21(2)(f)", "Policies to assess effectiveness of risk-management measures", rProc),
	mn("nis2", "NIS2 21(2)(g)", "Basic cyber hygiene practices and training", rProc),
	mn("nis2", "NIS2 21(2)(h)", "Policies on cryptography and encryption", rCrypto),
	mn("nis2", "NIS2 21(2)(i)", "Human resources security, access control and asset management", rIAM),
	ev("nis2", "NIS2 21(2)(i-assets)", "Asset visibility for enrolled endpoints", "Enrolled agents and SBOM show the endpoint and software inventory.", sigFleet, sigSBOM),
	mn("nis2", "NIS2 21(2)(j)", "Multi-factor authentication and secured communications", rIAM),
	ev("nis2", "NIS2 21-monitor", "Continuous monitoring of systems for malicious activity", "Behavioural detections and findings telemetry.", sigDetect, sigTelem),
	ev("nis2", "NIS2 23-early-warning", "Significant-incident early warning and notification readiness", "Incident workflow and overdue-incident tracking support the timeline; filing is manual.", sigWorkflow, sigTimely),
	mn("nis2", "NIS2 20-governance", "Management body approval and oversight of measures", rLegal),

	// EU DORA
	mn("dora", "DORA 5-governance", "ICT risk governance by the management body", rProc),
	mn("dora", "DORA 6-framework", "ICT risk management framework documented and reviewed", rProc),
	ev("dora", "DORA 8-identification", "Identification and inventory of ICT assets and functions", "Enrolled agents and SBOM inventory.", sigFleet, sigSBOM),
	ev("dora", "DORA 9-protection", "Protection and prevention of ICT risk", "Behavioural detections and file-integrity events on enrolled hosts.", sigDetect, sigFIM),
	ev("dora", "DORA 10-detection", "Detection of anomalous activity and ICT incidents", "Detections, findings and alert routing.", sigDetect, sigTelem, sigAlerts),
	mn("dora", "DORA 11-response-recovery", "ICT business continuity and response and recovery plans", rBCP),
	mn("dora", "DORA 12-backup", "Backup policies, restoration and recovery methods", rBCP),
	mn("dora", "DORA 13-learning", "Learning and evolving from incidents", "Incident workflow history can feed reviews; the review itself is manual."),
	ev("dora", "DORA 17-incident-process", "ICT-related incident management process", "Incident workflow transitions and overdue tracking.", sigWorkflow, sigTimely),
	ev("dora", "DORA 18-classification", "Classification of ICT incidents and cyber threats", "Findings carry severity and triage state.", sigTelem, sigWorkflow),
	ev("dora", "DORA 19-reporting", "Reporting of major ICT incidents", "Incident timeline supports reports; Kavach does not file them.", sigWorkflow, sigAudit),
	mn("dora", "DORA 24-testing-programme", "Digital operational resilience testing programme", rProc),
	mn("dora", "DORA 26-tlpt", "Threat-led penetration testing", "Penetration testing is an external exercise; not observable."),
	mn("dora", "DORA 28-third-party", "General principles for ICT third-party risk management", rVendor),
	mn("dora", "DORA 30-contract-terms", "Key contractual provisions for ICT services", rVendor),

	// GDPR Art.32
	mn("gdpr-32", "GDPR 32(1)(a)", "Pseudonymisation and encryption of personal data", rCrypto),
	ev("gdpr-32", "GDPR 32(1)(b)", "Ongoing confidentiality, integrity, availability and resilience of systems", "Detections, file integrity and agent availability.", sigDetect, sigFIM, sigFleet),
	mn("gdpr-32", "GDPR 32(1)(c)", "Ability to restore availability and access after an incident", rBCP),
	ev("gdpr-32", "GDPR 32(1)(d)", "Regular testing and evaluation of security measures", "Compliance evidence endpoints and audit log give a repeatable observation record.", sigAudit, sigFleet),
	ev("gdpr-32", "GDPR 32(2)-risk", "Account taken of risks from accidental or unlawful destruction, loss, alteration", "File-integrity events on monitored paths.", sigFIM),
	mn("gdpr-32", "GDPR 32(4)", "Persons acting under authority process data only on instructions", rProc),
	ev("gdpr-32", "GDPR 33-breach-support", "Evidence supporting personal-data breach assessment", "Findings and incident timeline; the breach decision and notice are manual.", sigWorkflow, sigTelem),
	mn("gdpr-32", "GDPR 25-by-design", "Data protection by design and by default", rLegal),

	// UK Cyber Essentials
	mn("uk-cyber-essentials", "CE-firewalls", "Boundary firewalls and internet gateways", rConfig),
	ev("uk-cyber-essentials", "CE-secure-config", "Secure configuration of devices and software", "File-integrity events show drift on monitored configuration paths.", sigFIM),
	ev("uk-cyber-essentials", "CE-updates", "Security update management", "SBOM supplies installed-version inventory; patch status is not assessed.", sigSBOM),
	mn("uk-cyber-essentials", "CE-access-control", "User access control", rIAM),
	ev("uk-cyber-essentials", "CE-malware", "Malware protection", "Behavioural detections on enrolled endpoints (observation only).", sigDetect, sigFleet),
	ev("uk-cyber-essentials", "CE-scope-devices", "In-scope device inventory", "Enrolled agents list devices in scope.", sigFleet),

	// Australia Essential Eight
	mn("au-essential-eight", "E8-app-control", "Application control", "Kavach observes execution but does not enforce or audit allow-listing policy."),
	ev("au-essential-eight", "E8-patch-apps", "Patch applications", "SBOM supplies component versions; patch timing is not assessed.", sigSBOM),
	mn("au-essential-eight", "E8-office-macros", "Configure Microsoft Office macro settings", rConfig),
	mn("au-essential-eight", "E8-app-hardening", "User application hardening", rConfig),
	mn("au-essential-eight", "E8-restrict-admin", "Restrict administrative privileges", rIAM),
	ev("au-essential-eight", "E8-patch-os", "Patch operating systems", "SBOM and agent inventory supply OS and package versions.", sigSBOM, sigFleet),
	mn("au-essential-eight", "E8-mfa", "Multi-factor authentication", rIAM),
	mn("au-essential-eight", "E8-backups", "Regular backups", rBCP),
	ev("au-essential-eight", "E8-ML1-logging", "Maturity 1: events logged for key controls", "Findings ledger and audit log.", sigAudit, sigTelem),
	ev("au-essential-eight", "E8-ML2-central-logs", "Maturity 2: events centralised and protected", "Append-only findings ledger and audit log; log-host protection is manual.", sigAudit, sigTelem),
	ev("au-essential-eight", "E8-ML2-monitor", "Maturity 2: detected events analysed in a timely manner", "Detections, alert routing and incident workflow.", sigDetect, sigAlerts, sigWorkflow),
	ev("au-essential-eight", "E8-ML3-timely-response", "Maturity 3: incidents handled within defined timeframes", "Overdue high/critical incident tracking.", sigTimely, sigWorkflow),
	ev("au-essential-eight", "E8-ML3-integrity", "Maturity 3: unauthorised change detection on protected files", "File-integrity events.", sigFIM),

	// Australia ISM
	mn("au-ism", "ISM-governance", "Cyber security governance and roles", rProc),
	ev("au-ism", "ISM-incident-mgmt", "Cyber security incident management", "Incident workflow and alert routing.", sigWorkflow, sigAlerts),
	ev("au-ism", "ISM-monitoring", "Event logging and monitoring", "Audit log, findings and detections.", sigAudit, sigTelem, sigDetect),
	ev("au-ism", "ISM-malware", "Malicious code detection on endpoints", "Behavioural detections.", sigDetect, sigFleet),
	ev("au-ism", "ISM-software-inventory", "Software and system inventory", "SBOM and enrolled agents.", sigSBOM, sigFleet),
	ev("au-ism", "ISM-change-detect", "Detecting unauthorised changes to systems", "File-integrity events.", sigFIM),
	mn("au-ism", "ISM-cryptography", "Cryptographic fundamentals and key management", rCrypto),
	mn("au-ism", "ISM-network", "Network design and gateway security", rConfig),
	mn("au-ism", "ISM-personnel", "Personnel security and awareness", rProc),
	mn("au-ism", "ISM-physical", "Physical security of systems and facilities", rPhys),
	mn("au-ism", "ISM-access", "System access, authentication and privileged access", rIAM),
	mn("au-ism", "ISM-supply-chain", "Procurement and outsourcing", rVendor),

	// Singapore CCoP
	mn("sg-ccop", "CCoP-governance", "Governance and risk management of the CII", rProc),
	ev("sg-ccop", "CCoP-asset-mgmt", "Asset identification and inventory", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("sg-ccop", "CCoP-access", "Access control and identity management", rIAM),
	ev("sg-ccop", "CCoP-detection", "Cybersecurity monitoring and detection", "Detections, findings and alerts.", sigDetect, sigTelem, sigAlerts),
	ev("sg-ccop", "CCoP-incident", "Incident response and reporting readiness", "Incident workflow and overdue tracking; reporting to the regulator is manual.", sigWorkflow, sigTimely),
	ev("sg-ccop", "CCoP-logging", "Audit logging and retention", "Audit log and findings ledger; retention length is manual.", sigAudit, sigTelem),
	ev("sg-ccop", "CCoP-integrity", "Integrity monitoring of critical systems", "File-integrity events.", sigFIM),
	mn("sg-ccop", "CCoP-vuln-assess", "Vulnerability assessment and penetration testing", rVuln),
	mn("sg-ccop", "CCoP-resilience", "Resilience and continuity", rBCP),
	mn("sg-ccop", "CCoP-supply-chain", "Third-party and supply chain risk", rVendor),
	mn("sg-ccop", "CCoP-training", "Training and awareness", rProc),
	mn("sg-ccop", "CCoP-exercises", "Cybersecurity exercises", rProc),

	// Singapore MAS TRM
	mn("sg-mas-trm", "TRM-1-governance", "Technology risk governance and oversight", rProc),
	mn("sg-mas-trm", "TRM-3-risk-framework", "Technology risk management framework", rProc),
	ev("sg-mas-trm", "TRM-5-asset-mgmt", "IT asset and software inventory", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("sg-mas-trm", "TRM-6-sdlc", "Software development lifecycle and security by design", rProc),
	ev("sg-mas-trm", "TRM-7-change", "Change monitoring", "File-integrity events record changes on monitored paths.", sigFIM),
	mn("sg-mas-trm", "TRM-8-resilience", "IT service management and resilience", rBCP),
	mn("sg-mas-trm", "TRM-9-access", "Access control and privileged access", rIAM),
	mn("sg-mas-trm", "TRM-10-crypto", "Cryptography and key management", rCrypto),
	ev("sg-mas-trm", "TRM-11-incident", "Incident management and notification readiness", "Incident workflow and overdue tracking; MAS notification is manual.", sigWorkflow, sigTimely),
	ev("sg-mas-trm", "TRM-12-monitor", "Cyber event monitoring and detection", "Detections, findings and alerts.", sigDetect, sigTelem, sigAlerts),
	ev("sg-mas-trm", "TRM-13-malware", "Malware protection", "Behavioural detections.", sigDetect, sigFleet),
	mn("sg-mas-trm", "TRM-14-testing", "Security testing and assessment", rVuln),
	mn("sg-mas-trm", "TRM-15-third-party", "Third-party and cloud risk", rVendor),

	// Japan
	mn("jp-meti-nisc", "JP-CSMG-1", "Management recognises cyber risk and directs measures", rProc),
	mn("jp-meti-nisc", "JP-CSMG-2", "Security framework, systems and resources established", rProc),
	mn("jp-meti-nisc", "JP-CSMG-3", "Risk identification and response plans", rProc),
	ev("jp-meti-nisc", "JP-CSMG-4-protect", "Protective measures including endpoint protection", "Behavioural detections on enrolled endpoints.", sigDetect, sigFleet),
	ev("jp-meti-nisc", "JP-CSMG-5-detect", "Detection of anomalies and incidents", "Detections, findings and alerts.", sigDetect, sigTelem, sigAlerts),
	ev("jp-meti-nisc", "JP-CSMG-6-respond", "Incident response and recovery system", "Incident workflow; recovery is manual.", sigWorkflow),
	mn("jp-meti-nisc", "JP-CSMG-7-supply-chain", "Supply chain security management", rVendor),
	mn("jp-meti-nisc", "JP-CSMG-8-disclosure", "Information sharing and disclosure", rLegal),
	ev("jp-meti-nisc", "JP-NISC-logging", "Log collection and analysis (government standard theme)", "Audit log and findings ledger.", sigAudit, sigTelem),
	ev("jp-meti-nisc", "JP-NISC-asset", "Information asset management (government standard theme)", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("jp-meti-nisc", "JP-NISC-training", "Training and awareness", rProc),
	mn("jp-meti-nisc", "JP-NISC-physical", "Physical and environmental security", rPhys),

	// Saudi NCA ECC
	mn("sa-nca-ecc", "ECC-1-1", "Cybersecurity strategy", rProc),
	mn("sa-nca-ecc", "ECC-1-3", "Cybersecurity policies and procedures", rProc),
	mn("sa-nca-ecc", "ECC-1-5", "Cybersecurity risk management", rProc),
	mn("sa-nca-ecc", "ECC-1-9", "Cybersecurity in human resources", rProc),
	mn("sa-nca-ecc", "ECC-1-10", "Awareness and training", rProc),
	ev("sa-nca-ecc", "ECC-2-1", "Asset management", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("sa-nca-ecc", "ECC-2-2", "Identity and access management", rIAM),
	mn("sa-nca-ecc", "ECC-2-3", "Information system protection (hardening)", rConfig),
	ev("sa-nca-ecc", "ECC-2-3-malware", "Protection from malware on endpoints", "Behavioural detections.", sigDetect, sigFleet),
	mn("sa-nca-ecc", "ECC-2-5", "Network security management", rConfig),
	mn("sa-nca-ecc", "ECC-2-7", "Cryptography", rCrypto),
	mn("sa-nca-ecc", "ECC-2-9", "Backup and recovery management", rBCP),
	mn("sa-nca-ecc", "ECC-2-10", "Vulnerabilities management", rVuln),
	mn("sa-nca-ecc", "ECC-2-11", "Penetration testing", rVuln),
	ev("sa-nca-ecc", "ECC-2-12", "Event logs and monitoring management", "Audit log, findings and detections.", sigAudit, sigTelem, sigDetect),
	ev("sa-nca-ecc", "ECC-2-13", "Incident and threat management", "Incident workflow and alert routing.", sigWorkflow, sigAlerts),
	mn("sa-nca-ecc", "ECC-2-14", "Physical security", rPhys),
	mn("sa-nca-ecc", "ECC-3-1", "Cybersecurity resilience in business continuity", rBCP),
	mn("sa-nca-ecc", "ECC-4-1", "Third-party and cloud computing security", rVendor),

	// UAE IA
	mn("ae-ia", "IA-M1", "Strategy and planning", rProc),
	mn("ae-ia", "IA-M2", "Information security risk management", rProc),
	mn("ae-ia", "IA-M3", "Awareness and training", rProc),
	mn("ae-ia", "IA-M4", "Human resources security", rProc),
	ev("ae-ia", "IA-M5", "Compliance and audit support", "Audit log and fleet state provide repeatable observation records.", sigAudit, sigFleet),
	ev("ae-ia", "IA-M6", "Information security incident management", "Incident workflow and alert routing.", sigWorkflow, sigAlerts),
	ev("ae-ia", "IA-T1-asset", "Asset management", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("ae-ia", "IA-T2-physical", "Physical and environmental security", rPhys),
	mn("ae-ia", "IA-T3-access", "Access control", rIAM),
	ev("ae-ia", "IA-T4-ops-malware", "Operations: malware protection", "Behavioural detections.", sigDetect, sigFleet),
	ev("ae-ia", "IA-T4-ops-logging", "Operations: logging and monitoring", "Audit log and findings.", sigAudit, sigTelem),
	ev("ae-ia", "IA-T4-ops-change", "Operations: change monitoring", "File-integrity events.", sigFIM),
	mn("ae-ia", "IA-T5-comms", "Communications and network security", rConfig),
	mn("ae-ia", "IA-T6-crypto", "Cryptography", rCrypto),
	mn("ae-ia", "IA-T7-continuity", "Business continuity", rBCP),
	mn("ae-ia", "IA-T8-third-party", "Third-party security", rVendor),

	// Brazil LGPD
	ev("br-lgpd", "LGPD-46-measures", "Security measures protecting personal data from unauthorised access", "Detections and file-integrity events on enrolled hosts.", sigDetect, sigFIM),
	mn("br-lgpd", "LGPD-46-2", "Security measures from design to execution", rLegal),
	ev("br-lgpd", "LGPD-47-secure-ops", "Agents guarantee security of data throughout processing", "Fleet health and detection coverage.", sigFleet, sigDetect),
	mn("br-lgpd", "LGPD-48-communication", "Communication of security incident to authority and data subject", rLegal),
	ev("br-lgpd", "LGPD-48-evidence", "Evidence supporting incident description", "Incident timeline and findings.", sigWorkflow, sigTelem),
	mn("br-lgpd", "LGPD-49-systems", "Systems structured to meet security requirements and standards", rConfig),
	mn("br-lgpd", "LGPD-50-governance", "Good practice and governance programme", rProc),
	ev("br-lgpd", "LGPD-37-records", "Records of processing activities support", "Audit log can support activity records; the register itself is manual.", sigAudit),
	mn("br-lgpd", "LGPD-41-dpo", "Data protection officer appointed", rLegal),

	// South Africa POPIA
	ev("za-popia", "POPIA-19-1", "Secure integrity and confidentiality by technical and organisational measures", "Detections and file-integrity events.", sigDetect, sigFIM),
	ev("za-popia", "POPIA-19-2a", "Identify reasonably foreseeable internal and external risks", "Detections and findings supply observed threat context.", sigDetect, sigTelem),
	ev("za-popia", "POPIA-19-2b", "Establish and maintain safeguards against identified risks", "Endpoint detection and alerting.", sigDetect, sigAlerts),
	ev("za-popia", "POPIA-19-2c", "Regularly verify safeguards are effectively implemented", "Fleet health and audit log show ongoing operation.", sigFleet, sigAudit),
	ev("za-popia", "POPIA-19-2d", "Update safeguards in response to new risks", "Detection rule coverage is updated and visible.", sigDetect),
	mn("za-popia", "POPIA-20", "Processing only on instruction of the responsible party", rLegal),
	mn("za-popia", "POPIA-21", "Security measures regarding processing by an operator", rVendor),
	ev("za-popia", "POPIA-22-evidence", "Evidence supporting security-compromise notification", "Incident timeline and findings; notification to the Regulator and subjects is manual.", sigWorkflow, sigTelem),
	mn("za-popia", "POPIA-22-notify", "Notification of security compromises", rLegal),

	// US CMMC 2.0 L2 / NIST 800-171 families
	mn("us-cmmc-l2", "CMMC-AC", "Access Control family", rIAM),
	mn("us-cmmc-l2", "CMMC-AT", "Awareness and Training family", rProc),
	ev("us-cmmc-l2", "CMMC-AU", "Audit and Accountability family", "Audit log, findings ledger and review workflow.", sigAudit, sigTelem, sigWorkflow),
	ev("us-cmmc-l2", "CMMC-CM", "Configuration Management family", "SBOM inventory and file-integrity change events.", sigSBOM, sigFIM),
	mn("us-cmmc-l2", "CMMC-IA", "Identification and Authentication family", rIAM),
	ev("us-cmmc-l2", "CMMC-IR", "Incident Response family", "Incident workflow, alert routing and overdue tracking.", sigWorkflow, sigAlerts, sigTimely),
	mn("us-cmmc-l2", "CMMC-MA", "Maintenance family", rProc),
	mn("us-cmmc-l2", "CMMC-MP", "Media Protection family", rPhys),
	mn("us-cmmc-l2", "CMMC-PS", "Personnel Security family", rProc),
	mn("us-cmmc-l2", "CMMC-PE", "Physical Protection family", rPhys),
	mn("us-cmmc-l2", "CMMC-RA", "Risk Assessment family", rVuln),
	mn("us-cmmc-l2", "CMMC-CA", "Security Assessment family", rProc),
	mn("us-cmmc-l2", "CMMC-SC", "System and Communications Protection family", rConfig),
	ev("us-cmmc-l2", "CMMC-SI", "System and Information Integrity family", "Detections, file-integrity events and agent coverage.", sigDetect, sigFIM, sigFleet),
	ev("us-cmmc-l2", "CMMC-SI-3-14-6", "Monitor systems to detect attacks and indicators", "Detections and findings telemetry.", sigDetect, sigTelem),
	ev("us-cmmc-l2", "CMMC-AU-3-3-1", "Create and retain system audit logs", "Audit log; retention length is manual.", sigAudit),

	// FedRAMP Moderate
	mn("us-fedramp-moderate", "FR-AC", "Access Control family", rIAM),
	mn("us-fedramp-moderate", "FR-AT", "Awareness and Training family", rProc),
	ev("us-fedramp-moderate", "FR-AU", "Audit and Accountability family", "Audit log, findings ledger and review workflow.", sigAudit, sigTelem, sigWorkflow),
	mn("us-fedramp-moderate", "FR-CA", "Assessment and Authorization (assessment itself)", rProc),
	ev("us-fedramp-moderate", "FR-CA-7", "Continuous monitoring", "Fleet health, detections and audit log.", sigFleet, sigDetect, sigAudit),
	ev("us-fedramp-moderate", "FR-CM", "Configuration Management family", "SBOM inventory and file-integrity events.", sigSBOM, sigFIM),
	mn("us-fedramp-moderate", "FR-CP", "Contingency Planning family", rBCP),
	mn("us-fedramp-moderate", "FR-IA", "Identification and Authentication family", rIAM),
	ev("us-fedramp-moderate", "FR-IR", "Incident Response family", "Incident workflow, alert routing and overdue tracking.", sigWorkflow, sigAlerts, sigTimely),
	mn("us-fedramp-moderate", "FR-MA", "Maintenance family", rProc),
	mn("us-fedramp-moderate", "FR-MP", "Media Protection family", rPhys),
	mn("us-fedramp-moderate", "FR-PE", "Physical and Environmental Protection family", rPhys),
	mn("us-fedramp-moderate", "FR-PL", "Planning family", rProc),
	mn("us-fedramp-moderate", "FR-PS", "Personnel Security family", rProc),
	mn("us-fedramp-moderate", "FR-RA", "Risk Assessment family", rVuln),
	ev("us-fedramp-moderate", "FR-SA", "System and Services Acquisition family (software inventory)", "SBOM supports component transparency; acquisition governance is manual.", sigSBOM),
	mn("us-fedramp-moderate", "FR-SC", "System and Communications Protection family", rConfig),
	ev("us-fedramp-moderate", "FR-SI", "System and Information Integrity family", "Detections, file integrity and agent coverage.", sigDetect, sigFIM, sigFleet),
	mn("us-fedramp-moderate", "FR-SR", "Supply Chain Risk Management family", rVendor),

	// Canada
	ev("ca-cccs", "CCCS-asset", "Know what needs protecting: asset inventory", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("ca-cccs", "CCCS-backup", "Back up and encrypt data", rBCP),
	ev("ca-cccs", "CCCS-patching", "Patch and update systems", "SBOM supplies versions; patch status is not assessed.", sigSBOM),
	ev("ca-cccs", "CCCS-malware", "Protect against malware", "Behavioural detections.", sigDetect, sigFleet),
	mn("ca-cccs", "CCCS-access", "Manage and control administrative privileges", rIAM),
	mn("ca-cccs", "CCCS-mfa", "Multi-factor authentication", rIAM),
	ev("ca-cccs", "CCCS-logging", "Logging and monitoring", "Audit log and findings.", sigAudit, sigTelem),
	ev("ca-cccs", "CCCS-incident", "Incident response plan and handling", "Incident workflow.", sigWorkflow),
	mn("ca-cccs", "CCCS-training", "Train employees", rProc),
	mn("ca-cccs", "CCCS-network", "Secure network perimeter", rConfig),
	ev("ca-cccs", "PIPEDA-4.7", "PIPEDA safeguards principle: protect personal information", "Detections and file-integrity events.", sigDetect, sigFIM),
	ev("ca-cccs", "PIPEDA-breach-records", "Breach of security safeguards record-keeping support", "Incident timeline and findings; the breach record and report are manual.", sigWorkflow, sigAudit),

	// South Korea ISMS-P
	mn("kr-ismsp", "ISMSP-1.1", "Management system establishment and scope", rProc),
	mn("kr-ismsp", "ISMSP-1.2", "Risk management", rProc),
	mn("kr-ismsp", "ISMSP-2.1", "Policies and organisation", rProc),
	ev("kr-ismsp", "ISMSP-2.1-asset", "Information asset identification", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	mn("kr-ismsp", "ISMSP-2.2", "Human resources security", rProc),
	mn("kr-ismsp", "ISMSP-2.4", "Physical security", rPhys),
	mn("kr-ismsp", "ISMSP-2.5", "Authentication and access management", rIAM),
	mn("kr-ismsp", "ISMSP-2.7", "Cryptography application", rCrypto),
	ev("kr-ismsp", "ISMSP-2.9-ops", "System and service operation management: change and malware", "File-integrity and behavioural detections.", sigFIM, sigDetect),
	ev("kr-ismsp", "ISMSP-2.9-logs", "Log and access record management and review", "Audit log and findings.", sigAudit, sigTelem),
	ev("kr-ismsp", "ISMSP-2.11", "Incident prevention and response", "Incident workflow and alerts.", sigWorkflow, sigAlerts, sigDetect),
	mn("kr-ismsp", "ISMSP-2.12", "Disaster recovery", rBCP),
	mn("kr-ismsp", "ISMSP-3.1", "Personal information protection: collection and use", rLegal),
	mn("kr-ismsp", "ISMSP-3.5", "Data subject rights", rLegal),
	ev("kr-ismsp", "ISMSP-3.4-breach", "Personal information breach response support", "Incident timeline; notification is manual.", sigWorkflow, sigTelem),

	// Hong Kong
	mn("hk-hkma", "HKMA-governance", "Cyber governance and oversight", rProc),
	ev("hk-hkma", "HKMA-identify", "Identification of IT assets and cyber risk inputs", "Enrolled agents and SBOM.", sigFleet, sigSBOM),
	ev("hk-hkma", "HKMA-protect", "Protection controls on endpoints", "Behavioural detections and file integrity.", sigDetect, sigFIM),
	ev("hk-hkma", "HKMA-detect", "Cyber threat detection and monitoring", "Detections, findings and alerts.", sigDetect, sigTelem, sigAlerts),
	ev("hk-hkma", "HKMA-respond", "Incident response and recovery handling", "Incident workflow and overdue tracking; recovery is manual.", sigWorkflow, sigTimely),
	mn("hk-hkma", "HKMA-resilience-testing", "Intelligence-led cyber attack simulation testing", "External red-team exercise; not observable."),
	mn("hk-hkma", "HKMA-third-party", "Third-party service provider risk", rVendor),
	mn("hk-hkma", "PCPD-DPP4", "Data protection principle 4: security of personal data", rLegal),
	ev("hk-hkma", "PCPD-DPP4-tech", "Technical safeguards for personal data security", "Detections and file integrity support technical safeguard evidence.", sigDetect, sigFIM),
	ev("hk-hkma", "PCPD-breach-evidence", "Data breach incident evidence", "Incident timeline and findings; notification is a controller decision.", sigWorkflow, sigTelem),
}
