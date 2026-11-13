# Regional threat landscape content

Observation only. Pack `internal/edr/content/regional.json` (batch `regional-v1`, 120 rules, ids `rgn-*`) and adversary pack `internal/edr/adversaries/regional.json` (41 profiles) add region-specific tradecraft that is publicly documented. Rules are original, written from public descriptions in the author's own words, and prefer specific artefacts (file names, registry keys, parent-child pairs, command-line flags) over broad matches. Every rule carries positive and negative samples and passes the benign corpus at medium or higher; rules prone to benign hits are `low` and tagged `noisy-risk`.

## Coverage by region

| Region | Topics (rule id fragments) |
|--------|----------------------------|
| Latin America | Astaroth/Guildma WMIC XSL and ExtExport side-loading, Metamorfo/Casbaneiro AutoIt and script hosts, BBTok MSBuild, Grandoreiro/Mekotio regsvr32 and Chrome extension loading, Blind Eagle Startup `.url`, Remcos and AsyncRAT artefacts (`rgn-latam-*`) |
| South Asia | BITTER mshta tasks, SideCopy rekeywiz side-loading, CHM abuse, raw-IP mshta (`rgn-sasia-*`) |
| East Asia | Korean HWP and Ghostscript exploit tails, NPKI certificate theft, AppleSeed ESTsoft lookalike, BabyShark Run key, 3CX supply chain, Windows Sandbox abuse (Japan), Ichitaro and WPS Office exploit tails, Sunlogin RCE, frp/nps/fscan, HAFNIUM Exchange web shells, PlugX side-load pairs, Alibaba and Tencent cloud agent removal, COATHANGER, Pygmy Goat, BPFDoor (`rgn-kr-*`, `rgn-jp-*`, `rgn-cn-*`) |
| Russia and Ukraine | NotPetya, WhisperGate, HermeticWiper, CaddyWiper, RoarBat-style wiping, AcidRain, Prestige, Gamaredon remote templates, Russian-origin remote tools (Ammyy, Radmin, RMS, LiteManager), Telegram and webhook relays, volunteer DDoS tooling (`rgn-ru-*`) |
| Middle East | Shamoon, ZeroCleare, Moses Staff DiskCryptor, DarkComet, njRAT, OilRig IIS modules, Fox Kitten tunnels, RMM abuse (Atera, ScreenConnect, SimpleHelp, AnyDesk, NetSupport), BitLocker misuse (`rgn-me-*`) |
| Africa | West African BEC toolset on Windows: Agent Tesla, NanoCore, LokiBot, NetWire, hollowing hosts (`rgn-afr-*`) |
| Ransomware by region | Ransom-note names for Clop, Cuba, Ryuk, Babuk, LockBit 3.0, ALPHV, Medusa, Rhysida, BlackByte, Akira, Trigona, Phobos/8Base, REvil, Black Basta, Prestige; ALPHV, Royal, Akira, vssadmin, ESXi behaviours (`rgn-rw-*`) |
| Europe and SE Asia | Ebury, Telegram bot C2, UltraViewer, USB hiding (`rgn-eu-*`, `rgn-sea-*`) |

Gap: African mobile-money fraud tooling on Windows has almost no public Windows-side tradecraft (it is mostly Android and social engineering), so it is not covered beyond the BEC toolset above.

## Adversary pack

41 additional groups from underrepresented regions (Latin America, South Asia, Middle East, Southeast Asia, Central Asia, Africa-targeting actors). Technique lists were taken from the relationships in the official ATT&CK Enterprise STIX bundle (`mitre-attack/attack-stix-data`), restricted to non-revoked, non-deprecated techniques, so id formats and existence are verified. Origin, motivation and target summaries are paraphrased from the ATT&CK group descriptions. All profiles are marked `medium` confidence: the individual group pages on attack.mitre.org were not each fetched and compared (only G0099 was spot-checked), so none is labelled `high`.

## Sources

* MITRE ATT&CK groups and software pages, https://attack.mitre.org/groups/ and https://attack.mitre.org/software/
* CISA and FBI AA22-057A, destructive malware in Ukraine (WhisperGate, HermeticWiper, CaddyWiper): https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-057a
* ASD ACSC with CISA and partners AA24-190A, APT40 tradecraft: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a
* JPCERT/CC, MirrorFace attack against Japanese organisations: https://blogs.jpcert.or.jp/en/2024/07/mirrorface-attack-against-japanese-organisations.html
* ANSSI CERT-FR, Sandworm campaign targeting Centreon: https://cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf
* CISA and NCSC UK, Infamous Chisel: https://cisa.gov/analysis-reports/ar23-243a and https://www.ncsc.gov.uk/news/uk-allies-support-ukraine-calling-out-russia-gru-malware-campaign
* NCSC UK malware analysis reports (Pygmy Goat): https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports
* CERT-EU threat landscape reports: https://www.cert.europa.eu/publications/threat-intelligence/tlr2025/pdf
* CERT-In advisories (Akira, WannaCry): https://www.cert-in.org.in/
* ESET on Latin American banking trojans: https://www.welivesecurity.com/2021/12/15/dirty-dozen-latin-america-amavaldo-zumanek/ and https://www.welivesecurity.com/2020/10/01/latam-financial-cybercrime-competitors-crime-sharing-ttps/
* CISA AA22-335A (Cuba), AA23-061A (Royal), AA23-319A (Rhysida)

KrCERT/CC and BSI material was searched for and not found, so no rule cites them.

## Unverified or heuristic items

Not cross-checked against a primary source; treat as audit leads:

* `rgn-jp-ichitaro-spawns-shell` (Ichitaro parent binary names)
* `rgn-cn-plugx-sxs-programdata` (ProgramData\SxS staging path)
* `rgn-eu-ebury-library` (library names)
* `rgn-rw-prestige-readme` and `rgn-rw-prestige-enc-registry`
* `rgn-cn-tencent-agent-removal` and the Alibaba agent paths
* ransom-note file names in `rgn-rw-*` (from memory of public reports, not re-fetched)
* `rgn-me-njrat-kl-registry`, `rgn-cn-wps-spawns-shell`, `rgn-me-bitlocker-protector-add`
* Technique choices for the Shamoon, BPFDoor and COATHANGER rules follow the closest ATT&CK technique, not an ATT&CK mapping of the exact artefact.

## Noisy-risk rules (severity low)

webhook relays, mhddos/db1000n, SimpleHelp, ScreenConnect off-path, LiteManager, GotoHTTP, UltraViewer, CHM from user directories, msiexec remote quiet install, Squirrel update, BitLocker protector, NETLOGON executables, CCleaner Agomo, PlugX SxS, USB attrib hiding.
