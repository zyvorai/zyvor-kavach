# Research: network-device configuration audits (vendor and benchmark survey)

Date: 2026-11-23. Scope: what firewall, SASE and proxy vendors and benchmark bodies check in configuration audits, and what Kavach built from it ([netcfg-posture.md](netcfg-posture.md)). Companion to [RESEARCH-vendors-network.md](RESEARCH-vendors-network.md) (logs) and [RESEARCH-vendors-posture.md](RESEARCH-vendors-posture.md) (posture and generic firewall review).

## Honesty about sources

Time and tooling were limited. Directly fetched and read in this pass: the Palo Alto Networks "Security policy rulebase best practices" page and the Fortinet FortiGate 7.4 "Best practices" administrative page. Web search (summaries only, not full pages) supported the PAN-OS rule element names and the XPath of the security rulebase, the FortiGate `config firewall policy` setting names (`logtraffic`, `srcaddr`, `service`, `ssl-ssh-profile`, `status`) and the FortiGate `allowaccess` and `trusthost` behaviour. Everything about Check Point, Cisco ASA/FTD hardening guides, Juniper SRX, pfSense/OPNsense, CIS Benchmarks, NIST SP 800-41, Batfish, Capirca, Nipper, AlgoSec, Tufin and FireMon below comes from general knowledge and was not searched or fetched in this pass: marked `[U]` (unverified). No benchmark or vendor text was copied; rule wording in Kavach is original and references are ideas only.

## What the sources say

| Source | Checks and concepts | Status |
|---|---|---|
| Palo Alto rulebase best practices (fetched) | Broad rules above specific rules cause shadowing; review the Rule Shadow list after commit because it does not persist; any-zone rules limited to basic infrastructure such as DNS and NTP and kept near the top; find rules without log forwarding; use Policy Optimizer for unused rules and unused applications; disable before delete and tag the disabled rule with the date. Descriptions are not covered on that page. | fetched |
| PAN-OS XML structure (search) | Security rules sit at `/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name]`; elements include `disabled`, `log-start`, `log-end`, `log-setting`, `description`, `from`, `to`. Source, destination, application, service and action element contents were not confirmed by the search; they are used from general knowledge `[U]`. The interface-management profile elements and the path that binds a profile to an interface are `[U]`. | partly verified |
| Palo Alto Best Practice Assessment (BPA) | A report that grades a configuration against best practice by area and compares to peers. Not fetched `[U]`. Concept used: a score and per-area findings. | `[U]` |
| FortiGate administrative hardening (fetched) | Idle timeout under about ten minutes; non-standard admin ports; disable weak encryption protocols; trusted HTTPS certificate; disable HTTP and Telnet; `admin-host` when redirection stays on; legacy SHA256 admin password hashes should be converted to PBKDF2 on 7.4.8 and later. `allowaccess`, `trusthost` and `admin-telnet` were not on that page. | fetched |
| FortiGate interface access and trusted hosts (search) | `set allowaccess` takes a protocol list on `config system interface`; `trusthost1..` live under `config system admin`; guidance is to allow only ping on WAN and HTTPS and SSH elsewhere, avoid HTTP and Telnet. `admin-telnet`, `admin-ssh-v1`, `admin-https-ssl-versions`, `strong-crypto` and `ssl-min-proto-version` in `system global` are `[U]`. | partly verified |
| FortiGate security rating | A Security Fabric audit that scores a configuration against recommended settings `[U]`. Concept used: a score. | `[U]` |
| Check Point compliance blade | Maps configuration to regulations and best practice with a score `[U]`. Not parsed (no verified export format). | `[U]` |
| Cisco ASA / FTD hardening guides | Management access restricted by interface and source (`ssh`, `telnet`, `http` lines), SSH version 2, no Telnet, AAA for console access, logging to a remote host, ACL hygiene, no `permit ip any any` on outside interfaces, strong IKE and SSL settings `[U]`. Syntax of the `access-list`, `object`, `object-group`, `access-group`, `ssh`, `telnet` and `snmp-server` lines is from general knowledge of the command reference `[U]`. | `[U]` |
| Juniper SRX hardening | Not researched. Not built. | `[U]` |
| pfSense / OPNsense audit plugins | Not researched. The `config.xml` formats are different and were not verified. Not built. | `[U]` |
| CIS Benchmarks for firewalls | Exist for several vendors `[U]`. No benchmark text was read. Rule references say "benchmark ideas" only; control numbers are not used. | `[U]` |
| NIST SP 800-41 | Firewall policy guidance: default deny, least privilege, change control, logging `[U]`. Cited as an idea. | `[U]` |
| Batfish, Capirca, Nipper | Batfish models configurations offline and finds unreachable (shadowed) lines; Capirca generates ACLs from policy definitions; Nipper audits device configurations offline and reports findings with ratings `[U]`. Concept used: offline rule-base reachability analysis. | `[U]` |
| AlgoSec, Tufin, FireMon | Commercial rule-base analytics: shadowed and redundant rules, any-any, unused rules and objects, risky services, rule bloat, change tracking and compliance reports `[U]`. | `[U]` |

## Ranked ideas and decisions

| Rank | Idea | Decision |
|---|---|---|
| 1 | Offline rule-base analytics over a normalised model (shadowed, redundant, any-any, any-service, risky service from untrusted source, logging off, disabled, temporary markers, unused and duplicate objects) | Built, four vendor parsers feed one model |
| 2 | Management-plane exposure and weak administrative protocols (interface profiles, `allowaccess`, `ssh`/`telnet`/`http` lines) | Built |
| 3 | Weak crypto, SNMP and credential patterns in the text | Built; credential values never shown |
| 4 | Posture score and diff between two exports | Built (score from severities; diff by what rules match, not by name) |
| 5 | Resolving PAN-OS profile groups, Panorama shared and inherited policy, FortiGate internet-service databases, NAT | Not built: inherited or database-backed policy is not in an export; findings say so |
| 6 | Check Point, Juniper SRX, pfSense, OPNsense, Sophos, SonicWall parsers | Not built: no verified export format in this pass; a wrong parser is worse than none |
| 7 | Live audit (pull config over an API, hit counts from the device, unused-rule detection from traffic logs) | Rejected: Kavach never connects to a device. Hit counts are used only if an export carries them (none of the parsers reads them today) |

## Boundaries checked

Nothing here calls a device, controller, cloud, identity provider or threat feed, scans a host, fetches a link or changes a configuration. XML with a DOCTYPE or entity declaration is refused before parsing; the decoder never loads external entities. See [netcfg-posture.md](netcfg-posture.md) for limits and the tests.
