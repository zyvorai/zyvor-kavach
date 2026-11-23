# Network-device configuration posture review

Offline analytics over a configuration export that you send to Kavach: PAN-OS XML, FortiGate `show` text, Cisco ASA running-config, `iptables-save` and `nft list ruleset`. Kavach is observation only: it never connects to a firewall, never pulls a configuration, never calls a cloud, identity or threat-intelligence service, never scans a host and never fetches a link. It reads the text you give it. Research and sources: [RESEARCH-network-posture.md](RESEARCH-network-posture.md). Related: [network-detection.md](network-detection.md) (network logs), [firewall-rule-review.md](firewall-rule-review.md) (generic JSON/CSV rule export), [content-testing.md](content-testing.md).

## What it is and is not

Findings are heuristics from an export, not proof of exploitability or exposure. An export may omit inherited, global or shared policy (Panorama, FortiGate global objects), objects can resolve differently on the device, and zone and interface trust is guessed from names (see below). Every finding carries a severity, ATT&CK guidance (technique entries in the guidance catalog), why it matters, the exact location (line number and section or XML path), a benign explanation and a reference sentence. The reference sentences are original and name benchmark and vendor ideas only; no benchmark or vendor text is copied and no control numbers are used.

## Surface

| Route | Body | Purpose |
|---|---|---|
| `POST /v1/netcfg/analyze?format=&host=` | the raw export, or a JSON envelope `{config, format, host, now}` | analyse one export, store findings (admin token) |
| `POST /v1/netcfg/diff` | JSON `{old, new, format}` | compare two exports of one device (admin token, nothing stored) |
| `GET /v1/netcfg/sources` | none | formats, rules, limits |

CLI: `kavachctl netcfg analyze FILE [--format F] [--host H] [--json]`, `kavachctl netcfg diff OLD NEW [--format F] [--json]`, `kavachctl netcfg sources`. Detection-as-code: test kind `netcfg` in `kavachctl content test` (config text in `lines`, optional `format`), and 40 built-in examples in `internal/edr/content_examples/netcfg-analytics.jsonl` (one positive and one near-miss negative per rule, enforced by `TestEveryRuleHasPassingExamples`).

Limits: 8 MiB body; 200,000 lines read (more are cut and the report says `truncated`); 16 KiB per line (longer lines are cut); 20,000 rules; 50,000 objects; 64 addresses or services per rule field after object expansion (a rule that exceeds it, or names an object that is not defined in the export, is skipped by shadow analysis and counted in `rules_skipped_by_shadow_analysis`); object nesting 4 deep; XML nesting 48 and 400,000 elements; shadow analysis compares at most 2,000 rules per scope, 4,000,000 pairs overall and stops at a 4 second budget (a note says so); 25 findings per rule in the report and 2,000 stored per request.

## Supported subsets (exact)

Only the fields below are read. "[U]" marks names or defaults that came from general knowledge rather than a fetched page and were not checked against a real export. A parser that cannot read the subset says so (HTTP 400) instead of guessing.

| format | Reads |
|---|---|
| `pan-xml` | `config/devices/entry/vsys/entry` (and `shared`): `rulebase/security/rules/entry` (also `pre-rulebase`, `post-rulebase`) with `from`, `to`, `source`, `destination`, `application`, `service`, `action` (allow vs anything else), `disabled`, `log-start`, `log-end`, `log-setting`, `description`, `profile-setting`, `negate-source`, `negate-destination`, `source-user`, `category`; `address/entry` (`ip-netmask`, `ip-range`, `fqdn`), `address-group/entry` (`static/member`), `service/entry` (`protocol/tcp\|udp/port`), `service-group/entry` (`members/member`), `zone/entry` (`network/*/member`). `network/profiles/interface-management-profile/entry` (`ssh`, `telnet`, `http`, `https`, `snmp`, `permitted-ip`) and the `interface-management-profile` element inside interface entries are [U]. Application names in the risky list (`telnet`, `ftp`, `tftp`, `ms-rdp`, `smb`, `mssql-db`, `mysql`, `postgres`, `snmp`, `vnc-base`, `rlogin`) are [U]. `log-end` absent is unknown, not assumed. |
| `fortigate` | `config firewall policy` (`name`, `srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `service`, `action`, `status`, `logtraffic`, `comments`, `schedule`, `av-profile`, `ips-sensor`, `webfilter-profile`, `application-list`, `profile-group`, `ssl-ssh-profile`, `utm-status`, `internet-service`, `*-negate`, `users`, `groups`); `firewall address` (`subnet`, `type`, `start-ip`, `end-ip`, `fqdn`), `firewall addrgrp`, `firewall service custom` (`tcp-portrange`, `udp-portrange`, `protocol`), `firewall service group`, built-in service names (a small table, for example HTTPS, SSH, RDP, ALL); `system interface` (`allowaccess`, `role`); `system admin` (`trusthost1..10`, `password`); `system global` (`admin-telnet`, `admin-ssh-v1`, `admin-https-ssl-versions`, `strong-crypto`, `ssl-min-proto-version`) [U]; `system snmp community` (`name`), `system snmp user` (`security-level`) [U]; `vpn ipsec phase1[-interface]`, `phase2[-interface]` (`proposal`, `dhgrp`, `mode`, `psksecret`) [U]; `vpn ssl settings` (`ssl-min-proto-ver`, `tlsv1-0`, `tlsv1-1`, `sslv3`) [U]; `config log ... setting` (`status`). `config vdom` / `edit NAME` nesting gives one scope per vdom. Defaults are not assumed: `logtraffic` absent is unknown; trusted hosts absent means unrestricted [U]. |
| `asa` | `access-list NAME [line N] [extended] permit\|deny PROTO SRC [PORT] DST [PORT] [log [disable]] [inactive] [time-range X]` and `remark`; `access-group NAME in\|out\|global [interface IF]`; `object network` (`host`, `subnet`, `range`, `fqdn`), `object service`, `object-group network\|service\|protocol` (`network-object`, `port-object`, `service-object`, `protocol-object`, `group-object`), `name`; `interface` + `nameif` + `security-level` (level 0 or an untrusted-looking name means untrusted); `ssh\|telnet\|http ADDR MASK IF`, `ssh version`, `ssh key-exchange`, `ssh cipher`, `ssl server-version`, `ssl cipher`, `snmp-server community`, `username ... password`, `enable password`, `passwd`, `logging enable`, `no logging enable`, `crypto ikev1\|ikev2\|isakmp policy` (`encryption`, `hash`, `integrity`, `group`). All of this syntax is [U]: written from general knowledge of the command reference, not from a fetched page or a real device. `standard`, `webtype` and `ethertype` lists are skipped with a note. |
| `iptables` | `iptables-save` / `ip6tables-save`, `*filter` only: `:CHAIN POLICY`, `-A CHAIN` with `-s -d -p -i -o --sport --dport` and multiport `--sports/--dports`, `-m state/conntrack` (`--state`, `--ctstate`), `-m comment`, `-j ACCEPT\|DROP\|REJECT`. Other modules and options become an opaque condition; negation marks the rule complex; user-chain jumps, LOG and RETURN are not terminal and are not analysed. |
| `nft` | `nft list ruleset`: `table FAMILY NAME { chain NAME { type ... hook H ...; policy P; RULES } }` with `iif`, `iifname`, `oif`, `oifname`, `ip\|ip6 saddr\|daddr`, `ip protocol`, `meta l4proto`, `tcp\|udp dport\|sport`, `ct state`, `icmp type`, braces sets, `comment`, verdicts `accept`, `drop`, `reject`. Named sets (`@name`) and maps are opaque. |

`auto` sniffs the content: `<` first means PAN-OS XML; `config firewall|system|vpn|log ...` lines mean FortiGate; `*filter` means iptables; `table inet|ip|... NAME {` means nftables; `access-list` or `object-group` lines mean ASA. Force a format when unsure.

Not supported: Check Point, Juniper (SRX), pfSense, OPNsense, Sophos, SonicWall, WatchGuard, Meraki, cloud security groups (use [iac-exposure.md](iac-exposure.md)), Panorama device-group inheritance, FortiManager policy packages, NAT and routing.

## Normalised model and analytics

Each parser fills one model: rules (scope, order, action, enabled, source and destination zones, source and destination address sets, service ranges, applications, an opaque `extra` condition string, logging state, description), objects with use counts, and device-level issues. Address sets hold prefixes plus opaque tokens (ranges, FQDNs, undefined names) that compare by equality only. Service sets hold protocol and port ranges.

Shadow analysis is first-match: for each enabled, fully resolved rule B, an earlier enabled rule A covers B when B is inside A on zones, addresses, services and applications and A has no condition that B lacks (the `extra` string: schedules, users, time ranges, source ports, connection state, other modules). A covers B with the opposite action: `netcfg-rule-shadowed` (high when the hidden rule is a deny); same action: `netcfg-rule-redundant`. Only the first covering rule is named. Rules in different scopes (an ASA access list, a FortiGate vdom, a PAN-OS rulebase, an iptables chain) are never compared. Cost is capped as listed under Limits.

Untrusted means: the source zone or interface name matches `untrust|outside|internet|external|wan|public|ext|isp` (case-insensitive), or on ASA the interface has security level 0, or, where the format has no zones (iptables, nftables, ASA without a bound list), the source is "any". A zone named `dmz` or `guest` is not treated as untrusted. This is a guess from names; rename-heavy environments will see misses and false alarms.

## Rules

| Rule | Severity | Technique | Fires when | Main benign cause |
|---|---|---|---|---|
| `netcfg-permit-any-any` | critical (high when zones are specific) | T1562.004 | a permit has any source, destination, service and application (critical only with any zone too) | outbound allow-all from one trusted zone, lab |
| `netcfg-permit-any-service` | high or medium | T1562.004 | a permit allows all services with an any source or destination | trust inside one tier |
| `netcfg-permit-risky-service` | high (medium for SSH alone) | T1133 | a permit reaches telnet, FTP, TFTP, rsh, SMB, NetBIOS, MSRPC, RDP, SSH, SNMP, VNC, WinRM, X11, LDAP, MSSQL, Oracle, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached or the Docker API from an any or untrusted-looking source | an intentionally published service |
| `netcfg-rule-shadowed` | medium (high for a hidden deny) | T1562.004 | see above | inherited policy not in the export |
| `netcfg-rule-redundant` | low | T1562.004 | covered by an earlier rule with the same action | kept for counters |
| `netcfg-rule-no-logging` | medium (low for deny) | T1562 | logging explicitly off (`log-end no` without `log-start yes`, `logtraffic disable`, ASA `log disable`) | collected elsewhere |
| `netcfg-rule-disabled` | low | T1562 | a disabled rule | planned change |
| `netcfg-rule-temporary` | low (medium for a permit with a past date) | T1562 | name or description has temp, test, poc, remove, expires, until, migration ... or a date (YYYY-MM-DD, YYYYMMDD) before the reference time | a creation date |
| `netcfg-rule-no-description` | low | T1562 | a permit with no description or comment (PAN-OS, FortiGate, ASA remark) | descriptions kept in tickets |
| `netcfg-permit-no-inspection` | low | T1562 | PAN-OS permit with no `profile-setting`, FortiGate permit with no profile or `utm-status disable`, facing an untrusted side | group or default applies |
| `netcfg-object-unused` | low | T1562 | an address or service object not referenced in the export | used in another part |
| `netcfg-object-duplicate` | low | T1562 | two objects with the same value | ownership |
| `netcfg-mgmt-exposed-untrusted` | high | T1133 | SSH, HTTPS, HTTP, Telnet or SNMP management on an untrusted-looking interface (PAN-OS without a permitted-ip list; ASA `ssh\|telnet\|http` from any address, or from a network larger than /16, on such an interface) | restricted by something not in the export |
| `netcfg-mgmt-weak-protocol` | high | T1040 | Telnet or plain HTTP administration enabled (interface profile, `allowaccess`, `admin-telnet`, ASA `telnet`) | isolated lab |
| `netcfg-admin-unrestricted` | medium | T1133 | FortiGate administrator with no trusted host, or ASA management from any address on a trusted interface | jump host |
| `netcfg-weak-crypto` | medium | T1600 | SSLv3, TLS 1.0 or 1.1 allowed, SSH 1, DES/3DES/MD5, DH groups 1, 2, 5, IKE aggressive mode, a low SSH or SSL cipher level | legacy peers |
| `netcfg-weak-snmp` | high | T1078.001 | a default or well-known SNMP community (public, private, cisco, admin ...) or SNMPv3 no-auth-no-priv | filtered management network |
| `netcfg-default-credentials` | high | T1078.001 | FortiGate `password`, `psksecret` or similar not stored as `ENC`; ASA `username`, `enable` or `passwd` without `encrypted`; empty values; `nopassword` | placeholder in a template |
| `netcfg-default-policy-accept` | medium | T1562.004 | iptables or nft INPUT/FORWARD chain with policy ACCEPT and no unconditional final deny | another firewall in front |
| `netcfg-logging-disabled` | medium or low | T1562 | ASA `no logging enable`; for ASA with no `logging enable` and for a FortiGate export with a `system global` block but no enabled log target, low (absence in a partial export) | logging in a section not exported |

New ATT&CK guidance entries: T1600, T1078.001, T1040. The rule list is `GET /v1/netcfg/sources`.

## Posture score and diff

Score: 100 minus the weights of the findings (critical 20, high 8, medium 3, low 1), counting at most five findings per rule so one noisy rule cannot zero the score; floor 0. Grades: A at 90 or more, B 75, C 60, D 40, F below. It is a relative indicator for one export over time, not a compliance grade.

`kavachctl netcfg diff OLD NEW` (and `POST /v1/netcfg/diff`) parses both with the same format (auto-detected from the old file), matches rules by what they match (scope, action, zones, addresses, services, applications, conditions), not by name, and reports `permit-added` (severity by breadth: critical, high, medium or low), `deny-removed` (medium, high for an any-source any-service deny), `deny-added`, `permit-removed`, `rule-enabled`, `rule-disabled`, the score delta and posture findings that are new or resolved. A pure rename is not reported; order changes are not reported. Nothing is stored. Same-device is on you: the tool cannot check.

## Privacy and hostile input

Credential values are never copied into a finding, a report, a log line or the store: parsers record only that a credential-looking value exists and, for SNMP communities, its length. Free text that does reach output (rule names, descriptions, interface names, paths) goes through control-character stripping, a redaction pass for `password`, `secret`, `community`, `psk`, `key`, `token` style assignments, the data-governance redactor (API keys, e-mail addresses, long hex) and a 300 character bound. XML is parsed with Go's decoder with no entity map and no charset reader: any DOCTYPE or entity declaration is refused before anything is expanded, external entities are never loaded, nesting over 48 or 400,000 elements is refused. Text parsers use no backtracking regular expressions over unbounded input (Go RE2) and every line is cut at 16 KiB. Tests in `internal/edr/netcfg_test.go`: entity bomb, external entity, deep nesting, element bomb, foreign charset, unterminated XML, NUL and CRLF, 5 MiB lines, regex-DoS style text, 200,000-line and 5,000-rule cardinality, shadow-analysis caps, oversized object groups, secret canaries in forti and asa fixtures and in free text, route authentication and error cases.

## Caveats

Parsers were written from public documentation, search summaries and general knowledge; none was run against an export from a real device. Fixtures in `internal/edr/testdata/netcfg/` are synthetic (documentation address ranges). Fields marked [U] may be wrong for a given software version. The detection-as-code examples prove that each rule fires on its own example, not that the rule is right for your device. A real export will exercise syntax these parsers do not know; in that case a rule is skipped (counted) or the file is refused, never guessed.
