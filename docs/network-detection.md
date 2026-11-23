# Network-log detection

Offline analytics over network logs that you export and send to Kavach: Zeek, Suricata EVE, DNS query logs, cloud flow logs, NetFlow/IPFIX CSV exports and a documented subset of firewall logs. Kavach is observation only: it analyses what you send. It never captures packets, never scans a host, never fetches a link, never looks an address, domain or certificate up, never downloads a threat feed and never blocks or sinkholes anything. Research and sources: [RESEARCH-vendors-network.md](RESEARCH-vendors-network.md). Related: [web-detection.md](web-detection.md) (access and authentication logs), [identity-detection.md](identity-detection.md), [firewall-rule-review.md](firewall-rule-review.md) (firewall configuration review).

## What it is and is not

Thresholds are fixed constants tuned for summarising a log you send, not for production alerting. Every finding states a confidence word and a benign explanation, and every description ends with "heuristic over the logs you sent; investigate, not proof of compromise". Statistics see only the window you supplied: there is no baseline from earlier days. Nothing here was validated against captures from real devices; the fixtures are synthetic (`internal/edr/testdata/network/`, documentation address ranges only).

## Routes (admin token for POST)

| Route | Body | Purpose |
|---|---|---|
| `POST /v1/net/logs?format=&host=` | the raw log | analyse one log; format `auto` by default |
| `POST /v1/net/analyze` | JSON `{log, format, host, bad_nets, fingerprints}` | same, with your own address list and fingerprint list |
| `GET /v1/net/sources` | none | formats, rule ids, thresholds, limits |
| `GET /v1/net/timeline?ip=&host=&window_minutes=` | none | join findings already stored by address, host and time (any bearer token) |

CLI: `kavachctl netlog analyze FILE [--format F] [--host H] [--bad-nets FILE] [--fingerprints FILE] [--json]`, `kavachctl netlog sources`, `kavachctl netlog timeline [--ip A] [--host H] [--window-minutes N]`.

Limits: 8 MiB body, 100,000 records (413 beyond), 64 KiB per line or record, a 3 second analysis budget (the report says `truncated` when it is hit), at most 25 findings per rule per request, 2,000 stored findings per request, 5,000 entries in each user list. Every per-key table (connection pairs, scan buckets, DNS domains and clients, alert groups) has a hard cap, so a log of millions of distinct addresses or names cannot grow memory without bound; once a cap is reached new keys are ignored (counts for existing keys continue).

## Supported formats (exact subsets)

| format | Input | Fields read |
|---|---|---|
| `zeek` | Zeek TSV with `#separator`, `#unset_field`, `#empty_field`, `#path`, `#fields` headers; logs may be concatenated | per path: conn (`ts id.* proto service duration orig_bytes resp_bytes conn_state`), dns (`query qtype_name rcode_name answers TTLs`), ssl (`server_name established subject issuer ja3 ja3s ja4 validation_status`), x509 (`certificate.subject certificate.issuer certificate.not_valid_after`), http (`host status_code`; paths, queries and user agents are not read), ssh (`auth_success`), notice (`note msg src dst p`), smb_files, smb_mapping and dce_rpc (`path name action endpoint operation`). Other paths (weird, files, kerberos, ntlm, rdp ...) are counted as `other` and otherwise ignored. |
| `zeek-json` | Zeek JSON lines (`_path` optional; the path is inferred from the fields) | the same fields |
| `eve` | Suricata EVE JSON lines or a JSON array | `alert` (signature, category, severity, action), `flow` (bytes, age, state), `dns` (rrname, rrtype, rcode, answers with rdata and ttl), `tls` (sni, subject, issuerdn, notafter, ja3, ja3s, ja4), `http` (hostname, status); other event types are counted |
| `dns` | JSON lines with `ts/time`, `client/src_ip/id.orig_h`, `qname/query/domain`, optional `qtype`, `rcode`, `answers`, `ttl` | one query per record |
| `dnscsv`, `flowcsv` | CSV with a header row; columns are matched by name from a fixed alias table (for example `ts te td sa da sp dp pr ipkt ibyt` as exported by nfdump, or `time src dst sport dport proto bytes action`) | a header with no time or address column is refused |
| `vpc` | AWS VPC flow logs, space separated, default version-2 order or a custom header line starting `version` | addresses (`pkt-srcaddr`/`pkt-dstaddr` preferred), ports, protocol, bytes, start, end, action; NODATA and SKIPDATA rows are rejected |
| `nsg` | Azure NSG flow log JSON, version 1 or 2 (`records[].properties.flows[].flows[].flowTuples[]`) | tuple fields; only `B` (begin) tuples count as new connections, bytes come from `C` and `E` tuples. NSG flow logs retire on 30 September 2027. |
| `panos` | PAN-OS CSV syslog (a syslog header is tolerated) | TRAFFIC: addresses, ports, rule name, protocol, action, bytes, elapsed. THREAT: addresses, action, threat name. CONFIG: command, admin, client, result. SYSTEM: only failed-login lines. THREAT, CONFIG and SYSTEM positions were not verified against documentation. |
| `fortigate` | `key=value` syslog | `eventtime` or `date time`, `type subtype action srcip dstip srcport dstport proto sentbyte rcvdbyte logdesc msg user status cfgpath`. `cfgattr` values are never read. UTM/IPS lines become threat events. |
| `asa` | Cisco ASA / FTD syslog with a timestamp that includes the year (or ISO 8601) | message ids 106023, 106100, 302013, 302015, 710003 (traffic), 113005, 605004, 611102 (administrator login failures), 111008, 111010, 502103 (configuration or privilege changes: the command text is never kept). Other ids are rejected and counted. |

Not supported: binary NetFlow v5/v9, IPFIX and sFlow, pcap, Check Point, Juniper, Sophos, WatchGuard, SonicWall, pfSense/OPNsense, Azure virtual-network flow logs, GCP VPC flow logs.

`auto` sniffs the first lines. Force a format when a log is unusual.

## Rules

Each rule has ATT&CK guidance (technique entries in the guidance catalog; `T1568`, `T1568.001`, `T1568.002` and `T1562.004` were added with this feature).

| Rule | Technique | Fires when | Main false positives |
|---|---|---|---|
| `net-an-beaconing` | T1071 | an internal host connects to the same public address and port at least 12 times, median interval 5 s to 6 h, median absolute deviation at most 15% of the median and at least 85% of intervals within 20% of it. Confidence medium only with 30 or more connections and deviation at most 8%. Ports 53, 67, 68, 123, 137, 138, 514, 1900, 5353 are skipped. | update checks, monitoring agents, chat and sync clients |
| `net-an-long-connection` | T1071 | a Zeek connection to a public address lasted 4 hours or more | VPN, remote admin, streaming |
| `net-an-port-scan-vertical` / `-horizontal` | T1046 | one source, in a 300 s bucket, probed at least 20 ports on one host or one port on at least 25 hosts, counting refused, reset or empty connections (Zeek `S0 REJ RSTOS0 RSTRH SH SHR`, denied flows and firewall denies, accepted flows of at most 200 bytes) | authorised scanners, inventory tools |
| `net-an-login-bruteforce` | T1110 | 30 or more connections within 600 s from one source to one address on ports 22, 23, 21, 3389 or 5900; or 10 failed Zeek ssh.log authentications | automation, health checks (a connection count cannot tell failure from success) |
| `net-an-ssh-guesser-success` | T1110 | a successful SSH authentication after the failures above from the same source to the same host | a user who mistyped a password |
| `net-an-smb-fanout` | T1021.002 | an internal host connected to SMB (445, 139) on 8 or more internal hosts within 600 s | file servers, backup, software deployment |
| `net-an-eastwest-fanout` | T1021 | 10 or more internal hosts on ports 135, 22, 23, 3389, 5985, 5986, 5900 within 600 s | jump hosts, patching, monitoring |
| `net-an-smb-admin-share` | T1021.002 | Zeek smb_files, smb_mapping or dce_rpc text names ADMIN$, C$, svcctl, atsvc or psexe | IT administration |
| `net-an-tls-selfsigned` / `-expired` | T1573 | an established TLS session to a public address with a self-signed certificate, or a certificate whose not-after date precedes the event (Zeek ssl or x509, EVE tls) | internal appliances, neglected services |
| `net-an-tls-fingerprint-match` | T1573 | a JA3, JA3S or JA4 value is on the fingerprint list you supplied | fingerprints are shared by many programs |
| `net-an-zeek-notice` | T1071 | a Zeek notice is present; relayed with its note name, not re-evaluated | whatever your Zeek policy raises |
| `net-an-dns-dga` | T1568.002 | a client queried 3 or more distinct registered domains whose second-level label has 10 to 63 characters and scores at least 4 of 5 (entropy of 3.2 bits or more, vowel share below 20%, a consonant run of 5 or more, digits at least 30%, fewer than 45% common English bigrams). Confidence medium when at least half of those queries were NXDOMAIN. | hash-like CDN, cloud and tracking names. Dictionary-word DGAs are not detected. |
| `net-an-dns-tunnel` | T1071.004 | one registered domain with at least 100 distinct subdomains averaging 30 or more characters, or at least 20 subdomains with a label of 52 or more characters, or at least 50 TXT/NULL/ANY queries and 20 subdomains | CDN and antivirus cloud lookups, DNS blocklists |
| `net-an-dns-nxdomain-storm` | T1568.002 | one client received 50 or more NXDOMAIN answers for 30 or more distinct names in one minute | broken software, search-domain misconfiguration |
| `net-an-dns-fast-flux` | T1568.001 | a domain resolved to 8 or more public addresses in 4 or more /16 networks (/32 for IPv6) with a minimum TTL of 300 s or less | CDNs and load balancers (confidence low) |
| `net-an-exfil-volume` | T1048 | an internal-to-public pair sent at least 50 MiB and is an outlier over the pairs in the log (robust z-score 0.6745 x (x - median) / MAD at least 6, or at least 10 times the median when MAD is 0); needs at least 10 pairs | backups, uploads, video calls |
| `net-an-rare-port` | T1571 | at least 5 connections from one host to one public address on a port of 1024 or more that no other host in the log used | custom applications, games |
| `net-an-badlist-contact` | T1071 | an address in a connection, flow, firewall, TLS, HTTP, DNS answer or alert record is in your supplied address/CIDR list | depends on your list |
| `net-an-alert-storm` | T1595 | 200 or more Suricata alerts from one source in a minute | scanners, load tests, noisy signatures |
| `net-eve-c2`, `net-eve-exploit`, `net-eve-recon`, `net-eve-dos`, `net-eve-credential`, `net-eve-policy` | T1071, T1190, T1595, T1499, T1110, T1071 | one finding per source and mapped class summarising count, signatures, categories and how many were blocked by the sensor. Suricata severity 1 raises it to high, 3 lowers it to low. The category-to-technique mapping is coarse keyword matching on the classification text. | an alert is a signature match, not proof |
| `net-an-fw-deny-storm` | T1595 | 100 or more denies from one source within 300 s (firewall or flow records) | a misconfigured client retrying |
| `net-an-fw-allow-after-deny` | T1190 | an external source denied 20 or more times toward a host and then allowed within 600 s | a legitimate retry after a rule change |
| `net-an-fw-threat-allowed` | T1190 | a firewall threat log with an allow or alert-only action | the device chose not to block |
| `net-an-fw-config-change` | T1562.004 | a firewall configuration or privilege change message | planned changes |
| `net-an-fw-admin-login-failed` | T1110 | 5 or more failed administrator logins from one source or user in the log | a mistyped password |

Not built: newly seen and newly registered domain detection. It needs registration data or reputation, which means an external lookup; "first seen in this log" says nothing about a domain's age. The research document explains this and the other rejected ideas.

## Evidence timeline

`GET /v1/net/timeline?ip=10.0.0.5&window_minutes=30` returns a ranked list of stored findings that carry the address exactly in their destination, description or evidence, or that share a host label with such a finding (agent hosts only: analytics labels such as `net:` or `web:` are not used for host joins) within the window. The score is severity (10 per level) plus 5 for a direct address match plus 5 for each additional family (network, web, auth, identity, cloud, ransomware, ioc, host) among the matched findings. With neither `ip` nor `host` the response lists the addresses seen in two or more families. The view reads findings and adds none. Correlation is not causation: a finding that merely mentions an address is not proof the address took part.

## Privacy and hostile input

Free text (notice messages, signatures, firewall messages, certificate subjects) is stripped of control characters, bounded to 200 characters and has credential-looking values redacted (`password=`, `token=`, `api_key=`, bearer and basic credentials, URL user info). HTTP paths, queries, cookies and user agents are never read; firewall command text and configuration attribute values are never kept. User lists are capped, comments are ignored and invalid lines are counted, not echoed. Malformed lines, NUL bytes, CRLF, overlong lines, deep JSON, unterminated quotes and cardinality bombs are covered by tests (`internal/edr/net_test.go`).

## Caveats

Parsers for PAN-OS (beyond TRAFFIC), FortiGate and ASA were written from vendor field documentation and memory, not tested against captures from real devices. Zeek field names follow the documentation; a site with local Zeek scripts that rename fields needs a forced format and may find fields missing. Time zones: Zeek epochs and EVE offsets are exact; FortiGate `date`/`time` and PAN-OS generated times are treated as UTC.
