# Zscaler export analytics

Offline analytics over files that you export from Zscaler and send to Kavach: ZIA NSS web, firewall and DNS logs, ZPA LSS user-activity logs, an exported ZIA/ZPA policy set, and ZDX-style probe metrics. Kavach is observation only: it never connects to Zscaler, never calls an API, never pulls a log or a policy, never looks anything up and never enforces. It reads the text you give it. Related: [network-detection.md](network-detection.md) (Zeek, Suricata, flow and firewall logs), [netcfg-posture.md](netcfg-posture.md) (device configuration review, the pattern the policy review follows), [tripwires.md](tripwires.md), [content-testing.md](content-testing.md).

## What it is and is not

Findings are heuristics over an export, not proof of compromise or of a policy failure. The log carries whatever labels the gateway applied (categories, actions, threat names), the export may omit fields, and geography is only what the log says. Every finding names a benign explanation. URL query strings and userinfo are dropped before anything reaches a finding. Free text is stripped of control characters and bounded.

## Surface

| Route | Body | Purpose |
|---|---|---|
| `POST /v1/zscaler/logs?format=&host=` | raw export, or JSON `{log, format, host, sanctioned_apps, work_start_hour, work_end_hour}` | `zs-an-*` analytics, per-user and per-app risk; findings stored (admin token) |
| `POST /v1/zscaler/policy?host=` | the policy export (JSON object), or `{policy, host, now}` | `zspol-*` posture review, score and grade; findings stored (admin token) |
| `POST /v1/zscaler/zdx` | CSV/TSV/JSON probe metrics, or `{probes, host}` | experience score per user, application and pair, `zdx-an-*` rules (admin token) |
| `GET /v1/zscaler/sources` | none | formats, rules, limits |

CLI: `kavachctl zscaler logs FILE [--format auto|json|csv|tsv] [--host H] [--sanctioned FILE] [--work-start H] [--work-end H] [--json]`, `zscaler policy FILE`, `zscaler zdx FILE`, `zscaler sources`. Detection-as-code: test kinds `zslog` (records or lines, optional `format`), `zspolicy` (one policy JSON object in `records` or `lines`) and `zdx` in `kavachctl content test`; 71 built-in lines in `internal/edr/content_examples/zscaler-analytics.jsonl` give every one of the 35 rules a positive and a near-miss negative example, enforced by `TestEveryRuleHasPassingExamples`. The content-harness inventory families are `zscaler-analytic`, `zscaler-policy` and `zdx-analytic`.

Limits: 8 MiB body; 100,000 log records or probe rows (more are refused with 413); 20,000 policy rules; 25 findings per rule in the report and 2,000 stored per request; 200 fields read per record.

## Log formats

JSON (one object, an array, or JSON lines; a Splunk HEC-style `{"event": {...}}` wrapper is unwrapped), CSV and TSV with a header row. `auto` picks by the first character and the header. Field names are matched after lower-casing and dropping every non-alphanumeric character, so `ClientIP`, `client_ip` and `clientip` are one key, and a feed's key names are whatever the operator put in the NSS/LSS feed template. Each record is classified by the names it carries: ZPA (`connectionstatus`, `connector`, ...), DNS (`dns_req`, `reqaction`, ...), firewall (`csip`, `cdip`, `nwsvc`, ...), otherwise web. A record with no recognised name is rejected and counted. Time accepts RFC 3339, `2006-01-02 15:04:05`, epoch seconds or milliseconds, and the NSS default `Mon DD hh:mm:ss YYYY` style (`Nov 20 10:00:00 2026`), always read as UTC.

Fields read (lower-cased, punctuation removed). "[V]" were checked against a Zscaler-hosted or Google SecOps parser page that lists them; "[U]" came from general knowledge and could not be checked, because Zscaler's help pages (help.zscaler.com) are rendered by script and returned no text to the fetch tool used for this work.

| Feed | Fields |
|---|---|
| ZIA web | `datetime` [V], `user` [V], `department` [V], `location` [V], `clientip` [V], `serverip` [V], `hostname` [V], `url` [V], `action` [V], `reason` [V], `urlcategory` [V], `urlsupercategory` [V], `urlclass` [V], `requestmethod` [V], `protocol` [V], `appname` [V], `appclass` [V], `requestsize` [V], `responsesize` [V], `transactionsize` [V], `threatname` [V], `threatcategory` [V], `threatclass` [V], `threatseverity` [V], `pagerisk` [V], `dlpdictionaries` [V], `dlpengine` [V], `filetype` [V], `unscannabletype` [V]. The [V] mark means the key appears in the JSON template of the Google SecOps "Zscaler Webproxy" parser page, which mirrors NSS web feed field names; the exact `%s{...}` NSS tokens and the value vocabularies (for example what `urlclass` or `threatclass` contain, and which values mean a sandbox verdict) are [U]. |
| ZIA firewall | `datetime` [V], `user` [V], `department` [V], `locationname` [V] (also read as `location`), `csip` [V], `cdip` [V], `ssip` [V], `sdip` [V], `csport` [V], `cdport` [V], `sdport` [V], `ssport` [V], `action` [V], `nwsvc` [V], `nwapp` [V], `proto` [V], `ipcat` [V], `destcountry` [V], `threatcat` [V], `threatname` [V], `inbytes` [V], `outbytes` [V], `rulelabel` [V], `ipsrulelabel` [V]. [V] here means the key is in the default feed format shown on the Google SecOps "Zscaler Firewall" parser page; that page maps `action` values Allow to allow and Drop, Block or Reset to block, which is how Kavach reads them. The `%s{...}` NSS tokens and the vocabularies of `nwsvc` and `ipcat` are [U] |
| ZIA DNS | `datetime` [V], `user` [V], `department` [V], `location` [V], `reqaction` [V], `resaction` [V], `dns_reqtype` [V], `dns_req` [V], `dns_resp` [V], `srv_dport` [V], `clt_sip` [V], `srv_dip` [V], `category` [V], `respipcategory` [V], all in the default feed format of the Google SecOps "Zscaler DNS" parser page. A Zscaler help page names `REQ_ALLOW` and `REQ_BLOCK` as example request-action values. A block on either `reqaction` or `resaction` counts as blocked; the full action vocabulary is [U] |
| ZPA user activity | `LogTimestamp` [V], `Username` [V], `Application` [V], `AppGroup` [V], `Host` [V], `Connector` [V], `ConnectionStatus` [V], `Policy` [V], `ClientCountryCode` [V], `ClientLatitude` [V], `ClientLongitude` [V], `ClientPublicIP` [V], `InternalReason` [V], `ClientZEN` [V], `ConnectorZEN` [V], listed in the user-activity template on the Google SecOps ZPA parser page and in the Elastic ZPA integration sample. Both sources show `ConnectionStatus` values open, close and active, not a denial, and the Google page lists reason codes for `InternalReason` such as `APP_NOT_REACHABLE` and `ZPN_STATUS_AUTH_FAILED`. Because a denial is therefore not visible in `ConnectionStatus`, Kavach now also treats an `InternalReason` containing block, deny, reject, drop or fail as a denied attempt; which reason codes mean a policy denial is still [U] |

Action words are folded to allow, block or other by substring (`Allowed`, `Blocked`, `REQ_BLOCK_DROP`, `Reject`, `Allow`). Values of `None`, `N/A` and `-` are treated as empty, so `dlpdictionaries: None` is no DLP match.

## Log rules (`zs-an-*`, 16)

| Rule | Fires when |
|---|---|
| `zs-an-threat-allowed` | a web record has a threat name or category and the action is allow |
| `zs-an-sandbox-allowed` | the threat class, category or name mentions a sandbox and the action is allow |
| `zs-an-blocked-then-allowed` | the same user and host is blocked, then allowed within 30 minutes |
| `zs-an-dlp-allowed` | a DLP dictionary or engine matched and the action is allow |
| `zs-an-dlp-repeat` | one user has 5 or more DLP-blocked requests |
| `zs-an-risky-category-allowed` | an allowed request in a risky category (anonymiser, proxy avoidance, newly registered or revived, phishing, malicious, botnet, cryptomining, dynamic DNS, command and control, spyware, peer-to-peer); one finding per user and category |
| `zs-an-unsanctioned-saas` | needs `sanctioned_apps`: an allowed app in a data-moving class (file sharing, storage, webmail, messaging, generative AI, remote access) outside the list, from 3 or more users or 5 MiB or more uploaded |
| `zs-an-large-upload` | 100 MiB or more sent by one user to one host |
| `zs-an-unscannable-allowed` | 3 or more allowed transactions with an unscannable type for one user |
| `zs-an-zpa-denied-burst` | 10 or more denied ZPA attempts by one user in 10 minutes |
| `zs-an-zpa-app-sweep` | 8 or more distinct applications by one user in 10 minutes |
| `zs-an-impossible-travel` | coordinates imply more than 900 km/h over at least 500 km within 12 hours (high), or the country changed within an hour when only a country is present (medium) |
| `zs-an-off-hours` | 5 or more web or ZPA events outside the working hours (default 06:00 to 22:00 UTC) and at least 30 percent of the user's events |
| `zs-an-bypass-tool` | allowed anonymiser, proxy-avoidance or VPN categories, a DNS-over-HTTPS resolver host in web or DNS records, or DNS-over-TLS (port 853) in firewall records |
| `zs-an-dns-tunnel-like` | 20 or more DNS names with a 40 or more character label (or 80 or more characters) under one parent domain for a user |
| `zs-an-fw-risky-port-allowed` | the firewall allowed telnet, MSRPC, NetBIOS, SMB, RDP, VNC or WinRM to a public address |

Thresholds are fixed constants tuned for summarising a supplied log, not for production alerting. Working hours are UTC unless you shift them with `work_start_hour` and `work_end_hour`.

## Risk scoring per user and per application

Every finding that names a user adds its severity weight (high 8, medium 3, low 1, at most 5 per rule per user) to that user's score, capped at 100. Levels: high from 30, medium from 10. The report lists the top 20 users with the rules that fired. Applications seen in web records get a score from: a data-moving class and an allow (10), not on the sanctioned list when one was supplied (15), 5 MiB or more uploaded (5), plus the weight of an unsanctioned-app finding. `sanctioned` is `yes`, `no` or `unknown` (no list supplied). The score is a ranking aid, not a probability.

## Policy export review (`zspol-*`, 15)

The export is one JSON object. Recognised keys (case and punctuation ignored): `url_filtering_rules`, `firewall_filtering_rules`, `dlp_web_rules`, `ssl_inspection_rules`, `cloud_app_control_rules`, `zpa_access_policies` (also `policies`), `zpa_app_segments`, and an optional `sanctioned_apps` list. Within a rule: `name`, `order`/`rank`/`ruleOrder`, `state` (`ENABLED` or anything else is off), `action` (a string, or an object with `type`), `urlCategories`, `users`, `groups`, `departments`, `locations`, `cloudApplications`/`applications`, `srcIps`, `destAddresses`, `nwServices`, `dlpEngines`, `lastModifiedTime` (epoch), `description`, and for ZPA `conditions[].operands[].objectType` (`APP`, `APP_GROUP`, `SAML`, `SCIM`, `SCIM_GROUP`, `POSTURE`, `TRUSTED_NETWORK`, `CLIENT_TYPE`). These names follow the ZIA and ZPA list API shapes as remembered and are [U]. An empty or `ANY` list is read as any. Nothing in the export is executed or fetched.

| Rule | Severity | Meaning |
|---|---|---|
| `zspol-url-allow-any` | high | enabled URL allow with no category, user or app scope |
| `zspol-url-risky-allowed` | high | an allow rule naming a risky category |
| `zspol-rule-shadowed` | medium, high for a block | a rule after an enabled universal rule with a different action (URL, firewall, SSL) |
| `zspol-fw-any-any-allow` | critical | firewall allow with no source, destination or service restriction |
| `zspol-fw-risky-service-allow` | high | RDP, SMB, telnet, VNC, WinRM or NetBIOS allowed to any destination |
| `zspol-ssl-bypass-broad` | high | do-not-decrypt rule covering every category, more than 10 categories, or file, storage, webmail, anonymiser or proxy categories |
| `zspol-ssl-inspection-absent` | high | SSL rules exist but none decrypts or inspects |
| `zspol-dlp-missing` | medium | web policy present, no enabled DLP web rule |
| `zspol-dlp-monitor-only` | low | every enabled DLP rule only allows |
| `zspol-app-unsanctioned-allow` | medium | cloud-app allow naming an app outside `sanctioned_apps` (or every app when no list is given) |
| `zspol-rule-stale` | low, medium when a date has passed | an enabled allow rule not modified for a year, or named or described as temporary |
| `zspol-zpa-allow-all-apps` | high | ZPA allow with no `APP` or `APP_GROUP` condition |
| `zspol-zpa-any-user` | medium | ZPA allow with no SAML, SCIM or group condition |
| `zspol-zpa-no-device-posture` | low | ZPA allow with no posture, trusted-network or client-type condition |
| `zspol-zpa-wildcard-segment` | high | an application segment with a bare `*` or `*.tld` domain or the full port range |

The posture score and grade reuse the device-configuration scale (100 minus severity weights, at most 5 per rule; A from 90, B 75, C 60, D 40).

## ZDX-style experience score (`zdx-an-*`, 4)

Input is a CSV, TSV, JSON or JSON-lines export of probe rows with `user`, `app`, `time` and any of: `page_fetch_ms`, `server_response_ms`, `availability_pct`, `dns_ms`, `latency_ms`, `packet_loss_pct`, `cpu_pct`, `memory_pct`, `wifi_dbm` (common aliases such as `pft`, `ttfb`, `loss`, `rssi` are read). Each metric maps linearly from a good value (100) to a bad value (0); weights are application 55 (page fetch 30, availability 15, server response 10), DNS 10, network 20 (latency 10, loss 10) and device 15 (CPU 5, memory 5, Wi-Fi 5); metrics that are absent are left out and the weights renormalised. The report gives a score and band per user, per application and per user-application pair, the average metrics, the sub-score per area and the weakest area. Bands follow Zscaler's public Poor (0 to 33), Okay (34 to 65) and Good (66 to 100) description [U]. The weights and curves are Kavach's own and this is not the proprietary ZDX Score. Rules: `zdx-an-poor-experience` (3 or more probes, Poor pair), `zdx-an-packet-loss` (2 percent or more), `zdx-an-dns-slow` (200 ms or more), `zdx-an-device-pressure` (CPU or memory 90 percent or more); all low severity.

## Zscaler capabilities that were considered and not added

The goal was every feature that fits Kavach's boundaries (offline, stdlib only, observation only, no connection, no enforcement). Not added, with the reason:

- Policy enforcement and inline products (secure web gateway, URL filtering, cloud firewall, DLP, Cloud Sandbox detonation, CASB inline control, TLS interception, ZPA brokering and connectors): these act on live traffic. Kavach only reviews what they exported.
- Risk360 quantification: it is a Zscaler-hosted model over tenant telemetry; the per-user and per-app risk above is a small log-derived ranking, not a reproduction.
- Zscaler Deception: Kavach already has a declared decoy registry ([tripwires.md](tripwires.md)); a deception-alert log from Zscaler can be sent as a log with the decoy names registered.
- CASB and SSPM posture over SaaS tenants: needs the SaaS API; a CASB log has a different (and larger) field list than the web feed and is not parsed. The Google SecOps CASB parser page lists fields such as `act_type_name`, `filename`, `dlpdictnames`, `extcollabnames` and `threatname` that a later parser could read.
- Cloud Connector, Browser Isolation, ZPA app-connector health and ZPA audit logs: no parser; their field lists could not be fetched.

## Research notes

Sources used: the help.zscaler.com NSS feed output format pages for web, firewall and DNS logs and the ZPA log streaming user-activity page were requested again on 2026-11-24 and still returned an empty page (client-rendered). The Google SecOps "Zscaler Webproxy", "Zscaler Firewall", "Zscaler DNS" and "Zscaler ZPA" parser pages and the Elastic ZPA integration page were readable and gave the key names marked [V] above. The policy-export key names in the policy section remain [U]. Everything marked [U] is from general knowledge of the product and could not be checked. Findings text and thresholds are original; no vendor text is copied. Check the field list of your own feed template before relying on a field.
