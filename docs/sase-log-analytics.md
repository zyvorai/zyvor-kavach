# Cloudflare and Cisco Umbrella log analytics

Offline analytics over logs you export from Cloudflare and Cisco Umbrella, plus a posture review of an exported Cloudflare ruleset list. Kavach stays observation only: it reads what you send, stores findings, and never connects to Cloudflare or Cisco, fetches a log, looks an address up or changes a policy. URL query strings are dropped from every finding and evidence field.

| Surface | Route (admin token) | Command |
|---|---|---|
| Cloudflare logs | `POST /v1/cloudflare/logs` | `kavachctl cloudflare logs FILE [--format F] [--host H]` |
| Cloudflare ruleset review | `POST /v1/cloudflare/policy` | `kavachctl cloudflare policy FILE` |
| Umbrella logs | `POST /v1/umbrella/logs` | `kavachctl umbrella logs FILE [--format F] [--host H]` |
| Rules and limits | `GET /v1/cloudflare/sources`, `GET /v1/umbrella/sources` | `kavachctl cloudflare sources`, `kavachctl umbrella sources` |

Limits: 8 MiB body, 100,000 log records (413 beyond), 20,000 ruleset rules, 25 findings per rule reported. Findings are stored with host label `cloudflare:NAME` or `umbrella:NAME` (from `?host=`).

## Cloudflare logs

Input is a Logpush export in JSON, JSON lines, CSV or TSV with a header row. Four datasets are recognised by their field names: `cf-http` (HTTP requests), `cf-fw` (firewall events), `cf-gwdns` (Gateway DNS) and `cf-gwhttp` (Gateway HTTP). Field names are folded to lower-case letters and digits, so `ClientIP` and `client_ip` are one key.

Fields read, and where each was checked. **[V]** means the name appears on the Cloudflare developer-documentation field reference page fetched on 2026-11-24; **[U]** means from general knowledge.

| Dataset | Fields |
|---|---|
| HTTP requests | `ClientIP`, `ClientRequestHost`, `ClientRequestPath`, `ClientRequestMethod`, `ClientRequestUserAgent`, `ClientCountry`, `ClientIPClass`, `EdgeResponseStatus`, `EdgeStartTimestamp`, `SecurityAction`, `WAFAttackScore`, `WAFRCEAttackScore`, `WAFSQLiAttackScore`, `WAFXSSAttackScore`, `BotScore`, `BotScoreSrc` [V]. `ClientIPClass` values unknown, badHost, searchEngine, allowlist, monitoringService, noRecord, scan, tor [V]. `SecurityAction` values (block, challenge, jschallenge, managedChallenge, log, skip, bypass, the `...Solved` and `...Bypassed` forms and others) [V]. That a bot score of 1 to 10 means very likely automated, and that an attack score of 1 to 20 is the "attack" band, are from Cloudflare's WAF attack score page as summarised by search, not a fetched table: **[U]** |
| Firewall events | `Action`, `Source`, `RuleID`, `MatchIndex`, `Kind`, `LeakedCredentialCheckResult` (password_leaked, username_and_password_leaked, username_password_similar, username_leaked, clean), `ClientIP`, `ClientRequest*`, `EdgeResponseStatus`, the WAF score fields [V] |
| Gateway DNS | `QueryName`, `ResolverDecision`, `QueryTypeName`, `RCode`, `Email`, `UserID`, `DeviceName`, `SrcIP`, `SrcIPCountryCode`, `MatchedCategoryNames`, `QueryCategoryNames`, `ResolvedIPCategoryNames`, `CNAMECategoryNames`, `MatchedIndicatorFeedNames`, `QueryIndicatorFeedNames` [V]. The page lists only the example `overrideForSafeSearch` for `ResolverDecision`; which values mean a block is **[U]**, so Kavach treats a decision containing block, deny, drop or sinkhole as blocked and everything else as not blocked |
| Gateway HTTP | `HTTPHost`, `HTTPMethod`, `URL`, `Action`, `HTTPStatusCode`, `Email`, `UserID`, `DeviceName`, `SourceIP`, `UserAgent`, `CategoryNames`, `UploadMatchedDlpProfiles`, `DownloadMatchedDlpProfiles`, `UntrustedCertificateAction` (none, block, error, passThrough) [V]. The vocabulary of `Action` is not enumerated on the page: **[U]** |

### Rules (12)

| Rule | Severity | Fires when |
|---|---|---|
| `cf-an-attack-score-allowed` | high | WAF attack score 1 to 20 and the request was served (status below 400, not blocked or challenged) |
| `cf-an-injection-score-allowed` | high | SQLi, XSS or RCE score 1 to 20 and served |
| `cf-an-waf-block-burst` | medium | 20 or more blocked or challenged requests from one client IP |
| `cf-an-leaked-credential-login` | high | leaked-credential result password_leaked or username_and_password_leaked on a served POST |
| `cf-an-automated-bot-allowed` | medium | 20 or more served requests to one host from one IP with bot score 10 or less, not a verified bot |
| `cf-an-bad-client-class-allowed` | low | 3 or more served requests from a tor, scan or badHost class IP |
| `cf-an-origin-error-burst` | low | 25 or more 5xx responses for one host |
| `cf-an-gateway-dns-threat-allowed` | high | Gateway DNS query matched a malware, phishing, botnet, command-and-control or similar category or feed and the decision is not a block |
| `cf-an-gateway-untrusted-cert-passthrough` | medium | Gateway HTTP `UntrustedCertificateAction` is passThrough |
| `cf-an-gateway-dlp-allowed` | high | Gateway HTTP DLP profile match and the action is not a block |
| `cf-an-gateway-dns-tunnel-like` | high | 20 or more very long (80+ characters or a 40+ character label) names under one parent |
| `cf-an-gateway-nxdomain-burst` | medium | 30 or more NXDOMAIN answers (`RCode` 3) to one identity |

Per-identity risk (client IP for HTTP datasets, user, device or email for Gateway) is the weighted sum of findings (high 8, medium 3, low 1, at most five per rule, capped at 100).

## Ruleset review

Input is the JSON a Rulesets API list or get returns, saved to a file: one ruleset, an array, or an object whose `result` holds them. Fields used: ruleset `name` and `phase`; rule `action`, `expression`, `enabled`, `description` and `action_parameters.overrides.action`. The rule and ruleset field names (`rules`, `action`, `expression`, `enabled`, `description`, `action_parameters`) were checked on the Cloudflare ruleset-engine JSON object page [V]. That page shows only the phase `http_request_firewall_custom` and the action `block`; the phase names `http_request_firewall_managed` and `http_ratelimit` and the actions `execute`, `skip` and `log` are from memory and **[U]**, and the review matches phases by substring (`firewall_managed`, `ratelimit`, `firewall_custom`).

| Rule | Severity | Fires when |
|---|---|---|
| `cfpol-no-managed-waf` | high | no enabled `execute` rule in a managed-rules phase |
| `cfpol-no-rate-limit` | medium | no enabled rule in a rate-limiting phase |
| `cfpol-skip-broad` | high | enabled `skip` rule whose expression is empty, `true`, or matches `ip.src` against `0.0.0.0/0` |
| `cfpol-log-only-action` | medium | enabled custom or managed rule with action `log` (or an override action of `log`) |
| `cfpol-disabled-rules` | low | 3 or more disabled rules |
| `cfpol-undocumented-rules` | low | 3 or more enabled rules without a description |

The posture score starts at 100 and subtracts 15 per high, 8 per medium and 3 per low finding type (at most five instances each); the grade is A at 90 and above, then B, C, D at 80, 70, 60, else F. Expressions are read as text and never evaluated; account-level rulesets that are not in the export are not seen.

## Cisco Umbrella logs

Umbrella writes DNS and proxy logs to an S3 bucket as gzip CSV with **no header row**. Kavach reads that form by column position and also reads files with a header, JSON lines or the camelCase proxy keys that a public SIEM parser page lists (`ts`, `identity`, `internalIp`, `externalIp`, `destinationIp`, `contentType`, `verdict`, `url`, `referer`, `userAgent`, `statusCode`, `avDetections`, `ampDisposition`, `ampMalware`, `blockedCategories`, `categories`).

Column positions (headerless), counting from 0. These come from the unlabeled sample rows on the Graylog Illuminate Cisco Umbrella content pack page and are inferred, not taken from Cisco's field table: the official Umbrella log-format pages (docs.umbrella.com, redirected to securitydocs.cisco.com) returned a socket error twice, so the order is **[U]** and should be compared with one of your own files.

| Log | Columns |
|---|---|
| DNS | 0 timestamp, 1 identity, 3 internal IP, 4 external IP, 5 action (Allowed or Blocked), 6 query type, 7 response code (NOERROR, NXDOMAIN), 8 domain, 9 categories |
| Proxy | 0 timestamp, 1 identity, 2 internal IP, 3 external IP, 4 destination IP, 5 content type, 6 action (Allowed or Blocked), 7 URL, 9 user agent, 10 status code |

A headerless row is recognised when its first cell parses as a time and it has 8 or more columns; a DNS row is told from a proxy row by the position of the Allowed or Blocked word. Category and AV columns in the proxy form are not read headerless because their positions could not be confirmed; use a headered export to get `umb-an-proxy-malware-allowed`. The category names matched below (Malware, Phishing, Command and Control, Botnet, Cryptomining, Potentially Harmful, Proxy/Anonymizer, Newly Seen Domains, Dynamic DNS) are **[U]** except Malware and Potentially Harmful, which the Google SecOps parser page quotes.

### Rules (6)

| Rule | Severity | Fires when |
|---|---|---|
| `umb-an-threat-category-allowed` | high | an allowed DNS or proxy record carries a malware, phishing, command-and-control, botnet, cryptomining, ransomware or Potentially Harmful category |
| `umb-an-anonymizer-allowed` | medium | allowed traffic in a proxy, anonymiser, newly seen, dynamic DNS, tunnel or VPN category |
| `umb-an-dns-tunnel-like` | high | 20 or more very long names under one parent |
| `umb-an-nxdomain-burst` | medium | 30 or more NXDOMAIN answers to one identity |
| `umb-an-block-burst` | medium | 25 or more blocked requests from one identity |
| `umb-an-proxy-malware-allowed` | high | proxy record with an antivirus detection or a malicious AMP disposition and an allowed verdict |

## Testing

All 24 rules have a positive and a negative example in `internal/edr/content_examples/sase-analytics.jsonl` under the content-harness kinds `cflog`, `umblog` and `cfpolicy` (see [content-testing.md](content-testing.md)); `kavachctl content selftest` and `go test` fail if one stops firing or starts firing on its negative. All fixtures are synthetic (`example.test` names, documentation IP ranges). The parsers were not run against a real Cloudflare or Umbrella export.

## What was not added

Check Point, FortiAnalyzer, Netskope, Prisma Access and Okta ThreatInsight logs were not added in this round. Cloudflare Zero Trust access logs, Magic Transit and Spectrum datasets, and Umbrella audit and cloud-firewall logs are not read. Nothing here is a Cloudflare or Cisco product behaviour claim: thresholds are Kavach's own heuristics, and every finding states a plausible benign cause.

## Sources

Cloudflare developer documentation: HTTP requests and firewall events log-field references, Gateway DNS and Gateway HTTP log-field references, the ruleset-engine JSON object page and the WAF attack score pages (fetched or searched 2026-11-24). Graylog Illuminate Cisco Umbrella content pack page, Google SecOps Cisco Umbrella DNS and web-proxy parser pages. Findings text is original; no vendor text is copied.
