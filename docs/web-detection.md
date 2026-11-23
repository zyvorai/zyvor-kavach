# Web access-log and authentication-log detection

Kavach analyses web access logs and authentication logs that you SEND it, offline. It is observation only: it raises findings and reports, and never blocks a request, throttles a client, locks an account or contacts a server. It does not fetch logs, scan a host, follow a link, call a cloud API or look an IP address up (geolocation, if you want impossible-travel detection, must already be in your log). Research behind the choices is in [RESEARCH-vendors-detection.md](RESEARCH-vendors-detection.md).

Four capabilities, one pipeline:

| Capability | What it does | Where it lives |
|---|---|---|
| Web attack detection | 49 `web-` content rules over each access-log line: injection, traversal and inclusion, command injection, framework and appliance exploit probes, SSRF, scanner User-Agents, secret-file and admin-interface probes, web shell footprints | content pack `internal/edr/content/web_access.json`, batch `web-access-v1` |
| API discovery | Endpoint inventory (method, templated path, status mix, client count, query-parameter names), and with an OpenAPI JSON you send: shadow endpoints, undocumented-but-protected endpoints, verb drift, undeclared query parameters, documented operations never seen | `internal/edr/web_analytics.go` |
| Flood and credential-abuse summary | Per-client and distributed HTTP flood windows, login-endpoint brute force, distributed credential stuffing, path enumeration, User-Agent rotation | built-in windowed detectors (`web-an-*`) |
| Authentication-log analytics | Credential stuffing, many sources against one account, request velocity, success after a failure storm, impossible travel and fast country change from geo fields you supply | `internal/edr/auth_logs.go` (`auth-an-*`) |

## Why some detections are content rules and some are built in

Per-line detections go through the existing content framework ([content-framework.md](content-framework.md)): schema, ATT&CK mapping, positive and negative samples, benign-baseline check, lifecycle and shadow mode, content versions and tuning all apply, and custom content ([custom-content.md](custom-content.md)) can add `web-` style rules at run time. Counting detections (a flood, a stuffing campaign, impossible travel) need state across lines, which the per-event framework cannot express, so they follow the existing failed-login-burst precedent ([auth_burst.go](../internal/edr/auth_burst.go)): fixed-threshold built-ins registered in the ATT&CK rule map, reported as findings with `observe-only` tags. Shadow-API results are a report, not findings, because an undocumented endpoint is a posture question rather than an attack.

## Routes

All ingest routes need the admin token (agent credentials and sessions are refused, like [cloud-audit.md](cloud-audit.md)).

| Route | Body | Purpose |
|---|---|---|
| `POST /v1/web/logs?format=&host=` | raw log text | detection and analytics, no OpenAPI |
| `POST /v1/web/analyze` | JSON `{"log": "...", "format": "", "host": "", "openapi": {...}}` | same, plus the shadow-API check against the OpenAPI JSON in `openapi` |
| `POST /v1/auth/logs?host=` | JSON array, `{events\|records\|logs\|items\|entries\|value: [...]}`, one object, or JSON lines | authentication-log analytics |
| `GET /v1/web/sources` | none | formats, loaded `web-` rule count, analytic rule ids, limits (any authenticated caller) |

CLI: `kavachctl web analyze FILE [--openapi FILE.json] [--format F] [--host H] [--json]`, `kavachctl web sources`, `kavachctl authlog analyze FILE [--host H] [--json]`. There is no MCP tool: ingestion needs the admin token, which MCP deliberately does not hold (the same position as cloud audit and IOC import).

Limits: 8 MiB body (413), 50,000 lines or records (413), 64 KiB per line (longer lines are counted as `oversize_lines` and rejected), 3 s rule-evaluation budget (remaining lines are counted in `not_evaluated` but still feed the analytics), 2,000 stored findings per request, 5,000 inventory endpoints, 4 MiB and 5,000 paths for an OpenAPI document.

## Log formats

`format=auto` (default) chooses per line:

* **combined / common** (NGINX, Apache, HAProxy `option httplog` variants that end up in this shape): `ip ident user [time] "METHOD target PROTO" status bytes "referer" "user-agent"`. Backslash escapes inside quoted fields are honoured (`\"`). A request line that is not `METHOD target` (a TLS handshake sent to a plain HTTP port, binary probes) is kept with method `INVALID`.
* **JSON lines**: nested objects are flattened to dotted keys and field names are matched case-insensitively from a list that covers NGINX `escape=json` formats, Elastic Common Schema (`source.ip`, `http.request.method`, `url.original`, `http.response.status_code`, `user_agent.original`), Cloudflare Logpush HTTP request logs (`ClientIP`, `ClientRequestMethod`, `ClientRequestURI`, `EdgeResponseStatus`, `ClientRequestUserAgent`, `ClientRequestHost`, `EdgeStartTimestamp`) and generic names (`remote_addr`, `client_ip`, `uri`, `status`, `http_user_agent`, `time_iso8601`, ...).
* **logfmt**: `key=value` or `key="quoted value"` separated by spaces or commas. This covers the F5 BIG-IP ASM / Advanced WAF request-log key names (`ip_client`, `method`, `uri`, `response_code`, `date_time`, `vs_name`) when your logging profile writes them that way. Other F5 profile layouts will be rejected line by line rather than misread.

Not supported: AWS ALB and CloudFront formats (space or tab delimited with different field order), IIS W3C (field order comes from a header line), `X-Forwarded-For` parsing (the client address is exactly what the log field says, because the header is attacker controlled). Convert those to JSON lines first. Timestamps accepted: `02/Jan/2006:15:04:05 -0700`, RFC 3339, `YYYY-MM-DD hh:mm:ss`, and epoch seconds, milliseconds, microseconds or nanoseconds. Lines without a usable timestamp still go through rule detection, enumeration and inventory, but not the time-window detectors (`untimed` counts them).

## Normalisation and what is stored

Each line becomes the process-shaped event the rule engine already matches (the same trick as `cld-` rules):

| field | content |
|---|---|
| `executable` | `web:access` (every `web-` rule requires it, so these rules cannot fire on host process events) |
| `operation` | HTTP method (`INVALID` for a non-HTTP request line) |
| `parent_exe` | User-Agent, control characters removed, 200 characters |
| `path` | percent-decoded request path |
| `destination` | client address as logged |
| `host` | `web:<virtual host>`, or `web:<?host=>` when you pass one |
| `command` | `status=<n> bytes=<n> len=<raw target length> dec=<0-3> target=<decoded path and query>` |

The target is percent-decoded up to three passes (`dec` records how many passes changed it, so double encoding is itself detectable), `+` becomes a space in the query only, NUL, CR and LF stay visible as `<nul>`, `<cr>`, `<lf>`, other control characters become spaces, and at most 2,048 characters are matched. The true length is kept in `len=`. Raw targets over 8 KiB are cut before decoding.

What Kavach keeps (privacy boundary):

* Matching runs on the unredacted target. The stored finding evidence is cut to 300 characters and the VALUE of any query parameter whose name contains `pass`, `pwd`, `secret`, `token`, `key`, `auth`, `sess`, `sid`, `jwt`, `cred`, `signature`, `sig`, `code`, `otp` or `bearer` is replaced with `REDACTED` (tested, including percent-encoded parameter names).
* The API inventory keeps query-parameter NAMES only, never values, and at most 64 distinct client addresses per endpoint.
* Request and response bodies, cookies and headers other than the User-Agent never reach Kavach because access logs do not carry them; `Authorization` and `Cookie` values are not read even if a JSON line contains them.
* Authentication logs: only an allow-list of fields is read (time, user, source address, outcome, country, latitude, longitude). A `password` field in a record is ignored and never stored.
* Nothing is persisted except the findings, which go to the normal findings store. There is no new state file.

## The `web-` rule pack

Counted from `web_access.json` (49 rules, batch `web-access-v1`, `event_type: process`, `os: any`). Ids are `web-<family>-<what>`; `web-an-` is reserved for the analytic detectors below.

| Family | Rules | ATT&CK | Severity |
|---|---|---|---|
| SQL injection (`web-sqli-*`, `web-nosqli-operator`) | UNION SELECT, boolean tautology, time delay, schema or error-based functions, file and command primitives, stacked statements, NoSQL operators | T1190 | high to critical |
| Cross-site scripting (`web-xss-*`) | script tag, tag with event handler, `javascript:` URI | T1190 | medium |
| Traversal and inclusion (`web-lfi-*`, `web-rfi-*`) | repeated `../` (also after decoding), `..;/`, sensitive system files, PHP and URI stream wrappers, remote include parameters | T1190, T1552.001 | medium to high |
| Command injection (`web-cmdi-*`) | separator plus command, shell path or switch, download-and-run | T1059, T1105 | high |
| Exploit classes (`web-exploit-*`) | Log4Shell lookup (request or User-Agent), Spring class-loader and routing expression, Shellshock, OGNL expressions, SSTI probes, XXE, prototype pollution, Java serialization marker, LDAP filter injection, CRLF injection | T1190 | medium to critical |
| Evasion (`web-evasion-*`) | NUL byte, multiply encoded attack characters, oversized target | T1027 | low to medium |
| SSRF (`web-ssrf-*`) | cloud metadata endpoints, gopher/dict/ldap/tftp schemes | T1552.005, T1190 | medium to high |
| Recon and exposure | attack-tool User-Agents, dotfile and secret-store probes (and a high-severity variant when the server answered 2xx), backup and config copies, admin and debug interfaces, unusual methods, malformed request lines, GraphQL introspection | T1595.002, T1552.001 | low to high |
| Known exploit probes (`web-cve-*`, `web-recon-iot-router-probe`) | edge appliances and enterprise software (F5 BIG-IP iControl REST and TMUI, Citrix ADC, FortiOS, Confluence, vCenter, MOVEit, Ivanti), frameworks (PHPUnit, Laravel Ignition, ThinkPHP, Drupal, PHP-CGI, Exchange autodiscover), consumer routers | T1190 | medium to high |
| Web shell footprint (`web-webshell-*`, `web-upload-script-put`) | server-side script served from an upload directory, well-known shell names, shell-command parameters, PUT of a script that returned 2xx | T1505.003, T1059 | high |
| Brute force | POST to WordPress `xmlrpc.php` | T1110 | medium |

Honesty notes:

* A path or parameter match is a request-level signal. It does not mean the target is vulnerable or was compromised; check the status code and your own inventory. Rules that need a successful response (`web-exposure-secret-file-served`, the web shell rules, `web-upload-script-put`) say so in their match.
* CVE identifiers in rule descriptions are public references for the technique; each rule was written from the public description of the request pattern, not copied from any vendor, WAF or community rule set.
* Rules are case-insensitive, linear-time (RE2 or plain substring), at most 256 characters per regex, and evaluated only against the first 2,048 characters of the target. A payload hidden beyond that is not seen (the `len=` rule flags oversized targets).
* `web-scanner-ua-attack-tool` also fires for your own authorised scans: add an exception or move the rule to `testing` with the lifecycle API ([rule-health.md](rule-health.md), [content-tuning.md](content-tuning.md)).
* There is no anomaly score across rules (OWASP CRS style). Each line can raise several findings; analysts correlate them by client address and host.

## Built-in analytic detectors

Thresholds are fixed heuristics, not tuned to your traffic. All findings carry tags `analytics`, `observe-only`, the technique id and `web-access` (or `auth`).

| Rule | Fires when | ATT&CK | Severity |
|---|---|---|---|
| `web-an-http-flood-source` | one client sends 200 or more requests in one 10 second bucket (20 req/s), max 25 clients per request | T1499.002 | medium |
| `web-an-http-flood-distributed` | a 10 second bucket holds 1,000 or more requests from 50 or more sources and no source is 50% or more of it (the heaviest such window; up to 20 windows are listed in `flood_windows`) | T1499.002 | high |
| `web-an-login-bruteforce` | one client makes 20 or more POSTs to a login-like path in a minute and 80% or more fail (400, 401, 403, 422, 429) | T1110 | medium |
| `web-an-credential-stuffing` | in a 5 minute window: 100 or more login POSTs, 20 or more sources, 80% or more failing, and a median of 5 or fewer attempts per source (low and slow, distributed) | T1110.004 | high |
| `web-an-path-enumeration` | one client makes 60 or more requests, 40 or more distinct 4xx paths and 80% or more 4xx | T1595.003 | medium |
| `web-an-ua-rotation` | one client uses 10 or more distinct User-Agent values over 30 or more requests | T1595 | low |
| `auth-an-credential-stuffing` | in a 10 minute window: 50 or more failures against 20 or more accounts from 10 or more sources, median 5 or fewer per source | T1110.004 | high |
| `auth-an-distributed-account-attack` | 10 minute window: one account fails from 8 or more different sources | T1110 | medium |
| `auth-an-high-velocity` | one source makes 100 or more attempts in a minute | T1110 | medium |
| `auth-an-success-after-failures` | a success from a source that failed 5 or more times against 3 or more accounts in the previous 10 minutes | T1078 | high |
| `auth-an-impossible-travel` | two successful logins by one account from different sources whose geo coordinates imply 500 km or more at 900 km/h or more | T1078 | medium |
| `auth-an-country-change-fast` | no coordinates, but the country differs within 60 minutes | T1078 | low |

Login-like paths are POSTs whose decoded path contains `login`, `signin`, `sign-in`, `sign_in`, `logon`, `authenticate`, `/auth`, `/session`, `/token`, `wp-login`, `/oauth`, `/sso`, or any POST to `xmlrpc.php`. An access log has no username and cannot distinguish a failed password from other 4xx answers, and some applications answer a failed login with 200; for those, send the application's own authentication log to `POST /v1/auth/logs` instead, which has users and outcomes. Impossible travel is the classic VPN, proxy and mobile-carrier false-positive: investigate before acting. Findings are rate-capped (25 per rule per request).

Logs are sorted by timestamp before windowing, so out-of-order input is fine. Fixed 10 second, 5 minute and 10 minute buckets can split a burst that straddles a boundary into two halves below the threshold.

## API discovery and the shadow-API check

The inventory groups requests by method and a templated path. Without an OpenAPI document numeric segments become `{id}`, UUIDs `{uuid}`, 16 or more hex characters `{hash}`, and 24 or more character segments containing a digit `{token}`; named identifiers such as `/users/alice` stay literal, so an API keyed on names can hit the 5,000 endpoint cap (`endpoints_truncated`). Static assets (`.js`, `.css`, images, fonts, `.txt`, `.html`) are counted in `static_requests_skipped`, not inventoried.

With an OpenAPI 3.x or Swagger 2.0 document as JSON in the `openapi` field (YAML is not supported because Kavach takes no YAML dependency; convert it first), the report adds:

* `shadow_endpoints`: observed method and path with no matching path in the spec and at least one 2xx or 3xx answer.
* `undocumented_protected`: no spec match, seen at least once with 401 or 403 and never with 2xx or 3xx. Exists but is protected; document it or confirm it should not exist.
* `verb_drift`: the path is in the spec, the method is not, and the server answered 2xx or 3xx (`HEAD` and `OPTIONS` are ignored).
* `param_drift`: query-parameter names seen on a documented operation that the spec does not declare (path, operation and `#/components/parameters` references are resolved).
* `spec_operations_not_observed`: documented operations with no traffic in this log. Absence in one log sample means nothing about the whole API.

A request is only considered if it falls under the spec base path (`basePath`, or the path of the first `servers[].url`). Matching prefers the spec path with the most literal segments, so `/pets/mine` beats `/pets/{petId}`. 404-only paths are scanner noise and are not reported. This is traffic-derived discovery only: Kavach does not crawl, probe or fetch anything, and it sees only what your log sampled.

## Worked example

```sh
kavachctl web analyze testdata/access.log --openapi openapi.json --host shop.example.org
curl -s -H "Authorization: Bearer $KAVACH_ADMIN_TOKEN" -X POST \
  'http://127.0.0.1:8099/v1/web/logs?format=combined' --data-binary @access.log
```

Response (abridged, values illustrative):

```json
{"mode":"observe-only","lines":15,"parsed":15,"rejected":0,"untimed":0,
 "status_classes":{"2xx":11,"4xx":3},"by_rule":{"web-sqli-union-select":1,"web-scanner-ua-attack-tool":2},
 "findings":13,"peak_requests_per_second":0.2,
 "api":{"spec_loaded":true,"endpoints_total":6,
  "shadow_endpoints":[{"method":"GET","path":"/api/v1/internal/debug/dump","requests":1,"statuses":{"2xx":1}}],
  "param_drift":[{"method":"GET","path":"/admin/export","undeclared_params":["token"]}]}}
```

## Adding or tuning a rule

Add to `internal/edr/content/web_access.json` (or custom content) with `executable equals web:access` as the first condition, a positive sample and at least two near-miss negatives (the pack-shape test enforces this), then run `go test ./internal/edr/ -run 'TestContentHarness|TestWeb'`. Fixtures in `internal/edr/testdata/web/` and `testdata/auth/` drive the end-to-end tests; add a raw log line there when you change the normaliser, because rule samples alone do not prove the normaliser produces what the rule expects (the same lesson as [cloud-audit.md](cloud-audit.md)).

## Limits and honesty

* The pack, fixtures and tests were written by one author from public descriptions of the attack classes. Agreement between them shows consistency, not coverage of your real traffic, and there is no accuracy or false-positive measurement on production logs. Run it over a sample of your own logs before relying on it, and expect noise from security scanners, vulnerability-management tools and unusual but legitimate parameters.
* It is not a WAF. It sees a request after the fact, cannot see bodies or headers (so POST-body injection, header injection and most deserialization attacks are invisible unless they reach the URL), and cannot block anything.
* Thresholds for floods and credential abuse are constants. They are meant for the summary use case ("what happened in this log"), not as tuned production alerting.
* Source addresses are what the log says. Behind a CDN or load balancer the log must carry the real client address (for example a `real_ip` field), or every client looks like the proxy.
* `web-an-*` and `auth-an-*` findings are not content rules: they do not appear in `GET /v1/content/rules`, have no lifecycle record and are not tunable per rule other than through exceptions. They are in the ATT&CK map so coverage and findings views show them.
