# Appliance configuration review: F5 BIG-IP, nginx extras and the version advisory table

Kavach stays observation-only and offline here. It reads configuration text an analyst sends (`kavachctl inspect config FILE`, `POST /v1/inspect/config`); it never connects to a BIG-IP or an nginx host, never runs `tmsh`, never fetches an advisory and never follows an include. Everything runs through the existing configuration assessment framework (policies in `internal/edr/configpolicies/*.json`, the loader, self-tests and report shape described in [config-assessment.md](config-assessment.md)). Findings carry weight 0 and the report is `not_scored`; a passing result is not an attestation.

## F5 BIG-IP (`bigip` format)

Input: `bigip.conf`, `bigip_base.conf`, the output of `tmsh list`, or a config file taken from a qkview that the analyst extracted and pasted. The format is sniffed from the name (`bigip*.conf`, `*.scf`) or from the content (`#TMSH-VERSION:` header or tmsh stanzas such as `ltm virtual ... {`). The qkview archive itself is not opened (a bounded archive reader plus manifest format was judged out of scope for this round; see [RESEARCH-vendors-posture.md](RESEARCH-vendors-posture.md)).

Parser (`inspect_config_bigip.go`): hand-written, bounded (24 levels of nesting, 60,000 statements, 4 KiB tokens, 20,000 settings), tolerant of unbalanced braces (reported as a parse note). Keys are `<class>.<kind>.<property>` such as `sys.httpd.allow` or `net.self.allow-service`; `ltm profile client-ssl NAME` is keyed `ltm.profile.client-ssl.*`. Object-level findings are computed while parsing and emitted as `risk.bigip-*` settings. iRule (Tcl) bodies are tokenised like any other braces and are not analysed.

Policies (`bigip.json`, 12; original wording; the concepts come from F5's public hardening guidance, which this project read only through the F5 community "Security best practices" article):

| Policy | Severity | What it checks |
|---|---|---|
| `bigip-httpd-allow-all` | critical | management web interface allow list contains all/any/0.0.0.0/0 |
| `bigip-sshd-allow-all` | high | SSH allow list contains all/any |
| `bigip-httpd-ssl-protocol` | medium | management TLS protocol string allows TLS 1.0/1.1 |
| `bigip-selfip-allow-all` | high | self IP with `allow-service all` |
| `bigip-selfip-allow-default` | medium | self IP with `allow-service default` instead of an explicit list |
| `bigip-ssl-weak-ciphers` | high | client-ssl or server-ssl cipher string names RC4, DES/3DES, MD5, EXPORT, NULL or LOW |
| `bigip-virtual-wildcard-port` | medium | virtual server on every port with no source restriction |
| `bigip-snmp-default-community` | high | community `public` or `private` |
| `bigip-remote-syslog` | low | no remote syslog server |
| `bigip-password-policy` | medium | password policy enforcement not enabled |
| `bigip-httpd-idle-timeout` | low | idle timeout above 1200 s |
| `bigip-sshd-inactivity-timeout` | low | SSH inactivity timeout 0 |

Absence handling follows the framework: where the default depends on the TMOS version or the setting may live in another file (`bigip_base.conf` versus `bigip.conf`) the result is `unknown`, not a pass.

## nginx extras (`web2.json`, 7 policies)

Added to the 10 existing nginx checks: `web-nginx-proxy-pass-client-host` (an upstream built from `$host`, `$http_*`, `$arg_*`, `$cookie_*` or a regex capture; open-proxy and server-side request forgery primitive), `web-nginx-proxy-ssl-verify` (https upstream without `proxy_ssl_verify on`), `web-nginx-stub-status`, `web-nginx-ignore-invalid-headers`, `web-nginx-underscores-in-headers`, `web-nginx-access-log-off`, `web-nginx-session-tickets`. The nginx parser does not track `location` or `server` context, so these are file-level observations (a `stub_status` inside an `allow`/`deny` protected location is still reported; read the evidence).

## Version advisory table (`config-advisory` analyzer)

When the submitted text contains a version string, it is compared with a versioned table:

* BIG-IP: the `#TMSH-VERSION: 15.1.5.1` header written at the top of tmsh configuration files.
* nginx: `nginx version: nginx/1.25.3` (output of `nginx -V`) or `Server: nginx/1.25.3`, anywhere in the text.

Table format `kavach-config-advisories/1` (JSON, at most 2 MiB and 5,000 entries; strictly validated):

```json
{"format":"kavach-config-advisories/1","source":"my feed","advisories":[
 {"id":"CVE-2099-0001","aliases":["K00000000"],"product":"bigip","severity":"high",
  "summary":"original one-line description",
  "ranges":[{"introduced":"15.1.0","fixed":"15.1.5.1"},{"introduced":"12.1.0","last_affected":"12.1.99"}],
  "kev":false,"source":"vendor advisory URL","source_verified":true}]}
```

A range matches when `introduced <= v < fixed` (or `<= last_affected`). Versions are dotted numbers, compared numerically with missing parts as zero; a part with a trailing suffix (`5-hf2`) keeps its number and drops the suffix. Because branches are fixed independently (nginx 1.30.x and 1.31.x, BIG-IP 13.1, 14.1, 15.1, 16.1) each branch is its own range.

To replace the embedded table set `KAVACH_CONFIG_ADVISORIES=/path/advisories.json` before starting Kavach; the file is read once at first use. An invalid file is reported in the analyzer summary (`advisory_warning`) and the embedded sample is used instead.

The embedded table (`configadvisories/sample.json`) is a labelled sample, not a feed, and every entry has `source_verified: false` for these reasons:

* The 15 nginx entries were read from the nginx.org security advisories page on 2026-11-23 through a summarising fetch tool. Ids, ranges and fixed versions are as that tool reported them, one id was normalised from a typo on the page, and the ids look unusual enough that they must be re-checked against nginx.org and the CVE records before anyone acts on them.
* The 3 BIG-IP entries (CVE-2022-1388 / K23605346, CVE-2022-41617, CVE-2022-35243) come from third-party scanner and vulnerability-database pages seen in a web search; the F5 pages were not opened.

Every advisory finding says so in its evidence. Limits: only the version string is compared. Advisories often require a provisioned module or a configured feature, and distribution packages backport fixes without changing the version, so a match means "check the vendor advisory", not "exploitable". An unlisted version is not "not vulnerable"; the table is small.

## Tests

`inspect_config_posture_test.go` covers the fixtures in `internal/edr/testdata/posture/` (a weak and a hardened BIG-IP file, a weak nginx file), the version comparison table (branch boundaries, suffixes, malformed versions), advisory-file validation (rejected formats, products, severities, ranges, oversize input) and hostile input to the BIG-IP parser (100,000 opening braces, unterminated quotes, NUL bytes, 20,000-word values, 5,000-deep nesting) with a time limit and entry-count bound.
