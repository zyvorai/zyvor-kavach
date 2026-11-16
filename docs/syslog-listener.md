# Agentless syslog listener (competitive backlog #22)

Observation only. Receives syslog from network gear and appliances that cannot run an agent and
feeds normalised events into the same ingest and rule-evaluation path as `POST /v1/events/{type}`.
Files: `internal/edr/syslog_parse.go`, `syslog_listener.go`, `syslog_test.go`.

## Enabling (default OFF, no default bind)

```
KAVACH_SYSLOG=udp:10.0.0.5:514,tcp:10.0.0.5:514,tls:10.0.0.5:6514
KAVACH_SYSLOG_ALLOW=10.1.0.0/16,192.0.2.7
KAVACH_SYSLOG_TLS_CERT=/path/cert.pem   # required for tls: entries
KAVACH_SYSLOG_TLS_KEY=/path/key.pem
KAVACH_SYSLOG_MAX_CONNS=64              # optional
KAVACH_SYSLOG_RATE=200                  # optional, messages/s per source (burst = 2x)
```

- Every listen entry must be `proto:host:port`. A bare port such as `udp:514` is refused (no implicit bind).
- An empty `KAVACH_SYSLOG_ALLOW` makes the listener refuse to start (reason shown in `/v1/syslog/status` and the log).
- The server binary has no TLS env of its own (it uses `--tls-cert/--tls-key` flags), so the syslog TLS
  files have their own env vars. TLS 1.2 minimum, no client-cert requirement.
- Plaintext `udp:`/`tcp:` prints a warning at start and in status. Syslog over UDP/TCP is unauthenticated and
  unencrypted, UDP source addresses can be spoofed, and the allowlist is only an address filter. Use `tls:` and a
  restricted network segment where possible.

## Hard limits

| Limit | Value |
|---|---|
| Max message | 8 KiB (oversize counted as `oversize`; TCP newline framing discards to LF, octet-counted oversize closes the connection) |
| Max connections | 64 default (`max_conns` drops) |
| Per-source rate | 200 msg/s default, burst 2x (`rate_limited`) |
| Source table | 4096 tracked sources (`source_table_full`) |
| Queue | 4096 items; full queue drops (`queue_full`) |
| Read deadline | 60 s absolute per frame (slow-loris safe) |
| Source filter | CIDR allowlist required (`not_allowed`) |
| Responses | Never written to any sender |

Drops are counted, never silent. Unparsed lines are counted and the latest 50 are kept (truncated to 512
chars, secrets such as `password=`, `token=`, `Bearer ...` redacted).

## Event path and host namespacing

Parsed messages become `auth`, `dns` (telemetry) or network events. Telemetry goes through
`TelemetryEvent.Validate`, `TelemetryStore.Add`, then `Store.IngestTelemetry` (what the POST handler does after
auth); flows go through `Store.IngestNetwork`. No new evaluation path.

Host is always `syslog:<name>` where `<name>` is the parsed hostname with only `[A-Za-z0-9._-]` kept (so `:` can
never appear) or the sender IP. A device can therefore never write into an enrolled agent's host (tested with
`agent1`, `syslog:agent1`, `agent1:evil`). Network events carry `source=syslog:<senderIP>`. TelemetryEvent has no
source field, so `kind` carries `syslog:<senderIP>` for auth/dns events. Timestamps from the device are used only
within +-48 h of receipt, otherwise receipt time is used.

## Endpoints

- `GET /v1/syslog/status` (auth): enabled, listeners, allowlist, limits, received, parsed by format, parsed
  without event, unparsed, events by type, dropped by reason, rate-limited, queue length, last message per source.
- `GET /v1/syslog/samples` (auth): bounded redacted unparsed lines.
- `POST /v1/syslog/parse` (admin or session): `{"line": "...", "sender": "<ip, optional>"}`, returns the parse and
  the normalised events, never ingests.

## Worked example

```bash
# 1. Enable on the server (explicit address, source allowlist required)
export KAVACH_SYSLOG=udp:10.0.0.5:514
export KAVACH_SYSLOG_ALLOW=10.1.0.0/16
go run ./cmd/kavach -mode server -listen 127.0.0.1:8099 &

# 2. Check the state (enabled=false and a `note` when KAVACH_SYSLOG is unset)
kavachctl syslog status
curl -s -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/syslog/status

# 3. Dry-run a line before pointing a device at the listener (nothing is ingested)
kavachctl syslog parse '<38>Nov 16 10:00:01 gw sshd[411]: Failed password for root from 203.0.113.9 port 4242 ssh2'
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" $KAVACH_URL/v1/syslog/parse \
  -d '{"line":"<38>Nov 16 10:00:01 gw sshd[411]: Failed password for root from 203.0.113.9 port 4242 ssh2","sender":"10.1.0.7"}'

# 4. Send a test message from an allowed source and look at the counters
logger -n 10.0.0.5 -P 514 -d "test message"
kavachctl syslog samples
```

The same lines also work through MCP as `syslog_status`, `syslog_samples` and `syslog_parse` (a dry run
that needs an admin token on the server).

## Failure modes and troubleshooting

| Symptom | Meaning and fix |
|---|---|
| `enabled: false` in status | `KAVACH_SYSLOG` is unset (normal default) or the listener failed to start; the start error is in the status payload and the server log |
| Refuses to start with an empty allowlist | Set `KAVACH_SYSLOG_ALLOW` to at least one CIDR or address |
| `udp:514` is refused | Entries must be `proto:host:port`; there is no implicit bind address |
| `tls:` entry fails | `KAVACH_SYSLOG_TLS_CERT` and `KAVACH_SYSLOG_TLS_KEY` are both required |
| Nothing arrives, `dropped_by_reason.not_allowed` rises | The sender is outside the allowlist. Behind NAT the source address is the NAT address |
| `rate_limited` or `queue_full` rise | A chatty source exceeds 200 msg/s (burst 2x) or the 4096-item queue is full. Raise `KAVACH_SYSLOG_RATE` (accepted range above 0 up to 100000) or reduce the source |
| Messages counted but `parsed_without_event` rises | The shape is recognised but maps to no Kavach telemetry type (for example web access logs) |
| `unparsed` rises | New device format; read `GET /v1/syslog/samples` (redacted, newest last) and open a parser request |
| Windows event forwarding | Not parsed (see below) |
| Port below 1024 fails to bind | The container runs non-root; use a high port, or map it with the Service |

Limits of this feature: syslog over UDP or plain TCP is unauthenticated and spoofable; the allowlist only filters
addresses. Parsers were written from public format descriptions and covered by repository tests with synthetic lines;
no live device was used (see the unverified list below).

## Supported shapes (mapping)

| Shape | Maps to |
|---|---|
| sshd Accepted/Failed (password, publickey, keyboard-interactive/pam, ...), Invalid user | auth, method ssh |
| sudo command line, "N incorrect password attempts" | auth, method sudo |
| `pam_*(svc:auth): authentication failure; ... user=` | auth failure (ssh for sshd, sudo for sudo, else console) |
| nginx/Apache combined or common access line | recognised, no event (no Kavach telemetry type fits an HTTP request) |
| Cisco ASA 106100, 106023, 302013/302014-style "Built ... connection" | network with deny/allow verdict |
| Fortinet key=value (`dstip`, `dstport`, `action`; `qname`) | network, dns |
| Palo Alto TRAFFIC CSV (type at field 4, dst addr 9, dst port 26, action 31, 1-based) | network |
| dnsmasq `query[A] name from ip` | dns |
| CEF / LEEF (login-named events with a user, dst/dhost+dpt, requestdns) | auth (method console), network, dns |

Windows event forwarding as syslog: no parser. Formats vary by forwarder and none was opened; such lines are
counted as RFC 3164/5424 and yield no event, or are sampled as unparsed.

## Sources actually opened

- RFC 5424, https://www.rfc-editor.org/rfc/rfc5424 : header `<PRI>1 TS HOST APP PROCID MSGID SD MSG`, PRI = facility*8+severity,
  RFC 3339 timestamp, `-` as NILVALUE, structured data as `[id name="value"]` with `"`, `\`, `]` escaped,
  receivers must accept 480 octets and should accept 2048, UTF-8 BOM marks UTF-8 text in MSG.
- RFC 3164, https://www.rfc-editor.org/rfc/rfc3164 : PRI, `Mmm dd hh:mm:ss` timestamp without year, hostname, TAG up to
  32 alphanumerics, 1024-byte limit, receivers must tolerate malformed input and default a missing PRI to 13.
- RFC 6587, https://www.rfc-editor.org/rfc/rfc6587 : octet-counting (`LEN SP MSG`, leading digit) vs non-transparent
  framing (trailer, usually LF, first char `<`), legacy senders mixing the two, no security in plain TCP syslog, RFC 5425 for TLS.
- nginx `ngx_http_log_module`, https://nginx.org/en/docs/http/ngx_http_log_module.html : predefined `combined` format
  and the `syslog:` prefix for `access_log`.
- Apache httpd logs, https://httpd.apache.org/docs/2.4/logs.html : Common and Combined Log Format field layout.
- Palo Alto PAN-OS traffic log fields, https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields :
  comma-separated field order (reserved, receive time, serial, type, subtype, reserved, generated time, source,
  destination, NAT addresses, rule, users, application, vsys, zones, interfaces, log action, session id, repeat
  count, ports, NAT ports, flags, protocol, action). The page summary gave order, not numeric indexes.
- Cisco ASA syslog 101001-199021, https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-101001-to-199021.html :
  106100 template (ACL id, protocol, source interface/address/port, `->`, destination, hit count) and 106023 beginning with "Deny".
  Only the first part of the page was read.
- Filebeat syslog input, https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-syslog : confirms UDP/TCP/Unix inputs,
  rfc3164/rfc5424/auto formats, delimiter vs rfc6587 framing, max message size and connection caps, TLS option. Used as design comparison.
- IBM QRadar LEEF overview, https://www.ibm.com/docs/en/dsm?topic=leef-overview : only confirms LEEF is QRadar's event format
  sent over syslog, UTF-8. No field details (see unverified).
- Wazuh data collection index, https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html : only
  confirms the server can receive logs via syslog. No syslog configuration details were readable.

## UNVERIFIED (not read from a source; written from general knowledge, covered only by my own golden tests)

- CEF format (ArcSight spec fetch returned HTTP 403): header `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`,
  `|` and `\` escaped in header, `=` and `\` in extension, space-separated `key=value`, and the keys `src dst dpt act suser outcome requestdns`.
  The key set is partly cross-checked by the repo's own CEF writer in `siem_export.go`.
- LEEF 1.0 tab delimiter, LEEF 2.0 delimiter field (single char or `xHH`), and the attribute names `usrName dstPort dstName`; IBM pages read did not contain them.
- OpenSSH, sudo, Linux-PAM and auditd message texts (no vendor page opened). Regexes cover `Accepted|Failed <method> for [invalid user] U from IP port N`,
  `Invalid user U from IP`, `U : TTY=.. ; PWD=.. ; USER=.. ; COMMAND=..`, `U : N incorrect password attempts`, `pam_unix(svc:auth): authentication failure; ... rhost= user=`.
  auditd is not parsed.
- Fortinet FortiGate field names `srcip dstip dstport action qname qtype` (page fetch returned only navigation or 404).
- Cisco ASA 106023 and 302013 exact text (only 106100 template was read) and the PAN-OS numeric field positions used in code.
- dnsmasq `query[A] name from ip`.
- RFC 3339 timestamps in otherwise RFC 3164 lines (rsyslog style) are accepted as a de-facto extension.
- Windows event forwarding as syslog: not researched, not parsed.
- Shutdown (corrected): earlier versions of this page said the `kavach` binary had no graceful-shutdown hook. It now
  has one: on SIGINT or SIGTERM the server marks `/readyz` as 503, drains HTTP, then calls the lifecycle registry, in which
  the syslog listener is registered as stopper `syslog` (`StopSyslog()` closes the sockets and waits for goroutines).
  Confirmed in `cmd/kavach/main.go` and `internal/edr/syslog_listener.go`; a live shutdown was not exercised in this pass.
