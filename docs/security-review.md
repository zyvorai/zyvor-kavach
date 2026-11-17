# Kavach security review

Pre-release review of Kavach itself (the observation-only platform), done as a
defender would review a product before shipping. Findings are proven with tests
that stay in the tree, so regressions fail CI.

## Scope

In scope: `cmd/kavach` (server), `internal/edr` (API, stores, ingest,
analyzers, importers, opt-in network features), the session/token model, HTTP
headers, TLS defaults, request-size and memory bounds, and panics on malformed
input.

Not in scope (see "Not reviewed"): the dashboard front end
(`internal/edr/dashboard.html`, reviewed separately), `kavachctl`/`kavach-mcp`
clients beyond TLS flags, Helm/k8s manifests, build and release pipeline, the
eBPF sensor, and third-party dependency CVEs.

## Method

1. Read the auth helpers (`authz.go`, `dashboard.go`, `enrollment.go`) and every
   place a token is compared.
2. Enumerated every registered route with the same extractor the OpenAPI
   coverage test uses, then probed the live handler tree (not the source text)
   with: no credentials, a wrong bearer, a forged/expired/foreign-key session
   cookie and a valid per-host agent credential.
3. Streamed oversized bodies into every write route and counted bytes consumed.
4. Sent malformed-but-authenticated JSON (`null`, `[]`, wrong types, binary) to
   every route and recovered panics.
5. Grepped every outbound-network, file-write, regex-compile, zip/tar and
   `append`-to-global site and read each.
6. Added fuzz targets and ran each for 12 s.

Tests added (all in `internal/edr`):

| File | What it proves |
| --- | --- |
| `security_routes_test.go` | Route walk: every non-public route returns 401/403 without credentials or with a bad bearer; ingest routes reject unauthenticated well-formed payloads; agent credentials and forged/expired/foreign-signed cookies never open any other route. Explicit allowlists (`publicRoutes`, `ingestRoutes`) with reasons; stale entries fail. |
| `security_body_test.go` | Every write route stops reading an authenticated body at or below ~40 MiB (streams 96 MiB). |
| `security_panic_test.go` | No route panics on 12 malformed bodies. |
| `security_headers_test.go` | Security headers, `Cache-Control: no-store` on API, login throttle survives `KAVACH_RATE_LIMIT=0`, per-IP bad-bearer throttle, empty token fails closed, cookie flags. |
| `security_misc_test.go` | URL/domain/email/config/script inspectors make zero outbound requests; admin token never appears in any GET response; metrics label set is bounded; IOA regex validation; RE2 linear time; per-host map bound. |
| `security_fuzz_test.go` | Fuzz targets: inspect text kinds, inspect file bytes, event ingest, telemetry validate, hunt query parser, lab rule parser, byte-pack parser, syslog parser, Sigma converter. Existing evidence-parser fuzzers retained. |

Fuzz result: 9 new targets, 12 s each, no crashers.

## Re-run it

The tests added by the review stay in CI. To repeat the checks locally:

```bash
go test ./internal/edr -count=1 -run 'EveryRouteRequiresAuth|IngestRoutesReject|AgentCredentialAndForged|WriteRoutesCap|RoutesDoNotPanic|HardenHeaders|LoginThrottle|BadBearer|EmptyToken|SessionCookie|InspectorsNeverFetch|AdminTokenNever|MetricsCardinality|IOAPattern|UserRegexIsLinear|FileDetectionsHostMap'
go test -race -timeout 30m ./...
go test ./internal/edr -run '^$' -fuzz FuzzParseSyslog -fuzztime 12s    # one of the nine targets
```

The route walk (`security_routes_test.go`) enumerates routes from the source, so routes added after the review
(for example the exposure, cloud-audit and syslog routes) are covered by the same "401 without credentials" and
"agent credential opens nothing else" checks. The behaviours below were read from the code at the current commit,
not re-proven by new tests.

## Findings

Severity is the impact on a deployed controller, assuming the attacker position
named in the evidence column.

| # | Finding | Severity | Status | Evidence |
| --- | --- | --- | --- | --- |
| 1 | `POST /v1/bas` panics on a `null`/invalid body (nil map write); six sibling world-platform handlers panic on a literal `null` body. net/http recovers, but it is an unhandled-input crash path and logs stack traces. | Medium (authenticated) | Fixed | `TestRoutesDoNotPanicOnMalformedBodies` failed before the fix (`world_platform.go`, `hunt_cases_audit.go`). |
| 2 | `POST /v1/ebpf/events`, `/v1/ebpf/features/{id}`, `/v1/finance/events`, `/v1/sectors/events` decoded JSON with no body cap (an authenticated client could stream an unbounded body into memory). | Medium (authenticated) | Fixed (4 MiB / 4 KiB caps) | `TestWriteRoutesCapRequestBody` listed all four at 96 MiB read. |
| 3 | Metrics middleware labelled requests by raw path (first 3 segments) and raw method. Unauthenticated probes of random paths/methods grew the label map without bound (memory DoS, and `|` in a method corrupted keys). | High (unauthenticated) | Fixed: label is the registered mux pattern, method restricted to a known set. | `TestMetricsCardinalityBounded`. |
| 4 | An empty server token (library embedders; the CLI already requires 8+ chars) made an empty `Authorization` header authenticate and made the session HMAC key empty and forgeable. Several handlers compared with raw `subtle.ConstantTimeCompare` which accepts empty==empty. | High (embedder misconfiguration) | Fixed: all token compares use `secureEqual` (rejects empty secret); `validSession` rejects an empty secret; login rejects empty. | `TestEmptyTokenFailsClosed`. |
| 5 | Login throttling was disabled entirely by `KAVACH_RATE_LIMIT=0`; PUT/PATCH were never write-limited; no throttle on token guessing against Bearer routes (only `/v1/session` was limited). | Medium | Fixed: login limiter always on; PUT/PATCH limited; per-IP failed-auth throttle (burst 20, then 1 per 5 s) on every route, login excluded because it has its own limiter. | `TestLoginThrottleSurvivesRateLimitOff`, `TestRepeatedBadBearerIsThrottledPerIP`. |
| 6 | API responses lacked `Cache-Control: no-store`. | Low | Fixed for `/v1/*` and `/metrics`. | `TestHardenHeadersAndNoStore`. |
| 7 | HTTP server had only `ReadHeaderTimeout`: slow-body clients could hold connections open indefinitely; no header size limit. | Medium | Fixed: `ReadTimeout` 2 min (largest upload is 32 MiB), `IdleTimeout` 2 min, `MaxHeaderBytes` 64 KiB. No `WriteTimeout` because `/v1/stream` is SSE. | `cmd/kavach/main.go`. |
| 8 | IOA (`POST /v1/ioa`) accepted any pattern up to 8 KiB without validating it; every rule was recompiled for every ingested event while holding a global lock; no rule-count cap. Invalid rules silently never matched. | Medium (authenticated; RE2 is linear-time so no ReDoS, but compile cost and memory are not) | Fixed: patterns validated and capped at 512 bytes, compiled once and cached, 500 rules max; 20 000 IOC max. | `TestIOAPatternValidatedAndBounded`, `TestUserRegexIsLinearTime`. |
| 9 | Unbounded in-memory ledgers fed by POST bodies: watchlists, exclusions, custom rules, forensics requests, ITSM tickets, BAS runs, RBAC roles, AI memory keys, cases, per-host file-burst map (host names are untrusted). | Medium (authenticated) | Fixed: 1000-entry tail caps (RBAC roles and cases refuse growth so built-in roles are never evicted), 256 AI memory keys, 10 000 cases, 5 000 hosts in the file detector. | `TestFileDetectionsHostMapBounded`; code in `world_platform.go`, `authz.go`, `cases.go`, `file_events.go`, `ai_platform.go`. |
| 10 | Weak token accepted: minimum length 8. | Low | Mitigated: startup warning under 16 chars; length floor left at 8 to avoid breaking deployments. Recommend a random 32+ character secret. | `cmd/kavach/main.go`. |
| 11 | Netra poller opt-in `InsecureSkipVerify` TLS client had no explicit minimum version. | Low | Fixed (`MinVersion` TLS 1.2). The opt-in itself is accepted as a lab feature. | `netra_poller.go`. |

### Reviewed and found sound (no change)

- Auth on every route: 0 unauthenticated data routes. Public set is exactly
  `/healthz`, `/livez`, `/readyz`, `/`, two static SVGs, `POST /v1/session`,
  `POST /v1/logout`, and the deception canary beacon `GET|POST /c/{id}` (public by
  design, per-IP and global rate limited, never reflects input). Agent ingest
  routes authenticate a per-host credential bound to the event's host.
- Per-host agent credentials are SHA-256 hashed at rest, compared in constant
  time, host-scoped, revocable, and cannot call any non-ingest route.
- Constant-time comparison: all token, cookie-signature and credential
  comparisons use `crypto/subtle`.
- Session cookie: HttpOnly, SameSite=Strict, Path=/, 1 h expiry, HMAC-signed
  with timestamp, `Secure` when the server terminates TLS.
- Path traversal / file writes: every write path is a fixed store path derived
  from the `--state` flag, written 0600 via temp file + rename. No request
  field reaches a filesystem path. The evidence importer parses uploads in
  memory (per-artefact, count and total caps, 32 MiB). Archive analysis reads
  zip/tar entries in memory with size and ratio limits; nothing is extracted, so
  zip-slip has no sink. There is no server-side bundle zip writer.
- SSRF: vuln, CERT and EPSS feeds use fixed https URLs with a host allowlist
  checked again on every redirect; intel-feed and webhook clients use a dial
  guard that re-resolves and refuses private/loopback/link-local addresses
  (anti DNS rebinding) and refuses redirects. SIEM webhook/syslog targets come from
  operator environment variables, not request data. The URL, domain and email
  inspectors never fetch (proved by test).
- ReDoS: Go `regexp` is RE2 (linear time). User regex sites (lab rules, hunt
  queries, config rules, IOA) have length caps (IOA added here).
- Models/posture memory: per-host, per-user and per-domain maps have explicit
  caps (`mlMaxHosts`, `mlExtMaxHosts`, `mlExtMaxUsers`, `mlDNSMaxRegs`,
  `maxPostureAssets`, auth-burst key cap with eviction).
- Error messages: handlers return fixed strings ("storage error", "bad json");
  validation errors echo only parser/validator text.
- TLS: server `MinVersion` TLS 1.2, optional mTLS (`RequireAndVerifyClientCert`),
  non-loopback listeners refuse to start without TLS, agent client never sets
  `InsecureSkipVerify`.
- Headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, CSP with `frame-ancestors 'none'` and
  `base-uri 'none'`. No CORS headers are emitted (same-origin only).
- Secrets: the admin token is never in any GET body or header (test). Agent
  tokens are returned once at enrolment with `Cache-Control: no-store`. Logs
  contain error values and static text only.

## Additions since the review (read from the code, not separately reviewed)

| Area | Auth and bounds | Note |
| --- | --- | --- |
| Software exposure (`/v1/exposure/*`, [exposure.md](exposure.md)) | Reads need a token or session; SBOM upload, advisory import and deletes need the admin token (a session is refused with 403). 8 MiB bodies, 20,000 components per SBOM, 2,000 hosts, 50,000 advisories | Offline; no network request. Only name, version, purl and type are retained |
| Cloud audit ingest (`POST /v1/cloud/audit/events`, [cloud-audit.md](cloud-audit.md)) | Admin token only (agent credentials and sessions refused). 4 MiB body, 1,000 records per request (413), 2 s evaluation budget | Reads records you send; never calls a cloud API |
| Syslog listener ([syslog-listener.md](syslog-listener.md)) | Off by default; explicit `proto:host:port` binds; mandatory source allowlist; `POST /v1/syslog/parse` is admin or session and never ingests | Plaintext syslog is unauthenticated and spoofable by nature. Host names are namespaced `syslog:<name>` |
| Parse-only inspectors (URL, e-mail extras, .NET, OneNote, packages) | Same 32 MiB inspect bound as other kinds | `TestURLNeverFetches` and `TestInspectorsNeverFetch` prove no outbound request |
| SIEM push sink (`KAVACH_SIEM_*`, `internal/edr/siem.go`) | Operator environment only, never request data | The webhook client has a 5 s timeout but does not use the SSRF dial guard of alert rules, has no retry and no signature; point it only at trusted receivers |
| Console login | `POST /v1/session` takes `{"token": ...}`; the form's username `admin` is cosmetic (the password is the token) | One shared token; see accepted risks |

## Known gaps found while documenting (items 1-3 and the token fallback now fixed)

These came out of a documentation pass that compared docs to code. They are observations, not new test-proven findings.

1. **Fixed:** mTLS `optional` is now real. `-client-auth optional` uses `VerifyClientCertIfGiven`; the chart passes it for `mtls.mode=optional` and `require` for `required`. Tests: `TestServerTLSConfigModes`. See [agent-mtls.md](agent-mtls.md). Not tried on a live cluster.
2. **Fixed:** a corrupt `<store>.incidents` file is moved aside to `.corrupt-<unixtime>` and the ledger starts empty (`TestIncidentLedgerCorruptMovedAside`). The credential registry stays fail-closed on invalid JSON, now with a clear error instead of a bare JSON error (`TestCredentialRegistryCorruptFailsClosedClearly`); see [persistence-files.md](persistence-files.md).
3. **Fixed:** the chart no longer sets `KAVACH_TLS_INSECURE` for agents and `tls.agentInsecureSkipVerify` was removed. The agent never skips verification (the safer option); use `-ca` / `mtls.secretName`.
4. **`KAVACH_SIEM_FORMAT` is cosmetic:** the push payload is always ECS-flavoured JSON.
5. **`deploy-remote.sh`** logs the admin token at the end of a run and its random-token fallback is unreachable
   (`${KAVACH_ADMIN_TOKEN:-Admin@321}`), so the lab default is used whenever the variable is empty ([deploy-remote.md](deploy-remote.md)).
   (`kavachctl` now accepts `KAVACH_ADMIN_TOKEN` as the lowest-precedence token fallback, so the `~/.kavach/env` the script writes works.)

## Accepted risks

| Risk | Rationale |
| --- | --- |
| Single shared admin token; a session cookie is equivalent to it. `KAVACH_RBAC` roles (selected by `X-Kavach-Role`) are advisory restrictions for the token holder, not an authorisation boundary. | By design for this release; there is no lower-privilege credential to escalate from. Multi-user auth is future work. |
| Sessions are stateless (HMAC, 1 h); logout clears the cookie but a stolen cookie stays valid until expiry. Rotating the token invalidates all sessions. | Stateless design; short lifetime. |
| Rate limiting keys on `RemoteAddr`. Behind a reverse proxy all clients share one bucket; `X-Forwarded-For` is deliberately not trusted. | Avoids spoofable limits; deploy limits at the proxy as well. |
| Per-IP limiter maps reset when they pass 10 000 keys. | Bounded memory over perfect accounting. |
| Cookie `Secure` is set from `r.TLS`; a TLS-terminating proxy in front of a loopback listener yields a non-Secure cookie. | The server refuses plaintext on non-loopback; terminate TLS at a trusted local proxy only. |
| Findings JSONL (`--state`) is append-only and not rotated, so disk grows with ingest volume. | Operational concern; rotate externally. |
| Opt-in lab switches: `KAVACH_NETRA_TLS_INSECURE`, `kavachctl`/`kavach-mcp` `KAVACH_TLS_INSECURE` (auto on loopback). | Explicit operator opt-in, documented as lab-only. |
| Telemetry/file ingest authenticates after body decode, so unauthenticated callers can make the server parse up to the per-route body cap (16 KiB to a few MiB) before a 401. | Bounded work; moving auth earlier requires reading the host from the body for per-host credentials. The failed-auth throttle now applies. |
| Inspect endpoints read up to 32 MiB into memory for authenticated callers. | Authenticated, rate limited, and analyzers have their own budgets. |

## Open items

None rated Medium or above. Suggested follow-ups: server-side session
revocation list, per-user tokens with real RBAC, trusted-proxy aware client IP,
log rotation for the findings file.

## Not reviewed
- Everything listed under "Additions since the review" as an independent security review (only auth and bounds were read).

- `internal/edr/dashboard.html` (front end XSS, DOM sinks, CSP interaction) was
  explicitly out of scope for this pass.
- Helm charts, container images, k8s RBAC/NetworkPolicy, and the deployed demo
  hosts (no network testing was done; everything ran against `httptest`).
- Build/release pipeline, signing, dependency CVE scan (`govulncheck`).
- eBPF sensor and its kernel-side verifier surface; Windows/macOS agents.
- Cryptographic review of the HMAC session design beyond the checks above.
- Long-duration fuzzing (each target ran 12 s only) and the evidence-parser
  fuzzers beyond their existing seeds.
- `kavachctl`, `kavach-mcp` and `netra-bridge` beyond their TLS and token
  handling flags.
- Full audit of every package-level slice for growth: the POST-fed ledgers were
  checked and capped; internal-only slices (derived from bounded stores) were
  sampled, not exhaustively proved.
