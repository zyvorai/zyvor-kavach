# Security configuration assessment (inspector kind `config`)

Competitor backlog item 23 (Wazuh SCA, Fleet CIS policies; Defender and Falcon document configuration assessment). Kavach has no configuration-collection channel and stays observation-only, so this works on configuration text an analyst submits: `POST /v1/inspect/config` (raw text or `{"text","name"}`), same size limits and auth as the other inspector kinds. The text is parsed only: never executed, never included or fetched, never stored (only the report and sha256 are kept in the capped ring). Remediation text is advice; nothing is applied.

## How it works

1. `SniffConfigFormat(name, text)` picks a format from the client label (for example `sshd_config`, `Dockerfile`, `*.tf`) and then from content. Unrecognised input yields one info finding `cfg-unrecognized-format`.
2. A hand-written, stdlib-only parser turns the file into flat `(key, value, line)` settings. YAML formats (Kubernetes, docker-compose) reuse the existing safe YAML-subset parser from the Sigma importer (`miniYAMLParse` in `content_sigma.go`); multi-document `---` streams are split first.
3. Each policy for that format is evaluated: `pass`, `fail`, `not_applicable` or `unknown`.
4. Findings use ids `cfg-<policy>` (weight 0: a configuration gap is not a malware signal, so the inspector's score/level is not meaningful for this kind). Full results, counts and the compliance percentage are in report meta `config-assess.summary`.

Formats: sshd_config, sysctl.conf, login.defs, sudoers, auditd rules, PAM stacks, nginx, Apache httpd, Kubernetes manifests, Dockerfile, docker-compose, Terraform HCL, and (added later) F5 BIG-IP tmsh configuration (`bigip`), Terraform plan JSON (`tfplan`) and CloudFormation templates (`cfn`). The three newer formats are described in [appliance-config-review.md](appliance-config-review.md) and [iac-exposure.md](iac-exposure.md); they use the same policy files, loader and self-tests.

Parser depth (honest limits): sshd/sysctl/login.defs/sudoers/auditd/PAM/nginx/Apache are real line or statement parsers. Kubernetes and compose use the YAML subset (block maps and sequences, flow lists, quoted scalars; anchors, flow maps such as `{}` and other YAML features are rejected and reported as a parse note). Terraform is parsed at line level only: blocks, attributes and multi-line values are tracked, but variables, modules, `for_each`, expressions and interpolation are not evaluated, and a few correlations (ingress port with CIDR) are approximated by a per-block summary string. Includes (`Include`, `@includedir`, `@include`) are noted, never followed. sshd `Match` blocks are kept apart from the global settings.

## Policy format

Policies are embedded JSON in `internal/edr/configpolicies/*.json` (original wording; no benchmark text or numbering was copied). Fields: `id`, `title`, `description`, `rationale`, `severity` (low|medium|high|critical), `applies_to.formats` (+ informational `hints`), optional `applies_when` (precondition; unmet means `not_applicable`), `check`, `on_absent`, `absence_note`, `remediation`, `references`, optional `frameworks`, and `positive`/`negative` samples (plus `more_samples` for multi-format policies).

`check` is the PASS condition: a leaf (`key` or `key_regex`, `op`, `value`/`values`, optional `occ`) or `all` / `any` / `not`. Ops: `equals`, `not_equals`, `in`, `not_in`, `regex`, `not_regex`, `present`, `absent`, `lt`, `le`, `gt`, `ge`. `occ` says which occurrence of a repeated key counts (`all`, `any`, `first`, `last`); the default follows the format (sshd first, sysctl/login.defs last, others all). Regexes are Go RE2 (linear time) and capped at 256 characters at load.

Absence: `on_absent` states what a setting that is not in the file means: `fail` (the default applies and is unsafe), `pass` (the default is safe), `unknown` (the default is distribution or kernel specific, or lives in a file we cannot see), or `evaluate` (the check itself handles presence). The reason is written in `absence_note` on every policy. sysctl policies are `unknown` when absent on purpose: a sysctl file rarely lists every key and the running value cannot be known from it.

Known evaluation limits: a repeated key must satisfy `all` occurrences by default; a leaf over a key that does not exist is false (use `not`/`absent` or `on_absent` for "no bad value"). Kubernetes per-container gaps are detected through synthetic `container.unset.*` markers. Kubernetes and compose results carry no line numbers.

## Using it

```sh
kavachctl inspect config /etc/ssh/sshd_config          # parse-only; prints findings cfg-<policy> and the summary
kavachctl inspect config Dockerfile --json
curl -H "Authorization: Bearer $KAVACH_TOKEN" -X POST localhost:8080/v1/inspect/config \
  -d '{"name":"sshd_config","text":"PermitRootLogin yes\nPasswordAuthentication yes\n"}'
```

The `name` helps format sniffing (`sshd_config`, `Dockerfile`, `*.tf`, `docker-compose.yml`); without it the content is sniffed. Read `config-assess.summary` in the report meta: `counts`, `compliance_pct`, per-policy `results`. Severity mix of the 186 shipped policies (counted from the files on 2026-11-23): 8 critical, 60 high, 68 medium, 50 low.

A second analyzer, `config-extra` (`inspect_config_extra.go`), runs on the same kind and adds regex-based checks for CI pipeline YAML (GitHub Actions, GitLab CI) plus a few Kubernetes and Dockerfile checks outside the 150 policies. It is text matching, not YAML evaluation: anchors, includes, templates, matrix expansion and reusable workflows are not resolved, so it can miss or over-match. Its findings also carry weight 0 and the report is not scored.

## Authoring a policy (worked example)

Policies live in `internal/edr/configpolicies/<area>.json` as `{"area": "...", "policies": [ ... ]}` (any `*.json` there is embedded). This example was run through the policy validator and the policy self-test while writing this page; it is illustrative and is not shipped. The default value in `absence_note` is from general knowledge and is unverified: check the vendor documentation and fill `absence_source` and `default_verified_on` when you do.

```json
{ "id": "ssh-max-sessions-example",
  "title": "SSH daemon allows many multiplexed sessions per connection",
  "description": "Checks that MaxSessions is not raised above 10.",
  "rationale": "A high session limit makes one authenticated connection a larger pivot point.",
  "severity": "low",
  "applies_to": { "formats": ["sshd"] },
  "check": { "key": "maxsessions", "op": "le", "value": "10" },
  "on_absent": "pass",
  "absence_note": "Default is 10 (unverified for every version).",
  "remediation": "Set MaxSessions to 10 or lower.",
  "references": ["OpenSSH sshd_config(5) manual page (public)"],
  "positive": "MaxSessions 50\n",
  "negative": "MaxSessions 4\n" }
```

1. `check` is the PASS condition. `positive` must make it fail and `negative` must make it pass; `cfgSelfTest` enforces both.
2. Decide `on_absent` deliberately (`fail`, `pass`, `unknown` or `evaluate`) and write the reason in `absence_note`; the loader rejects a policy without remediation or an absence note.
3. Keep regexes under 256 characters. Reference public documentation, never copy benchmark text or numbering.
4. Run `go test ./internal/edr/ -run 'TestConfig|Inspect.*Config' -v`, then `go test ./internal/edr/ -run 'Docs|OpenAPI|Content|Lab'` if you also touched docs. Update the counts table below by recounting the files; the table was recounted on 2026-11-16 and totals 150 policies across 12 files (`audit` 13, `compose` 12, `dockerfile` 14, `kubernetes` 24, `login` 6, `pam` 6, `permissions` 2, `ssh` 17, `sudo` 10, `sysctl` 16, `terraform` 15, `web` 15); recounted on 2026-11-23 after adding `bigip` 12, `iac` 17 and `web2` 7 (nginx extras), 186 policies across 15 files.
5. Add a hardened and a stock sample to `inspect_config_benign_test.go` when the policy could plausibly fail on a normal file, so a false fail is caught by the test rather than by a user.

## Honest limits (summary)

* Policies are Kavach's own wording and thresholds; 19 of the 150 still carry an UNVERIFIED marker (counted by searching the policy JSON; the section below attributes them to Kubernetes references), and none is a certified benchmark. A passing score is not a compliance attestation.
* The percentage covers one submitted file. Drop-ins, includes, runtime state and distribution defaults can differ, so a 100% file can sit on a weaker system.
* There is no collector: Kavach never reads configuration from a host, so someone has to submit the text, and a stale submission is judged as written.

## Counts

| Area | Policies | Formats |
|---|---|---|
| SSH daemon | 17 | sshd |
| sysctl / kernel and networking | 16 | sysctl |
| login.defs | 6 | logindefs |
| PAM | 6 | pam |
| sudo | 10 | sudoers |
| auditd | 13 | auditd |
| file-permission directives | 2 | dockerfile, k8s (plus the login.defs UMASK policy in the login area) |
| nginx / Apache (TLS, headers, hardening) | 15 | nginx (10), apache (9); 4 policies cover both |
| Kubernetes workloads and RBAC | 24 | k8s |
| Dockerfile | 14 | dockerfile |
| docker-compose | 12 | compose |
| Terraform | 15 | terraform |
| F5 BIG-IP | 12 | bigip |
| Terraform plan / CloudFormation | 17 | tfplan (all 17) and cfn (14 of them) |
| nginx extras | 7 | nginx |
| Total | 186 | |

## Report

`config-assess.summary` contains `counts` (pass, fail, not_applicable, unknown), `compliance_pct` = pass / (pass + fail), the per-policy `results` (status, reason, evidence with secrets redacted, remediation, absence note), parse notes and a note stating that the percentage covers only the submitted file and only the policies that apply to its format. Unknown and not_applicable are excluded from the percentage. A file can score 100 percent while the running system differs (drop-ins, includes, distribution defaults, runtime overrides).

## Tests

`inspect_config_test.go` validates the loader (unique ids, severity, remediation and absence note present, no regex over 256 chars, every policy's positive sample fails and negative sample passes), absence semantics, the sniffer, the HTTP route for the new kind, redaction and parser totality on hostile input. `inspect_config_benign_test.go` runs typical hardened and typical stock configurations: hardened files must have zero failures and stock files may fail only on listed, explainable gaps. It caught one real false-fail during development (a `*_PASSWORD_FILE` path was treated as a literal secret); that is now a regression test.

## Sources actually opened (public pages, summaries in my own words)

Only these pages were opened during the original research. Items verified later are listed under "Verification pass 2026-11-16" below; everything else was written from general knowledge and is marked UNVERIFIED.

1. https://kubernetes.io/docs/concepts/security/pod-security-standards/ - Pod Security Standards. The Baseline level forbids sharing host network/PID/IPC namespaces, privileged containers, `hostPath` volumes, and an Unconfined seccomp profile, and allows only a short list of added Linux capabilities. Only the first 100000 of 112422 characters were read and the Restricted section was not in that text. Verified on 2026-11-16 by reading the full page: the Restricted items used here (runAsNonRoot true, allowPrivilegeEscalation false, drop ALL capabilities with only NET_BIND_SERVICE allowed back, seccomp profile explicitly set) are in the Restricted standard.
2. https://man.openbsd.org/sshd_config - OpenSSH sshd_config manual. Used for the defaults and meanings of PermitRootLogin (default prohibit-password), PasswordAuthentication (yes), PermitEmptyPasswords (no), X11Forwarding (no), MaxAuthTries (6), LogLevel (INFO), ClientAliveInterval (0 = never probes), ClientAliveCountMax (3), AllowTcpForwarding (yes), HostbasedAuthentication (no), PermitUserEnvironment (no, can bypass restrictions via LD_PRELOAD), and the cipher/MAC defaults. The page does not mention a `Protocol` keyword.
3. https://docs.docker.com/engine/security/ - Docker Engine security. Containers get a reduced capability set by default; recommended practice is to drop everything and add back only what is needed; the daemon is root-equivalent so only trusted users should control it; the API should use a Unix socket or HTTPS; user namespaces are available but off by default.
4. https://docs.docker.com/build/building/best-practices/ - Dockerfile best practices. Run as a non-root `USER` with explicit UID/GID; tags are mutable and digests pin an image (at the cost of manual updates, with update bots as the remedy); prefer `COPY` over `ADD` except for remote fetches with `--checksum`; `ENV` values persist in image layers; combine `apt-get update` and `install`.
5. https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html - Wazuh SCA. A policy is YAML made of checks; each check has a description, rationale, remediation and optional compliance mappings, and rules over files, directories or commands with regex matching and a condition; results are passed, failed or not applicable (with a reason). This shaped the status model and the policy field list (the declarative check format here is original).
6. https://www.open-scap.org/features/standards/ - OpenSCAP. Confirmed only that SCAP is a set of specifications for automated configuration, vulnerability and compliance checking whose components work together. The page does not describe rule/check/profile structure.
7. https://www.cisecurity.org/cis-benchmarks - CIS Benchmarks landing page. Confirmed only that they are consensus secure-configuration guides for many product families. Profile levels were not described on the fetched text. The benchmark documents themselves were not opened and nothing from them (text, numbering) is used.

Tried and not read: the NSA/CISA Kubernetes Hardening Guidance PDF (HTTP 403 again on 2026-11-16). A search-result excerpt of it confirms the topics of non-root containers, immutable file systems, resource limits (LimitRange/ResourceQuota) and disabling automatic service account token mounting, so the references of k8s-run-as-non-root, k8s-read-only-rootfs, k8s-memory-limit, k8s-cpu-limit and k8s-sa-token say so. The other Kubernetes policies keep an explicit UNVERIFIED marker on that reference, and no claim depends on it.

## Verification pass 2026-11-16

The defaults behind every `absence_note` that was marked UNVERIFIED were checked against vendor documentation and are now recorded per policy in `absence_source` and `default_verified_on` (optional fields; empty means unverified). Results are in `verification-log.md`: sshd IgnoreRhosts yes, LoginGraceTime 120 s, StrictModes yes, no SHA-1 in the default KexAlgorithms, no Protocol keyword (OpenBSD sshd_config manual); sudo env_reset on, use_pty on only from 1.9.14, timestamp_timeout 5 minutes (sudoers manual); login.defs PASS_MIN_DAYS 0 and UMASK 022 when unset (man7 login.defs(5)); Apache ServerTokens Full, TraceEnable on, Options FollowSymlinks, SSLProtocol default `all -SSLv3` (since 2.4.17) where `all` still includes TLSv1 and TLSv1.1 (httpd docs); Azure storage account defaults in the current azurerm provider docs (allow_nested_items_to_be_public false, https_traffic_only_enabled true, min_tls_version TLS1_2 for new accounts).

## UNVERIFIED parts

- All sysctl, login.defs, PAM, sudoers, auditd, nginx, Apache and Terraform checks and their thresholds come from general practitioner knowledge, not from a page opened in this research. The numeric thresholds (MaxAuthTries 4, grace time 60 s, password max age 365 days, HSTS six months and similar) are this project's own choices, stated as such in the policy text, not quotes from any benchmark.
- The previously UNVERIFIED defaults in `absence_note` fields were all checked on 2026-11-16 (see above); they hold for current releases only and older versions were not checked. 19 of the 24 Kubernetes policies still carry an UNVERIFIED NSA/CISA reference.
- `frameworks` hints (NIST SP 800-53 CM-6 on every policy, a few ATT&CK technique ids) are labelled hints; the mappings were not checked against the NIST or MITRE pages.
- Competitor details above come from the single Wazuh page; nothing was verified about how Defender or Falcon implement configuration assessment beyond the existing matrix.
