# Identity-provider log analytics (Okta and Microsoft Entra)

Offline analytics over sign-in and audit logs exported from an identity provider. Kavach is observation only: it detects and reports. It never calls Okta, Entra or any other provider, never looks an address up, and never locks, resets, revokes or blocks anything. You export the logs; Kavach reads them. Research and sources: [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md). Related: generic authentication logs in [web-detection.md](web-detection.md) (`/v1/auth/logs`, `auth-an-*`) and cloud audit rules in [cloud-audit.md](cloud-audit.md).

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `POST /v1/idp/logs?host=&dormant_days=` | admin token | analyse an export; stores findings, returns a report |
| `GET /v1/idp/sources` | any authenticated | providers, rule ids with technique and severity, limits |

CLI: `kavachctl idplog analyze FILE [--host NAME] [--dormant-days N] [--json]`, `kavachctl idplog sources`.

The body is a JSON array, a wrapper object (`events`, `records`, `logs`, `items`, `entries`, `value`), one object, or JSON lines. Limits: 8 MiB body, 50,000 records (413 above), 64 KiB per JSON line, fixed caps of 25 findings per rule per request. Records that are not objects, have no parseable time, or name no user are counted as `rejected` with up to five sample errors. `host` labels findings `idp:<name>` (default `idp:logs`).

```bash
kavachctl idplog analyze okta-system-log.jsonl --host okta-prod
curl -s -X POST -H "Authorization: Bearer $KAVACH_TOKEN" --data-binary @entra-signins.json "$KAVACH_URL/v1/idp/logs?dormant_days=120"
```

## What is read

Only an allow-list of fields is read. Tokens, passwords, cookies and every other field are never read or stored, and any text that reaches a finding is sanitised and truncated.

| Provider | Detected by | Fields read |
|---|---|---|
| Okta System Log | an `eventType` field | `eventType`, `published`, `actor.alternateId`, `outcome.result`, `client.ipAddress`, `client.device`, `client.userAgent.rawUserAgent`, `client.geographicalContext.country` and `.geolocation.lat/lon`, `authenticationContext.externalSessionId`, `target[].type/alternateId/displayName`, `debugContext.debugData.privilegeGranted`, `severity` |
| Entra audit | an `activityDisplayName` field | `activityDateTime`, `activityDisplayName`, `result`, `initiatedBy.user.userPrincipalName/ipAddress` or `initiatedBy.app.displayName`, `targetResources[].type/userPrincipalName/displayName`, `modifiedProperties` (state values and role name only) |
| Entra sign-in | a `userPrincipalName` field | `createdDateTime`, `userPrincipalName`, `ipAddress`, `status.errorCode`, `clientAppUsed`, `appDisplayName`, `deviceDetail`, `location.countryOrRegion` and `geoCoordinates`, `riskLevelDuringSignIn`, `riskLevelAggregated`, `riskState`, `sessionId` |
| generic | neither of the above | `user`, `username`, `email`, `outcome`, `result`, `ip`, time fields |

Events are classified: sign-in, MFA denied or prompt, MFA enrolled, MFA removed or reset, role grant, password reset, authentication-policy change, application credential or consent, provider risk. Okta classes use event types such as `user.mfa.okta_verify.deny_push`, `system.push.send_factor_verify_push`, `user.mfa.factor.activate`, `user.mfa.factor.reset_all`, `user.account.privilege.grant`, `user.account.reset_password`, `policy.rule.deactivate`, `system.api_token.create` and `*consent.grant`. Entra audit classes use substrings of the activity name ("member to role", "registered security info", "deleted security info", "reset password", "delete conditional access policy", "service principal credentials", "consent to application"). Entra error code 500121 counts as an MFA denial. The field and event names were verified against provider documentation except where [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md) marks them unverified.

## Rules

Findings use `idp-an-*` rule ids, ATT&CK mappings and the usual guidance (`GET /v1/guidance`). All thresholds are fixed heuristics chosen by Kavach, not vendor values.

| Rule | Technique | Severity | Fires when |
|---|---|---|---|
| `idp-an-mfa-fatigue` | T1621 | medium | 5 or more denied or repeated MFA prompts for one user within 10 minutes |
| `idp-an-mfa-fatigue-then-success` | T1621 | high | a successful sign-in for the same user within 15 minutes after such a burst |
| `idp-an-password-spray` | T1110.003 | high | one source fails against 10 or more accounts within 10 minutes with at most 3 tries per account |
| `idp-an-impossible-travel` | T1078.004 | medium | two successful sign-ins at least 500 km apart implying 900 km/h or more, using geography in the log |
| `idp-an-newdevice-privilege-change` | T1098 | high | an MFA enrolment, MFA removal, role grant or password reset for a user within 30 minutes after a sign-in from a device or country not seen earlier in the file (needs 3 earlier successes as a baseline) |
| `idp-an-admin-role-grant` | T1098.003 | medium, high for privileged role names or self-grant | any administrator role grant |
| `idp-an-mfa-removed` | T1556.006 | medium | an authentication factor removed or reset |
| `idp-an-reset-then-mfa-enroll` | T1098.005 | high | a new MFA method registered within 60 minutes after a password reset for the same account |
| `idp-an-legacy-auth-success` | T1078.004 | medium | a successful Entra sign-in with a legacy protocol client (IMAP, POP, SMTP, ActiveSync and similar) |
| `idp-an-dormant-account-use` | T1078 | medium | a successful sign-in after `dormant_days` (default 90) without one in the file |
| `idp-an-session-multi-source` | T1550.004 | high | one session id used from two sources in different countries, or 500 km apart, within 10 minutes |
| `idp-an-auth-policy-weakened` | T1556 | medium | an Okta policy rule or zone deactivated or deleted, an Entra conditional-access policy deleted or updated to a disabled state |
| `idp-an-app-credential-or-consent` | T1098.001 | medium | an API token created, an application credential added, or consent granted |
| `idp-an-provider-risk-signal` | T1078.004 | medium or high | a successful sign-in the provider itself marked medium or high risk, or an Okta threat event |

## Report

```json
{"mode":"observe-only","received":4,"parsed":4,"rejected":0,"by_provider":{"entra":2,"okta":2},
 "by_event_class":{"signin":2,"mfa_deny":1,"role_grant":1},"distinct_users":3,
 "by_rule":{"idp-an-admin-role-grant":1},"findings":1,"dormant_after_days":90,"note":"..."}
```

`tripwire_hits` is added when you have declared decoys that appear in the file ([tripwires.md](tripwires.md)).

## Honest limits

- Baselines exist only inside the file you send. "New device" or "dormant" means new or dormant within that file; send a long enough window.
- Sign-in records without geography cannot produce impossible-travel findings. VPNs, shared devices, mobile carriers and travel cause false positives.
- Okta's newer engine reports a denied push as a generic factor failure rather than `deny_push`; the failure case of `user.authentication.auth_via_mfa` is counted too, but tenants differ.
- Entra audit activity names vary by tenant and language; unmatched names are classified `other` and ignored.
- Role-name privilege matching is a keyword list ("global admin", "super admin", "privileged", "org admin", and similar), not your role model.
- Findings are leads, not proof. No finding claims a compromise.
- Findings are stored per request; sending the same file twice stores them twice (finding ids include the timestamp).
