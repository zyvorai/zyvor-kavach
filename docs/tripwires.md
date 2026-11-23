# Declared tripwires: honey accounts, decoy values, hosts, IPs and paths

You declare decoys that already exist in your environment, and Kavach matches them against the logs you send. Any appearance of a decoy is worth a look. Kavach is observation only: it opens no listener for these decoys, never contacts them and never blocks anyone. This is separate from Kavach-generated canaries ([`/v1/deception/canaries`](observability.md), which trip over an HTTP callback or an agent report). Research: [RESEARCH-vendors-identity-intel.md](RESEARCH-vendors-identity-intel.md).

Decoy values must be non-functional. Do not register a real credential: values are stored in `<store>.tripwires.json` (mode 0600), masked in API output (`akia******`) and never written into findings, but they are kept so that matching works.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `POST /v1/deception/tripwires` | admin token | declare a decoy: `{"kind","match","label","owner"}` |
| `GET /v1/deception/tripwires` | any authenticated | list (values masked), hit counts, limits and rule ids |
| `DELETE /v1/deception/tripwires/{id}` | admin token | remove |
| `POST /v1/deception/tripwires/scan?source=` | admin token | match against JSON records or plain text lines (8 MiB, 50,000 records, 3 s budget) |

CLI: `kavachctl tripwire list`, `add --kind K --match M --label L [--owner O]`, `delete ID`, `scan FILE [--source NAME]`.

Declared tripwires are also matched automatically whenever you upload logs to `POST /v1/auth/logs`, `POST /v1/idp/logs` or `POST /v1/ransom/logs`; the response gains `tripwire_hits`.

## Kinds

| Kind | Matches | Rule | Technique |
|---|---|---|---|
| `account` | a honey account in a user-like field (key containing user, account, principal, actor, login, upn, email or target). `CORP\svc`, `svc@corp` and `svc` compare equal, case-insensitive | `tripwire-account-used` (critical when the record shows a successful outcome, else high) | T1078 |
| `ip` | an address in an address-like field, exactly | `tripwire-decoy-touched` | T1595 |
| `value` | a planted token or secret, as a substring of the record text | `tripwire-value-seen` | T1552.001 |
| `hostname` | a decoy host or DNS name, as a substring | `tripwire-decoy-touched` | T1595 |
| `path` | a decoy URL path, as a substring | `tripwire-decoy-touched` | T1595 |

Limits: 2,000 account and IP tripwires, 100 value, hostname and path tripwires (these are substring scans and are bounded so a scan stays inside its time budget), 6 to 200 characters for substring kinds, 3 to 128 for accounts. At most 25 findings per rule per request; the same decoy from the same source address and account is reported once per 10 minutes of log time. Findings use host `tripwire:<source>` and carry the source address as the destination.

## Honest limits

- Choose distinctive names. A honey account called `admin` matches every `admin@...` record. Short substrings match unrelated text.
- Substring matching looks at the first 4 KiB of each record's concatenated text and at most 200 fields.
- Records without a parseable time use the scan time, which affects only the coalescing window.
- A decoy that nobody logs is never seen; Kavach cannot know whether your logging covers it.
- Plain text input is matched line by line with no field structure, so `account` and `ip` kinds only match JSON records.
