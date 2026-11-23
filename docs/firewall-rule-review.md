# Firewall and WAF rule export review

Offline and observation-only. Kavach does not connect to a firewall, read a vendor console or push a change. The analyst converts a vendor export into a small generic format and submits it as kind `config` (`kavachctl inspect config rules.json`, `POST /v1/inspect/config`). The `config-firewall` analyzer (`inspect_config_firewall.go`) reviews rule hygiene and reports findings with weight 0 (`not_scored`).

## Format

JSON `kavach-fwrules/1`, or a bare JSON array of rules, or CSV/TSV/semicolon-delimited text with a header row:

```json
{"format":"kavach-fwrules/1","vendor":"any","default_action":"deny",
 "objects":[{"name":"web-servers","members":["10.1.0.10","10.1.0.11"]}],
 "rules":[{"id":"r1","action":"allow","source":["any"],"destination":["web-servers"],
           "service":["tcp/443","tcp/22"],"enabled":true,"log":true,"hits":120,"comment":"..."}]}
```

Fields: `id`/`name`, `action` (allow|accept|permit|pass vs deny|drop|reject|block|discard; anything else is treated as not-allow), `enabled` (default true), `source`/`destination`/`service` (lists, or one string split on `; , |`; aliases `src`, `dst`, `services`), `log`, `hits`, `comment`. An omitted source, destination or service means any. Addresses: `any`, `*`, `0.0.0.0/0`, `::/0`, an IP, a CIDR, or a name. Services: `any`, `tcp/443`, `udp:53`, `tcp/1000-2000`, a bare protocol, or a few well-known names (`ssh`, `https`, `rdp`...). CSV columns: `action` and `source` required; `id`, `name`, `destination`, `service`/`port`, `enabled`, `log`, `hits`/`hit_count`, `comment` optional. Objects are expanded to depth 4 from the same file only.

## Checks

| Finding id | Severity | Meaning |
|---|---|---|
| `fw-any-any-allow` | critical | allow, any source, any destination, any service |
| `fw-any-source-any-service` | high | allow any source on any service |
| `fw-world-admin-port` | high | any source reaches 22, 23, 3389, 5900, 5985, 5986 |
| `fw-world-data-port` | high | any source reaches common datastore ports |
| `fw-any-destination-any-service` | medium | a source may reach anything on any service |
| `fw-broad-source-network` | medium | allow from a network of /8 or larger (IPv6 /16) |
| `fw-shadowed-conflict` | medium | a later rule is fully covered by an earlier rule with the opposite action |
| `fw-no-default-deny` | medium or low | no final deny-all and default_action allow (medium) or not stated (low) |
| `fw-redundant-rule` | low | covered by an earlier rule with the same action |
| `fw-allow-no-logging` | low | allow rule with `log` false |
| `fw-unused-rule` | low | enabled rule with zero hits (only when the export has hit counts) |
| `fw-disabled-rule` | low | disabled rules left in the base |
| `fw-unused-object` | low | object not referenced by any rule or object |

One finding is emitted per check with the count in the title and up to 10 examples in the evidence. Meta `config-firewall.summary` has counts, notes and the shadow-analysis status.

## Limits

First match wins in the listed order. Zones, interfaces, users, applications, schedules, negated matches, NAT and WAF signature policies are not modelled, and unknown named objects compare by name only, so shadowing is a review aid that can miss or over-report on rule bases that depend on those. Caps: 5,000 rules, 64 addresses or services per field after expansion (a note names the rule), 3,000 enabled rules for shadow analysis (otherwise skipped, status in the summary), a 20-million-comparison budget with the context polled between rules.

Vendor ideas behind the checks (Palo Alto rule order and Policy Optimizer, Fortinet administrative-access guidance) are summarised, with their sources and what was not verified, in [RESEARCH-vendors-posture.md](RESEARCH-vendors-posture.md).
