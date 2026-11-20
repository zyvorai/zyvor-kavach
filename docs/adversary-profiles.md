# Adversary profiles

Kavach embeds 101 concise profiles of well-documented public threat groups and ransomware families (`internal/edr/adversaries/*.json`, validated at load). Counted from the files on 2026-11-16: `groups.json` 50, `ransomware.json` 10, `regional.json` 41 (the regional set is described in [regional-threats.md](regional-threats.md)); by kind 74 nation-state, 17 cybercrime, 10 ransomware; every profile is `medium` confidence. Each lists aliases, motivation, typical targets, the ATT&CK technique ids publicly attributed to the actor, a confidence label and sources. Observation only: nothing here detects, blocks or contains an actor.

## Research notes

* MITRE ATT&CK Groups (https://attack.mitre.org/groups/): a table of roughly 180 groups with ID, name, "Associated Groups" and description. Each group page separates Techniques, Software, Campaigns and References. Two caveats the site states itself: associated names are not exact overlaps, and the technique list reflects only open-source reporting, not everything the actor may do. Kavach copies both caveats into its framing (`note` field, `confidence`).
* ATT&CK APT29 page (https://attack.mitre.org/groups/G0016/): shows the per-technique "use" narrative with a citation for each, which is the model Kavach follows for traceability (every profile carries source URLs).
* CrowdStrike adversary naming (https://crowdstrike.com/blog/naming-adversaries-and-why-it-matters-to-security-teams): animal-suffix taxonomy by category (Bear, Panda, Kitten, Spider and so on). The takeaway for a UI is to lead with a stable name and show vendor aliases beside it.
* CrowdStrike and Microsoft mapping (https://www.itpro.com/security/crowdstrike-microsoft-threat-actor-naming-convention-collaboration): in 2025 the two vendors published a shared cross-reference of actor names rather than a single taxonomy, confirming that alias lists are the practical way to present actors across vendors.
* Forrester commentary (https://www.forrester.com/blogs/decoding-the-naming-game-why-standardizing-threat-actor-names-alone-wont-enhance-your-security-posture-or-response): naming alone does not improve posture; what helps defenders is mapping actor behaviour to controls. That is why Kavach's value-add is per-technique coverage and gaps, not the profile text.
* CISA #StopRansomware advisories (https://www.cisa.gov/stopransomware): source for the ransomware family entries (LockBit 3.0, ALPHV, Akira, Play, Rhysida, BlackByte, Royal, Hive, Conti, Medusa).

Pattern adopted from vendor UIs: actor card (name, aliases, motivation, targets), a technique list with a per-technique status, and a ranked overview. Kavach status values are `exact` (a rule maps to that technique), `related` (a rule maps to the parent or a sibling sub-technique) and `gap`.

## Data limits

* Technique lists are a curated subset of publicly reported use, written from memory of the cited ATT&CK/CISA pages and marked `medium` confidence. Verify against the cited source before relying on a specific mapping. Nothing is invented, but omissions and small errors are possible.
* Origin fields say "as publicly reported/attributed"; they are not Kavach attribution.
* Coverage means Kavach has a rule that can observe the technique. It does not mean the actor is present, and a covered technique may still be evaded.

## Adding or correcting a profile

Profiles are JSON in `internal/edr/adversaries/` (any `*.json` there is embedded). The loader rejects unknown fields and the whole set fails to load on the first invalid profile, so a mistake is caught by `go test ./internal/edr/ -run Adversar` rather than at runtime. Rules the validator enforces: kebab-case unique `id` (max 64), non-empty `name`, `kind`, `motivation` and `targets`, `confidence` of `high|medium|low`, at least one technique id of the form `T1234` or `T1234.001` with no duplicates, and at least one source with a title and an `https://` URL.

Worked example (illustrative; not shipped):

```json
{ "pack": "example", "profiles": [ {
  "id": "example-group", "name": "Example Group", "aliases": ["EG"],
  "kind": "cybercrime", "attributed_origin": "as publicly reported: unknown",
  "motivation": "financial", "targets": "retail and hospitality",
  "techniques": ["T1566.001", "T1059.001", "T1486"],
  "confidence": "medium",
  "sources": [ { "title": "Vendor report title", "url": "https://example.com/report" } ] } ] }
```

Steps: copy each technique id from the cited report (not from memory), keep `confidence` at `medium` unless a primary source lists the technique for the actor, run the test command above, then check `kavachctl adversary show example-group` for the per-technique status. A `gap` means no Kavach rule maps to that technique: add a rule (see [content-framework.md](content-framework.md)) rather than editing the profile.

The similarity feature ([research-ttp.md](research-ttp.md)) is built from the same profiles, so adding a profile changes its idf weights and can move rankings; re-run `go test ./internal/edr/ -run TTP -v` after a change.

## API

* `GET /v1/adversaries` (filters `kind`, `technique`, `q`)
* `GET /v1/adversaries/{id}`: profile plus per-technique coverage, coverage percent, gaps, observed hits
* `GET /v1/adversaries/coverage`: all actors ranked by coverage and by observed hits from the ATT&CK matrix

CLI: `kavachctl adversary list|show|coverage`. MCP tools: `adversary_list`, `adversary_profile`, `adversary_coverage`.
* The mapping from a rule to a technique is one rule to one technique, so coverage percentages count techniques with at least one rule, and say nothing about how many variants of the technique are detected (see the validation lab for measured results).
* Coverage is computed against the embedded content and the ATT&CK matrix hit counters; custom rules count only to the extent the matrix includes them. This was not separately verified.
* All 101 profiles carry `medium` confidence, so the field does not discriminate between them.
