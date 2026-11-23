# Attack-path (toxic combination) scoring

CNAPP products (Wiz, Orca, Microsoft Defender for Cloud, CrowdStrike, Tenable) rank risk by combinations: an internet-exposed workload that carries an exploitable vulnerability and an over-privileged identity is a path; each part alone is a lower priority. Kavach does the same over data it already holds, offline and read-only. It never probes a network, queries an identity provider or changes state.

## Inputs

* Stored findings (the findings store) and software-exposure matches from ingested SBOMs ([exposure.md](exposure.md)), via `GET /v1/exposure/attack-paths`.
* Posted findings or signals via `POST /v1/exposure/attack-paths/evaluate` (stateless, nothing stored, 1 MiB, 5,000 items). Findings can be the `findings` of an inspector report: `cfg-iac-*`, `cfg-bigip-*`, `cfg-advisory-*`, `fw-*` ids, each with `host`, `id`, `title`, `severity`. Set `"include_stored": true` to combine them with the stored data.

## Classification (keyword table in `attack_paths.go`)

Each finding is classified from its id, title and tags into signal kinds: `internet_exposure` (for example `sg-open`, `0.0.0.0/0`, `T1190`, `T1133`, `selfip-allow`, `rds-public`), `excess_privilege` (`iam-admin`, `wildcard`, `passrole`, `trust-any`, `privileged`, `hostpath`, `T1078`, `T1098`), `sensitive_data` (`s3-`, `bucket`, `storage-unencrypted`, `T1530`, `T1552`), `vulnerable_software` (`cfg-advisory-`, `CVE-`, SBOM matches) and `active_threat` (stored findings of high or critical severity that match no other kind). `[pass]`, `[unknown]` and info results never count. Posted signals can name the kind directly.

## Scoring

Per asset (host label), take the strongest severity per kind. Contribution = kind weight x severity factor, with weights exposure 30, vulnerable software 25, active threat 25, excess privilege 25, sensitive data 20 and factors critical 1.0, high 0.8, medium 0.5, low 0.25. Known-exploited vulnerable software adds 10. Each kind beyond the first adds a synergy of 10. The score is capped at 100; levels: critical >= 80, high >= 60, medium >= 40, else low. An asset becomes a path only with at least two kinds and at least one entry-like kind (exposure, vulnerable software or active threat): privilege plus data alone is not a path. Output is sorted by score then host and is deterministic.

Each path lists its steps in order, the per-kind factors, the signals (up to 30) and `break_points`: for each kind the highest-severity signal and the generic action that would remove it, so the report shows which single fix breaks the chain.

```sh
kavachctl exposure attack-paths --min_score 40
curl -H "Authorization: Bearer $KAVACH_TOKEN" -X POST localhost:8080/v1/exposure/attack-paths/evaluate \
  -d '{"findings":[{"host":"app-9","id":"cfg-iac-sg-open-admin","title":"[fail] open","severity":"high"},
                   {"host":"app-9","id":"cfg-advisory-cve-2022-1388","title":"[fail] in range","severity":"critical"}]}'
```

MCP: `kavach_attack_paths` (read-only GET).

## Limits

Assets are matched by host label, not by a verified network or identity graph, so "same asset" does not prove the exposed port reaches the vulnerable process or that the identity can be assumed from the host. Classification is keyword based and will mis-sort some findings. The weights are this project's own choices, not a published formula (Orca's and Google's exact formulas are not public in the pages read). The score orders review work and is not a probability.
