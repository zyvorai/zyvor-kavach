# Netskope-inspired observation surfaces

Kavach maps the major [Netskope One](https://www.netskope.com) pillars to observation-only endpoints. Nothing is proxied, decrypted, blocked or coached.

| Netskope pillar | Kavach endpoint | What it does |
|-----------------|-----------------|--------------|
| CASB (shadow IT / SaaS) | `GET /v1/netskope/casb` | Top cloud apps from ingested destinations |
| Next-Gen SWG | `GET /v1/netskope/swg` | Heuristic web-risk signals |
| DLP | `GET /v1/netskope/dlp` | Findings tagged as sensitive-data movement |
| Private Access / ZTNA | `GET /v1/netskope/ztna` | Private-destination accesses observed |
| AI Security / Skylight | `GET /v1/netskope/ai` | Known GenAI endpoint usage |
| Summary | `GET /v1/netskope/summary` | Pillar list and status |

## SSPM
SaaS Security Posture Management is covered by existing config/posture tools (`netcfg`, `inspect_config`, compliance packs). Add operator-supplied SaaS config exports the same way.

## Philosophy
- Detect and report only.
- All data comes from already-ingested network events, findings or operator reports.
- No inline proxy, no content decryption, no policy enforcement.
- Complements the earlier NetScope summary and XDR storyline.

See also [netscope.md](netscope.md), [ROADMAP.md](ROADMAP.md) and the competitive matrix.
