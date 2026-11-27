# SSE / cloud-visibility observation surfaces

Observation-only visibility for the main pillars found in modern SASE/SSE platforms. Nothing is proxied, decrypted or blocked.

| Pillar | Endpoint | What it does |
|--------|----------|--------------|
| SaaS / shadow IT | `GET /v1/sse/casb` | Top cloud apps from ingested destinations |
| Web risk | `GET /v1/sse/web` | Heuristic web-risk signals |
| Sensitive data | `GET /v1/sse/dlp` | Findings tagged as sensitive-data movement |
| Private access | `GET /v1/sse/private` | Private-destination accesses observed |
| GenAI usage | `GET /v1/sse/ai` | Known GenAI endpoint usage |
| Summary | `GET /v1/sse/summary` | Pillar list and status |

## Philosophy
- Detect and report only.
- All data comes from already-ingested network events, findings or operator reports.
- No inline proxy, no content decryption, no policy enforcement.
- Complements existing network scoping and the XDR storyline.

See also [ROADMAP.md](ROADMAP.md).
