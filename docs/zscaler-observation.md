# Zscaler observation summaries

High-level, observation-only views on top of the existing Zscaler log parsers (NSS/LSS, policy review, ZDX).

| Pillar | Endpoint | What it does |
|--------|----------|--------------|
| ZIA (Internet Access) | `GET /v1/zscaler/zia` | Internet / SaaS related findings |
| ZPA (Private Access) | `GET /v1/zscaler/zpa` | Private or ZPA-related destinations |
| ZDX (Digital Experience) | `GET /v1/zscaler/zdx` | Experience / latency / probe signals |
| Summary | `GET /v1/zscaler/summary` | Pillar overview |

## Philosophy
- Detect and report only.
- No calls to Zscaler APIs, no proxy, no blocking.
- Complements the existing `zscaler_*.go` parsers and the generic SSE observation surfaces.

Wire `RegisterZscalerObservation` in `APIWithCredentials` and restart the controller.
