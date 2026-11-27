# Additional observation features (2026-11-27)

All remain observation-only.

## India finance
- `GET /v1/finance/india` — findings matching UPI, IMPS, NEFT/RTGS, RBI, IRDAI, GST, IFSC or `fin-in-*` patterns.
- See also [finance-india.md](finance-india.md).

## AI brief
- `GET /v1/ai/brief?host=&rule=` — structured multi-finding brief (summary, severity, top rules, suggestion).
- Heuristic only; optional external LLM can enrich later. No actions.

## Kubernetes observation
- `GET /v1/k8s/summary` — counts of container/pod, KubeVirt VM and Cilium/network-policy related findings.
- See also [kubernetes.md](kubernetes.md).

Wire the three `Register*` functions in `APIWithCredentials` and restart the controller.
