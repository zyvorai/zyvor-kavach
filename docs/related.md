# Related findings and posture snapshot

Two small observation-only helpers.

## Endpoints

- `GET /v1/related?host=&rule=` — other findings on the same host or matching a rule fragment.
- `GET /v1/posture/snapshot` — quick counts of hosts and severity buckets from current findings.

No live probes, no actions.

Wire `RegisterRelated` in `APIWithCredentials`.
