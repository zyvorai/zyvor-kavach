# NetScope — observation-only network scoping

NetScope summarises destinations, flow volume and simple risk signals from network events already ingested by Kavach (agent, eBPF pins, Netra poller or syslog).

It never captures packets itself, never contacts external systems, and never blocks or drops traffic.

## Endpoints

- `GET /v1/netscope/summary?host=` — top destinations with counts, first/last seen, unique hosts and a heuristic risk label.
- `GET /v1/netscope/risk` — destinations scored medium or high by the same heuristic.

Both require the usual bearer token or session.

## Risk heuristic (informational)

- Private / loopback addresses → `info`
- High connection count → `medium` or `high`
- Explicit Tor / onion indicators → `high`

These are starting points only. Tune or replace them with your own content rules.

## Relation to other surfaces

- Complements `GET /v1/xdr/storyline` (timeline) and the Netra poller.
- Works with the existing network-event ingest (`POST /v1/network-events`).
- Observation-only; containment remains a request ledger.

See also [ROADMAP.md](ROADMAP.md) and [architecture.md](architecture.md).
