# High-availability and external state store

Kavach currently uses a single-replica file-backed store (see [persistence-files.md](persistence-files.md)).

## Planned: Postgres option

Set `KAVACH_STORE=postgres` (default remains `file`).

When implemented:

- Findings, incidents, cases, exposure, content versions and other state move to Postgres.
- Schema migrations run automatically on startup.
- File backend stays the default for air-gapped and simple deployments.
- Multi-replica becomes possible.

Until then the controller remains single-replica by design.

See the full plan in [ROADMAP.md](ROADMAP.md#2-external-state-store-option-postgres).
