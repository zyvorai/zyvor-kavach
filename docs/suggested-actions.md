# Suggested actions ledger

Kavach remains observation-only. It can now record **recommended containment** as structured requests that an operator or external system must act on.

## Endpoints

- `GET /v1/actions?status=pending` — list recorded suggestions
- `POST /v1/actions` — manually record a suggestion
- `POST /v1/actions/suggest` — scan recent high/critical findings and record recommendations (still never executes)

## Storage

File-backed by default (`<state>.actions.json`). Override with `KAVACH_ACTIONS_FILE`.

## Philosophy

- Nothing is killed, isolated, blocked or quarantined by Kavach.
- The ledger is an exportable request list for SOAR, ticketing or human operators.
- Auto-suggest only creates records from existing findings.

Wire `RegisterSuggestedActions` in `APIWithCredentials` and restart the controller.
