# Wiring the new observation endpoints

The feature files are on main, but the routes only become live when their `Register*` functions are called from `APIWithCredentials` in `internal/edr/edr.go`.

## One-line fix

After the existing `Register*` calls, add:

```go
RegisterAllExtra(mux, token, store)
```

`RegisterAllExtra` (in `register_extra.go`) wires:

- SSE observation (`/v1/sse/*`)
- India finance (`/v1/finance/india`)
- AI brief (`/v1/ai/brief`)
- K8s summary (`/v1/k8s/summary`)
- Zscaler summaries (`/v1/zscaler/*`)
- Suggested actions (`/v1/actions*`)
- Related findings + posture snapshot (`/v1/related`, `/v1/posture/snapshot`)

Restart the controller after the change.

## Why "nothing there"

The Go files and docs were merged, but without the registration call the HTTP server never mounts the handlers, so the endpoints do not exist at runtime.
