# Remote deploy

`scripts/deploy-remote.sh` syncs the repo over SSH (rsync), builds and imports the
image when needed, installs the Helm chart `helm/kavach`, restarts the Deployment and
probes `/healthz`. Default lab access is **HTTPS NodePort `:30899`**. Kavach stays
observation-only: nothing in this flow gives the platform any containment ability.

## Gated deploy flow

The script itself does not run tests. It is a deployment tool and will happily ship a
broken tree. Treat the steps below as a gate you run first; deploy only when every
gate is green. They mirror the CI jobs in `.github/workflows/ci.yml` (`go`, `go-full`,
`image`).

| Gate | Command | Why |
|---|---|---|
| Race suite | `go test -race -timeout 30m ./...` | Goroutine safety, reduced statistical corpora. The `internal/edr` package needs more than Go's default 10 minute timeout, so the flag is required. See [testing.md](testing.md) |
| Full suite | `go test ./...` | Full corpus sizes and size-bound coverage, no race detector |
| Vet | `go vet ./...` | Static checks (same as CI) |
| Image | `docker build -t kavach:ci .` | Proves the Dockerfile still builds (CI `image` job) |

```bash
go test -race -timeout 30m ./... \
  && go test ./... \
  && go vet ./... \
  && ./scripts/deploy-remote.sh sus@80.79.5.173 --k8s --envoy-gateway
```

Then verify (the script already curls `/healthz` at the end, but `--verify-only` is the
repeatable check):

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --verify-only
```

Do not push or deploy from a tree where either test run was skipped; the two runs prove
different things (race safety versus full statistical coverage).

## Usage

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s
# -> https://HOST:30899
./scripts/deploy-remote.sh HOST USER --quick        # argument order HOST USER also works
./scripts/deploy-and-test.sh                        # lab wrapper, defaults to the shared demo host
./scripts/deploy-and-test.sh sus@80.79.5.173 --quick
```

| Profile / flag | What it does |
|---|---|
| default / `--k3s` | Sync, build binaries and image (podman preferred, else docker), import into k3s containerd, Helm. Expects K3s or a kubeconfig; runs `scripts/lib/ensure-cilium-k3s.sh` when present |
| `--k8s` | Helm on an existing kubeconfig (`~/.kube/config` is preferred when readable) |
| `--quick` | Sync + Helm only (image must already exist on the host) |
| `--verify-only` | No sync or build; print `kubectl get deploy,svc,pods` and `curl -skf https://127.0.0.1:<nodePort>/healthz` on the host |
| `--envoy-gateway` | Sets `KAVACH_ENVOY_GATEWAY=1`, runs `k8s/bootstrap/ensure-envoy-gateway.sh` when present and installs the chart with `envoyGateway.enabled=true` (see [envoy-gateway.md](envoy-gateway.md)) |
| `--cilium-gateway` | Sets `KAVACH_GATEWAY_API=1` (Cilium GatewayClass, optional). NodePort remains the default path |
| `--dry-run` | Skips rsync and prints the generated remote script instead of running it. It still opens one SSH connection to read the remote `$HOME` |

The remote host needs `kubectl` and `helm`; the script exits with an error if either is
missing. If Go is absent it installs a toolchain (version pinned in the script) under
`/usr/local/go`, which needs passwordless `sudo`.

### Environment variables read by the script

| Variable | Default | Meaning |
|---|---|---|
| `KAVACH_ADMIN_TOKEN` | `Admin@321` (lab only) | Admin token installed into the chart as `auth.token`. This is the variable the script reads, not `KAVACH_TOKEN`. An empty value also falls back to `Admin@321` (the script's random-secret branch is unreachable). Set a real secret for anything beyond a lab |
| `KAVACH_NODE_PORT` | `30899` | HTTPS NodePort for the controller |
| `KAVACH_ENVOY_HTTPS_NODE_PORT` | `30943` | HTTPS NodePort of the Envoy Gateway listener |
| `KAVACH_REMOTE_SUBDIR` | `.deployments/kavach` | Remote checkout directory, relative to the target user's `$HOME`. Use a path outside `.deployments/` on hosts where sibling projects `rsync --delete` the shared parent |
| `KAVACH_ENVOY_GATEWAY`, `KAVACH_GATEWAY_API` | `0` | Same as the two gateway flags |

The rsync uses `--delete` and excludes `.git`, `bin`, `data`, `web/node_modules`,
`website/node_modules`, `.DS_Store` and `.cursor`. Anything else you leave in the remote
checkout directory is removed on the next deploy.

## What the script installs

- A **persistent self-signed TLS Secret** `kavach-tls-static` (EC P-256, 10 years, SAN
  includes the host IP), created once so a redeploy does not change the certificate and
  browsers keep their exception. Delete the Secret to rotate it. Skipped when
  `--envoy-gateway` is used (the chart then manages `kavach-tls`).
- `helm upgrade --install kavach ./helm/kavach -n kavach-system --create-namespace --wait --timeout 300s`
  with `tls.enabled=true`, `agent.enabled=false`, `service.type=NodePort` and the image tag
  pinned in the script and chart (`0.1.1`).
- A forced `rollout restart deployment/kavach` (the image tag is fixed, so a restart is
  how freshly imported content takes effect) followed by `rollout status` (180 s).
- On the remote host, `~/.kavach/admin-token` and `~/.kavach/env` (`KAVACH_URL`,
  `KAVACH_TLS_INSECURE=true`, `KAVACH_ADMIN_TOKEN`), mode 600. `kavachctl` picks up `KAVACH_URL` and
  `KAVACH_TLS_INSECURE` from `~/.kavach/env`, and also reads `KAVACH_ADMIN_TOKEN` from it as a token fallback
  (lowest precedence, after `KAVACH_TOKEN` and `ZYVOR_EDR_TOKEN`), so `kavachctl` works on that host without further setup.

The script logs `ADMIN_TOKEN=...` at the end of a run. Treat deploy logs as secret
material and do not paste them into tickets.

### State and persistence

The chart enables a PVC by default (`persistence.enabled=true`, 2 Gi, `ReadWriteOnce`,
mounted at `/app/data`). The controller runs with `-state /app/data/findings.jsonl
-credentials /app/data/agents.json`, so every file in
[persistence-files.md](persistence-files.md) lands in that volume next to `findings.jsonl`.
The chart defaults to one replica (`replicaCount: 1`) with an `ReadWriteOnce` volume; the file-backed stores are written by one process. A rolling restart gives the old pod a 20 s termination grace period; the server
drains HTTP for up to 7 s and stops background workers within 5 s (`/readyz` returns 503
first so load balancers stop routing).

Optional SIEM push (`siem.*`) and Netra poller (`netra.poller.*`) values are chart
settings; see [siem-export.md](siem-export.md) and [architecture.md](architecture.md).
mTLS is `mtls.mode` (see [agent-mtls.md](agent-mtls.md)).

## Auth

SSH keys / `ssh-agent`. Non-root users need passwordless sudo for the k3s kubeconfig
mirror and the container image import. The controller token must be at least 8
characters (the process refuses to start otherwise) and a warning is logged under 16;
use a random 32+ character secret outside the lab. Use chart `auth.existingSecret` to
keep the token out of Helm values.

## After deploy

```bash
export KAVACH_URL=https://HOST:30899
export KAVACH_TOKEN="${KAVACH_ADMIN_TOKEN:-Admin@321}"
export KAVACH_TLS_INSECURE=true            # self-signed lab certificate

curl -sk https://HOST:30899/healthz        # public probes: /healthz /livez /readyz
curl -sk -H "Authorization: Bearer $KAVACH_TOKEN" https://HOST:30899/v1/summary
kavachctl doctor                           # URL, token, /livez, /readyz, auth, TLS hint
kavachctl status --wait                    # waits for a healthy board

# Envoy Gateway (if --envoy-gateway):
curl -sk https://kavach.HOST.sslip.io:30943/healthz
```

### Console

1. Open `https://HOST:30899/` or the Envoy URL.
2. Sign in with username **`admin`** and, as the password, the controller token
   (`KAVACH_ADMIN_TOKEN`, lab default `Admin@321`). The console posts the token to
   `POST /v1/session` and receives an HttpOnly, SameSite=Strict cookie valid for 1 hour.
3. Prefer `kavachctl status --wait` for a CLI health board.

## Troubleshooting

| Symptom | Likely cause and check |
|---|---|
| `kubectl required on remote host` / `helm required on remote host` | Install them on the target; the script does not install them |
| `podman or working docker required to build/import image` | Default profile builds an image; use `--quick` if the image already exists, or install a runtime |
| `k3s ctr not available - skipping containerd import` | Not a k3s host; use `--k8s` and make the image pullable, or import it into your runtime yourself |
| Helm `--wait` times out | `kubectl -n kavach-system describe pod`; common causes are a missing `tls.existingSecret`, a PVC that cannot bind (no default StorageClass; set `persistence.storageClass` or `existingClaim`) or an image the node cannot pull |
| `healthz not ready yet` | Retry with `--verify-only`. `/healthz` is served over HTTPS, so use `curl -k` for the self-signed certificate |
| Console login fails but the token works with curl | The console password is the token itself; confirm `KAVACH_ADMIN_TOKEN` matches what the chart was installed with (`kubectl -n kavach-system get secret`) |
| Browser warns after every deploy | Only when the TLS Secret was deleted or `--envoy-gateway` mints a new one; keep `kavach-tls-static` |
| `429` from the API right after deploy scripts | Write requests are limited per client IP (`KAVACH_RATE_LIMIT`, default 100 per second) and repeated bad tokens are throttled per IP; see [observability.md](observability.md) |
| Previous data missing after redeploy | The PVC was disabled or replaced. Findings and models live only on the volume (see [persistence-files.md](persistence-files.md)) |

See [tutorial.md](tutorial.md), [console.md](console.md), [envoy-gateway.md](envoy-gateway.md).
