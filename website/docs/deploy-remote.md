# Remote deploy

`scripts/deploy-remote.sh` syncs the repo over SSH, builds/imports the image when
needed, and installs the Helm chart. Default lab access is **HTTPS NodePort
`:30899`**.

## Usage

```bash
./scripts/deploy-remote.sh sus@80.79.5.173 --k8s
# → https://HOST:30899
```

| Profile | What it does |
|---|---|
| default / `--k3s` | Sync + build + import image + Helm (expects K3s) |
| `--k8s` | Helm on an existing kubeconfig |
| `--quick` | Sync + Helm only (image already on the host) |
| `--verify-only` | curl healthz on the remote NodePort |

Opt-in: `--cilium-gateway` notes Gateway API enablement (NodePort remains the
default path).

## Auth

SSH keys / `ssh-agent`. Non-root users need passwordless sudo for k3s kubeconfig
mirror and container image import. Set `KAVACH_TOKEN` (or chart `auth.token` /
`auth.existingSecret`) before install — minimum 16 characters.

## After deploy

```bash
curl -k -H "Authorization: Bearer $KAVACH_TOKEN" https://HOST:30899/v1/summary
```

Remote checkout defaults to `~/.deployments/kavach` (`KAVACH_REMOTE_SUBDIR`
overrides).
