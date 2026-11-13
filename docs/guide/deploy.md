# Deploying the dashboard

Owning epic: E39 (issue E39-02). Inventory, measured sizes and what the image contains: [`deploy/README.md`](../../deploy/README.md). First-time installation: [`install.md`](install.md).

The dashboard, the REST API (`/api/v1`) and the CLI ship as one image built from [`deploy/docker/Dockerfile`](../../deploy/docker/Dockerfile). It listens on port 8080, keeps all state under `/data` and runs as user 10001 with a read-only root filesystem.

## Build the image

```console
$ make images                                # = docker build -f deploy/docker/Dockerfile -t codekavach:local .
$ docker build -f deploy/docker/Dockerfile -t registry.example/codekavach:0.1.0 \
    --build-arg VERSION=0.1.0 --build-arg REVISION=$(git rev-parse --short HEAD) .
```

Build arguments:

| Argument | Default | Effect |
|----------|---------|--------|
| `OPENGREP_VERSION` | `1.33.1` | Opengrep release binary in `/usr/local/bin`; empty leaves it out |
| `BANDIT_VERSION` | `1.9.4` | Bandit in the image's environment; empty leaves it out |
| `VERSION`, `REVISION` | `0.1.0.dev0`, `unknown` | OCI labels |
| `NODE_IMAGE`, `PYTHON_IMAGE`, `UV_IMAGE` | digest-pinned | Base images; `deploy/docker/refresh-digests.sh` re-pins them |

The build context is filtered by [`.dockerignore`](../../.dockerignore). It excludes `.env`, state directories (`.codekavach/`), vaults, ledgers, key files, caches, tests and `ui/node_modules`; a test (`tests/unit/repo/test_deploy_files.py`) pins each exclusion. Do not weaken it: what reaches the context can reach a layer.

## Run with Docker Compose

```console
$ cp .env.example .env     # set CODEKAVACH_ADMIN_PASSWORD and, optionally, the AgentRouter key
$ docker compose up -d --build
$ docker compose ps        # STATUS shows (healthy) once /api/v1/health answers
```

| Setting in `.env` | Meaning |
|-------------------|---------|
| `CODEKAVACH_ADMIN_PASSWORD` | Password of the `admin` account created on first start |
| `CODEKAVACH_AGENTROUTER_API_KEY` | Key for the `agentrouter` provider; empty keeps the stack offline |
| `CODEKAVACH_VAULT_PASSPHRASE` | Derives the pseudonym vault key. Empty: the server generates one in the data volume (`/data/vault.passphrase`). Keep it, or old vaults become unreadable |
| `CODEKAVACH_BIND`, `CODEKAVACH_PORT` | Host address and port; the default `127.0.0.1:8080` is reachable from this machine only |

The service runs with `read_only: true`, `no-new-privileges` and all capabilities dropped; `/data` (named volume) and `/tmp` (tmpfs) are the only writable paths.

### Local model (profile `local-llm`)

```console
$ docker compose --profile local-llm up -d
$ docker compose exec ollama ollama pull qwen2.5-coder:7b
```

The Ollama container has no published port; CodeKavach reaches it at `http://ollama:11434`. It sets `OLLAMA_NO_CLOUD=1` because model tags ending in `-cloud` or `:cloud` run on the vendor's servers while the client still talks to the local daemon.

### No network at all (profile `airgapped`)

```console
$ docker compose --profile airgapped up -d codekavach-airgapped
$ docker compose exec codekavach-airgapped codekavach demo --out /data/demo-out
```

`codekavach-airgapped` is attached only to the internal network `airgap`, which has no default route, and runs with `CODEKAVACH_PROFILE=airgapped` and no provider key. An internal network cannot publish a port: reach the dashboard through a reverse proxy attached to `airgap`, or use the CLI with `docker compose exec`. For a machine with no network at all, use the bundle ([`install.md`](install.md#air-gapped-bundle)).

### Backup and upgrade

```console
$ docker run --rm -v codekavach_codekavach-data:/data -v "$PWD":/backup busybox tar czf /backup/codekavach-data.tgz -C /data .
$ git pull && docker compose up -d --build     # the volume is kept
```

The backup holds vaults, ledgers and reports, which contain client code: store it with the classification of that code.

## Run on Kubernetes (Helm)

The chart [`deploy/helm/codekavach`](../../deploy/helm/codekavach) was linted and rendered with Helm 3.17.

```console
$ kubectl create namespace codekavach
$ kubectl -n codekavach create secret generic codekavach-secrets \
    --from-literal=CODEKAVACH_ADMIN_PASSWORD='choose-one' \
    --from-literal=CODEKAVACH_SERVER_VAULT_PASSPHRASE='choose-another' \
    --from-literal=CODEKAVACH_AGENTROUTER_API_KEY='...'
$ helm install codekavach deploy/helm/codekavach -n codekavach \
    --set image.repository=registry.example/codekavach --set image.tag=0.1.0
$ kubectl -n codekavach port-forward svc/codekavach 8080:8080
```

What the chart sets up:

- One replica with the `Recreate` strategy (the server keeps SQLite state on a ReadWriteOnce volume), readiness and liveness probes on `/api/v1/health`.
- Pod security: non-root user 10001, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token.
- A PVC for `/data` with `helm.sh/resource-policy: keep`, so uninstalling does not delete vaults and ledgers.
- A NetworkPolicy that denies all egress except DNS and the CIDRs listed per provider host in `networkPolicy.providerEgress`. NetworkPolicy matches addresses, not host names: list the CIDRs that serve `agentrouter.org`, or translate the entries into FQDN rules if your CNI supports them (for example Cilium). With no CIDRs, remote providers cannot be reached, which is the air-gapped behaviour.
- An optional Ingress (`ingress.enabled=true`).

Secrets are read only from the Secret named in `secrets.existingSecret`; the chart has no field that takes a secret value (checked by `tests/unit/repo/test_deploy_files.py`).

## Engines in a container

Opengrep and Bandit run as subprocesses inside the CodeKavach container, under the engine sandbox of the analyse-engines stage. No Docker socket is mounted and no Docker-in-Docker is needed. Mounting a Docker socket into the container would give it control of the host and is not supported.
