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

## Google sign-in

Optional and off by default. With no `CODEKAVACH_GOOGLE_*` variable set the login page shows no Google button, the two Google routes answer 404 and the server contacts no Google host.

| Variable | Meaning |
|---|---|
| `CODEKAVACH_GOOGLE_CLIENT_ID` | OAuth 2.0 client ID (type "Web application") from the Google Cloud console. Not a secret. |
| `CODEKAVACH_GOOGLE_CLIENT_SECRET` | The client secret. A secret value: keep it in `.env` or a secret store, never in git. `CODEKAVACH_GOOGLE_CLIENT_SECRET_FILE` may name a file that holds it instead. |
| `CODEKAVACH_GOOGLE_ALLOWED_DOMAINS` | Comma list of e-mail domains that may sign in, for example `thapar.edu`. |
| `CODEKAVACH_GOOGLE_ALLOWED_EMAILS` | Comma list of single addresses that may sign in. If both lists are empty, any Google account with a verified e-mail address may sign in. |
| `CODEKAVACH_GOOGLE_DEFAULT_ROLE` | Role of an account created by a first sign-in: `viewer` (default), `developer`, `auditor` or `admin`. |
| `CODEKAVACH_PUBLIC_URL` | The URL people open the dashboard at, for example `https://kavach.example.edu`. Set it behind a reverse proxy or TLS terminator; without it the server uses the scheme and host of the request. |

Sign-in is on only when both the client ID and the client secret are set. In the Google Cloud console (APIs & Services, Credentials, the OAuth client) register:

- **Authorised redirect URI**: `<base>/api/v1/auth/google/callback`, where `<base>` is `CODEKAVACH_PUBLIC_URL` or the address in the browser. For compose on this machine that is `http://localhost:8080/api/v1/auth/google/callback`. It must match exactly, including scheme and port; `localhost` and `127.0.0.1` are different origins to Google.
- **Authorised JavaScript origin**: `<base>` (for example `http://localhost:8080`). The server flow does not need it; the hosted demo's button does (below).

Role mapping: a person's first sign-in creates a local account whose user name is their e-mail address, with the default role and no local password. An administrator changes the role under Admin, Users and roles; later sign-ins keep it. A local account whose user name is already that e-mail address is reused with its role. Disabling the account blocks Google sign-in too. Every sign-in, refusal and created account is in the audit log.

The flow is OpenID Connect authorisation code with PKCE, `state` and `nonce`; the dashboard receives the same session token as a password login, in the URL fragment. The server calls `oauth2.googleapis.com` once per sign-in and the browser visits `accounts.google.com`. That is identity traffic: it carries a person's name and e-mail address, never source code, does not go through the egress transport and is not written to the egress ledger, which records only what is sent to an LLM provider. The `airgapped` profile cannot reach Google, so leave the variables empty there.

The [hosted demo](../demo/README.md) on GitHub Pages has no server, so its Google button uses Google Identity Services in the browser with the public client ID only (`VITE_GOOGLE_CLIENT_ID` in the Pages workflow) and signs the visitor into the sample data under their own name. It needs the authorised JavaScript origin `https://jatinsingh1603.github.io` and no redirect URI.

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
