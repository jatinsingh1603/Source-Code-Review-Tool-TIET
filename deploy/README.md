# `deploy/`

Deployment: Docker, Compose, Helm and the air-gapped bundle. Owning epic: E39 (issue E39-02). The step-by-step guide is [`docs/guide/deploy.md`](../docs/guide/deploy.md); this page is the inventory and the facts behind it.

| Path | What it is |
|------|------------|
| [`docker/Dockerfile`](docker/Dockerfile) | The server image: web dashboard, REST API and CLI in one image. Multi-stage (Node 22 builds `ui/`, uv installs the locked Python environment with the `server` and `reports` extras), runtime on `python:3.12-slim` with the WeasyPrint libraries, non-root user 10001, HTTP health check on `/api/v1/health`, `codekavach serve --host 0.0.0.0 --port 8080 --data-dir /data`. |
| [`docker/refresh-digests.sh`](docker/refresh-digests.sh) | Re-pins the base images to the current digest of their tag. |
| [`../docker-compose.yml`](../docker-compose.yml) | The local stack. Service `codekavach`; profile `local-llm` adds Ollama; profile `airgapped` runs a second instance on a network with no route out. |
| [`../.env.example`](../.env.example) | The variables compose reads. No secret value is in it. |
| [`helm/codekavach/`](helm/codekavach/) | Helm chart: Deployment, Service, PVC, ConfigMap, ServiceAccount, optional Ingress, default-deny egress NetworkPolicy. Secrets are read from an existing Secret. |
| [`bundle/build-bundle.sh`](bundle/build-bundle.sh) | Builds the air-gapped bundle on a connected machine. |
| [`bundle/install.sh`](bundle/install.sh) | Installs the bundle offline, in Docker mode or pip mode, after checking every file against `SHA256SUMS`. |

`make images`, `make up`, `make down`, `make logs`, `make bundle` and `make helm-lint` wrap these.

## Modes

| Mode | How | What leaves the machine |
|------|-----|-------------------------|
| Laptop | `uv run codekavach ...` or `docker compose up -d` | With `mock`, `replay` or a local Ollama model: no connection is opened by the review. With `agentrouter` (or another remote provider): the sanitised payloads recorded in the egress ledger of each scan, to that provider's host only. |
| Self-hosted server | Helm chart or compose on a server | As for the laptop. The NetworkPolicy denies all egress except DNS and the CIDRs you list per provider host. |
| Air-gapped | `make bundle` on a connected machine, `install.sh` on the offline one; compose profile `airgapped` | Nothing: the container sits on an internal Docker network with no default route, and the profile `airgapped` disables remote providers and integrations. |

## What the image contains

- CodeKavach with the `server` and `reports` extras, from `uv.lock` (hash-checked by uv).
- The rule packs in `rules/`, the mapping data in `data/`, the JSON schemas in `docs/schemas/` and the sample project `fixtures/kavachbank` (with its replay cassettes).
- The dashboard, built from `ui/` (`npm ci && npm run build`, dependencies in their own cached layer), served by `codekavach serve` at `/`.
- Engines, both run as separate processes:
  - **Opengrep 1.33.1** (LGPL-2.1, unmodified release binary, sha256 checked at build time). Leave it out with `--build-arg OPENGREP_VERSION=`.
  - **Bandit 1.9.4** (Apache-2.0, from PyPI). Leave it out with `--build-arg BANDIT_VERSION=`.
  - **eslint-plugin-security** is not in the image: it needs a Node runtime in the final layer (about 150 MB). Mount or install it yourself; the engine is then reported as available by `codekavach doctor`.
  - Engines that `docs/research/INSIGHTS.md` section 5 marks AVOID for bundling (CodeQL, Brakeman, TruffleHog, Bearer, SonarQube analysers, MobSF) are not in the image.
- No compiler in the final layer; `git` (for projects with a git source) and `tini` as PID 1.

## Secrets

Neither the image, the compose file nor the chart holds a secret value.

| Variable | Kind | Used for |
|----------|------|----------|
| `CODEKAVACH_ADMIN_PASSWORD` | plain value you choose | the built-in `admin` dashboard account (default `kavach-admin`, printed at server start) |
| `CODEKAVACH_AGENTROUTER_API_KEY` | secret value | the `agentrouter` provider; empty means offline |
| `CODEKAVACH_VAULT_PASSPHRASE` (compose) / `CODEKAVACH_SERVER_VAULT_PASSPHRASE` (in the container) | secret value, optional | the key of the pseudonym vault. A container has no OS keyring, so the image sets `privacy.vault.key_source = passphrase` and `privacy.vault.passphrase = env:CODEKAVACH_SERVER_VAULT_PASSPHRASE`. When it is empty, the wrapper `/usr/local/bin/codekavach` ([`docker/codekavach.sh`](docker/codekavach.sh)) generates `/data/vault.passphrase` (mode 0600) on first start and gives it to the server and to every CLI run in the container |

## Measured

Recorded on 2026-11-12, linux/amd64, Docker 28.5:

| Item | Size |
|------|------|
| Server image `codekavach:local` (uncompressed, as listed by `docker images`) | 617 MB |
| Build from a warm cache / from cold | about 1 min / about 4 min |
| Air-gapped bundle `codekavach-airgapped-0.1.0.dev0.tar.gz` (image + 66 wheels for manylinux x86-64 / CPython 3.12 + rules, data, sample) | 247 MB |

Verified on that build: `docker run --rm --network none --read-only ... codekavach:local scan /data/kb --provider mock` completes all stages offline with the vault on a passphrase key, and `codekavach demo` inside the container writes `report.pdf`. The bundle's `install.sh --pip` installs from the bundled wheels inside a `python:3.12-slim` container started with `--network none`, and a mock scan of the sample then completes.

The pip mode installs the wheel, which does not carry `rules/`; the rule packs come from the bundle directory (`--rules <bundle>/rules/mit/packs/default`). The Docker mode keeps the checkout layout and needs no flag.

## Not done yet (E39-02 follow-ups)

- Separate slim CLI and full images; cosign signing with the E39-01 helpers.
- The build-time licence gate that reads the engine manifest and fails the build.
- Published images: `.github/workflows/container.yml` builds this Dockerfile for amd64 and arm64 and pushes `ghcr.io/jatinsingh1603/codekavach` with SBOM and provenance; a separate slim CLI image and the licence gate are still open.
- The Python bundle tooling (`tools/bundle/build_bundle.py`, `verify_bundle.py`, a manifest schema), the PowerShell installer, OSV snapshots and the `airgapped` doctor checks.
- A network-less CI job; size budget tests; the hosted-mode Terraform sketch.
- Running engines inside the cluster with Docker-in-Docker versus a mounted socket: not needed for the current engines, which run as plain subprocesses in the same container.
