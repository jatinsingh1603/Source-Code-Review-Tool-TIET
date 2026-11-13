# Docker demo and handover

Owning epic: E39 (issue E39-02). The full deployment guide is [`docs/guide/deploy.md`](../guide/deploy.md); the dashboard walk-through is [`DEMO2.md`](DEMO2.md).

One image, one command. The container holds the API server, the web dashboard and the CLI. State lives in the `codekavach-data` volume. Nothing leaves the machine unless you give it an LLM key.

Image: `ghcr.io/jatinsingh1603/codekavach` (tags `main`, `sha-<short>`, and `latest` plus `<version>` on release tags; amd64 and arm64). Each push carries an SBOM and a provenance attestation.

## What to say

- "This is the whole product in one container. The Thapar team runs one command and gets the dashboard, the REST API and the CLI."
- "Nothing is baked in: no key, no customer code, no telemetry. The key is supplied at run time and the container runs read-only, as a non-root user, with every Linux capability dropped."
- "For a closed network there is an air-gapped profile with no route out. It uses a local Ollama model or the offline mock provider."

## One-command demo (from the published image)

Needs Docker with Compose v2 and `curl`. No clone of the full toolchain is needed beyond this repository (for the compose files).

```bash
scripts/demo-docker.sh --seed
```

Expected output (abridged):

```text
Pulling ghcr.io/jatinsingh1603/codekavach:main ...
Waiting for http://127.0.0.1:8080/api/v1/health ... ok
CodeKavach is running.
  Dashboard : http://127.0.0.1:8080
  Login     : admin / kavach-admin
```

`--seed` runs one sample scan of the bundled KavachBank project with the offline mock provider, so the dashboard has findings the moment you log in. Stop with `scripts/demo-docker.sh --down` (`--purge` also deletes the data volume). `make demo-docker` is the same as `--seed`.

## On stage: what to show

| Show | Command |
| --- | --- |
| It is one container | `docker compose ps` |
| It runs as non-root with a read-only filesystem | `docker compose exec codekavach id` and `docker inspect codekavach-codekavach-1 --format '{{.HostConfig.ReadonlyRootfs}}'` |
| The engines are inside | `docker compose exec codekavach opengrep --version` and `... bandit --version` |
| The CLI is the same tool | `docker compose exec -w /data codekavach codekavach doctor` (`-w /data`: the image is read-only, so the CLI works from the data volume) |
| Nothing needs the network | `docker compose --profile airgapped up -d codekavach-airgapped`, then `docker compose exec codekavach-airgapped codekavach demo --out /data/demo-out` (scans the bundled sample with the mock provider and prints `zero_leak_passed  True`) |

Build or pull the image the day before: the first build downloads base images and takes a few minutes.

## Handover commands for the Thapar team

Without cloning anything:

```bash
docker run --rm -p 127.0.0.1:8080:8080 -v codekavach-data:/data \
  -e CODEKAVACH_ADMIN_PASSWORD='choose-a-password' \
  ghcr.io/jatinsingh1603/codekavach:latest
```

Open http://127.0.0.1:8080 and sign in as `admin`.

With Compose (this repository):

```bash
cp .env.example .env            # edit the values you need
docker compose up -d --build    # builds locally
# or run the published image instead of building:
docker compose -f docker-compose.yml -f deploy/docker/compose.ghcr.yml up -d --no-build
```

Pin a build for a repeatable demo: `CODEKAVACH_IMAGE=ghcr.io/jatinsingh1603/codekavach:sha-<short>`.

If `docker pull` says `denied` or `unauthorized`, the package is private. The owner must set it to public in GitHub, Packages, codekavach, Package settings, Change visibility. Until then run `docker login ghcr.io` with a token that has `read:packages`, or build locally with `scripts/demo-docker.sh --build`.

## Setting the LLM key

Put it in `.env` (git-ignored), never in a command history, the repository or a GitHub secret of this demo repository:

```bash
CODEKAVACH_AGENTROUTER_API_KEY=<your key>
```

Then `docker compose up -d` again. Pick the provider and privacy level in the dashboard (Settings) or per scan. With the key empty, the dashboard offers only the offline mock provider (replay is for the CLI demo), which is enough for the demo.

For GitHub-hosted runs (Action, CI) the client adds their own key as a repository secret named `CODEKAVACH_LLM_API_KEY`. The demo repository has no such secret and uses the mock or replay provider.

## Air-gapped mode with Ollama

```bash
# local model, still on the normal network
docker compose --profile local-llm up -d
docker compose exec ollama ollama pull qwen2.5-coder:7b

# no route out at all: mock, replay and local Ollama only
docker compose --profile airgapped up -d codekavach-airgapped
```

In a truly offline site, load the image from a file: on a connected machine `docker save ghcr.io/jatinsingh1603/codekavach:latest | gzip > codekavach.tar.gz`, move it, then `docker load < codekavach.tar.gz`. Do the same for `ollama/ollama` and pull the model into the `ollama-models` volume beforehand.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `pull access denied` | Package is private, or you are not logged in. See the visibility note above. |
| Health check never turns green | `docker compose logs codekavach`. Usually a port clash: set `CODEKAVACH_PORT=8081`. |
| Cannot reach the dashboard from another machine | The port binds to 127.0.0.1. Set `CODEKAVACH_BIND=0.0.0.0` and change the admin password first. |
| Login fails | The admin password is fixed at first start in the data volume. `scripts/demo-docker.sh --down --purge` resets it. |
| Vault unreadable after editing `.env` | `CODEKAVACH_VAULT_PASSPHRASE` changed. Restore the old value or purge the volume. |
| Apple Silicon is slow | An old image without an arm64 build is running under emulation. Pull `:main` again. |
| `npm error Exit handler never called` while building locally | The default Docker build network stalls npm on some hosts. Build with `docker build --network host -f deploy/docker/Dockerfile -t codekavach:local .` (the demo script does this). The published image avoids the issue. |
| Empty dashboard | Run `scripts/demo-docker.sh --seed`, or start a scan from the dashboard. |

## Fallback if the network fails on the day

Run `scripts/demo-docker.sh --build` beforehand so the local image `codekavach:local` exists, then bring it up with plain `docker compose up -d`. Everything in the demo works offline with the mock provider.
