# Installing CodeKavach

Owning epic: E39 (issues E39-01, E39-02). Deploying the dashboard on a server or a cluster: [`deploy.md`](deploy.md).

Three ways in, from the least to the most set-up:

| Way | You need | You get |
|-----|----------|---------|
| Docker Compose | Docker 24 or newer with the compose plugin | Dashboard, REST API and CLI on `http://127.0.0.1:8080` |
| From a checkout with uv | Python 3.12 or 3.13, [uv](https://docs.astral.sh/uv/), git | The CLI; `codekavach serve` for the dashboard |
| Air-gapped bundle | Docker, or Python 3.12, on a machine with no network | Either of the above, installed from local files only |

Supported platforms: Linux (x86-64 and arm64) and macOS. Windows through WSL 2 or Docker Desktop.

## Docker Compose (recommended for the dashboard)

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET.git codekavach
$ cd codekavach
$ cp .env.example .env        # set CODEKAVACH_ADMIN_PASSWORD; add the AgentRouter key for a real model
$ docker compose up -d --build
$ docker compose logs -f codekavach    # wait for the health check; Ctrl-C to stop following
```

Open `http://127.0.0.1:8080` and log in as `admin` with the password from `.env` (default `kavach-admin`). The first build takes a few minutes; later starts take seconds. State (database, vaults, ledgers, reports) lives in the Docker volume `codekavach_codekavach-data` and survives `docker compose down`. `docker compose down -v` deletes it.

The same image runs the CLI:

```console
$ docker compose exec -w /data codekavach codekavach doctor
$ docker compose exec codekavach codekavach demo --out /data/demo-out
```

`make up`, `make down` and `make logs` are shortcuts for the compose commands.

## From a checkout with uv

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET.git codekavach
$ cd codekavach
$ uv sync --all-extras
$ uv run codekavach --version
$ uv run codekavach demo --out demo-out             # offline, mock provider
$ uv run codekavach serve --host 127.0.0.1 --port 8080   # dashboard (needs ui/dist: cd ui && npm ci && npm run build)
```

PDF reports need the Pango and HarfBuzz runtime libraries:

| System | Command |
|--------|---------|
| Debian, Ubuntu | `sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core` |
| Fedora | `sudo dnf install pango harfbuzz dejavu-sans-fonts` |
| macOS | `brew install pango` |

Without them every other report format still works and the PDF is skipped with a message.

Optional engines, found on `PATH`: [Opengrep](https://github.com/opengrep/opengrep/releases) 1.33.1 (release binary), Bandit (`uv tool install bandit==1.9.4`) and eslint-plugin-security (needs Node). `codekavach doctor` lists what it found. The Docker image already contains Opengrep and Bandit.

## Using a real model

The `agentrouter` provider calls the AgentRouter gateway (model `gpt-5.6-sol`). Put the key in the environment, never in a file inside the repository:

```console
$ export CODEKAVACH_AGENTROUTER_API_KEY=...        # or add it to .env for compose
$ uv run codekavach scan fixtures/kavachbank --provider agentrouter
```

Only the sanitised payloads recorded in the scan's egress ledger are sent. Without a key, use `--provider mock` (local, deterministic) or `--provider replay` (recorded answers).

## Air-gapped bundle

On a connected machine with Docker:

```console
$ make images bundle
$ ls deploy/bundle/out/
codekavach-airgapped-0.1.0.dev0.tar.gz  codekavach-airgapped-0.1.0.dev0.tar.gz.sha256
```

Copy both files to the offline machine, then:

```console
$ sha256sum -c codekavach-airgapped-0.1.0.dev0.tar.gz.sha256
$ tar xzf codekavach-airgapped-0.1.0.dev0.tar.gz
$ codekavach-airgapped-0.1.0.dev0/install.sh            # Docker mode: loads the image, writes ~/codekavach
$ codekavach-airgapped-0.1.0.dev0/install.sh --pip      # or: a virtual environment from the bundled wheels
```

The installer checks every file against `SHA256SUMS` before it does anything else. Wheels are resolved for one platform and interpreter (default `manylinux_2_28_x86_64`, CPython 3.12); build another bundle with `--platform` and `--python` for a different target. Models are not in the bundle: copy an Ollama volume with permissively licensed weights separately, or use the mock and replay providers.
