# Install runbook

Every way to get CodeKavach onto a machine, in the order we would recommend them to a new user. Each path ends with a check command and its expected result. Release downloads are on the repository's Releases page; every release carries `SHA256SUMS`.

Nothing here needs a paid key. The `mock` provider answers on the machine; for a real model see "Using a real model" at the end.

## 1. Docker (dashboard + API + CLI in one container)

```console
$ cp .env.example .env            # optional: set CODEKAVACH_ADMIN_PASSWORD, never commit .env
$ docker compose up -d --build    # dashboard on http://127.0.0.1:8080
$ docker compose exec codekavach codekavach --version
```

Expected: the container is `running`, the dashboard answers on port 8080, `--version` prints the version. Stop with `docker compose down` (the scan state stays in the `codekavach-data` volume; `down -v` deletes it). Profiles `local-llm` (Ollama) and `airgapped` are described at the top of `docker-compose.yml`.

## 2. `uv tool install` from git (CLI only, no clone)

```console
$ curl -LsSf https://astral.sh/uv/install.sh | sh      # once, if uv is missing
$ uv tool install "codekavach @ git+https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET"
$ codekavach --version
$ codekavach demo --out demo-out        # offline, mock provider; writes report.html
```

Add extras when you need them: `"codekavach[server,reports] @ git+https://..."`. Pin a release with `@v0.1.0` after the URL. Upgrade with `uv tool upgrade codekavach`.

## 3. Wheel from a release

```console
$ gh release download <tag> -R jatinsingh1603/Source-Code-Review-Tool-TIET -p '*.whl' -p SHA256SUMS
$ sha256sum -c SHA256SUMS --ignore-missing      # expect: codekavach-...whl: OK
$ uv tool install ./codekavach-*.whl            # or: pip install ./codekavach-*.whl
$ codekavach --version
```

Without `gh`, download the same files from the release page in a browser. The sdist (`.tar.gz`) is there too, as is `codekavach-sample-report.zip`: unzip it and open `report.html` to see a finished report with nothing installed.

## 4. VS Code extension (.vsix)

```console
$ gh release download <tag> -R jatinsingh1603/Source-Code-Review-Tool-TIET -p '*.vsix'
$ code --install-extension codekavach-*.vsix
```

Or in VS Code: Extensions view, "..." menu, "Install from VSIX...". The extension needs either the CLI (path 2 or 3) or a running server (path 1). Full steps: [`vscode.md`](vscode.md).

## 5. GitHub Action

In the repository to be scanned, add a workflow such as the one in [`action/README.md`](../../action/README.md). GitHub-hosted runs use the `mock` provider (no key, nothing leaves the runner) and upload SARIF to the Security tab. To let a client use a real model, they add their own key as a repository secret named `CODEKAVACH_LLM_API_KEY` (Settings, Secrets and variables, Actions) and pass it to the action as an environment variable. We never add our key to any repository.

## Using a real model

The demo machine can use AgentRouter (`--provider agentrouter`, model `gpt-5.6-sol`); keep the key in a file outside the repository and export it into the shell only. The key must never be committed, pasted into a doc or added as a GitHub secret by us.

## From source (developers)

```console
$ uv sync --all-extras
$ uv run codekavach --version
```
