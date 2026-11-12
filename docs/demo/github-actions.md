# GitHub Actions runbook

Surface: CodeKavach as a security review step in the client's own pipeline. The workflow [`.github/workflows/codekavach-review.yml`](../../.github/workflows/codekavach-review.yml) runs the repository's own action ([`action/`](../../action/README.md)) on the sample bank application `fixtures/kavachbank` and publishes the result in four places: the run page, the job summary, the Security tab (code scanning) and a downloadable artifact. On a pull request from this repository it also posts one comment and updates it on every push. About four minutes on stage.

## Live run

- Latest green run, triggered by `workflow_dispatch`: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/runs/43287079496>
- Every run of the workflow: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/workflows/codekavach-review.yml>
- Code scanning alerts from CodeKavach: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/security/code-scanning?query=tool%3ACodeKavach>

The Security tab is visible to people with write access to the repository. Log in as an owner before the session.

## What to say

"This is the same core as the command line and the dashboard, running in the client's own CI with the client's own keys. Here it uses the mock provider: it answers on the runner and opens no connection, so this public repository stores no key and nothing leaves the runner. The ledger still records, and the job checks, what would have been sent. A client changes one input and adds one secret to use a real model."

## What the audience sees

| Where | What | Point at |
|-------|------|----------|
| Run page | One job, *Security review (kavachbank, mock provider, L3)*, green | The *CodeKavach scan* step reports the gate as failed, but the job continues on error, so the run stays green and still shows the findings. |
| Job summary (bottom of the run page) | Severity table, the ten most severe findings with CWE and a link to the line, the privacy attestation, links to the alerts | The attestation rows: level L3, provider `mock`, model requests recorded, ledger chain intact, stored payloads re-hashed, **Zero-leak check PASSED** with the number of planted terms searched. The action's own table of all findings follows. |
| Security tab, Code scanning | One alert per finding, tool *CodeKavach*, category `codekavach`, on the real file and line | Open the SQL injection alert in `services/api/accounts.py`: severity, rule, the line in the file. The model saw a pseudonymised slice; the alert names the original file because the mapping was restored on the runner. |
| Artifact `codekavach-reports` | `report.html`, `report.pdf`, `codekavach.sarif`, `verification.txt`, `verification.json`, `summary.md`, `scan.json` | Open `report.pdf` (executive summary, risk matrix, evidence, privacy attestation) and `verification.txt` (three lines: chain, payloads, terms). |
| Pull request (same-repository PRs only) | One comment with the same summary, updated in place on each push | Not exercised live yet (no PR has touched `fixtures/**` or `src/**` since the workflow landed). If the audience asks, open a PR that edits `fixtures/kavachbank/README.md`. |

Numbers from the run linked above (they change as rules and the risk model change): 55 findings (15 critical, 24 high, 11 medium, 5 low), 30 model requests recorded, 0 blocked, ledger chain intact (60 records), 11 distinct payloads re-hashed with 0 mismatches, 31 planted terms searched with 0 occurrences, 55 code-scanning alerts. The Security tab grades alerts by the numeric `security-severity` score in the SARIF, so its critical and high counts can differ from the severity column of the summary; the alerts and findings are the same 55.

What the zero-leak line does and does not show: it searches the stored payloads for each planted secret and identifier verbatim. Structure (control flow, library calls, the shape of literals) still leaves at L3; `codekavach eval leakage` measures that. Say it before someone asks.

## Running it live

From the browser: **Actions**, **CodeKavach review**, **Run workflow**, keep `fail-on: critical` and `privacy-level: L3`, **Run workflow**. With the GitHub CLI:

```console
$ gh workflow run codekavach-review.yml -R jatinsingh1603/Source-Code-Review-Tool-TIET -f fail-on=critical -f privacy-level=L3
$ gh run watch -R jatinsingh1603/Source-Code-Review-Tool-TIET
```

A run takes about four minutes. Start it at the beginning of the session and come back to it, or show the latest green run and start a new one only if there is time.

Triggers: `workflow_dispatch`; `pull_request` touching `fixtures/**`, `src/**` or the workflow; `push` to `main` touching `fixtures/kavachbank/**` or the workflow.

## What the workflow does

1. Copies `fixtures/kavachbank` to the runner's temporary directory without `ground-truth/` (the answer key) and `cassettes/` (recorded model answers), so the application is scanned as its own project, as in a client repository. Sets a random vault passphrase for the job (masked in the log).
2. Runs `uses: ./action` with `provider: mock`, `privacy-level: L3`, `fail-on: critical` and `continue-on-error: true`.
3. Renders `report.html` and `report.pdf` with `codekavach report`.
4. Runs `codekavach privacy ledger verify --check-terms ground-truth/terms.txt --include-blocked --require-payloads`. A failure here fails the job, because only the scan step has `continue-on-error`.
5. Rewrites the SARIF paths to be relative to the repository root and uploads them with `github/codeql-action/upload-sarif` (pinned to a commit) under category `codekavach`. Skipped for pull requests from forks, which get a read-only token.
6. Writes the job summary with [`.github/scripts/codekavach_summary.py`](../../.github/scripts/codekavach_summary.py), uploads the artifact (kept 30 days), and on same-repository pull requests posts or updates the comment marked `<!-- codekavach-review -->`.

Permissions: `contents: read`, `security-events: write` (SARIF), `actions: read` (code scanning reads the run), `pull-requests: write` (the comment). No secret is used.

## How a client adds it to their repository

Copy this into `.github/workflows/codekavach.yml` of the client's repository. It starts with the mock provider, so it works before any key exists.

```yaml
name: CodeKavach

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload to code scanning
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - id: ck
        uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@main
        with:
          target: .            # the repository root (see "Known limits")
          provider: mock       # step 2 below switches to a real model
          privacy-level: L3
          fail-on: high        # the job fails at or above this severity
      - name: Upload SARIF to code scanning
        if: always() && steps.ck.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          sarif_file: ${{ steps.ck.outputs.sarif-path }}
          category: codekavach
```

Pin `@main` to a release tag or commit once one is published. The action's own `upload-sarif: "true"` input also works, but uses an unpinned upload action; the explicit step above is pinned.

### Step 2: a real model with the client's own key

1. Add the key as a repository secret named `CODEKAVACH_LLM_API_KEY`: **Settings**, **Secrets and variables**, **Actions**, **New repository secret**; or `gh secret set CODEKAVACH_LLM_API_KEY` and paste the key at the prompt. Keep the key out of files and workflow inputs (inputs are printed in the log).
2. Change the scan step:

```yaml
      - id: ck
        uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@main
        with:
          target: .
          # Fork PRs get no secrets: they fall back to the deterministic engines.
          provider: ${{ github.event.pull_request.head.repo.fork && 'none' || 'agentrouter' }}
          privacy-level: L3
          fail-on: high
        env:
          CODEKAVACH_LLM__PROVIDERS__AGENTROUTER__PRESET: agentrouter
          CODEKAVACH_LLM__PROVIDERS__AGENTROUTER__API_KEY: env:CODEKAVACH_LLM_API_KEY
          CODEKAVACH_LLM_API_KEY: ${{ secrets.CODEKAVACH_LLM_API_KEY }}
          CODEKAVACH_ACCEPT_EGRESS: "1"   # the operator's recorded consent to send sanitised payloads
```

The `agentrouter` preset fills in the endpoint, the model and the request headers; another provider uses its own preset name (for example `openai`) in both the provider id and the `PRESET` variable. Provider settings come from environment variables because a project's `codekavach.toml` may not set endpoints or credentials unless the project is trusted (error `CK-CFG-040`). Only the sanitised payload of the chosen level is sent, and the egress ledger records it. The action refuses any provider on `pull_request_target`.

This step has not been run on GitHub from this repository: by design no key is stored here. The same provider settings were checked locally with `codekavach providers list`, which lists `agentrouter` (`gpt-5.6-sol`, host `agentrouter.org`, minimum level L3).

### Known limits for clients

- Scan the repository root (`target: .`). Scanning a subdirectory of a git checkout currently returns no findings; this workflow scans a copy of the fixture for that reason.
- The vault key: the action sets a random passphrase for the job when the workflow does not choose a key source, because hosted runners have no OS keyring. The vault does not outlive the job. A workflow that verifies the ledger in later steps (as this one does) sets the passphrase itself, at job level, so that every step uses the same one.

## Before the demo

- [ ] The latest run of *CodeKavach review* is green and less than a day old; if not, start one (see above) and wait for it.
- [ ] Logged in to GitHub as an owner; the Security tab shows the CodeKavach alerts.
- [ ] The artifact `codekavach-reports` of that run downloads and `report.pdf` opens.
- [ ] Browser tabs open: the run page (scrolled to the summary), the code-scanning list filtered by `tool:CodeKavach`, one alert, the workflow file.

## If something fails

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Run red at *Verify the egress ledger* | A planted term in a payload, a broken chain, or a payload the key cannot open | Do not demo the run. Read `verification.txt` in the artifact; show the last green run instead and say why. |
| Scan step shows a Python traceback at start-up | A dependency released a breaking version (Typer 0.29 did; it is now held below 0.29) | Show the last green run; pin the dependency in `pyproject.toml` and rerun. |
| No alerts in the Security tab | Not logged in with write access, or the SARIF upload was skipped (fork PR) | Log in as an owner; use the run from `workflow_dispatch`. |
| Run cancelled | A newer push to the same pull request | Rerun from the run page. Dispatches and pushes to `main` are not cancelled. |
| GitHub is slow or down | | Fall back to the local one-command demo ([`DEMO1.md`](DEMO1.md)) and the artifact downloaded during rehearsal. |
