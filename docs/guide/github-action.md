# GitHub Action guide

CodeKavach as a security review step in your own pipeline, with your own keys. The action in [`action/`](../../action/README.md) installs the CLI on the runner, scans the checkout and publishes the result: a job summary, a SARIF file for the Security tab (code scanning), and outputs that later steps can use. It is the same core as the command line and the dashboard. With the `mock` provider or `provider: none` it opens no connection to a model, so it works before any key exists and nothing leaves the runner. Inputs, outputs and permissions are listed in the [action's README](../../action/README.md); other CI systems are covered in section 7 of the [command-line guide](cli.md#7-ci-pipelines).

## Add it to your repository

Copy this into `.github/workflows/codekavach.yml` of the repository to be reviewed. It starts with the mock provider, so it works before any key exists.

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
        uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@283b6d7f0f552713a0622e2ac0426eae7290451a # main, 2026-11-13
        with:
          target: .            # the repository root (see "Known limits")
          provider: mock       # the next section switches to a real model
          privacy-level: L3
          fail-on: high        # the job fails at or above this severity
      - name: Upload SARIF to code scanning
        if: always() && steps.ck.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          sarif_file: ${{ steps.ck.outputs.sarif-path }}
          category: codekavach
```

The action is pinned to a commit, not `@main`: the job runs whatever the ref points to with your token and key in its environment, so move the pin only after reviewing the new commit. The action's own `upload-sarif: "true"` input also works; it uses the same pinned upload action.

### A real model with your own key

1. Add the key as a repository secret named `CODEKAVACH_LLM_API_KEY`: **Settings**, **Secrets and variables**, **Actions**, **New repository secret**; or `gh secret set CODEKAVACH_LLM_API_KEY` and paste the key at the prompt. Keep the key out of files and workflow inputs (inputs are printed in the log).
2. Change the scan step:

```yaml
      - id: ck
        uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@283b6d7f0f552713a0622e2ac0426eae7290451a # main, 2026-11-13
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

This configuration has not been run on GitHub from the CodeKavach repository, which by design stores no key. The same provider settings were checked locally with `codekavach providers list`, which lists `agentrouter` (`gpt-5.6-sol`, host `agentrouter.org`, minimum level L3).

### Known limits

- Scan the repository root (`target: .`). Scanning a subdirectory of a git checkout can return no findings; the example workflow below scans a copy of the sample project for that reason.
- The vault key: the action sets a random passphrase for the job when the workflow does not choose a key source, because hosted runners have no OS keyring. The vault does not outlive the job. A workflow that verifies the ledger in later steps (as the example below does) sets the passphrase itself, at job level, so that every step uses the same one.


## A complete example: the review workflow of this repository

[`.github/workflows/codekavach-review.yml`](../../.github/workflows/codekavach-review.yml) runs the action on the sample application `fixtures/kavachbank` with the `mock` provider, verifies the egress ledger and publishes the result in four places. Use it as a model for a workflow that also keeps the reports and checks the ledger.

- Runs of the workflow: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/workflows/codekavach-review.yml>
- Code scanning alerts from CodeKavach: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/security/code-scanning?query=tool%3ACodeKavach> (the Security tab is visible to people with write access to the repository)

| Where | What |
|-------|------|
| Run page | One job, *Security review (kavachbank, mock provider, L3)*. The *CodeKavach scan* step reports the severity gate as failed (the sample has planted critical findings), but that step continues on error, so the run stays green and still publishes the findings. |
| Job summary | Severity table, the ten most severe findings with CWE and a link to the line, and the privacy attestation: level, provider, model requests recorded, ledger chain intact, stored payloads re-hashed, the zero-leak check with the number of planted terms searched. The action's own table of all findings follows. |
| Security tab, Code scanning | One alert per finding, tool *CodeKavach*, category `codekavach`, on the real file and line. The model saw a pseudonymised slice; the alert names the original file because the mapping was restored on the runner. |
| Artifact `codekavach-reports` (kept 30 days) | `report.html`, `report.pdf`, `codekavach.sarif`, `verification.txt`, `verification.json`, `summary.md`, `scan.json` |
| Pull request (same-repository pull requests only) | One comment with the same summary, updated in place on each push. |

The Security tab grades alerts by the numeric `security-severity` score in the SARIF, so its critical and high counts can differ from the severity column of the summary; the alerts and the findings are the same set.

What the zero-leak line does and does not show: it searches the stored payloads for each planted secret and identifier verbatim. Structure (control flow, library calls, the shape of literals) still leaves at L3; `codekavach eval leakage` measures that.

### Starting a run

From the browser: **Actions**, **CodeKavach review**, **Run workflow**, keep `fail-on: critical` and `privacy-level: L3`. With the GitHub CLI:

```console
$ gh workflow run codekavach-review.yml -R jatinsingh1603/Source-Code-Review-Tool-TIET -f fail-on=critical -f privacy-level=L3
$ gh run watch -R jatinsingh1603/Source-Code-Review-Tool-TIET
```

A run takes about four minutes. Triggers: `workflow_dispatch`; `pull_request` touching `fixtures/**`, `src/**` or the workflow; `push` to `main` touching `fixtures/kavachbank/**` or the workflow.

### What the workflow does

1. Copies `fixtures/kavachbank` to the runner's temporary directory without `ground-truth/` (the answer key) and `cassettes/` (recorded model answers), so the application is scanned as its own project, as in a client repository. Sets a random vault passphrase for the job (masked in the log).
2. Runs `uses: ./action` with `provider: mock`, `privacy-level: L3`, `fail-on: critical` and `continue-on-error: true`.
3. Renders `report.html` and `report.pdf` with `codekavach report`.
4. Runs `codekavach privacy ledger verify --check-terms ground-truth/terms.txt --include-blocked --require-payloads`. A failure here fails the job, because only the scan step has `continue-on-error`.
5. Rewrites the SARIF paths to be relative to the repository root and uploads them with `github/codeql-action/upload-sarif` (pinned to a commit) under category `codekavach`. Skipped for pull requests from forks, which get a read-only token.
6. Writes the job summary with [`.github/scripts/codekavach_summary.py`](../../.github/scripts/codekavach_summary.py), uploads the artifact (kept 30 days), and on same-repository pull requests posts or updates the comment marked `<!-- codekavach-review -->`.

Permissions: `contents: read`, `security-events: write` (SARIF), `actions: read` (code scanning reads the run), `pull-requests: write` (the comment). No secret is used.


## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Run red at *Verify the egress ledger* | A listed term in a payload, a broken chain, or a payload the vault key cannot open | Read `verification.txt` in the artifact; the failing line names the term and the payload hash. Do not rely on that run's attestation. |
| Scan step shows a Python traceback at start-up | A dependency released a breaking version | Pin the action to a commit whose lock file is known to work, and report it. |
| No alerts in the Security tab | You are not signed in with write access, or the SARIF upload was skipped (pull request from a fork) | Sign in as a maintainer; use a run started by `workflow_dispatch` or a push. |
| Run cancelled | A newer push to the same pull request | Rerun from the run page. Dispatches and pushes to `main` are not cancelled. |
| The job fails although the scan worked | Findings at or above `fail-on` | That is the gate. Lower it with `fail-on`, or add `continue-on-error: true` to the scan step and gate elsewhere. |
