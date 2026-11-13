# CodeKavach GitHub Action

Runs the CodeKavach CLI in your own CI, with your own keys, and publishes the results. It is a
composite action: it installs the CLI from this repository and calls `codekavach scan`,
`codekavach findings` and optionally `codekavach sync github`.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
- uses: jatinsingh1603/Source-Code-Review-Tool-TIET/action@283b6d7f0f552713a0622e2ac0426eae7290451a # main, 2026-11-13
  with:
    provider: none        # or agentrouter, openai, anthropic, ...
    privacy-level: L3
    fail-on: high
    upload-sarif: "true"
```

Pin the action to a commit hash, as above, not to `@main`: the job runs whatever that ref points
to with your token and provider key in its environment. Move the pin only after reviewing the new
commit.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | `.` | Directory to scan |
| `privacy-level` | `L3` | L0 to L4; what may leave your machine to an LLM |
| `provider` | `none` | `none` runs deterministic analysis only; otherwise a provider id |
| `model` | | Model override |
| `fail-on` | `high` | Fail the job at or above this severity (`none` never fails) |
| `upload-sarif` | `false` | Upload to code scanning (needs `security-events: write`) |
| `sync-issues` | `false` | One issue per finding (needs `issues: write`) |

Outputs: `scan-id`, `findings-count`, `highest-severity`, `sarif-path`, `outcome`.

## Secrets and consent

Provider keys and `GITHUB_TOKEN` are environment variables, never inputs (inputs show in logs). A
remote provider needs a recorded consent decision: the operator sets `CODEKAVACH_ACCEPT_EGRESS=1`
in the workflow, deliberately. The action does not set it. Requests to the LLM carry only the
sanitised payload of the chosen privacy level; the egress ledger records what was sent.

## Pull requests from forks

The action refuses to run an LLM provider on a `pull_request_target` trigger, because that
trigger exposes secrets while the scanned code is untrusted. Use `examples/codekavach-pr.yml`:
analysis on `pull_request` with a read-only token and no provider.

## Permissions

| Feature | Permission | If missing |
|---|---|---|
| Scan, job summary | `contents: read` | n/a |
| SARIF upload | `security-events: write` | the upload step fails; the scan result stands |
| Issue sync | `issues: write` | warning; the scan result stands |

## Air-gapped runners

Use `provider: none` or a local provider (Ollama). Nothing is sent outside the runner. The SARIF
upload and issue sync are the only calls to GitHub and can be left off.

## Not done here (needs a human)

- GitHub App registration and webhook hosting. `codekavach.integrations.github.webhook` has the
  signature check and an event-to-action mapping only.
- Marketplace publication (needs a public repository with a root `action.yml`).
- A Docker image variant. (The actions `action.yml` itself runs are pinned to commit hashes.)
- The workflow was not run on GitHub in this environment; `run.sh` was exercised locally.
