# Runbook: the CodeKavach CI pipeline

The repository's own continuous integration is part of the demo: a green badge on the README and a passing pipeline that checks the privacy claims on every push, not only on the day of the demo.

- Workflow: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- Runs on `main`: <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/workflows/ci.yml?query=branch%3Amain>
- Last green run checked for this runbook: see [Reference run](#reference-run).

## What to say (one minute)

"Every push to `main` runs the same gates a contributor runs locally with `make check`. Besides lint, types and tests on Linux and macOS with Python 3.12 and 3.13, the pipeline checks the privacy architecture itself: import contracts that make a second network path a build failure, the invariant tests I1 to I6, and the full offline demo with a zero-leak check on the egress ledger. A red pipeline blocks the badge; nothing here is a manual promise."

## What the pipeline proves

| Job | Command | What a green result means |
|-----|---------|---------------------------|
| `lint` | `make lock-check fmt-check lint changelog-check telemetry-check docs-check` plus schema drift, schema examples, CLI reference and schema compatibility | `uv.lock` matches `pyproject.toml`; Ruff format and lint clean; no telemetry package in the lock file; documentation links and anchors resolve; the published JSON Schemas and the command-line reference match the code; no breaking schema change without a version bump. |
| `typecheck` | `make type` | mypy in strict mode over `src/codekavach`. |
| `contracts` | `make contracts` (`lint-imports`) | The import contracts in `.importlinter` hold. The ones to name: **I1** only `privacy.egress.transport` may import a network client; **I2** the LLM layer never imports raw-code packages; **I3** the vault is not importable from analysis, LLM, risk, report or integrations; the CLI does not import the egress transport or the vault; no analysis engine is imported as a library (ADR-0002). |
| `hooks` | `pre-commit run --all-files`, then the secret scan as its own step | The same hooks a contributor runs: workflow schema, YAML/TOML/JSON, mypy, contracts, schema drift. The secret scan (detect-secrets against the audited `.secrets.baseline`) fails on a new finding; a baseline entry whose line number only moved does not fail it. |
| `commits` | `tools/dev/check_commit_msg.py --ci` | Every pushed commit follows `<area>: <summary>` with an issue reference and no tool attribution. |
| `test` (4 cells) | `make cov` with `-n auto --dist worksteal -m "not network and not perf"` | The whole suite on Linux and macOS, Python 3.12 and 3.13, on every core, with branch coverage and an 85 % gate. Sockets are disabled for every test (`pytest-socket`). This includes the privacy tests in `tests/privacy/`, below. |
| `perf` | `make perf` | The performance budgets on an unloaded runner: one process, no parallel workers, no coverage tracing. |
| `build` | `make build` | The wheel and sdist build; the wheel holds no tests, ships `py.typed` and the database migrations. |
| `licences` | `make licences` | Every runtime dependency's licence is allowed by the policy in `pyproject.toml`. |
| `demo` | `codekavach demo --out demo-out` (budget 3 minutes) | Demo 1 end to end on the mock provider: the scan, the ledger verification, the zero-leak check and the PDF report. The run fails if a listed KavachBank term occurs in any ledger payload. The pages are kept as the `demo-output` artefact. |
| `detector-eval` | `tools/detector_eval.py --check` | Recall of every HIGH-confidence secret/PII detector subtype on the labelled corpus is 1.0; the table is in the job summary. |
| `ui` | `npm ci && npm run build && npm test` in `ui/` | The web dashboard type-checks, builds and passes its unit tests. Green and skipped when `ui/package.json` is absent. |
| `docker` | `docker buildx build -f deploy/docker/Dockerfile` (no push) | The server image (API, dashboard and CLI) builds from a clean checkout. Publishing is the separate Container workflow. |
| `provider-conformance` | `pytest tests/conformance -m conformance` | Every registered LLM provider adapter (AgentRouter, OpenAI, Anthropic, Gemini and the others) meets the same request and response contract, in offline and recorded-cassette modes; no key and no connection. |
| `ci-ok` | | The single required check: green only when every job above is green. |

### The privacy invariants in the test job

These run in every `test` cell; the test files are under `tests/privacy/` and `tests/integration/`.

| Invariant | What is checked | Tests |
|-----------|-----------------|-------|
| I1 Single egress | Only the transport may import a network client; every other socket is refused; a new locked dependency must be classified as network-capable or reviewed offline before the build passes | `test_i1_single_egress.py`, `test_network_blocked.py`, `test_cli_no_network.py`, `test_core_offline.py` |
| I2 No raw code to the LLM layer | The LLM layer accepts sanitised payloads only; the static guard bites on a planted violation | `test_i2_static_guard.py`, `test_egress_guard.py`, `test_guard_bites.py` |
| I3 Vault locality | Vault contents never leave the vault module or appear in logs | `test_vault_locality.py`, `test_scoped_store.py`, `test_log_redaction_properties.py` |
| I4 Fail closed | An error or timeout in a privacy step blocks that candidate's payload | `test_fail_closed_pipeline.py`, `test_timeout_fail_closed.py` |
| I5 Determinism | Same salt, same input, same pseudonyms | `test_pseudonym_determinism.py`, `test_pipeline_salt_locality.py` |
| I6 Completeness | Property-based: no vault key of four or more characters occurs in any ledger payload; the ledger is hash-chained and tamper-evident | `test_i6_ledger.py`, `test_ledger_tamper.py`, `test_redaction_invariants.py` |
| Zero leak (demo) | The full KavachBank demo with sockets refused; no listed term in any ledger payload; a remote provider is refused | `tests/integration/test_demo_zero_leak.py` |

Run the privacy tests locally with `uv run pytest -n auto tests/privacy` (about a minute on four cores).

## Exact commands for the demo

Show in the browser (no terminal needed):

1. README on GitHub: the CI badge is green.
2. Click the badge: the list of runs on `main`. Open the latest green run.
3. The run summary graph: name the jobs from the table above. Open `test (ubuntu-latest, 3.12)`, scroll to the coverage total in the job summary.
4. Open the `contracts` job log: the line `Contracts: N kept, 0 broken.`
5. Open the `demo` job log: the zero-leak line and `report.pdf` written; download the `demo-output` artefact if asked.

Show the same gates locally (terminal, about two minutes without the full suite):

```bash
export PATH=$HOME/.local/bin:$PATH
uv sync --all-extras
make lint type contracts            # quality gates and import contracts
uv run pytest -q -n auto tests/privacy   # the invariant tests I1 to I6
uv run pytest -q tests/integration/test_demo_zero_leak.py
```

Expected output, in order: `All checks passed!` from Ruff; `Success: no issues found in N source files` from mypy; `Contracts: N kept, 0 broken.` from import-linter; `N passed` from both pytest runs.

To start a run by hand: on the Actions page choose **CI** then **Run workflow** on `main` (the workflow has a `workflow_dispatch` trigger).

## The time budget (issue #313)

The Linux test cell used to run every test, the perf budgets and coverage in one process, about 14.5 minutes against a 15-minute limit. Now the cells use all runner cores with pytest-xdist and the perf budgets have their own job with no parallel workers, so the timings stay meaningful. The `--durations=30` list at the end of each test cell's log names the slowest tests.

Measured on `main` over the twelve completed runs from 12 November 2026 22:12 UTC to 13 November 00:22 UTC, with about 12 700 tests: the Linux test jobs (`test (ubuntu-latest, 3.12)` and `3.13`) took 5 minutes 48 seconds to 11 minutes 39 seconds, never more than 59 % of the 20-minute job limit and under the old 15-minute limit in every run; the `perf` job took 4 to 7 minutes against 15. Issue #313 is closed on that record. The tests that run the whole KavachBank demo (one to two minutes each on a busy runner) are marked `slow` with their own 420-second timeout, and every test worker starts with the product's logging configuration, so a failing stage no longer renders a traceback with every frame's local variables.

## Secrets and the LLM in CI

CI never uses a real model and never needs a key: the demo job and every test use the offline `mock` or `replay` provider, and sockets are refused in tests. No repository secret is configured for CodeKavach.

A client who wants their own workflow to call a real provider adds the key as a repository secret named `CODEKAVACH_LLM_API_KEY` (Settings, Secrets and variables, Actions, New repository secret) and passes it to the step as an environment variable; see [`action/README.md`](../../action/README.md) and the [GitHub Actions runbook](github-actions.md). Never put a key in a workflow file or in the repository.

## If something is red on the day

| Symptom | Say | Do |
|---------|-----|----|
| The latest run is red or still running | "The team pushed during the last hours; here is the last completed green run." | Open the reference run below instead. |
| The latest run was cancelled | "Several commits arrived together; the pipeline tests the newest one and drops the queued ones in between." | Open the next completed run. |
| A macOS cell is slow or queued | "macOS runners are shared and slower; the Linux cells hold the same tests." | Open a Linux cell. |
| Only `commits` is red | "A commit message broke the convention, for example a subject over 72 characters. History on `main` is never rewritten; the job checks only the commits of each push, so the next push is judged on its own." | Open the job log: it names the commit and the rule. |
| Only the 3.13 test cells are red with `PytestUnraisableExceptionWarning ... sqlite3.Connection` | "Python 3.13 reports a database connection a test forgot to close; the warning lands on whichever test runs next, so the failing test name is not the culprit." | Find the test that creates a server or store without closing it (the serve banner tests were the last case, fixed in `63b22df`). |
| Only `hooks` is red at the secret scan step | "The scanner flags anything that looks like a credential, including a variable named `..._PASSWORD`. A real new secret blocks the push." | The log names the file and line; a name that is not a value gets `# pragma: allowlist secret`. |
| GitHub is unreachable | "The same gates run locally." | Run the local commands above. |

## Reference run

A green run of this pipeline on `main`, checked while preparing this runbook:

- <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/runs/43421402124>: commit `0254b15`, 13 November 2026 12:12 UTC, every job green (`ci-ok` success). `test (ubuntu-latest, 3.12)` took 9 minutes 2 seconds, `test (ubuntu-latest, 3.13)` 9 minutes 58 seconds, `perf` 5 minutes 54 seconds.
- <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/runs/43334263876>: commit `f05fcb2`, 13 November 2026, every job green (`ci-ok` success). `test (ubuntu-latest, 3.12)` took 10 minutes 44 seconds, `test (ubuntu-latest, 3.13)` 9 minutes 54 seconds, `perf` 4 minutes 24 seconds.
- <https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/runs/43331968149>: commit `eea512c`, 12 November 2026, every job green (`ci-ok` success), including the four test cells, `perf`, `ui`, `docker`, `demo`, `detector-eval` and `provider-conformance`. The test step of `test (ubuntu-latest, 3.12)` took 11 minutes 23 seconds, the whole job 11 minutes 39 seconds, against its 20-minute limit.

Later pushes from the feature streams may turn a run red until the next fix lands; open this run when the latest one is not green.
