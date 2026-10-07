# Using the command line

Owning epic: E05 (issue E05-33). Related: the generated [command-line reference](../reference/cli.md), [exit codes](../reference/exit-codes.md), [JSON output](../reference/cli-json-output.md), [global options](../reference/cli-global-options.md), [consent](../reference/cli-consent.md), [network behaviour](../reference/cli-network-behaviour.md), [`doctor`](../reference/cli-doctor.md) and the [configuration guide](../configuration/README.md).

This guide takes you from an installed tool to an audited report, and from there to a gated pipeline. It is written for two readers: a security engineer at a client (sections 1 to 6, 9 and 10) and a DevOps engineer (sections 7 and 8). Every section can be read on its own, so a command is repeated where it is needed instead of pointing back. The reference pages list every option; this page says which ones to reach for.

In the examples the program is called `codekavach`. From a checkout without an activated environment, put `uv run` in front of it. The examples use synthetic values only (`kavachbank`, `accrue_premium_interest`, `AKIAIOSFODNN7EXAMPLE`).

## What CodeKavach does and does not do

- It reviews source code and reports findings. It does not fix code and does not open pull requests.
- The evidence in a report is text snippets from the code, so a report holds client code. Treat it with the classification of the code.
- With the `mock` or `replay` provider, the ledger shows what would have been sent. Nothing was transmitted.
- A check that a listed term does not occur verbatim in the stored payloads does not measure structural leakage, which is what the shape of the code can reveal. The leakage evaluation measures that (epic E37).

## What this build can do

This is version 0.1.0.dev0. Some back ends belong to later epics. A command whose back end is missing exits with code 2 and prints `error[backend_unavailable]` with a hint that names the epic. The table is checked against the live command tree by `tests/docs/test_cli_guide_commands.py`, so it changes when a back end lands.

| Command | In this build | Epic |
|---------|---------------|------|
| `doctor`, `init`, `scan`, `providers list`, `privacy notice`, `privacy consent`, `completion`, `config` | yes | |
| `privacy inspect` | not in this build | E11 |
| `privacy ledger show`, `privacy ledger verify` | not in this build | E12 |
| `providers test` | not in this build | E22 |
| `report` | not in this build | E30 |
| `vault status`, `vault rotate`, `vault destroy` | not in this build | E10 |
| `demo` | not in this build | E13 |

`scan` runs the pipeline with the stages that are installed. With none installed it finishes with zero findings and the warning `no_stages`, so a clean result in this build says that nothing was analysed. Read the warning before you trust a result.

## 1 Install and check your setup

CodeKavach needs Python 3.12 or later. From a checkout:

```console
$ uv sync
$ codekavach version
codekavach 0.1.0.dev0
$ codekavach doctor
PASS  runtime:python              3.12.3
PASS  runtime:package             0.1.0.dev0
PASS  runtime:platform            Linux x86_64, stdout utf-8
PASS  config:valid                profile none, 0 warning(s)
PASS  storage:state-dir           does not exist yet and can be created
SKIP  storage:artefacts           not available in this build
PASS  storage:database            no database yet; the first scan creates it
SKIP  parsing:grammar:python      not available in this build
SKIP  parsing:grammar:javascript  not available in this build
WARN  secrets:keyring             the keyring backend is insecure and is refused
PASS  plugins:load                every allowed plugin loads
PASS  plugins:pipeline            0 stage(s) resolve into a valid order
PASS  provider:mock:configured    kind mock
SKIP  provider:mock:reachable     use --probe-providers
hint  secrets:keyring             install a keyring backend or use passphrase mode
9 passed, 1 warning, 0 failed, 4 skipped
```

Versions, platform and the keyring line differ between machines. `doctor` diagnoses and changes nothing. It exits with 1 when a required check failed (with `--strict`, also on a warning) and with 0 otherwise. A `WARN` is an optional tool that is missing, such as a keyring or an analysis engine, and the checks are listed in [cli-doctor.md](../reference/cli-doctor.md). `doctor` sends nothing over the network unless you pass `--probe-providers`.

## 2 First scan without any API key

The `demo` profile uses the `mock` provider, so nothing leaves the machine and no key is needed.

```console
$ codekavach init
wrote /path/to/proj/codekavach.toml
recommended: add .codekavach/ and codekavach-report/ to .gitignore (or run again with
--update-gitignore)
Next steps:
  1. Provide a key: export ANTHROPIC_API_KEY=... or codekavach config key set primary
  2. Check the configuration: codekavach config validate
  3. Scan: codekavach scan .
$ codekavach scan . --profile demo
         Scan
scan_01M4AZVWZEBM2972Q1
       4GCY9GS8
┌──────────┬──────────┐
│ Severity │ Findings │
├──────────┼──────────┤
│ critical │        0 │
│ high     │        0 │
│ medium   │        0 │
│ low      │        0 │
│ info     │        0 │
└──────────┴──────────┘
findings: 0
threshold: none; the severity gate is disabled
LLM provider: mock (local), level L3, payloads recorded: 0, blocked by guard: 0
provider is local/mock: payloads were recorded but not transmitted
next: codekavach privacy inspect --scan scan_01M4AZVWZEBM2972Q14GCY9GS8
next: codekavach report --scan scan_01M4AZVWZEBM2972Q14GCY9GS8
```

`init` writes a commented `codekavach.toml` and changes nothing else; `--stdout` prints it instead and `--minimal` leaves out the comments. The caption of the table is the scan id, wrapped to the width of the table, and the rows are the findings by severity. Then come the threshold, the provider with its privacy level, and the number of payloads that were recorded or blocked by the egress guard. The `next:` lines name the commands that continue from this scan. The warning `no_stages` goes to stderr, as every diagnostic does: stdout holds the result and stderr holds the rest.

The `demo` profile switches the severity gate off (`threshold: none`). A scan with another profile has a gate, so its exit code can be 1 (section 7).

## 3 See exactly what would be sent

Before you let any code go to a provider, look at what would be sent. Three commands show it, and they apply to the `mock` provider too, where the ledger records what would have been sent.

```console
$ codekavach privacy inspect --list
$ codekavach privacy ledger show
$ codekavach privacy ledger verify --check-terms terms.txt
```

- `privacy inspect` shows the original code next to the exact payload prepared for the model. `--list` prints only the table of payloads, `--limit` and `--file` select pairs, and `--candidate` picks a candidate by its id.
- `privacy ledger show` lists the recorded requests as metadata. It does not print payload text. `--outcome blocked` lists what the guard refused.
- `privacy ledger verify` recomputes the hash chain of the ledger and checks the stored payloads against their hashes. `--check-terms` takes a file with one sensitive term per line (four characters or more) and fails when a term occurs verbatim in a stored payload. `--ignore-case` also matches other capitalisation. A failed check exits with code 3.

These commands are not in this build yet (epics E11 and E12), so today each of them exits with code 2 and `error[backend_unavailable]`.

A terms file for the check holds terms like these:

```text
accrue_premium_interest
kavachbank
```

`codekavach privacy notice` prints the notice that the first run shows, for the effective settings, without marking it as shown.

> **What this does not protect.** What a payload still discloses is measured by the evaluation harness, not assumed to be zero. At levels L2 and L3 the control flow of a slice, the shape of string literals and the names of public library APIs are still visible to the provider. The term check shows that the terms you listed do not occur verbatim. It does not show that no meaning can be inferred from what remains; read "Known limits" in the repository `README.md` before you rely on a level for a sensitive path.

## 4 Choosing a privacy level and a provider

The privacy level says how much of the code is changed before it is sent. The strictness order is L1, L2, L3, L4, then L0, so L0 is the strictest.

| Level | What is sent | Meant for |
|-------|--------------|-----------|
| L0 | Nothing leaves. Only local engines or a local model | Air-gapped |
| L1 | Secrets and personal data replaced by typed placeholders | Trusted local or private model |
| L2 | L1, and identifiers, literals and comments pseudonymised | Private cloud tenancy |
| L3 | L2 applied to the minimal slice only (the default) | Public LLM APIs |
| L4 | No code; abstract data-flow facts and questions | Crown-jewel paths |

`--privacy-level` sets the level for one run and cannot go below the floor in `privacy.min_level`. The minimum of the provider's trust tier and the path rules in the configuration can make the level stricter for a provider or a file.

List the providers and the state of their credentials. Nothing is contacted.

```console
$ codekavach providers list --check-secrets
   id    kind  model  enabled  locality  host  tier   min level  credential    adapter
*  mock  mock  -      yes      local     -     local  L1         not-required  missing
default: mock (llm.default_provider = "auto")
```

The `adapter` column says whether this build has the adapter for the kind (epic E22). `codekavach providers test` sends a constant probe and reports whether the provider answers; it is not in this build yet.

A provider and its key belong in your user configuration file, not in the project file. A project file is written by whoever controls the repository, so an untrusted one may not set providers, endpoints or secret references (see "Project trust" in the [configuration guide](../configuration/README.md)). The key is a reference, not a value (the loader refuses a plaintext key, E03-19):

```toml
[llm.providers.primary]
kind = "anthropic"
model = "claude-sonnet-5-5"
api_key = "env:ANTHROPIC_API_KEY"
```

`codekavach config path` shows where the user file is, and `codekavach config key status` says whether a reference resolves.

**Consent.** CodeKavach does not contact a remote provider until a person has approved it for that provider and level ([consent](../reference/cli-consent.md)). A `mock`, a `replay` or a local provider needs none. The approval comes from, in this order: a stored grant, `--accept-egress` for one run, `CODEKAVACH_ACCEPT_EGRESS=1` for one process, or the question that `scan` asks on a terminal. Without one the run stops with exit code 3 before any work is done:

```console
$ codekavach scan . --provider primary
error[consent_required]: remote provider 'primary' has not been approved for level L3
hint: run 'codekavach privacy consent grant --provider primary' on a terminal, or pass --accept-egress for this run
```

Grants are kept per user, and a grant covers the level it was given for and every stricter one.

```console
$ codekavach privacy consent status
no consent has been recorded
store: /path/to/home/consent.json
$ codekavach privacy consent grant --provider primary
$ codekavach privacy consent revoke --provider primary
```

`privacy consent grant` shows the provider, the host, the model and the level, and asks. `--yes` approves without asking, and revoking with `--all` removes every grant.

## 5 Working offline

`--offline` opens no connection outside the machine: no remote provider and no integration. A command that needs the network is skipped or refused.

```console
$ codekavach scan . --offline --no-llm
$ codekavach scan . --profile airgapped
```

`--no-llm` runs the deterministic engines only. The built-in `airgapped` profile goes further: it sets the privacy level and its floor to L0, forbids remote providers (`llm.allow_remote = false`) and switches the GitHub and MCP integrations off. With it, `scan` prints `LLM provider: mock (local), level L0`. Which commands can reach the network at all is listed in [network behaviour](../reference/cli-network-behaviour.md), together with the tests that measure it.

## 6 Reports

`scan` writes the report formats that the profile or `--format` names, into the directory of `--output-dir` (default `codekavach-report`). The formats are `html`, `pdf`, `sarif` and `json`. The `report` command renders the reports of a stored scan again, without scanning:

```console
$ codekavach report --scan latest --format html --format sarif --output-dir codekavach-report
```

`--format` can be repeated or given as a comma-separated list, `--name` sets the file name without the extension, and `--no-overwrite` keeps existing files. The command is not in this build yet (epic E30). PDF output needs system libraries and a font that covers Devanagari; `codekavach doctor --category report` checks both. The paths of the written files are in the `report_files` list of the JSON result (section 8).

A report holds code snippets as evidence. Keep the report directory out of version control and give it the access of the code itself; `codekavach init --update-gitignore` adds it to `.gitignore`.

## 7 CI pipelines

The `ci` profile is meant for a pipeline run. It fails the scan on findings of high severity, writes SARIF, JSON and HTML reports, limits the model requests to 200 and does not ask questions. A session is non-interactive when `CI` is set, when `--json` or `--no-input` is given, or when stdin or stderr is not a terminal. A question that cannot be asked is answered no, so a missing approval fails with an error that names the flag to pass.

| Option | Effect |
|--------|--------|
| `--fail-on LEVEL` | Exit 1 when a finding at or above `critical`, `high`, `medium`, `low` or `info` exists; `none` switches the gate off |
| `--strict-privacy` | Exit 3 when the egress guard blocked a payload (without it the guard still refuses the payload and the exit code follows the findings) |
| `--strict` | Exit 4 when a stage failed and the scan went on |
| `--accept-egress` or `CODEKAVACH_ACCEPT_EGRESS=1` | Approve sending to the remote provider for this run |

**Exit codes.** `0` is clean. `1` is findings at or above the threshold. `2` is a usage, configuration or missing back end problem. `3` is a privacy control that refused the run. `4` is an internal failure, and `130` is a cancelled run. When several apply, the most severe wins: 4, then 3, then 1, then 0 ([exit codes](../reference/exit-codes.md)). A shell step that tells them apart:

```console
$ codekavach scan . --profile ci --json > result.json; code=$?
$ case $code in
    0) echo "clean" ;;
    1) echo "findings at or above threshold"; exit 1 ;;
    3) echo "privacy control refused the run"; exit 1 ;;
    *) echo "tool error ($code)"; exit $code ;;
  esac
```

**GitHub Actions.** The job installs CodeKavach, scans with the `mock` provider (no secret is needed), uploads the report directory and fails on every non-zero exit code. A finding (1) and a refusal (3) are reported as results; an internal failure (4) gets its own message.

```yaml
name: codekavach
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
      - name: Install CodeKavach
        run: |
          uv tool install git+https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET
          uv tool dir --bin >> "$GITHUB_PATH"
      - name: Scan
        run: |
          code=0
          codekavach scan . --profile ci --provider mock --json > result.json || code=$?
          case $code in
            0) echo "clean" ;;
            1) echo "::error::findings at or above the threshold" ;;
            3) echo "::error::a privacy control refused the run" ;;
            4) echo "::error::internal failure in CodeKavach; report it with the output of codekavach doctor" ;;
            *) echo "::error::codekavach exited with $code" ;;
          esac
          exit "$code"
      - name: Keep the reports
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: codekavach-report
          path: |
            codekavach-report/
            result.json
          if-no-files-found: ignore
```

The tool is installed from the project repository. Pin the reference to a commit (`...Tool-TIET@<commit>`), as you pin the actions, so that the pipeline does not change when the repository does.

**GitLab CI.**

```yaml
codekavach:
  image: python:3.12
  variables:
    UV_TOOL_BIN_DIR: /usr/local/bin
  script:
    - pip install uv
    - uv tool install git+https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET
    - |
      code=0
      codekavach scan . --profile ci --provider mock --json > result.json || code=$?
      case $code in
        0) echo "clean" ;;
        1) echo "findings at or above the threshold" ;;
        3) echo "a privacy control refused the run" ;;
        4) echo "internal failure in CodeKavach; report it with the output of codekavach doctor" ;;
        *) echo "codekavach exited with $code" ;;
      esac
      exit "$code"
  artifacts:
    when: always
    paths:
      - codekavach-report/
      - result.json
```

**A real provider in CI.** The key comes from the secret store of the platform, as an environment variable that the configuration refers to as `env:`. The provider belongs in a file that the pipeline writes outside the checkout and names with `--config`: a provider in the project file would be refused as untrusted, and a file outside the project root is treated as supplied by the operator. Consent for the run is given with `CODEKAVACH_ACCEPT_EGRESS`, because a configuration file cannot give it.

```yaml
      - name: Scan with a provider
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          CODEKAVACH_ACCEPT_EGRESS: "1"
        run: |
          cat > "$RUNNER_TEMP/codekavach.toml" <<'EOF'
          [llm.providers.primary]
          kind = "anthropic"
          model = "claude-sonnet-5-5"
          api_key = "env:ANTHROPIC_API_KEY"
          EOF
          codekavach scan . --profile ci --provider primary --config "$RUNNER_TEMP/codekavach.toml" --json > result.json
```

A workflow that runs for a pull request from a fork does not receive the secret, so use the `mock` job there. Do not trust the project file of such a pull request (`--trust-project-config`), because its author controls it.

## 8 Machine-readable output

With `--json`, stdout holds exactly one JSON document, the envelope, on one line. Progress, warnings for people and errors go to stderr, so do not merge the two streams with `2>&1`.

```console
$ codekavach scan . --profile ci --json
{"schema_version":"1","codekavach_version":"0.1.0.dev0","command":"scan","ok":true,"exit_code":0,"data":{"threshold":{"fail_on":"high","exceeded":false,"counted":0},"scan_id":"scan_01M4AZNDNJN3G9J7N6886NSV4C","target":".","privacy_level":"L3","provider":{"id":"mock","kind":"mock","remote":false,"model":null},"summary":{"findings_total":0,"by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0}},"egress":{"recorded":0,"blocked":0},"consent":{"source":"not-required"},"degraded_stages":[],"report_files":[],"state_dir":"/path/to/proj/.codekavach"},"warnings":[{"code":"no_stages","message":"no stages are installed; nothing was analysed","hint":null}],"errors":[]}
```

`ok` is true exactly when `exit_code` is 0, and the process exit code stays the authority. A scan with findings has `ok: false`, `exit_code: 1` and an empty `errors` list, so a consumer tells "completed with findings" from "failed" by `exit_code`. Keys that a consumer does not know are ignored; the envelope grows by adding keys ([JSON output](../reference/cli-json-output.md)).

Five recipes for `result.json`:

```console
$ jq '{ok, exit_code}' result.json
$ jq '.data.summary.by_severity' result.json
$ jq -r '.data.report_files[]' result.json
$ jq '.data.egress' result.json
$ jq -r '.errors[0].code // "none"' result.json
```

They give, in this order: whether the run passed and with which code; the number of findings per severity; the paths of the report files; the totals of payloads recorded and blocked by the egress guard; and the code of the first error, or `none`.

`--progress json` writes one JSON object per line to stderr while the scan runs, for a dashboard or a log collector:

```console
$ codekavach scan . --profile demo --progress json 2> progress.jsonl
$ jq -r '.event' progress.jsonl
scan.started
plan.resolved
scan.finished
```

The `--progress` modes are `auto`, `bar`, `plain`, `json` and `off`. The events of a stage run appear between `plan.resolved` and `scan.finished` once stages are installed.

## 9 Housekeeping

Each project keeps its state in `.codekavach/` (the vault, the ledger, the local database and the cache; `project.state_dir` changes it). Consent and the user configuration are per user, under the directory named by `CODEKAVACH_HOME` when it is set. Neither belongs in version control.

The vault holds the mapping between the original names and the pseudonyms that the provider saw. Its contents are not part of any output (invariant I3 in `docs/ARCHITECTURE.md`).

```console
$ codekavach vault status
$ codekavach vault rotate
$ codekavach vault destroy
```

- `vault status` shows metadata of the vault. `--unlock` unlocks it to count the entries.
- `vault rotate` re-encrypts the vault under a new key and is refused while a scan is running. `--key-backend` moves the key to the `keyring`, a `passphrase` or a `kms`.
- `vault destroy` deletes the vault, after which past scans can no longer be mapped back. It asks you to type the project name; `--yes` skips the question, and it is refused while a scan is running.

The vault commands are not in this build yet (epic E10). Shell completion is generated for your shell and printed to stdout:

```console
$ codekavach completion bash > ~/.local/share/bash-completion/completions/codekavach
```

`bash`, `zsh`, `fish` and `powershell` are supported; [cli-completion.md](../reference/cli-completion.md) has the line for each.

## 10 Troubleshooting

| Symptom | Exit | What to run |
|---------|------|-------------|
| `error[backend_unavailable]` with a hint such as `delivered by epic E12` | 2 | The command is not in this build ("What this build can do"). `codekavach doctor` lists the checks that are skipped for the same reason. |
| `warning[no_stages]` and zero findings | 0 | Nothing was analysed because no analysis stage is installed. `codekavach plugins list` and `codekavach doctor --category plugins` show what is installed. |
| `error[consent_required]` | 3 | Approve the provider: `codekavach privacy consent grant --provider ID` on a terminal, or `--accept-egress`, or `CODEKAVACH_ACCEPT_EGRESS=1` in a pipeline. |
| `error[confirmation_required]` in a pipeline | 2 | The session is non-interactive. Pass the flag that the hint names (for example `--yes`). |
| Configuration refused as untrusted (`CK-CFG-040`, `CK-CFG-041`) | 2 | `codekavach config validate`. Move the provider to your user file, or pass a file outside the project with `--config`, or review the file and run `codekavach config trust`. |
| `scan` exits with 1 | 1 | There are findings at or above the threshold. Read the summary and the report, or change the threshold with `--fail-on`. |
| `scan` exits with 3 under `--strict-privacy` | 3 | The egress guard blocked a payload. `codekavach privacy ledger show --outcome blocked` lists it (epic E12). |
| `WARN provider:ID:configured` | 0 | The reference does not resolve. `codekavach config key status`, then set the variable or change the reference. |
| `WARN report:pdf` or `report:fonts` | 0 | `codekavach doctor --category report` prints the install hint for your platform. |
| The JSON is not parseable | | stdout and stderr were merged. Redirect stdout only, as in section 8. |
| An `error[...]` line that names an exception type | 4 | Run the command again with `--debug` for a traceback on stderr, and include the output of `codekavach doctor` in the report. Exception text is not printed because it can quote code. |
| The run was interrupted | 130 | Run it again. |

Two settings help in most cases: `--verbose` prints more diagnostics on stderr, and `--log-file PATH` writes redacted debug logs to a file with mode `0600`.
