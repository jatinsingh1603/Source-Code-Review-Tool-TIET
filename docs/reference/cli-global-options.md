# Global command-line options

Every `codekavach` command accepts these options, before or after the subcommand
(`codekavach --json scan .` and `codekavach scan . --json` are equivalent). When an option is
given in both positions, the one nearer the subcommand wins. `--set` values from both positions
are combined.

Settings-backed options become the top layer of the configuration (precedence: defaults, user
file, project file, profile, `CODEKAVACH_*` settings variables, command line). They are applied
through the configuration loader, which enforces `privacy.min_level`, provider trust-tier floors
and organisation policy: a flag can make a run stricter or fail it (exit 2), never make it
silently weaker than configured.

| Option | Settings key | Settings-layer variable (E03-16) | Option variable |
|---|---|---|---|
| `--privacy-level L0..L4` | `privacy.level` | `CODEKAVACH_PRIVACY__LEVEL` | `CODEKAVACH_PRIVACY_LEVEL` |
| `--provider ID` | `llm.default_provider` | `CODEKAVACH_LLM__DEFAULT_PROVIDER` | `CODEKAVACH_PROVIDER` |
| `--model NAME` | `llm.model` | `CODEKAVACH_LLM__MODEL` | `CODEKAVACH_MODEL` |
| `--offline` | `llm.allow_remote = false`, `integrations.github.enabled = false`, `integrations.mcp.enabled = false` | (per key) | `CODEKAVACH_OFFLINE` |
| `--set KEY=VALUE` (repeatable) | `KEY` | `CODEKAVACH_<SECTION>__<KEY>` | none |

Output and loader options:

| Option | Meaning | Variable |
|---|---|---|
| `--json` | machine-readable JSON on stdout | `CODEKAVACH_JSON` |
| `--quiet`, `-q` | only results and errors | `CODEKAVACH_QUIET` |
| `--verbose`, `-v` (repeatable) | more diagnostics on stderr; `-vv` also prints tracebacks | `CODEKAVACH_VERBOSE` |
| `--debug` | tracebacks and debug logs on stderr | `CODEKAVACH_DEBUG` |
| `--no-input` | never prompt; a question that cannot be asked is answered no | none |
| `--log-level debug\|info\|warning\|error` | lowest level of log events on stderr; wins over `--verbose` and `--quiet` | `CODEKAVACH_LOG_LEVEL` |
| `--log-format console\|json` | format of log events on stderr | `CODEKAVACH_LOG_FORMAT` |
| `--log-file PATH` | also write debug logs to this file (mode `0600`), behind the same redaction as stderr | none |
| `--config PATH` | use this configuration file instead of the discovered project file | `CODEKAVACH_CONFIG` (read by the loader) |
| `--profile NAME` | apply a profile | `CODEKAVACH_PROFILE` (read by the loader) |
| `--no-user-config` | ignore the user configuration file | `CODEKAVACH_NO_USER_CONFIG` (read by the loader) |
| `--trust-project-config` | trust restricted keys in the project file for this run | `CODEKAVACH_TRUST_PROJECT_CONFIG` (read by the loader) |

## Commands with their own `--format`

The configuration commands (`codekavach config show|validate|path|profiles|key status`) have a `--format` option, because `config show` has more than one document form (`toml`, `json`). The two options do different things:

- `--format` selects the document. `--format json` prints it as raw JSON, meant for redirection into a file or for an editor integration.
- The global `--json` puts the JSON form of the same document into the envelope as `data`, with `exit_code` mirrored.

```text
$ codekavach config validate --json | jq '{ok, exit_code, valid: .data.valid}'
{"ok": true, "exit_code": 0, "valid": true}
```

`--json` together with another format on the command line (`--json --format toml`) is a usage error (`format_conflict`, exit 2). The document is the masked rendering in both cases: domain terms stay hidden and key references are shown as references.

`codekavach config ...` and `codekavach init` take the loader options (`--config`, `--profile`, `--no-user-config`, `--trust-project-config`, `--set`) from the global options above, before or after the command. `init --profile NAME` is the command's own option: it names the profile written into the new file.

## Logging

Log events go to stderr; stdout carries only the result of the command.

| Flags | Level on stderr |
|---|---|
| `--quiet` | `ERROR` |
| none | `WARNING` |
| `-v` | `INFO` |
| `-vv` or `--debug` | `DEBUG` |
| `-vvv` | `DEBUG`, including third-party loggers |

`--log-level` wins over these flags. Without any of them, `logging.level` applies when a configuration source sets it. The format is `--log-format`, else `json` under `--json`, else `logging.format` when configured, else `console`.

Every destination, including `--log-file`, sits behind the redaction processor of `codekavach.core.log`. Redaction catches secret-shaped values and oversized or multi-line fragments; it does not recognise arbitrary identifiers, so it reduces what a log can disclose and does not remove the risk.

## Non-interactive use

Some commands ask for confirmation: the consent gate before remote egress, destructive vault operations and key deletion. Questions are written to stderr and read from stdin.

A session is non-interactive when any of these holds: `--no-input`; `--json`; stdin or stderr is not a terminal; the environment variable `CI` is set to anything but `0` or `false`; the `ci` profile is active. In a non-interactive session no question is asked and the answer is "no": the command fails with `error[confirmation_required]` and a hint that names the pre-approval flag of that command (for example `--yes` or `--accept-egress`).

No environment variable and no configuration key means "yes". Pre-approval is always an explicit flag of the command that needs it.

## Rules

- `--offline` means this invocation opens no connection outside the machine: remote LLM providers
  are forbidden, the GitHub and MCP integrations are disabled and network probes are skipped. It
  does not change `privacy.level`; the persistent, stricter variant is the `airgapped` profile.
- `--model` needs a concrete provider: pass `--provider` or set `llm.default_provider`
  (`error[model_needs_provider]`, exit 2).
- `--offline` together with a remote provider fails (`error[offline_remote_conflict]`, exit 2).
- `--quiet` and `--verbose` contradict each other (`error[quiet_verbose_conflict]`, exit 2).
- `--help`, `--version` and `completion` read no configuration, so they are safe to run inside an
  untrusted repository.

## Commands delivered by later milestones

Four commands exist now, with their full option surface, although the code behind them belongs to later epics. Their grammar is fixed early so that the GitHub Action, the evaluation scripts and the demo runbook can be written against it, and so that the reference and the help snapshots show it.

| Command | What it will do | Back end | Epic |
|---------|-----------------|----------|------|
| `sync github` | Create or update one issue per finding in the client's repository and place the items on the client's Projects v2 board. It does not modify code, open pull requests or push commits. | `codekavach.integrations.github.run_github_sync` | E34 |
| `eval detection` | Measure detection quality on a labelled dataset, per privacy level and provider. | `codekavach.eval.run_detection_eval` | E36 |
| `eval leakage` | Attack the prepared payloads of a scan or dataset and report what an attacker recovers. | `codekavach.eval.run_leakage_eval` | E37 |
| `demo` | Run the Demo 1 sequence offline on the mock provider: scan, `privacy inspect --list`, `privacy ledger verify --check-terms`, report. | `codekavach.cli.demo_runner.run_demo` | E13 |

Each command validates its arguments first (a repository must look like `OWNER/NAME`, a level is `L0` to `L4`, a dataset path must exist, `sync github` refuses `--offline`), and then looks for its back end. While the owning epic has not landed, the outcome is the same for all four, in both output modes:

```text
error[backend_unavailable]: GitHub sync is not available in this build
hint: delivered by epic E34
```

The exit code is 2. Under `--json` the result is one envelope with `"ok": false`, `"data": null` and the same code, message and hint in `errors`. The commands do not pretend: they print no invented metric, write no placeholder file and open no connection. When the back end is present the command calls it once with the parsed arguments and prints its report.

`sync github` takes no token option. The token comes from the secret reference `integrations.github.token` (for example `env:GITHUB_TOKEN`), and the repository defaults to `integrations.github.repository`. `demo` uses the mock provider, so no consent is involved.
