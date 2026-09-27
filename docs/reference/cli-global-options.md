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
| `--config PATH` | use this configuration file instead of the discovered project file | `CODEKAVACH_CONFIG` (read by the loader) |
| `--profile NAME` | apply a profile | `CODEKAVACH_PROFILE` (read by the loader) |
| `--no-user-config` | ignore the user configuration file | `CODEKAVACH_NO_USER_CONFIG` (read by the loader) |
| `--trust-project-config` | trust restricted keys in the project file for this run | `CODEKAVACH_TRUST_PROJECT_CONFIG` (read by the loader) |

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
