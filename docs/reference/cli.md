# Command-line reference

This page is produced by tools/gen_cli_docs.py from the command tree. Do not edit it by hand.

Every command accepts `--help` / `-h`. The global options below are accepted before or after the sub-command. For a walk-through by task, see the [CLI user guide](../guide/cli.md).

## Contents

- [Global options](#global-options)
- [Exit codes](#exit-codes)
- [codekavach](#codekavach)
- [codekavach completion](#codekavach-completion)
- [codekavach config](#codekavach-config)
- [codekavach config init](#codekavach-config-init)
- [codekavach config key](#codekavach-config-key)
- [codekavach config key delete](#codekavach-config-key-delete)
- [codekavach config key set](#codekavach-config-key-set)
- [codekavach config key status](#codekavach-config-key-status)
- [codekavach config path](#codekavach-config-path)
- [codekavach config policy](#codekavach-config-policy)
- [codekavach config policy show](#codekavach-config-policy-show)
- [codekavach config policy sign](#codekavach-config-policy-sign)
- [codekavach config policy verify](#codekavach-config-policy-verify)
- [codekavach config profiles](#codekavach-config-profiles)
- [codekavach config schema](#codekavach-config-schema)
- [codekavach config show](#codekavach-config-show)
- [codekavach config trust](#codekavach-config-trust)
- [codekavach config untrust](#codekavach-config-untrust)
- [codekavach config validate](#codekavach-config-validate)
- [codekavach demo](#codekavach-demo)
- [codekavach doctor](#codekavach-doctor)
- [codekavach eval](#codekavach-eval)
- [codekavach eval detection](#codekavach-eval-detection)
- [codekavach eval leakage](#codekavach-eval-leakage)
- [codekavach init](#codekavach-init)
- [codekavach plugins](#codekavach-plugins)
- [codekavach plugins check](#codekavach-plugins-check)
- [codekavach plugins list](#codekavach-plugins-list)
- [codekavach privacy](#codekavach-privacy)
- [codekavach privacy consent](#codekavach-privacy-consent)
- [codekavach privacy consent grant](#codekavach-privacy-consent-grant)
- [codekavach privacy consent revoke](#codekavach-privacy-consent-revoke)
- [codekavach privacy consent status](#codekavach-privacy-consent-status)
- [codekavach privacy inspect](#codekavach-privacy-inspect)
- [codekavach privacy ledger](#codekavach-privacy-ledger)
- [codekavach privacy ledger show](#codekavach-privacy-ledger-show)
- [codekavach privacy ledger verify](#codekavach-privacy-ledger-verify)
- [codekavach privacy notice](#codekavach-privacy-notice)
- [codekavach providers](#codekavach-providers)
- [codekavach providers list](#codekavach-providers-list)
- [codekavach providers test](#codekavach-providers-test)
- [codekavach report](#codekavach-report)
- [codekavach scan](#codekavach-scan)
- [codekavach sync](#codekavach-sync)
- [codekavach sync github](#codekavach-sync-github)
- [codekavach vault](#codekavach-vault)
- [codekavach vault destroy](#codekavach-vault-destroy)
- [codekavach vault rotate](#codekavach-vault-rotate)
- [codekavach vault status](#codekavach-vault-status)
- [codekavach version](#codekavach-version)

## Global options

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--config` | PATH |  | Configuration file to use instead of the discovered project file. |
| `--profile` | TEXT |  | Profile to apply (for example demo or ci). |
| `--privacy-level` | [L0\|L1\|L2\|L3\|L4] |  | Privacy level for this run; cannot go below the configured floor. Environment: `CODEKAVACH_PRIVACY_LEVEL`. |
| `--provider` | TEXT |  | LLM provider id to use. Environment: `CODEKAVACH_PROVIDER`. |
| `--model` | TEXT |  | Model of the selected provider. Environment: `CODEKAVACH_MODEL`. |
| `--offline` | flag | off | Open no connection outside this machine (no remote provider or integration). Environment: `CODEKAVACH_OFFLINE`. |
| `--json` | flag | off | Write machine-readable JSON to stdout. Environment: `CODEKAVACH_JSON`. |
| `--quiet`, `-q` | flag | off | Print only results and errors. Environment: `CODEKAVACH_QUIET`. |
| `--verbose`, `-v` | count |  | More diagnostics on stderr; repeat for more. Environment: `CODEKAVACH_VERBOSE`. |
| `--debug` | flag | off | Print tracebacks and debug logs on stderr. |
| `--log-level` |  |  | Lowest level of log events on stderr; wins over --verbose and --quiet. Environment: `CODEKAVACH_LOG_LEVEL`. |
| `--log-format` |  |  | Format of log events on stderr. Environment: `CODEKAVACH_LOG_FORMAT`. |
| `--log-file` | PATH |  | Also write redacted debug logs to this file (created with mode 0600). |
| `--no-input` | flag | off | Never prompt; a question that cannot be asked is answered no. |
| `--no-user-config` | flag | off | Ignore the user configuration file. |
| `--trust-project-config` | flag | off | Trust restricted keys in the project configuration for this run. |
| `--set` | KEY=VALUE (repeatable) |  | Override one setting; may be repeated. |

## Exit codes

```text
Exit codes:
  0    OK             completed; nothing at or above the threshold
  1    FINDINGS       completed; problems at or above the threshold
  2    USAGE          cannot run as invoked (options, configuration, input, missing back end)
  3    PRIVACY_BLOCK  a privacy control refused the operation
  4    INTERNAL       unexpected failure inside CodeKavach
  130  CANCELLED      interrupted by the user
Precedence at the end of a command: 4 over 3 over 1 over 0; 2 only before work starts.
```

## codekavach

Privacy-preserving, LLM-assisted secure source code review.

```text
Usage: codekavach [OPTIONS] COMMAND [ARGS]...
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--version`, `-V` | flag | off | Show the version and exit. |

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach completion

Print a shell completion script.

Redirect it into your shell's completion directory; see docs/reference/cli-completion.md.

```text
Usage: codekavach completion [OPTIONS] [shell]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `SHELL` | TEXT |  | bash, zsh, fish or powershell; detected from SHELL when omitted. |

Global options apply.

## codekavach config

Inspect and manage configuration.

```text
Usage: codekavach config [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach config init

Write a commented starter codekavach.toml rendered from the settings models.

```text
Usage: codekavach config init [OPTIONS] [path]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `PATH` | PATH |  | Directory to write codekavach.toml into. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--profile` | TEXT |  | Profile to select in the file. |
| `--minimal` | flag | off | Only the active settings, without comments. |
| `--force` | flag | off | Replace an existing file; keeps a .bak copy. |
| `--stdout` | flag | off | Print the file instead of writing it. |
| `--update-gitignore` | flag | off | Add the state and report directories. |

Global options apply.

## codekavach config key

Store API keys in the OS keyring. The value is read from a hidden prompt or from standard input, never from an argument. Automation: printf %s "$KEY" | codekavach config key set primary --stdin

```text
Usage: codekavach config key [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach config key delete

Remove a key from the OS keyring; deleting a missing entry is not an error.

```text
Usage: codekavach config key delete [OPTIONS] {name}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `NAME` | TEXT | required | Entry name. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--service` | TEXT | codekavach | Keyring service. |
| `--yes` | flag | off | Delete without asking. |

Global options apply.

## codekavach config key set

Store a key in the OS keyring and print the reference to use.

```text
Usage: codekavach config key set [OPTIONS] {name}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `NAME` | TEXT | required | Entry name, usually the provider id. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--service` | TEXT | codekavach | Keyring service. |
| `--stdin` | flag | off | Read the key from standard input. |

Global options apply.

## codekavach config key status

Show which references each enabled provider and integration would try, and their state.

```text
Usage: codekavach config key status [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--format` | text \| json | text | Output format. |

Global options apply.

## codekavach config path

List every location CodeKavach reads, and whether it exists; creates nothing.

```text
Usage: codekavach config path [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | PATH |  | Project directory (default: here). |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--format` | text \| json | text | Output format. |

Global options apply.

## codekavach config policy

Inspect organisation policies and sign or verify their detached Ed25519 signatures. No key material is ever taken from an argument or printed.

```text
Usage: codekavach config policy [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach config policy show

Show the organisation policies that apply here, with their signature state.

```text
Usage: codekavach config policy show [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | PATH |  | Project directory; default: the current directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--format` | text \| json | text | Output format. |

Global options apply.

## codekavach config policy sign

Sign a policy file with an Ed25519 key and write the detached signature.

Meant for the policy owner's workstation, not for pipelines: keep the private key offline. An encrypted key's passphrase is asked for with hidden input. Create a key pair with `openssl genpkey -algorithm ed25519 -out policy.key` and `openssl pkey -in policy.key -pubout -out policy.pub`.

```text
Usage: codekavach config policy sign [OPTIONS] {policy}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `POLICY` | PATH | required | The policy file to sign. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--key` | PATH | required | Ed25519 private key, PEM PKCS#8 (mode 600). |
| `--out` | PATH |  | Signature file; default: POLICY.sig. |

Global options apply.

## codekavach config policy verify

Verify a policy's detached Ed25519 signature; exit 2 with code 054 when it fails.

```text
Usage: codekavach config policy verify [OPTIONS] {policy}
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `POLICY` | PATH | required | The policy file to verify. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--pubkey` | PATH | required | Ed25519 public key, PEM SubjectPublicKeyInfo. |
| `--sig` | PATH |  | Signature file; default: POLICY.sig. |

Global options apply.

## codekavach config profiles

List the built-in and user-defined profiles.

```text
Usage: codekavach config profiles [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | PATH |  | Project directory (default: here). |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--format` | text \| json | text | Output format. |

Global options apply.

## codekavach config schema

Print the JSON Schema of codekavach.toml, for editors and validation tools.

```text
Usage: codekavach config schema [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--policy` | flag | off | The schema of an organisation policy.toml instead. |
| `--output` | PATH |  | Write the schema to this file. |

Global options apply.

## codekavach config show

Print the configuration in force, masked, optionally with the origin of every key.

```text
Usage: codekavach config show [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | PATH |  | Project directory (default: here). |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--effective` | flag | on | Show the effective configuration (default). |
| `--layer` | TEXT |  | Show one layer: default, user, project, profile, env, cli. |
| `--format` | toml \| json | toml | Output format. |
| `--origin` | flag | off | Annotate every key with where its value came from. |
| `--section` | TEXT |  | Show one top-level table only. |
| `--check-secrets` | flag | off | Report whether each key reference resolves. |
| `--reveal-domain-terms` | flag | off | Print privacy.domain_terms in clear. |

Global options apply.

## codekavach config trust

Trust a project's configuration file, as it is now.

```text
Usage: codekavach config trust [OPTIONS] [path]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `PATH` | PATH |  | Project directory (default: here). |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--yes` | flag | off | Trust without asking. |
| `--list` | flag | off | List trusted projects instead of trusting one. |
| `--format` | text \| json | text | Format of --list. |

Global options apply.

## codekavach config untrust

Forget the trust granted to a project.

```text
Usage: codekavach config untrust [OPTIONS] [path]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `PATH` | PATH |  | Project directory (default: here). |

Global options apply.

## codekavach config validate

Check the configuration a scan would use, without scanning anything.

```text
Usage: codekavach config validate [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | PATH |  | Project directory (default: here). |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--format` | text \| json | text | Output format. |
| `--strict` | flag | off | Exit 1 when warnings are present. |
| `--check-secrets` | flag | off | Resolve the keys that a scan would use. |

Global options apply.

## codekavach demo

Run the Demo 1 sequence offline on the mock provider.

Runs, in order: a scan of the fixture, `privacy inspect --list`, `privacy ledger verify --check-terms` and the report, and writes the results below --out. Nothing leaves the machine. Delivered by epic E13.

```text
Usage: codekavach demo [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--fixture` | NAME_OR_PATH | kavachbank | The sample project to scan. |
| `--out` | PATH | codekavach-demo/ | Directory for the demo output. |
| `--keep-state` | flag | off | Keep the state directory after the demo. |

Global options apply.

## codekavach doctor

Check that this machine is ready to scan.

```text
Usage: codekavach doctor [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--category` | TEXT (repeatable) |  | Run this category only; repeatable. |
| `--check` | TEXT (repeatable) |  | Run this check only; repeatable. |
| `--strict` | flag | off | Warnings count as failures. |
| `--list` | flag | off | List the checks and run nothing. |
| `--timeout` | FLOAT >= 0.1 | 10.0 | Seconds allowed per check. |
| `--probe-providers` | flag | off | Also send a constant probe to each enabled provider (a few tokens on a paid API); remote providers need consent. |
| `--accept-egress` | flag | off | Approve contacting remote providers for the probe in this run. |

Global options apply.

## codekavach eval

Run the detection and leakage evaluations.

```text
Usage: codekavach eval [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach eval detection

Measure detection quality (precision, recall) on a benchmark dataset.

Runs the scan on a labelled dataset at each requested privacy level and with each requested provider, and compares the findings with the labels. Delivered by epic E36.

```text
Usage: codekavach eval detection [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--dataset` | NAME_OR_PATH | required | Benchmark dataset to evaluate on. |
| `--level` | Lx (repeatable) |  | Privacy level to evaluate; repeat for several (L0 to L4). |
| `--provider` | ID (repeatable) |  | Provider to evaluate; repeat for several. |
| `--out` | PATH |  | Where to write the results. |
| `--limit` | INTEGER >= 1 |  | Evaluate at most this many cases. |

Global options apply.

## codekavach eval leakage

Measure what a curious provider could reconstruct from the prepared payloads.

Attacks the payloads of a stored scan, or of a dataset, at each requested privacy level and reports how much an attacker recovers. Takes --scan or --dataset, not both; without either it uses the latest scan. Delivered by epic E37.

```text
Usage: codekavach eval leakage [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--scan` | [SCAN_ID\|latest] |  | A stored scan to attack. |
| `--dataset` | NAME_OR_PATH |  | A dataset to prepare and attack. |
| `--level` | Lx (repeatable) |  | Privacy level to evaluate; repeat for several (L0 to L4). |
| `--attacker` | NAME (repeatable) |  | Attack to run; repeat for several. |
| `--out` | PATH |  | Where to write the results. |

Global options apply.

## codekavach init

Write a commented starter codekavach.toml rendered from the settings models.

```text
Usage: codekavach init [OPTIONS] [path]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `PATH` | PATH |  | Directory to write codekavach.toml into. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--profile` | TEXT |  | Profile to select in the file. |
| `--minimal` | flag | off | Only the active settings, without comments. |
| `--force` | flag | off | Replace an existing file; keeps a .bak copy. |
| `--stdout` | flag | off | Print the file instead of writing it. |
| `--update-gitignore` | flag | off | Add the state and report directories. |

Global options apply.

## codekavach plugins

Inspect installed plugins and check that their stages form a pipeline.

Loads every installed plugin that the  settings allow.

```text
Usage: codekavach plugins [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach plugins check

Check that the installed stages resolve into a valid order. Loads every installed plugin.

```text
Usage: codekavach plugins check [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--strict` | flag | off | Also fail when two plugins share a name. |

Global options apply.

## codekavach plugins list

List every installed plugin with its status. Loads every installed plugin.

```text
Usage: codekavach plugins list [OPTIONS]
```

Global options apply.

## codekavach privacy

Inspect what is prepared for, and recorded as sent to, LLM providers.

```text
Usage: codekavach privacy [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach privacy consent

Show, grant and revoke consent for sending payloads to remote providers.

```text
Usage: codekavach privacy consent [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach privacy consent grant

Approve sending sanitised payloads to a remote provider at a level or stricter.

```text
Usage: codekavach privacy consent grant [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--provider` | TEXT | required | Provider id to approve. |
| `--level` | TEXT |  | Least strict level to approve; default: effective level. |
| `--yes` | flag | off | Approve without asking. |

Global options apply.

## codekavach privacy consent revoke

Remove recorded consent; the next remote run asks again.

```text
Usage: codekavach privacy consent revoke [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--provider` | TEXT |  | Provider id whose grants to remove. |
| `--all` | flag | off | Remove every grant. |

Global options apply.

## codekavach privacy consent status

List the recorded grants.

```text
Usage: codekavach privacy consent status [OPTIONS]
```

Global options apply.

## codekavach privacy inspect

Show original code next to the exact payload prepared for the LLM.

```text
Usage: codekavach privacy inspect [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--scan` | TEXT | latest | Scan id, or latest. |
| `--candidate` | TEXT (repeatable) |  | Candidate id; repeatable. |
| `--file` | TEXT |  | Only candidates with a location matching. |
| `--limit` | INTEGER | 5 | Pairs to show; 0 shows all. |
| `--layout` | auto \| columns \| stacked | auto | auto, columns or stacked. |
| `--list` | flag | off | Only the table of payloads, no code. |
| `--include-payload` | flag | off | JSON mode: add the sanitised text. |

Global options apply.

## codekavach privacy ledger

Audit the egress ledger.

```text
Usage: codekavach privacy ledger [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach privacy ledger show

List ledger entries as metadata (never payload text).

```text
Usage: codekavach privacy ledger show [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--scan` | TEXT | latest | Scan id, latest or all. |
| `--outcome` | sent \| blocked \| completed \| failed (repeatable) |  | Outcome to list; repeatable. |
| `--limit` | INTEGER | 50 | Records to show; 0 shows all. |
| `--since` | TEXT |  | Only records at or after this ISO 8601 time. |

Global options apply.

## codekavach privacy ledger verify

Recompute the hash chain and check stored payloads against their hashes.

```text
Usage: codekavach privacy ledger verify [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--require-payloads` | flag | off | Fail when a payload is missing or unreadable. |
| `--check-terms` | PATH (repeatable) |  | File of sensitive terms (one per line, 4+ characters) that must not occur verbatim in any stored payload; repeatable. Avoid generic words: a term equal to a placeholder subtype such as email matches the placeholders. |
| `--ignore-case` | flag | off | Also match terms case-insensitively. |
| `--include-blocked` | flag | off | Hits in blocked payloads also fail the check. |

Global options apply.

## codekavach privacy notice

Show the privacy notice for the effective settings; it is not marked as shown.

```text
Usage: codekavach privacy notice [OPTIONS]
```

Global options apply.

## codekavach providers

Inspect and test LLM providers.

```text
Usage: codekavach providers [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach providers list

List the configured providers; contacts nothing.

```text
Usage: codekavach providers list [OPTIONS]
```

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--kinds` | flag | off | List the adapter kinds of this build instead. |
| `--check-secrets` | flag | off | Report whether each credential reference resolves. |
| `--all` | flag | off | Include disabled providers. |

Global options apply.

## codekavach providers test

Send a constant probe to a provider and report whether it answers.

```text
Usage: codekavach providers test [OPTIONS] [provider_id]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `PROVIDER_ID` | TEXT |  | Provider id; default: the provider a scan would use. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--model` | TEXT |  | Model to use for this test. |
| `--structured` | flag | off | Also run the structured-output probe. |
| `--accept-egress` | flag | off | Approve contacting a remote provider for this run. |
| `--timeout` | FLOAT >= 1.0 | 30.0 | Seconds allowed per provider. |
| `--all` | flag | off | Test every enabled provider in turn. |

Global options apply.

## codekavach report

Render the report of a stored scan.

```text
Usage: codekavach report [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory whose stored scans are used. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--scan` | TEXT | latest | Scan id, or latest. |
| `--format` | TEXT (repeatable) |  | Report format(s); repeatable or comma-separated. |
| `--output-dir` | PATH |  | Directory for the report files. |
| `--name` | TEXT | report | File name without extension. |
| `--overwrite / --no-overwrite` | flag | on | Replace existing files. |
| `--fail-fast` | flag | off | Stop at the first format that fails. |

Global options apply.

## codekavach scan

Scan a code base and print a severity summary.

```text
Usage: codekavach scan [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Directory, archive or git URL to scan. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--fail-on` | critical \| high \| medium \| low \| info \| none |  | Severity that fails the scan. |
| `--no-llm` | flag | off | Run deterministic engines only. |
| `--format` | TEXT (repeatable) |  | Report format(s); repeatable or comma-separated. |
| `--output-dir` | PATH |  | Directory for report files. |
| `--jobs` | INTEGER |  | Worker processes. |
| `--include` | TEXT (repeatable) |  | Glob to include; repeatable. |
| `--exclude` | TEXT (repeatable) |  | Glob to exclude; repeatable; replaces configured ones. |
| `--rules` | PATH (repeatable) |  | Extra rule path; repeatable. |
| `--engine` | TEXT (repeatable) |  | Engine to enable; repeatable. |
| `--skip-engine` | TEXT (repeatable) |  | Engine to disable; repeatable. |
| `--strict` | flag | off | Exit 4 when a stage failed and the scan continued. |
| `--strict-privacy` | flag | off | Exit 3 when the egress guard blocked a payload. |
| `--resume` | [SCAN_ID\|latest] |  | Continue an interrupted scan (latest when no id is given). Needs the stored scan salt of the vault (E10); until then it is refused with resume_salt_changed. |
| `--no-cache` | flag | off | Run every stage again; use no cached result. |
| `--refresh-stage` | TEXT (repeatable) |  | Stage or group to run again; repeatable. |
| `--accept-egress` | flag | off | Approve sending sanitised payloads to the remote provider for this run. |
| `--progress` | auto \| bar \| plain \| json \| off | auto | Progress on stderr: auto picks bar on a terminal, plain when piped, off under --quiet or --json. |

Global options apply.

## codekavach sync

Send findings to a client system.

```text
Usage: codekavach sync [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach sync github

Create or update GitHub issues for a scan's findings and place them on a board.

Creates or updates one issue per finding in the client's repository and places the items on the client's Projects v2 board. It does not modify code, open pull requests or push commits. The token comes from the secret reference integrations.github.token, never from an option. It needs the network and refuses --offline. Delivered by epic E34.

```text
Usage: codekavach sync github [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--scan` | [SCAN_ID\|latest] | latest | The scan to send. |
| `--repo` | OWNER/NAME |  | Repository for the issues; default: integrations.github.repository. |
| `--project` | NUMBER_OR_URL |  | Projects v2 board to update. |
| `--issues / --no-issues` | flag | on | Create or update one issue per finding. |
| `--board / --no-board` | flag | on | Place the items on the project board. |
| `--dry-run` | flag | off | Show what would change; change nothing. |
| `--max-issues` | INTEGER >= 1 |  | Create or update at most this many issues. |

Global options apply.

## codekavach vault

Manage the local mapping vault. Its contents never appear in any output.

```text
Usage: codekavach vault [OPTIONS] COMMAND [ARGS]...
```

Run a sub-command with `--help` for its options.

Global options apply.

## codekavach vault destroy

Delete the vault; past scans can then no longer be mapped back. Refused during a scan.

```text
Usage: codekavach vault destroy [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--yes` | flag | off | Delete without asking for the project name. |

Global options apply.

## codekavach vault rotate

Re-encrypt the vault under a new key. Refused while a scan is running.

```text
Usage: codekavach vault rotate [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--key-backend` | keyring \| passphrase \| kms |  | Move the key to another backend. |

Global options apply.

## codekavach vault status

Show metadata of the project's vault; nothing is unlocked without --unlock.

```text
Usage: codekavach vault status [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | Project directory. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--unlock` | flag | off | Unlock the vault to count its entries. |

Global options apply.

## codekavach version

Show the version and exit.

```text
Usage: codekavach version [OPTIONS]
```

Global options apply.
