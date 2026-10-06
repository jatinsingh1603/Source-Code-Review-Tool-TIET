# Configuration reference

This page is produced from the settings models by `uv run python -m codekavach.config.docgen` and must not be edited by hand.
A test fails when it is stale. Settings are read from `codekavach.toml`, the user configuration
file, profiles, the environment and command-line flags, in that order of precedence (ADR-0006).
The error codes are in [error-codes.md](error-codes.md).

**Notation.** `a.b` is the key `b` in the table `[a]`. In keys, `*` stands for a name you choose
(`llm.providers.*.base_url` is the `base_url` of each provider you define) and `[]` for one item
of a list of tables (`privacy.paths[].level`). Keys with a `*` or `[]` have no environment
variable. Other keys are set with `CODEKAVACH_<SECTION>__<KEY>`, for example
`CODEKAVACH_SCAN__JOBS`; `<SECTION>` and `<KEY>` are the upper-case names.

## General

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `config_version` | 1 | `1` | `CODEKAVACH_CONFIG_VERSION` |  | Version of the configuration format; only 1 is supported. |
| `profile` | str \| unset | unset | `CODEKAVACH_PROFILE` |  | Name of the profile to apply. |
| `profiles` | table | `{}` | `CODEKAVACH_PROFILES` |  | Named profile overlays, interpreted by the profile layer. |

## `[project]`

Identity of the scanned project.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `project.name` | str \| unset | unset | `CODEKAVACH_PROJECT__NAME` |  | Project name for reports; when unset, the root directory name is used. |
| `project.client` | str \| unset | unset | `CODEKAVACH_PROJECT__CLIENT` |  | Client organisation shown on the report cover. |
| `project.description` | str \| unset | unset | `CODEKAVACH_PROJECT__DESCRIPTION` |  | One-paragraph description for the scope section of the report. |
| `project.state_dir` | path | `".codekavach"` | `CODEKAVACH_PROJECT__STATE_DIR` |  | Directory for the vault, ledger, local database and cache. |
| `project.languages` | list[Language] | `[]` | `CODEKAVACH_PROJECT__LANGUAGES` |  | Languages to analyse; an empty list means detect them automatically. |

## `[scan]`

What to scan and how.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `scan.include` | list[str] | `["**/*"]` | `CODEKAVACH_SCAN__INCLUDE` |  | Glob patterns of files to include, relative to the project root. |
| `scan.exclude` | list[str] | see note 1 | `CODEKAVACH_SCAN__EXCLUDE` |  | Glob patterns of files to exclude, relative to the project root. |
| `scan.respect_gitignore` | bool | `true` | `CODEKAVACH_SCAN__RESPECT_GITIGNORE` |  | Skip files that the repository's .gitignore ignores. |
| `scan.follow_symlinks` | bool | `false` | `CODEKAVACH_SCAN__FOLLOW_SYMLINKS` | tighten-only | Follow symbolic links while discovering files. |
| `scan.max_file_size_kb` | int | `1024` | `CODEKAVACH_SCAN__MAX_FILE_SIZE_KB` |  | Largest file, in kilobytes, that is analysed. |
| `scan.max_files` | int | `50000` | `CODEKAVACH_SCAN__MAX_FILES` |  | Largest number of files that is analysed. |
| `scan.max_total_size_mb` | int | `2048` | `CODEKAVACH_SCAN__MAX_TOTAL_SIZE_MB` |  | Largest total size, in megabytes, of the analysed files. |
| `scan.jobs` | int | `0` | `CODEKAVACH_SCAN__JOBS` | volatile | Number of parallel workers; 0 means the number of CPUs. |
| `scan.timeout_seconds` | int | `3600` | `CODEKAVACH_SCAN__TIMEOUT_SECONDS` | volatile | Wall-clock limit of a whole scan, in seconds. |
| `scan.skip_stages` | list[str] | `[]` | `CODEKAVACH_SCAN__SKIP_STAGES` | tighten-only | Pipeline stages to skip, by their stage name. |
| `scan.fail_on` | info \| low \| medium \| high \| critical \| none | `"high"` | `CODEKAVACH_SCAN__FAIL_ON` |  | Exit non-zero when a finding at or above this severity exists; none disables. |
| `scan.cache` | bool | `true` | `CODEKAVACH_SCAN__CACHE` | volatile | Reuse results of unchanged stages from earlier scans. |
| `scan.stage_timeout_seconds` | int | `1800` | `CODEKAVACH_SCAN__STAGE_TIMEOUT_SECONDS` | volatile | Default time limit of one pipeline stage, in seconds. |
| `scan.stage_timeouts` | table | `{}` | `CODEKAVACH_SCAN__STAGE_TIMEOUTS` | volatile | Per-stage or per-group time limits in seconds that override the default. |
| `scan.cache_max_size_mb` | int | `2048` | `CODEKAVACH_SCAN__CACHE_MAX_SIZE_MB` | volatile | Size budget of the stage cache, in megabytes, used when pruning. |
| `scan.cache_keep_scans` | int | `5` | `CODEKAVACH_SCAN__CACHE_KEEP_SCANS` | volatile | Number of most recent scans whose cache entries survive pruning. |

Defaults too long for the table:

1. `scan.exclude`: `[".git/**", ".codekavach/**", "node_modules/**", ".venv/**", "venv/**", "__pycache__/**", "dist/**", "build/**", "target/**", "vendor/**"]`

## `[privacy]`

What may leave the machine.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `privacy.level` | L0..L4 | `"L3"` | `CODEKAVACH_PRIVACY__LEVEL` | tighten-only | Default privacy level for every path. |
| `privacy.min_level` | L0..L4 | `"L1"` | `CODEKAVACH_PRIVACY__MIN_LEVEL` | tighten-only | Floor that no configured level may be weaker than. |
| `privacy.provider_tier_levels` | table | `{ local = "L1", private = "L2", public = "L3" }` | `CODEKAVACH_PRIVACY__PROVIDER_TIER_LEVELS` |  | Minimum privacy level per provider trust tier. |
| `privacy.paths[].pattern` | str | required |  |  | Glob relative to the project root. |
| `privacy.paths[].level` | L0..L4 \| unset | unset |  |  | Privacy level for matching files. |
| `privacy.paths[].never_send` | bool | `false` |  |  | Never prepare matching files for egress at any level. |
| `privacy.never_send` | list[str] | see note 1 | `CODEKAVACH_PRIVACY__NEVER_SEND` | union | Globs whose content is never prepared for egress at any level. |
| `privacy.domain_terms` | list[str] | `[]` | `CODEKAVACH_PRIVACY__DOMAIN_TERMS` | sensitive, union | Business words that must not appear verbatim in any payload. |
| `privacy.domain_terms_file` | path \| unset | unset | `CODEKAVACH_PRIVACY__DOMAIN_TERMS_FILE` |  | File with one domain term per line; lines starting with # are comments. |
| `privacy.public_allowlist_extra` | list[str] | `[]` | `CODEKAVACH_PRIVACY__PUBLIC_ALLOWLIST_EXTRA` | restricted | Extra identifiers kept un-pseudonymised; every entry weakens privacy. |
| `privacy.vault.key_source` | keyring \| passphrase \| kms | `"keyring"` | `CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE` | restricted | Source of the vault key: OS keyring, passphrase or key-management service. |
| `privacy.vault.passphrase` | secret reference \| unset | unset | `CODEKAVACH_PRIVACY__VAULT__PASSPHRASE` | restricted | Secret reference to the passphrase; required when key_source is passphrase. |

Defaults too long for the table:

1. `privacy.never_send`: `["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/id_rsa*", "**/id_ed25519*"]`

## `[llm]`

Language models and their providers.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `llm.enabled` | bool | `true` | `CODEKAVACH_LLM__ENABLED` | tighten-only | False runs deterministic engines only; nothing leaves. |
| `llm.default_provider` | str | `"auto"` | `CODEKAVACH_LLM__DEFAULT_PROVIDER` |  | A provider id, or auto to pick the first usable one. |
| `llm.model` | str \| unset | unset | `CODEKAVACH_LLM__MODEL` |  | Overrides the model of the selected provider for this run. |
| `llm.allow_remote` | bool | `true` | `CODEKAVACH_LLM__ALLOW_REMOTE` | tighten-only | False forbids every provider that is remote. |
| `llm.tasks` | list[triage \| discover \| explain \| remediate \| classify \| summarise] | `["triage", "explain", "remediate", "summarise"]` | `CODEKAVACH_LLM__TASKS` |  | LLM tasks to run. |
| `llm.temperature` | float | `0.0` | `CODEKAVACH_LLM__TEMPERATURE` |  | Sampling temperature, 0.0 to 2.0. |
| `llm.max_output_tokens` | int | `2048` | `CODEKAVACH_LLM__MAX_OUTPUT_TOKENS` |  | Maximum output tokens per request. |
| `llm.timeout_seconds` | int | `120` | `CODEKAVACH_LLM__TIMEOUT_SECONDS` | volatile | Timeout of one request in seconds. |
| `llm.max_retries` | int | `2` | `CODEKAVACH_LLM__MAX_RETRIES` | volatile | Retries of a failed request. |
| `llm.consensus` | int | `1` | `CODEKAVACH_LLM__CONSENSUS` |  | Models or samples asked per candidate. |
| `llm.cache` | bool | `true` | `CODEKAVACH_LLM__CACHE` | volatile | Cache responses keyed on the payload hash. |
| `llm.budget.max_requests` | int \| unset | unset | `CODEKAVACH_LLM__BUDGET__MAX_REQUESTS` |  | Maximum LLM requests. |
| `llm.budget.max_total_input_tokens` | int \| unset | unset | `CODEKAVACH_LLM__BUDGET__MAX_TOTAL_INPUT_TOKENS` |  | Maximum input tokens across all requests. |
| `llm.budget.max_total_output_tokens` | int \| unset | unset | `CODEKAVACH_LLM__BUDGET__MAX_TOTAL_OUTPUT_TOKENS` |  | Maximum output tokens across all requests. |
| `llm.budget.max_cost_usd` | float \| unset | unset | `CODEKAVACH_LLM__BUDGET__MAX_COST_USD` |  | Maximum estimated cost in US dollars. |
| `llm.providers.*.kind` | ProviderKind | required |  | restricted | Adapter kind. |
| `llm.providers.*.enabled` | bool | `true` |  | restricted | Whether the provider may be selected. |
| `llm.providers.*.model` | str \| unset | unset |  | restricted | Model identifier sent to the provider. |
| `llm.providers.*.base_url` | url \| unset | unset |  | restricted | Endpoint URL; where payloads and the API key are sent. |
| `llm.providers.*.allow_insecure_http` | bool | `false` |  | restricted | Accept plain http to a host outside the machine or private network. |
| `llm.providers.*.api_key` | secret reference \| unset | unset |  | restricted | Secret reference to the API key. |
| `llm.providers.*.trust_tier` | local \| private \| public \| unset | unset |  | restricted | Trust tier; derived from the kind and host when unset. |
| `llm.providers.*.region` | str \| unset | unset |  | restricted | Cloud region (bedrock). |
| `llm.providers.*.aws_profile` | str \| unset | unset |  | restricted | AWS profile name (bedrock). |
| `llm.providers.*.azure_deployment` | str \| unset | unset |  | restricted | Deployment name (azure-openai). |
| `llm.providers.*.api_version` | str \| unset | unset |  | restricted | API version (azure-openai). |
| `llm.providers.*.cassette_dir` | path \| unset | unset |  | restricted | Directory of recorded responses (replay). |
| `llm.providers.*.command` | list[str] \| unset | unset |  | restricted | Command line of the local CLI to run (cli-bridge). |
| `llm.providers.*.options` | table | `{}` |  | restricted | Adapter-specific options. |

## `[reporting]`

Which reports are written and how.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `reporting.formats` | list[html \| pdf \| docx \| sarif \| json \| csv \| xlsx \| markdown] | `["html", "sarif", "json"]` | `CODEKAVACH_REPORTING__FORMATS` |  | Report formats to write. |
| `reporting.output_dir` | path | `"codekavach-report"` | `CODEKAVACH_REPORTING__OUTPUT_DIR` | volatile | Directory for reports, relative to the project root. |
| `reporting.title` | str \| unset | unset | `CODEKAVACH_REPORTING__TITLE` |  | Report title; defaults to 'Secure Source Code Review: <project name>'. |
| `reporting.classification` | str | `"Confidential"` | `CODEKAVACH_REPORTING__CLASSIFICATION` |  | Classification printed in header and footer. |
| `reporting.auditor` | str \| unset | unset | `CODEKAVACH_REPORTING__AUDITOR` |  | Reviewing person or firm, for document control. |
| `reporting.logo` | path \| unset | unset | `CODEKAVACH_REPORTING__LOGO` |  | PNG or SVG image for the cover. |
| `reporting.template_dir` | path \| unset | unset | `CODEKAVACH_REPORTING__TEMPLATE_DIR` | restricted | Override directory for report templates. |
| `reporting.min_severity` | info \| low \| medium \| high \| critical | `"info"` | `CODEKAVACH_REPORTING__MIN_SEVERITY` |  | Findings below this are summarised, not detailed. |
| `reporting.snippet_context_lines` | int | `3` | `CODEKAVACH_REPORTING__SNIPPET_CONTEXT_LINES` |  | Lines shown around each evidence line. |
| `reporting.include_privacy_attestation` | bool | `true` | `CODEKAVACH_REPORTING__INCLUDE_PRIVACY_ATTESTATION` |  | Include the section showing what left the environment. |
| `reporting.compliance` | list[ComplianceFramework] | `["owasp-top10", "cwe-top25", "pci-dss", "iso27001", "nist-ssdf"]` | `CODEKAVACH_REPORTING__COMPLIANCE` |  | Compliance frameworks findings are mapped to. |

## `[engines]`

Which analysers run and how.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `engines.enabled` | list[str] | `[]` | `CODEKAVACH_ENGINES__ENABLED` |  | External engine ids to run; empty means every installed engine applicable to the detected languages. |
| `engines.disabled` | list[str] | `[]` | `CODEKAVACH_ENGINES__DISABLED` |  | External engine ids that are not run. |
| `engines.timeout_seconds` | int | `600` | `CODEKAVACH_ENGINES__TIMEOUT_SECONDS` | volatile | Time limit per engine in seconds. |
| `engines.rule_packs` | list[str] | `["default"]` | `CODEKAVACH_ENGINES__RULE_PACKS` |  | Native rule packs from rules/. |
| `engines.rule_paths` | list[path] | `[]` | `CODEKAVACH_ENGINES__RULE_PATHS` |  | Extra directories of native YAML rules. |
| `engines.native.rules` | bool | `true` | `CODEKAVACH_ENGINES__NATIVE__RULES` |  | Native pattern rules. |
| `engines.native.taint` | bool | `true` | `CODEKAVACH_ENGINES__NATIVE__TAINT` |  | Native taint analysis. |
| `engines.native.secrets` | bool | `true` | `CODEKAVACH_ENGINES__NATIVE__SECRETS` |  | Native secret detection. |
| `engines.native.sca` | bool | `true` | `CODEKAVACH_ENGINES__NATIVE__SCA` |  | Native software composition analysis. |
| `engines.native.iac` | bool | `true` | `CODEKAVACH_ENGINES__NATIVE__IAC` |  | Native infrastructure-as-code checks. |
| `engines.options.*.enabled` | bool \| unset | unset |  |  | Force the engine on or off; beats the section lists. |
| `engines.options.*.executable` | path \| unset | unset |  | restricted | Path of the engine executable instead of the one found on PATH. |
| `engines.options.*.args` | list[str] | `[]` |  | restricted | Extra command-line arguments passed to the engine. |
| `engines.options.*.env_passthrough` | list[str] | `[]` |  | restricted | Names of environment variables the sandboxed engine may see. |
| `engines.options.*.timeout_seconds` | int \| unset | unset |  | volatile | Time limit for this engine in seconds. |
| `engines.options.*.options` | table | `{}` |  |  | Engine-specific options passed to its adapter. |

## `[integrations]`

External systems that receive findings.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `integrations.github.enabled` | bool | `false` | `CODEKAVACH_INTEGRATIONS__GITHUB__ENABLED` | restricted | Master switch of the GitHub integration. |
| `integrations.github.repository` | str \| unset | unset | `CODEKAVACH_INTEGRATIONS__GITHUB__REPOSITORY` | restricted | Target repository written as owner/name. |
| `integrations.github.api_url` | url | `"https://api.github.com/"` | `CODEKAVACH_INTEGRATIONS__GITHUB__API_URL` | restricted | API base URL; GitHub Enterprise Server is allowed, https only. |
| `integrations.github.token` | secret reference \| unset | unset | `CODEKAVACH_INTEGRATIONS__GITHUB__TOKEN` | restricted | Secret reference to the token; env:GITHUB_TOKEN or env:GH_TOKEN when unset. |
| `integrations.github.dry_run` | bool | `true` | `CODEKAVACH_INTEGRATIONS__GITHUB__DRY_RUN` | restricted | Log intended writes without performing them. |
| `integrations.github.issue_sync` | bool | `false` | `CODEKAVACH_INTEGRATIONS__GITHUB__ISSUE_SYNC` | restricted | Raise one issue per finding. |
| `integrations.github.close_resolved` | bool | `true` | `CODEKAVACH_INTEGRATIONS__GITHUB__CLOSE_RESOLVED` | restricted | Close issues whose finding no longer appears. |
| `integrations.github.min_severity_for_issues` | info \| low \| medium \| high \| critical | `"medium"` | `CODEKAVACH_INTEGRATIONS__GITHUB__MIN_SEVERITY_FOR_ISSUES` | restricted | Lowest severity for which an issue is raised. |
| `integrations.github.max_issues_per_run` | int | `50` | `CODEKAVACH_INTEGRATIONS__GITHUB__MAX_ISSUES_PER_RUN` | restricted | Largest number of issues created or updated in one run. |
| `integrations.github.labels_prefix` | str | `"codekavach"` | `CODEKAVACH_INTEGRATIONS__GITHUB__LABELS_PREFIX` | restricted | Prefix of the labels the integration applies. |
| `integrations.github.project_owner` | str \| unset | unset | `CODEKAVACH_INTEGRATIONS__GITHUB__PROJECT_OWNER` | restricted | Organisation or user that owns the Projects v2 board. |
| `integrations.github.project_number` | int \| unset | unset | `CODEKAVACH_INTEGRATIONS__GITHUB__PROJECT_NUMBER` | restricted | Number of the Projects v2 board. |
| `integrations.github.sarif_upload` | bool | `false` | `CODEKAVACH_INTEGRATIONS__GITHUB__SARIF_UPLOAD` | restricted | Upload SARIF to code scanning. |
| `integrations.github.checks` | bool | `false` | `CODEKAVACH_INTEGRATIONS__GITHUB__CHECKS` | restricted | Create check runs and annotations. |
| `integrations.mcp.enabled` | bool | `false` | `CODEKAVACH_INTEGRATIONS__MCP__ENABLED` | restricted | Start the MCP server. |
| `integrations.mcp.transport` | stdio \| http | `"stdio"` | `CODEKAVACH_INTEGRATIONS__MCP__TRANSPORT` | restricted | Transport of the MCP server. |
| `integrations.mcp.bind` | str | `"127.0.0.1:8765"` | `CODEKAVACH_INTEGRATIONS__MCP__BIND` | restricted | Host and port the HTTP transport listens on. |
| `integrations.mcp.allow_non_loopback` | bool | `false` | `CODEKAVACH_INTEGRATIONS__MCP__ALLOW_NON_LOOPBACK` | restricted | Allow the HTTP transport to listen on a non-loopback address. |

## `[plugins]`

Which installed plugins may load.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `plugins.allow_distributions` | list[str] | `[]` | `CODEKAVACH_PLUGINS__ALLOW_DISTRIBUTIONS` | restricted | Distributions whose plugins may load; empty allows all, and codekavach itself is always allowed. |
| `plugins.disable` | list[str] | `[]` | `CODEKAVACH_PLUGINS__DISABLE` | restricted | Plugins to disable, written as kind:name, for example engine:semgrep. |

## `[logging]`

Diagnostic logging on stderr.

| Key | Type | Default | Environment variable | Markers | Description |
|-----|------|---------|----------------------|---------|-------------|
| `logging.level` | debug \| info \| warning \| error | `"info"` | `CODEKAVACH_LOGGING__LEVEL` |  | Lowest level of events that are written. |
| `logging.format` | console \| json | `"console"` | `CODEKAVACH_LOGGING__FORMAT` |  | Human-readable console text or one JSON object per line. |

## Markers

| Marker | Meaning |
|--------|---------|
| sensitive | value is masked in every output |
| restricted | an untrusted project file may not set it |
| tighten-only | a project file may tighten it but not loosen it |
| union | layers combine by union instead of replacing |
| volatile | excluded from the settings fingerprint |

## Reserved process variables

Other `CODEKAVACH_*` variables are errors (CK-CFG-060), so a misspelt setting is not silently ignored.

| Variable | Meaning |
|----------|---------|
| `CODEKAVACH_ACCEPT_EGRESS` | Approve sending sanitised payloads to a remote provider (CI). |
| `CODEKAVACH_CONFIG` | Configuration file to use instead of the discovered project file. |
| `CODEKAVACH_DEBUG` | Print tracebacks and debug logs on stderr. |
| `CODEKAVACH_HOME` | Directory of the user configuration, state and trust store. |
| `CODEKAVACH_JSON` | Write machine-readable JSON to stdout (the --json option). |
| `CODEKAVACH_LOG_FORMAT` | Format of log events on stderr: console or json. |
| `CODEKAVACH_LOG_LEVEL` | Lowest level of log events on stderr. |
| `CODEKAVACH_LOG_THIRD_PARTY` | Show log events of third-party libraries when true. |
| `CODEKAVACH_MODEL` | Model of the selected provider (the --model option). |
| `CODEKAVACH_NO_COLOR` | Disable colour in terminal output. |
| `CODEKAVACH_NO_USER_CONFIG` | Ignore the user configuration file when true. |
| `CODEKAVACH_OFFLINE` | Open no connection outside this machine (the --offline option). |
| `CODEKAVACH_ORG_POLICY` | Organisation policy file, applied after any system policy. |
| `CODEKAVACH_ORG_POLICY_PUBKEY` | Public key for organisation policy signatures. |
| `CODEKAVACH_ORG_POLICY_SHA256` | SHA-256 that the organisation policy file must match. |
| `CODEKAVACH_PERF_FACTOR` | Test harness: multiplier for performance budgets. |
| `CODEKAVACH_PRIVACY_LEVEL` | Privacy level for this run (the --privacy-level option). |
| `CODEKAVACH_PROFILE` | Name of the profile to apply (for example demo or ci). |
| `CODEKAVACH_PROVIDER` | LLM provider id to use (the --provider option). |
| `CODEKAVACH_QUIET` | Print only results and errors (the --quiet option). |
| `CODEKAVACH_SKIP_PERF` | Test harness: skip the performance budget tests. |
| `CODEKAVACH_TEST_NETWORK` | Test harness: allow tests marked network to open sockets. |
| `CODEKAVACH_TRUST_PROJECT_CONFIG` | Trust restricted keys in the project configuration. |
| `CODEKAVACH_UPDATE_GOLDEN` | Test harness: rewrite golden files instead of comparing. |
| `CODEKAVACH_UPDATE_SNAPSHOTS` | Test harness: rewrite the CLI help snapshots. |
| `CODEKAVACH_VERBOSE` | More diagnostics on stderr (the --verbose option). |

## Command-line flags and the keys they set

| Flag | Sets | Notes |
|------|------|-------|
| `--privacy-level` | `privacy.level` |  |
| `--provider` | `llm.default_provider` |  |
| `--model` | `llm.model` |  |
| `--offline` | `llm.allow_remote`, `integrations.github.enabled`, `integrations.mcp.enabled` | sets the keys to `false` when given; keys that are not part of this build are skipped |
| `--no-llm` | `llm.enabled` | sets the keys to `false` when given |
| `--fail-on` | `scan.fail_on` |  |
| `--include` | `scan.include` |  |
| `--exclude` | `scan.exclude` |  |
| `--engine` | `engines.enabled` |  |
| `--skip-engine` | `engines.disabled` |  |
| `--rules` | `engines.rule_paths` |  |
| `--format` | `reporting.formats` |  |
| `--output-dir` | `reporting.output_dir` |  |
| `--jobs` | `scan.jobs` |  |
| `--log-level` | `logging.level` |  |
| `--log-format` | `logging.format` |  |

## Conventional provider key variables

When a provider has no `api_key` reference, the variables below are tried in order. Configuration holds a reference to a key, not the key: a plaintext key is refused (CK-CFG-010, ADR-0006 D4).

| Provider kind | Variables |
|---------------|-----------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `gemini` | `GEMINI_API_KEY`, `GOOGLE_API_KEY` |
| `xai` | `XAI_API_KEY` |
| `azure-openai` | `AZURE_OPENAI_API_KEY` |
| `github` | `GITHUB_TOKEN`, `GH_TOKEN` |

## Tighten-only keys

A project file, and a profile it selects, may tighten these keys but not loosen them (CK-CFG-041).

| Key | Rule |
|-----|------|
| `privacy.level` | a project file may not lower the level |
| `privacy.min_level` | a project file may not lower the level |
| `privacy.provider_tier_levels.*` | a project file may not lower the level |
| `llm.allow_remote` | a project file may not switch it on |
| `llm.enabled` | a project file may not switch it on |
| `scan.follow_symlinks` | a project file may not switch it on |
| `scan.skip_stages` | a project file may not skip a protected stage |
