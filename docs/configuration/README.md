# Configuration guide

This guide shows how to get common configuration tasks done. For the meaning of every key see the [key reference](reference.md); for what an error code means see the [error codes](error-codes.md). The design decisions are in [ADR-0006](../adr/0006-configuration-layering-secrets-and-trust.md).

Every `toml` block here is parsed by a test, every block marked as a project file or user file is loaded by the real loader, and every `codekavach` command in a `console` block is checked to exist (`tests/unit/config/test_docs_examples.py`). The worked precedence example is reproduced by `tests/integration/config/test_guide_precedence_example.py`.

Contents: [Quick start](#quick-start) · [Where configuration lives](#where-configuration-lives) · [Precedence](#precedence) · [Profiles](#profiles) · [Providers and keys](#providers-and-keys) · [Privacy settings](#privacy-settings) · [Project trust](#project-trust) · [Troubleshooting](#troubleshooting)

## Quick start

From the root of a repository:

```console
codekavach init
codekavach config validate
codekavach scan .
```

`init` writes a commented `codekavach.toml` rendered from the settings models, with your directory name as the project name. It tells you what to do next, and it will not replace an existing file unless you pass `--force` (the old file is kept as a `.bak` copy). `config validate` checks what a scan would use without scanning anything; it exits 0 when the configuration is valid and 2 when it is not.

With no key configured, `llm.default_provider = "auto"` falls back to the local mock provider, so the first scan works offline and sends nothing.

Useful `init` options: `--profile NAME` selects a profile in the file, `--minimal` writes only the active settings without comments, `--stdout` prints the file instead of writing it, and `--update-gitignore` adds `.codekavach/` and `codekavach-report/` to `.gitignore` (without it, `init` recommends doing so).

## Where configuration lives

There are four places, and `codekavach config path` lists every one with whether it exists. It creates nothing.

| What | Where | Notes |
|------|-------|-------|
| Project file | `codekavach.toml` at the repository root | Found by walking up from the scan target; the search stops at the repository boundary (`.git`) and at your home directory, so a file above the repository is not used. |
| User file | `config.toml` in the user configuration directory | See below. |
| Organisation policy | `policy.toml` in a system location, or the file named by `CODEKAVACH_ORG_POLICY` | See the organisation policy guide when it is available. |
| State | `.codekavach/` in the project (setting `project.state_dir`) | The vault, ledger, local database and cache. It is created with owner-only access and a `.gitignore` of its own. |

The user configuration directory is the first of: `$CODEKAVACH_HOME`; `$XDG_CONFIG_HOME/codekavach`; the platform default, which is `~/.config/codekavach` on Linux, `~/Library/Application Support/codekavach` on macOS and `%APPDATA%\codekavach` on Windows. The trust store (`trusted-projects.json`) and the per-user consent state live in the same directory.

Organisation policies are read from `/etc/codekavach/policy.toml` on Linux, from `/Library/Application Support/CodeKavach/policy.toml` and `/etc/codekavach/policy.toml` on macOS, and from `%PROGRAMDATA%\CodeKavach\policy.toml` on Windows. A policy inside the project being scanned is refused (CK-CFG-051).

Two variables select a file explicitly: `CODEKAVACH_CONFIG` (or `--config`) replaces the discovered project file, and `CODEKAVACH_NO_USER_CONFIG=1` skips the user file. Relative paths inside any file are relative to the project root, not to the file.

## Precedence

Settings are merged from these layers, lowest to highest:

```text
defaults < user config < project config < profile < CODEKAVACH_* env < CLI flags
```

The organisation policy is not a layer. It is a set of constraints applied after the merge, and it can reject a value or clamp it to a compliant one; it cannot loosen anything (see [Project trust](#project-trust) for the project side of the same idea).

How layers combine:

- Tables merge key by key.
- Scalars and arrays replace: a higher layer's list is the list, not an addition.
- Two keys are the exception and only grow, so that a higher layer cannot drop an entry a lower one added: `privacy.never_send` and `privacy.domain_terms`. This is covered exhaustively by `tests/integration/config/test_precedence_matrix.py`.

A profile sits above the project file. That surprises people: a project that selects `profile = "ci"` gets the profile's `scan.fail_on` even when its own `[scan]` table sets another value.

### A worked example

A fictitious project `payments-api` for `examplebank`. The user file:

<!-- user-file -->
```toml
[scan]
fail_on = "critical"
jobs = 4

[privacy]
never_send = ["**/secrets/**"]
```

The project file, which selects the built-in `ci` profile:

<!-- project-file -->
```toml
config_version = 1
profile = "ci"

[project]
name = "payments-api"
client = "Example Bank"

[scan]
fail_on = "medium"
exclude = ["vendor/**", "generated/**"]

[privacy]
never_send = ["config/prod/**"]
```

`codekavach config show --origin` prints every effective key with a comment saying where its value came from. For the `[scan]` table it shows lines such as these (paths shortened):

```text
exclude = [
    "vendor/**",
    "generated/**",
]  # project: payments-api/codekavach.toml:10
jobs = 4                  # user: ~/.config/codekavach/config.toml:3
fail_on = "high"          # profile: builtin:ci
```

Tracing `scan.fail_on` through the layers: the default is `"high"`, the user file says `"critical"`, the project file says `"medium"`, the `ci` profile says `"high"`, and the profile wins over both files. Each run below changes one layer:

<!-- guide-precedence -->
| Run | `scan.fail_on` | Set by |
|-----|----------------|--------|
| `codekavach config show --origin` | `high` | `profile` |
| `codekavach config show --origin --profile airgapped` | `medium` | `project` |
| `CODEKAVACH_SCAN__FAIL_ON=low codekavach config show --origin` | `low` | `env` |
| `CODEKAVACH_SCAN__FAIL_ON=low codekavach config show --origin --set scan.fail_on=critical` | `critical` | `cli` |

The `airgapped` profile does not set `scan.fail_on`, so the project's value shows through. The other keys of the example:

<!-- guide-precedence-keys -->
| Key | Effective value | Set by |
|-----|-----------------|--------|
| `scan.jobs` | `4` | `user` |
| `scan.exclude` | `["vendor/**", "generated/**"]` | `project` |
| `privacy.never_send` | the defaults plus `**/secrets/**` and `config/prod/**` | `default, user, project` |

`privacy.never_send` is a union key, so the defaults, the user entry and the project entry are all present and the origin lists every contributor.

Flags have a variable twin. A single-underscore variable such as `CODEKAVACH_PROVIDER` feeds the `--provider` option, so it enters through the CLI layer and outranks the settings variable `CODEKAVACH_LLM__DEFAULT_PROVIDER` for the same key; `config show --origin` then reports `cli: --provider`. The full list is in the reference, under "Reserved process variables".

## Profiles

A profile is a named overlay of settings, selected with `--profile`, `CODEKAVACH_PROFILE` or `profile = "..."` in a file. The built-in profiles:

| Profile | Purpose | What it sets |
|---------|---------|--------------|
| `demo` | A laptop demonstration with no key | Provider `mock`, remote providers off, level L3, HTML, PDF, SARIF and JSON reports, `scan.fail_on = "none"`. |
| `ci` | A non-interactive pipeline run | `scan.fail_on = "high"`, SARIF, JSON and HTML reports, one retry, at most 200 LLM requests. |
| `airgapped` | Nothing leaves the machine | Level L0 and floor L0, remote providers off, GitHub and MCP integrations off. |
| `bank-strict` | A regulated financial client | Floor L3, public providers at L4, extra `never_send` globs, the full compliance annex, GitHub integration in dry-run. |

`codekavach config profiles` lists the built-in and your own profiles with where each is defined. Define your own in the user file or the project file as a `[profiles.<name>]` table. `extends` names one parent, built-in or yours, and `description` is shown in the list:

<!-- project-file -->
```toml
[profiles.nightly]
extends = "ci"
description = "Nightly run: lower threshold, more LLM requests."

[profiles.nightly.scan]
fail_on = "medium"

[profiles.nightly.llm.budget]
max_requests = 500
```

Rules worth knowing:

- A profile may not reuse a built-in name (CK-CFG-022), so a repository cannot redefine `airgapped`.
- Profile chains may not loop and may not name an unknown parent (CK-CFG-021).
- A profile selected by the project file is checked with the same tighten-only rules as the file itself, because it sits above it.
- A profile is a convenience that you can override with a higher layer. It is not a control. The binding control is the organisation policy.

## Providers and keys

A provider is a table under `[llm.providers.<id>]` in your **user** file, because a provider decides where code goes and an untrusted project file may not set one (see [Project trust](#project-trust)). A configuration file holds a reference to a secret, not the secret. Three reference forms exist:

| Reference | Reads the secret from | Use it for |
|-----------|-----------------------|------------|
| `env:NAME` | The environment variable `NAME` | CI, where the platform injects secrets |
| `keyring:SERVICE/USERNAME` | The operating system keyring (service defaults to `codekavach`) | A developer machine |
| `file:/absolute/path` | A file, with trailing newline removed | Container secrets mounted at `/run/secrets/...` |

A hosted provider with its key in the keyring, and an internal endpoint with its key in a mounted secret:

<!-- user-file -->
```toml
[llm]
default_provider = "primary"

[llm.providers.primary]
kind = "anthropic"
model = "claude-sonnet-5-5"
api_key = "keyring:codekavach/primary" # pragma: allowlist secret

[llm.providers.internal]
kind = "openai-compatible"
base_url = "https://llm.internal.examplebank.example/v1"
model = "internal-model"
api_key = "file:/run/secrets/llm_key" # pragma: allowlist secret
trust_tier = "private"
```

Store a key from a hidden prompt, or from standard input in automation. The value is not accepted as an argument, so it does not reach your shell history or the process list:

```console
codekavach config key set primary
codekavach config key status
codekavach config key delete primary
```

For automation, pipe the value in: `printf %s "$KEY" | codekavach config key set primary --stdin`. `config key status` shows which references each enabled provider and integration would try and whether each resolves; `config show --check-secrets` does the same inside the full listing. Neither prints a value.

What is refused, and why:

- A plaintext key anywhere in a file is an error in every layer (CK-CFG-010), and the message names the key and the line, not the value. Use a reference.
- A malformed reference is CK-CFG-011; one that cannot be resolved is CK-CFG-012.
- A secret file readable by group or others produces a warning (CK-CFG-013). Fix the mode with `chmod 600`.
- A keyring backend that is not secure enough to hold keys is refused (CK-CFG-014); use `env:` or `file:` instead.
- Plain `http` to a host outside your machine or private network is refused unless the provider sets `allow_insecure_http` (CK-CFG-034).
- A remote provider while `llm.allow_remote` is false is CK-CFG-031, and a remote default provider at privacy level L0 is CK-CFG-032.

For a hosted provider with no explicit `api_key`, the loader tries the conventional variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` or `GOOGLE_API_KEY`, `XAI_API_KEY`, `AZURE_OPENAI_API_KEY`).

## Privacy settings

`privacy.level` picks how much of your code a provider sees. The default is L3. The levels:

| Level | What leaves the machine |
|-------|-------------------------|
| L0 | Nothing. Local engines and local models only. |
| L1 | Code with secrets and personal data replaced by typed placeholders. |
| L2 | L1, plus identifiers, literals and comments pseudonymised. |
| L3 | L2, but only the minimal slice of code relevant to one suspected weakness. |
| L4 | No code. Abstract data-flow facts and questions only. |

For floors and for "the stricter wins" the order is by strictness, not by the digit: **L1 < L2 < L3 < L4 < L0**. L0 is strictest because nothing leaves; L4 is next because no code leaves. This matters for a floor: a floor of L3 accepts L0.

None of these levels removes all disclosure. At L2 and L3 the control flow of a slice, the shape of string literals and the names of public library APIs are still visible to the provider, and the automated check shows that recorded original names and secrets do not appear verbatim, not that no meaning can be inferred. Read "Known limits" in the [repository README](../../README.md) before you rely on a level for a sensitive path.

The settings, in the order you will usually reach for them:

- `privacy.level` is the default level for every path. `privacy.min_level` is a floor that no configured level may go below (CK-CFG-037).
- `privacy.provider_tier_levels` sets the minimum level per provider trust tier (`local`, `private`, `public`). The defaults are L1, L2 and L3. A public provider configured below L3 produces a warning (CK-CFG-038).
- `privacy.paths` assigns a level, or a `never_send` rule, to files by glob. The stricter of the path rule and the provider tier applies.
- `privacy.never_send` lists globs whose content is not prepared for egress at any level. It starts with `.env` files, keys and certificates, and it only grows: layers add entries and cannot remove them.
- `privacy.domain_terms` lists business words that must not appear verbatim in any payload; `privacy.domain_terms_file` reads them from a file with one term per line and `#` comments. Terms are treated as sensitive: `config show` masks them unless you pass `--reveal-domain-terms`.

A project that protects its payments code more strictly and lists two business terms:

<!-- project-file -->
```toml
[privacy]
level = "L3"
domain_terms = ["examplebank", "interest-ladder"]

[[privacy.paths]]
pattern = "src/payments/**"
level = "L4"

[[privacy.paths]]
pattern = "src/legacy/keys/**"
never_send = true
```

And a terms file kept next to it, referenced from the same table:

```toml
[privacy]
domain_terms_file = "domain-terms.txt"
```

Paths that must not be disclosed in any form should be given L4, L0 or `never_send`, as the README says. The vault key source (`privacy.vault.key_source`) and the extra public allow-list are restricted settings: a project file may not set them unless it is trusted.

There is no setting that turns off the egress guard, the ledger or redaction, and consent to send to a remote provider is not a setting either, because a scanned repository could set it. Consent is a per-user state, the `--accept-egress` flag, or `CODEKAVACH_ACCEPT_EGRESS=1` for CI (decision D8 of ADR-0006).

## Project trust

In CI and pull-request scans the project file is written by whoever opened the pull request, so it is only partly trusted. Two rules follow.

**It may tighten privacy but not loosen it.** A project file that lowers `privacy.level`, switches on `llm.allow_remote` or otherwise loosens a tighten-only key is refused (CK-CFG-041). The keys marked "tighten-only" in the reference are the ones concerned.

**An untrusted project may not set what decides where code goes or what runs.** Providers, endpoints, secret references, executable paths, plugin allow-lists and integration targets are the keys marked "restricted" in the reference. An untrusted project file that sets one is refused (CK-CFG-040):

<!-- expect: CK-CFG-040 -->
```toml-invalid
[llm.providers.hosted]
kind = "openai-compatible"
base_url = "https://llm.internal.examplebank.example/v1"
model = "internal-model"
```

and so is one that loosens a tighten-only key:

<!-- expect: CK-CFG-041 -->
```toml-invalid
[privacy]
level = "L1"
```

The fix for the first is to move the provider to your user file, as in [Providers and keys](#providers-and-keys). If you have reviewed the file and want its restricted keys honoured, trust the project:

```console
codekavach config trust
codekavach config trust --list
codekavach config untrust
```

Trust is stored by the SHA-256 of the file, so it lapses as soon as the file changes and you are asked again. Other ways to grant it for one run are the `--trust-project-config` flag and `CODEKAVACH_TRUST_PROJECT_CONFIG=1`; an organisation policy can switch all three off (`project_config.allow_trust = false`).

For CI on pull requests from forks: do not trust the checkout. Keep restricted settings in a file outside the repository and pass it with `--config`. A file named by `--config` that lies outside the project root is treated as operator-supplied, like your user file; one inside the project root is treated like a discovered project file. The project root is derived from the scan target, not from the `--config` path.

## Troubleshooting

Start with three commands:

```console
codekavach config validate
codekavach config path
codekavach config show --origin
```

`config validate` reports every problem with its code, the file and the line, and exits 2 when there is an error. `config path` shows which files exist and where the trust store and the policy would be. `config show --origin` shows where each value came from, which answers most "why is this value set?" questions; add `--section scan` to see one table.

| Symptom | Likely code | What to do |
|---------|-------------|------------|
| "unknown key" | CK-CFG-002 | A misspelt key or section. The message suggests the nearest known key. |
| "may not be set by an untrusted project configuration" | CK-CFG-040 | Move the key to your user file, or trust the project (see above). |
| "loosens a setting that it may only tighten" | CK-CFG-041 | Remove it from the project file. |
| "looks like a secret value" | CK-CFG-010 | Replace the value with a reference. |
| A key reference does not resolve | CK-CFG-012 | `codekavach config key status` shows which reference failed. |
| "privacy level below the floor" | CK-CFG-037 | Raise the level, or ask for the floor to be changed at its source (`config show --origin` names it). |
| "organisation policy" | CK-CFG-050 to CK-CFG-056 | The policy is read from a system location; its file and your organisation's administrator are the source. |
| An environment variable is ignored or rejected | CK-CFG-060 | Settings variables use the form `CODEKAVACH_<SECTION>__<KEY>`, with two underscores between parts. |

Every code, with its cause and fix, is in the [error codes](error-codes.md). The generated [key reference](reference.md) lists each setting with its type, default, environment variable and markers.
