# Organisation policy: administrator guide

This page is for the security team that rolls CodeKavach out across many developers and pipelines, and has to explain to an auditor what the control does and what it does not do. Developers should read the [configuration guide](README.md) first. The key reference is generated in [reference.md](reference.md), and every error code is in [error-codes.md](error-codes.md). The design decision behind this page is D7 of [ADR-0006](../adr/0006-configuration-layering-secrets-and-trust.md).

Contents: [Purpose and scope](#purpose-and-scope) · [File format](#file-format) · [Discovery and cumulative application](#discovery-and-cumulative-application) · [Enforcement](#enforcement) · [File trust checks](#file-trust-checks) · [SHA-256 pin](#sha-256-pin) · [Signing workflow](#signing-workflow) · [Project trust switch](#project-trust-switch) · [Inspecting the active policy](#inspecting-the-active-policy) · [Limits](#limits) · [Roll-out checklist](#roll-out-checklist)

## Purpose and scope

An organisation policy is a file that constrains configuration for everyone who runs CodeKavach on a machine or in a pipeline you manage. It is not a configuration layer. It is applied after the layers have been merged, and it can reject a value or move it to a compliant one; it cannot loosen anything. Users, projects, profiles, environment variables and flags all sit below it.

What it can constrain:

- the privacy level, per path rule and per provider trust tier, and the globs whose content is not prepared for egress;
- which provider kinds, provider ids and hosts may be used, and whether remote providers are allowed at all;
- whether the GitHub integration may be used and against which API hosts;
- whether a repository's own `codekavach.toml` may be trusted;
- any other settings key, by pinning it to a value (`lock`).

What it does not do is listed under [Limits](#limits). In short: it constrains the configuration of the tool that reads it. Per-path and per-provider resolution at scan time is the job of the policy engine (E25).

## File format

The file is TOML 1.0 named `policy.toml`. Every rule is optional; a rule that is absent imposes no constraint. Unknown keys, wrong types and plaintext secrets make the file invalid (CK-CFG-050), and a file that cannot be used stops the run.

| Key | Type | Meaning | Example line |
|-----|------|---------|--------------|
| `policy_version` | integer | Format version of the file. Required; only `1` exists. | `policy_version = 1` |
| `organisation` | string | Name of the issuing organisation, shown in diagnostics. Required. | `organisation = "Example Bank Ltd"` |
| `enforcement` | `"reject"` or `"clamp"` | What happens on a violation. Default `"reject"`. | `enforcement = "clamp"` |
| `issued` | date | Date the policy was issued; informational. | `issued = 2026-10-01` |
| `expires` | date | The policy stops loading after this date (CK-CFG-056). | `expires = 2027-03-31` |
| `privacy.min_level` | `L0` to `L4` | Floor for `privacy.level`, for every `privacy.paths` level and for the `privacy.min_level` setting. Order is by strictness: L1 < L2 < L3 < L4 < L0. | `min_level = "L3"` |
| `privacy.min_level_by_tier` | table of tier to level | Floor per provider trust tier (`local`, `private`, `public`). | `min_level_by_tier = { public = "L4" }` |
| `privacy.never_send` | list of globs | Added to `privacy.never_send` in every run. | `never_send = ["**/hsm/**"]` |
| `privacy.forbid_allowlist_extra` | boolean | True forbids `privacy.public_allowlist_extra` entirely. | `forbid_allowlist_extra = true` |
| `llm.allow_remote` | boolean | False forbids every remote provider. | `allow_remote = false` |
| `llm.allowed_kinds` | list of provider kinds | Provider kinds that may be configured. | `allowed_kinds = ["ollama", "azure-openai"]` |
| `llm.allowed_providers` | list of ids | Provider ids that may be used; an empty list means any id. | `allowed_providers = ["internal"]` |
| `llm.allowed_base_url_hosts` | list of hosts | Hosts that a remote provider's `base_url` may point at. A remote provider without an explicit `base_url` is refused so that the host can be checked. | `allowed_base_url_hosts = ["llm.internal.examplebank.example"]` |
| `integrations.allow_github` | boolean | False forbids the GitHub integration. | `allow_github = false` |
| `integrations.allowed_github_api_hosts` | list of hosts | Hosts that `integrations.github.api_url` may point at. | `allowed_github_api_hosts = ["api.github.com"]` |
| `project_config.allow_trust` | boolean | False ignores every way of trusting a project file. | `allow_trust = false` |
| `lock` | table of key to value | Settings keys pinned to a value in every run; each key must name a real setting. | `"privacy.vault.key_source" = "keyring"` |

The `mock` and `replay` provider kinds send nothing and are always allowed, whatever `llm.allowed_kinds` says.

An annotated excerpt, in clamp mode:

<!-- org-policy -->
```toml
policy_version = 1
organisation = "Example Bank Ltd"
enforcement = "clamp"               # tighten and warn instead of stopping the run
issued = 2026-10-01
expires = 2027-03-31                # set a renewal owner for this date

[privacy]
min_level = "L3"                    # no level below L3, whatever any layer says
min_level_by_tier = { public = "L4" }   # public providers receive abstract facts only
never_send = ["**/hsm/**"]          # added to the never_send globs of every run

[llm]
allowed_kinds = ["openai-compatible", "ollama"]
allowed_base_url_hosts = ["llm.internal.examplebank.example"]

[project_config]
allow_trust = false                 # a repository cannot unlock its own restricted keys

[lock]
"reporting.include_privacy_attestation" = true   # every report states what left the machine
```

Two complete, fictitious examples are kept as files and are validated by tests: [`policy.minimal.toml`](../examples/policy.minimal.toml), which shows every rule with a comment, and [`policy.bank-strict.toml`](../examples/policy.bank-strict.toml), which is the binding counterpart of the built-in `bank-strict` profile.

## Discovery and cumulative application

CodeKavach reads a policy from fixed places and nowhere else:

| System | Path |
|--------|------|
| Linux | `/etc/codekavach/policy.toml` |
| macOS | `/Library/Application Support/CodeKavach/policy.toml`, then `/etc/codekavach/policy.toml` |
| Windows | `%PROGRAMDATA%\CodeKavach\policy.toml` |

and from the one file named by `CODEKAVACH_ORG_POLICY`. A policy inside the project being scanned is refused (CK-CFG-051).

Every policy that is found applies, system files first and then the file named by the variable. The variable therefore adds a policy and cannot replace a system one, so setting it cannot weaken what is installed on the machine. No variable changes the list of system paths; this is deliberate, because an environment variable is among the easiest things for a pipeline definition to set.

When several policies apply, a configuration must satisfy all of them: floors combine to the strictest, allow-lists intersect, and `never_send` globs are added together. Two policies that lock the same key to different values contradict each other, and the run stops with CK-CFG-055 naming both files. A violation of a policy in `reject` mode stops the run even when another policy in `clamp` mode would have changed the same value.

## Enforcement

`enforcement = "reject"` (the default) makes the loader stop with CK-CFG-055 and list every violation, each with the origin of the offending value, so that a developer sees which file to change. Use it when you want a conflict to be visible.

`enforcement = "clamp"` fixes the violations it can and reports each change as a warning with the same code. Use it for a gradual roll-out, where developers should keep working while their configuration is corrected. Clamping moves a value only in the stricter direction and does not enable anything; property-based tests in `tests/unit/config/orgpolicy/test_enforce_clamp.py` check that clamping is monotone (never looser than its input) and idempotent (applying it twice equals applying it once).

Two rules are applied in both modes and are not checks: `privacy.min_level` raises the floor, and `privacy.never_send` adds globs. Every other rule is a check. In clamp mode a violation is handled like this:

| Rule | What clamp mode does |
|------|----------------------|
| `privacy.min_level` | Raises `privacy.level` and every `privacy.paths` level that is below the floor. |
| `privacy.min_level_by_tier` | Raises the tier's level in `privacy.provider_tier_levels`. |
| `privacy.forbid_allowlist_extra` | Empties `privacy.public_allowlist_extra`. |
| `llm.allow_remote` | Sets `llm.allow_remote` to false. |
| `llm.allowed_kinds`, `llm.allowed_providers`, `llm.allowed_base_url_hosts` | Disables the offending provider, unless it is named as `llm.default_provider`: the operator asked for it by name, so that remains an error. |
| `integrations.allow_github` | Switches the GitHub integration off. |
| `integrations.allowed_github_api_hosts` | Cannot be clamped; the run stops. |
| `lock` | Sets the key to the locked value. |

A locked key must already hold the locked value in reject mode. A key that nobody has set holds its default, so a lock whose value differs from the default fails every run until the value is configured, or until the policy is changed to `clamp`.

## File trust checks

A policy is read only if it passes these checks, and a failure stops the run (fail closed). Each has its own code:

| Check | What is required | Code |
|-------|------------------|------|
| Readable and valid | The file exists, is valid TOML, has no unknown key and holds no secret. | CK-CFG-050 |
| Location | The policy file and the public key are outside the project being scanned. | CK-CFG-051 |
| Ownership and mode (POSIX) | Owned by the current user or root, and not writable by group or others. | CK-CFG-052 |
| SHA-256 pin | When `CODEKAVACH_ORG_POLICY_SHA256` is set, the policy named by `CODEKAVACH_ORG_POLICY` matches it. | CK-CFG-053 |
| Signature | When a public key is configured, every policy has a valid detached signature. | CK-CFG-054 |
| Violation | The configuration satisfies every policy, and no two policies contradict each other. | CK-CFG-055 |
| Expiry | `expires` is not in the past. | CK-CFG-056 |

## SHA-256 pin

`CODEKAVACH_ORG_POLICY_SHA256` holds the hex SHA-256 of the policy file named by `CODEKAVACH_ORG_POLICY`. When it is set and the file differs, the run stops with CK-CFG-053. Compute it with `sha256sum policy.toml` and keep the value in the pipeline template, not in the repository.

The pin applies only to the policy named by the variable, not to system policies. It narrows one problem: a file that changed since the pin was set, in a pipeline whose template you control. It does nothing when the variable is not set.

## Signing workflow

A signature protects the integrity and origin of the policy file. When a public key is configured, every policy must have a detached Ed25519 signature next to it, and a policy without a valid one is refused (CK-CFG-054).

1. Generate the key pair on an offline machine, and keep the private key offline:

```console
openssl genpkey -algorithm ed25519 -out policy.key
openssl pkey -in policy.key -pubout -out policy.pub
```

2. Sign the policy. The tool takes the key from a file, asks for an encrypted key's passphrase with hidden input, and refuses a private key that others can read:

```console
codekavach config policy sign policy.toml --key policy.key
```

   This writes `policy.toml.sig`, the base64 of the 64-byte signature, next to the policy.

3. Check it before you distribute it:

```console
codekavach config policy verify policy.toml --pubkey policy.pub
```

   `verify` exits 2 with CK-CFG-054 when the signature does not match.

4. Install `policy.toml`, `policy.toml.sig` and `policy.pub` together, owned by root with mode `0644`. The public key is read from `CODEKAVACH_ORG_POLICY_PUBKEY`, or else from a file named `policy.pub` in the same directory as a system policy. Only Ed25519 is accepted.

A signature file without a configured public key produces a warning (CK-CFG-054) because it is not being checked. Re-sign after every edit; one changed byte of the policy or of the signature fails verification.

## Project trust switch

`project_config.allow_trust = false` makes every way of trusting a repository's `codekavach.toml` ineffective: the trust store, `CODEKAVACH_TRUST_PROJECT_CONFIG` and `--trust-project-config`. Restricted keys in a project file (providers, endpoints, executables, integration targets) are then refused whatever anyone says, and a developer who needs one must put it in their user configuration, where the policy still applies. See [project trust](README.md#project-trust) for the rule it overrides.

## Inspecting the active policy

```console
codekavach config policy show
codekavach config show --origin
```

`config policy show` lists the policies that apply here with the organisation, where each was found, a shortened SHA-256, whether its signature was checked, the enforcement mode, the dates and the rules that are set; it loads the policy the way a scan does, so it is also the quickest way to see why a policy is refused. `config show --origin` marks a value that a policy changed with the layer `org-policy` and names the policy file, and `config path` shows where the system policy and the public key are looked for.

## Limits

State these plainly to an auditor; each is a property of the design, not a defect that a later release removes.

- **Path pinning is not protection against a local administrator.** The trust anchor is the location of the file. It protects against the scanned repository and against project-level configuration, which cannot supply or weaken a policy. It does not protect against a local administrator, or against whoever controls the process environment: they can install another policy, set `CODEKAVACH_ORG_POLICY`, or run another copy of the tool.
- **The pin helps only where it is set.** `CODEKAVACH_ORG_POLICY_SHA256` narrows the process environment case when the pipeline template sets it, and only for the policy named by the variable.
- **Signatures do not give freshness.** A signature protects integrity and origin. An older policy that was validly signed still verifies until its `expires` date, so set `expires` and name an owner who renews it. If the public key comes from `CODEKAVACH_ORG_POLICY_PUBKEY`, whoever controls the environment controls the trust anchor; prefer the system path on managed machines.
- **Windows skips two checks.** On Windows the ownership and mode checks are skipped, because POSIX mode bits do not describe its access control lists. The location, pin, signature and expiry checks still apply, and the policy directory must be protected by its access control list.
- **A policy constrains configuration.** Per-path and per-provider resolution at scan time is the policy engine's job (E25) and relies on `privacy.min_level`. A policy says nothing about what a provider does with the data it receives.
- **Privacy levels disclose less, not nothing.** A floor of L3 does not remove the disclosures listed under "Known limits" in the [repository README](../../README.md).

## Roll-out checklist

- [ ] Choose the floor (`privacy.min_level`) and the tier levels (`privacy.min_level_by_tier`).
- [ ] Decide between `reject` and `clamp`.
- [ ] List the allowed provider kinds and hosts.
- [ ] Decide whether project trust is allowed (`project_config.allow_trust`).
- [ ] Set an expiry and name a renewal owner.
- [ ] Generate the key pair offline.
- [ ] Sign the policy.
- [ ] Install `policy.toml`, `policy.toml.sig` and `policy.pub` with root ownership and mode `0644`.
- [ ] Run `codekavach config policy show` on one workstation and one pipeline, and read the output.
- [ ] Add `codekavach config validate --strict` to the pipeline template, and set `CODEKAVACH_ORG_POLICY_SHA256` there if it names the policy by variable.
