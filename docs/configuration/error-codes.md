# Configuration error codes

Every configuration problem has a stable code of the form `CK-CFG-nnn`. A message names the key, the file and the line, not the value you supplied, because that value may be a mis-pasted credential or a business term (the loader tests check this). Warnings are marked; every other code is an error that stops the run. `codekavach config validate` reports all problems of a configuration at once. The settings themselves are in [reference.md](reference.md).

The codes are grouped by block: 00x files and syntax, 01x secrets, 02x profiles, 03x consistency rules, 04x project trust, 05x organisation policy, 06x environment and command-line overrides, 07x locations.

## Files and syntax (00x)

### CK-CFG-001

**Meaning.** A configuration file is not valid TOML.
**Typical cause.** A missing quote or bracket, or a value of the wrong form.
**Fix.** Go to the line in the message. `codekavach config validate` shows the file and line again after you edit it.

### CK-CFG-002

**Meaning.** A key is not a CodeKavach setting.
**Typical cause.** A typing mistake, or a key from another tool. The message suggests the closest known key.
**Fix.** Correct the spelling, or remove the key. The valid keys are in [reference.md](reference.md).

### CK-CFG-003

**Meaning.** A value has the wrong type, is outside its range, or is not one of the allowed choices.
**Typical cause.** `privacy.level = "L9"`, a negative `scan.jobs`, or a string where a list is expected.
**Fix.** Use a value that fits the type and the description of the key in [reference.md](reference.md).

### CK-CFG-004

**Meaning.** `config_version` is not a version this release reads.
**Typical cause.** The file was written by a newer CodeKavach.
**Fix.** Upgrade CodeKavach, or set `config_version = 1`.

### CK-CFG-005

**Meaning.** A configuration file cannot be used: it is missing, unreadable, too large, not UTF-8, not a regular file, or resolves outside the place it must stay in.
**Typical cause.** A wrong `--config` path, a symbolic link out of the project, or a file owned by another user.
**Fix.** Point to an existing regular file inside the project, and check its owner.

### CK-CFG-006

**Meaning.** (Warning.) The file uses a key that has been renamed or deprecated.
**Typical cause.** A configuration written for an earlier release.
**Fix.** Rename the key as the message says. The old key is read as the new one; if both are set, the old one is ignored.

## Secrets (01x)

### CK-CFG-010

**Meaning.** A configuration file contains what looks like a secret value.
**Typical cause.** An API key typed straight into `api_key`, or a token pasted into a comment.
**Fix.** Remove the value from the file, then store the key and put a reference in the file: `codekavach config key set primary` prints the reference to use, for example `keyring:codekavach/primary`, which you put in the `api_key` setting. References may also be `env:NAME` or `file:/absolute/path`.

### CK-CFG-011

**Meaning.** A secret reference is malformed.
**Typical cause.** A missing prefix, a relative `file:` path, or a name with characters that are not allowed.
**Fix.** Use `env:NAME`, `keyring:SERVICE/USERNAME` or `file:/absolute/path`.

### CK-CFG-012

**Meaning.** A secret reference cannot be resolved.
**Typical cause.** The environment variable is not set, the keyring entry does not exist, or the file cannot be read.
**Fix.** Set the variable, or run `codekavach config key set NAME`. `codekavach config key status` shows which references resolve, without revealing any value.

### CK-CFG-013

**Meaning.** (Warning.) A file that holds a secret can be read by group or others.
**Typical cause.** The file was created with a permissive mode.
**Fix.** Restrict it to its owner, for example `chmod 600 path`.

### CK-CFG-014

**Meaning.** The OS keyring backend is not secure enough to store keys.
**Typical cause.** A plaintext or null keyring backend, common in minimal containers.
**Fix.** Use an `env:` or `file:` reference instead, or install a real keyring backend.

## Profiles (02x)

### CK-CFG-020

**Meaning.** The selected profile does not exist.
**Typical cause.** A misspelt `--profile` or `profile` value.
**Fix.** `codekavach config profiles` lists the built-in and defined profiles.

### CK-CFG-021

**Meaning.** A profile extends an unknown profile, or profiles extend each other in a cycle.
**Typical cause.** `extends` names a profile that is not defined, or `a` extends `b` and `b` extends `a`.
**Fix.** Define the parent profile, or break the cycle.

### CK-CFG-022

**Meaning.** A profile you defined has the name of a built-in profile.
**Typical cause.** A profile called `ci` or `demo` in `[profiles]`.
**Fix.** Rename your profile. To change a built-in one, extend it under a new name.

## Consistency rules (03x)

### CK-CFG-030

**Meaning.** `llm.default_provider` names a provider that is not defined or is disabled.
**Typical cause.** A typing mistake, or `enabled = false` on the provider.
**Fix.** Define and enable the provider, or set `default_provider = "auto"`.

### CK-CFG-031

**Meaning.** A remote provider is selected while `llm.allow_remote` is false.
**Typical cause.** An organisation policy or a profile such as `airgapped` forbids remote use.
**Fix.** Choose a local provider, or allow remote use where policy permits it.

### CK-CFG-032

**Meaning.** The privacy level is L0 (nothing leaves the machine) but the default provider is remote.
**Typical cause.** A floor of L0 combined with a named remote provider.
**Fix.** Select a local provider, or lower the level where policy permits it.

### CK-CFG-033

**Meaning.** A setting that this kind of provider or mode needs is missing.
**Typical cause.** A provider without its `model` (or another key its kind needs), or a vault `key_source = "passphrase"` without a passphrase reference.
**Fix.** Add the missing key named in the message.

### CK-CFG-034

**Meaning.** A URL is malformed or insecure.
**Typical cause.** An `http://` endpoint for a remote host, or a URL that contains a user name or password.
**Fix.** Use `https://` without credentials in the URL, or set `allow_insecure_http` for a local test endpoint.

### CK-CFG-035

**Meaning.** An engine is both enabled and disabled.
**Typical cause.** The same id in `engines.enabled` and `engines.disabled`.
**Fix.** Keep it in one list.

### CK-CFG-036

**Meaning.** An integration feature is switched on without what it needs.
**Typical cause.** `issue_sync` without `repository`, or `project_number` without `project_owner`.
**Fix.** Set `integrations.github.enabled = true` and the missing keys, or switch the feature off.

### CK-CFG-037

**Meaning.** A privacy level is below `privacy.min_level`.
**Typical cause.** `privacy.level` or a path rule is lower than the floor set in the same configuration.
**Fix.** Raise the level to at least the floor.

### CK-CFG-038

**Meaning.** (Warning.) Public providers are configured below level L3.
**Typical cause.** A `privacy.provider_tier_levels.public` of L1 or L2.
**Fix.** Use L3 or stricter for public providers, unless your policy accepts the risk.

### CK-CFG-039

**Meaning.** A path rule or glob is invalid.
**Typical cause.** An empty or very long pattern, a backslash, an absolute path or drive letter, a `..` segment, or a path rule that sets both or neither of `level` and `never_send`.
**Fix.** Use project-relative globs with `/` separators, such as `src/**`, and set exactly one of `level` and `never_send` per rule.

## Project trust (04x)

### CK-CFG-040

**Meaning.** The project's `codekavach.toml` sets a restricted key, and the project is not trusted.
**Typical cause.** A repository file sets a provider, an endpoint, an executable path or an integration target. Such keys decide what runs or where data goes, so an untrusted repository may not set them.
**Fix.** Move the key to your user configuration file, or review the file and trust the project with `codekavach config trust`.

### CK-CFG-041

**Meaning.** The project configuration loosens a setting that it may only tighten.
**Typical cause.** A project file lowers `privacy.level` or switches on `llm.allow_remote`.
**Fix.** Remove the loosening from the project file. Loosening belongs in your user configuration, or in a trusted project.

### CK-CFG-042

**Meaning.** The trust store is unreadable or corrupt.
**Typical cause.** A damaged or hand-edited file in the user configuration directory.
**Fix.** Delete the file and trust your projects again with `codekavach config trust`.

## Organisation policy (05x)

### CK-CFG-050

**Meaning.** An organisation policy cannot be read or is invalid.
**Typical cause.** A configured policy file is missing, is not valid TOML, has an unknown key, or contains a secret.
**Fix.** Correct the policy file. `codekavach config policy show` loads it and reports the problem.

### CK-CFG-051

**Meaning.** A policy file, or the public key that checks it, is inside the project being scanned.
**Typical cause.** The policy was copied into the repository.
**Fix.** Install it where the repository cannot write, such as the system location or a path outside the project.

### CK-CFG-052

**Meaning.** A policy file or key has unsafe ownership or permissions.
**Typical cause.** It is owned by another user, or writable by group or others.
**Fix.** Make it owned by you or root and not writable by others, for example `chmod 644` on a file you own.

### CK-CFG-053

**Meaning.** The policy does not match the SHA-256 pinned in `CODEKAVACH_ORG_POLICY_SHA256`.
**Typical cause.** The file changed since the pin was set.
**Fix.** Check the change with your security team, then update the pin.

### CK-CFG-054

**Meaning.** A policy signature is missing, malformed or does not verify (or a configured public key is missing). A warning with the same code says that a `.sig` file exists but no public key is configured, so it is not being checked.
**Typical cause.** The policy was edited after signing, signed with another key, or has no `.sig` file.
**Fix.** Sign it again with `codekavach config policy sign`, then check it with `codekavach config policy verify`.

### CK-CFG-055

**Meaning.** The configuration violates the organisation policy, or two policies contradict each other. In clamp mode, a warning with this code says that a value was changed to comply.
**Typical cause.** A privacy level below the policy floor, a provider the policy does not allow, a locked key set to another value.
**Fix.** Change the setting as the message says. `codekavach config policy show` lists the active policies and their rules.

### CK-CFG-056

**Meaning.** The organisation policy has expired.
**Typical cause.** Its `expires` date is in the past.
**Fix.** Ask the issuing security team for a current policy.

## Environment and command-line overrides (06x)

### CK-CFG-060

**Meaning.** A `CODEKAVACH_*` environment variable is not recognised, or its value does not fit the setting.
**Typical cause.** A misspelt variable such as `CODEKAVACH_SCAN_JOBS` (settings use two underscores between section and key), or a non-numeric value for a number.
**Fix.** Use `CODEKAVACH_<SECTION>__<KEY>`, for example `CODEKAVACH_SCAN__JOBS=4`. The reserved variables are listed in [reference.md](reference.md).

### CK-CFG-061

**Meaning.** A `--set` override or a flag is malformed or conflicts with another.
**Typical cause.** A missing `=`, an unknown key, or the same key set by two options.
**Fix.** Write `--set section.key=value` with a key from [reference.md](reference.md), and give each key once.

## Locations (07x)

### CK-CFG-070

**Meaning.** `project.state_dir` or `reporting.output_dir` is in an unsafe place.
**Typical cause.** The output directory is the project root or inside the state directory that holds the vault, or the state directory is writable by others.
**Fix.** Choose a different directory, for example `reporting.output_dir = "codekavach-report"`.
