# ADR-0006: Configuration layering, secrets and trust

| | |
|---|---|
| Status | Accepted |
| Date | 2026-09-28 |
| Deciders | Project maintainers |
| Issue | #81 (E03-01) |
| Affects | `docs/ARCHITECTURE.md` section 11 (new); `codekavach.config`, `codekavach.cli`; the `PrivacyLevel` order in `codekavach.core.models`; E02, E05, E22, E25, E32, E34, E39 |

## Context and problem statement

CodeKavach is configured from several places:

- a project file `codekavach.toml`;
- a per-user file;
- `CODEKAVACH_*` environment variables;
- CLI flags;
- named profiles;
- an organisation policy file.

`docs/ARCHITECTURE.md` section 3 says only that `src/codekavach/config/` holds "settings models, loader, profiles, key handling". It does not fix:

- the precedence between these sources;
- how API keys are referenced;
- how far a project file is trusted;
- how privacy levels are ordered when a floor is applied.

These questions cut across E05 (CLI flags), E22 (provider keys), E25 (policy engine), E34 (GitHub token) and E39 (deployment), so they are decided once, here. Every other E03 issue implements what this record says.

A scanned repository is attacker-influenced in CI and pull-request scans (ARCHITECTURE section 6.4). If configuration were read naively, the repository under review could lower its own privacy level, point the tool at a hostile endpoint, or plant a key. That is the core risk this record addresses.

## Decision drivers

- Requirement R1: configuration must not become the way a secret leaks or the privacy level is lowered.
- Principle 7 (fail closed) and invariant I4.
- Reproducible, offline runs (R5, R13): loading configuration opens no connection (I1 scope).
- One strictness order for privacy levels across the whole code base.
- Familiar conventions for operators: TOML, XDG directories, twelve-factor environment overrides.

## Considered options

1. **YAML or JSON instead of TOML.** Rejected:
   - YAML has implicit typing surprises (`no` is `false`, `1.10` is `1.1`), several incompatible versions, and unsafe loaders in common libraries.
   - JSON has no comments, which a hand-edited security configuration needs.
   - TOML 1.0 is in the Python standard library (`tomllib`) and is already the format of `pyproject.toml`.
2. **Relying on pydantic-settings source ordering alone.** Rejected. It records no provenance ("which layer set this key"), which `config show --effective` and diagnostics need. It has no profile overlay and no notion of a constraint set applied after merging (the organisation policy). It also reads the environment implicitly, which conflicts with D9.
3. **Allowing plaintext keys in a permission-checked user file.** Rejected:
   - files are copied, backed up, attached to bug reports and committed by mistake;
   - permission checks do not exist on every platform;
   - a reference (`env:`, `keyring:`, `file:`) costs the user one indirection and removes a whole class of leaks.
4. **Treating the project file as fully trusted.** Rejected. In CI and pull-request scans the project file is written by whoever opened the pull request. Full trust would let the repository under review disable its own scrutiny or exfiltrate code to an endpoint of its choosing.
5. **A clamp-only organisation policy.** Rejected as the only mode. Silently clamping hides a conflict an administrator may need to see; reject mode makes the conflict an error. Clamp mode is kept as an explicit, cumulative option (E03-30).
6. **The decisions below (chosen).**

## Decision outcome

Chosen option 6, decisions D1 to D12.

**D1 Format and file names.**
- Configuration is TOML 1.0.
- Project file: `codekavach.toml` at the project root. There is one name only: no dotfile variant, and no `[tool.codekavach]` table in `pyproject.toml` in v1.0.
- User file: `config.toml` in the user configuration directory.
- Organisation policy: `policy.toml`.

**D2 Precedence, lowest to highest.**

```
defaults < user config < project config < profile < CODEKAVACH_* env < CLI flags     then: organisation policy (reject or clamp)
```

The organisation policy is not a layer. It is a constraint set applied after merging, which can reject or clamp and cannot loosen (E03-29, E03-30).

**D3 Merge semantics.**
- Tables merge recursively.
- Scalars and arrays replace.
- Arrays of tables replace as a whole.
- Two keys are union-merged across layers, so that a higher layer cannot drop an entry: `privacy.never_send` and `privacy.domain_terms`.

**D4 Secrets.** Configuration holds only a reference to a secret, never its value (enforced by E03-19):
- `env:NAME`
- `keyring:SERVICE/USERNAME`
- `file:/absolute/path`

The loader refuses plaintext secrets in every layer (E03-19). Resolution is lazy and returns `pydantic.SecretStr`, and the value is not stored on `Settings` (E03-18).

**D5 Strictness order of privacy levels.** For floors and for "the stricter wins" the order is `L1 < L2 < L3 < L4 < L0`.
- L0 is strictest because nothing leaves; L4 is next because no code leaves.
- The order is by strictness, not by the digit in the level name. With a numeric order (L0 lowest), a floor of L3 would reject an air-gapped L0 run, and `strictest(L0, L4)` would return L4.
- `PrivacyLevel.rank` and the enum's rich comparisons follow this order (L1=1, L2=2, L3=3, L4=4, L0=5), so there is exactly one order in the code base.
- `PrivacyLevel.strictest(a, b)` returns the level of higher strictness, and `sorted([L3, L1]) == [L1, L3]` holds.
- E02-04 implements the enum with exactly this rank table, E03-04 adds `at_least()` and the exhaustive tests that pin the order, and E25 compares levels only through these comparisons.

**D6 Project configuration is semi-trusted.** In CI and pull-request scans it is attacker-influenced.
- It may tighten privacy but not loosen it (E03-26).
- Unless the project is explicitly trusted, it may not set execution paths, network endpoints, secret references, provider definitions, plugin allow-lists or integration targets (E03-25). A project is explicitly trusted by a trust store entry (E03-27), `CODEKAVACH_TRUST_PROJECT_CONFIG=1`, or `--trust-project-config`.
- A profile selected by the project file is checked with the same tighten-only rules, because a profile layer sits above the project layer.
- A file passed with `--config` that lies outside the project root is operator-supplied and trusted like the user file. One inside the project root is treated like a discovered project file.
- The project root is always derived from the scan target, never from the `--config` path (E03-12).

**D7 Organisation policy.**
- It is discovered from fixed system paths and from `CODEKAVACH_ORG_POLICY`, and all discovered policies apply cumulatively.
- A policy is not loaded from inside the project root.
- On POSIX, the policy file, the user file and the policy public key must be owned by the current user or root and must not be writable by group or others.
- A policy can carry an optional SHA-256 pin and an optional Ed25519 detached signature (E03-28, E03-31).
- Any failure to read or verify a configured policy aborts the run (fail closed).

**D8 No off switches.**
- No configuration key disables the egress guard, the ledger, redaction or fail-closed behaviour.
- The least strict setting is `privacy.level = "L1"`, and only where the organisation policy and the provider trust tier allow it.
- Consent for remote egress is deliberately not a setting either, because a scanned repository's own `codekavach.toml` could set it. Consent is a per-user state file (`<user config dir>/consent.json`), `--accept-egress`, or `CODEKAVACH_ACCEPT_EGRESS=1` for CI, all owned by E05-13. Without one of them the run fails closed.

**D9 Offline and deterministic.**
- Loading configuration performs no network access, sends no telemetry and does not auto-load `.env` files.
- `Settings(...)` does not read the environment implicitly. Only the loader does, from an explicit snapshot.
- E03-44 tests that loading opens no connection.

**D10 Versioning.**
- Top-level `config_version = 1`.
- A higher, unknown version is an error.
- Renamed keys are handled by a rename map that emits warnings (E03-22).

**D11 CLI surface.**
- `codekavach init` is a top-level command in addition to the command groups listed in ARCHITECTURE section 3, and `codekavach config init` is an alias. All other configuration commands live under `codekavach config`.
- E03 implements the `config` group and `init` in `src/codekavach/cli/config.py`.
- The CLI code layout is flat: `src/codekavach/cli/app.py` plus one module per command group (`config.py`, `plugins.py`, `scan.py`, `privacy.py` and so on). There is no `cli/commands/` package.
- E05 mounts every group on the root application (E05-19 for `config` and `init`) and owns global options, exit codes and the CLI test harness.
- Settings variables use the `CODEKAVACH_<SECTION>__<KEY>` form. The CLI's global-option variables are the single-underscore names defined in E05-05: `CODEKAVACH_PRIVACY_LEVEL`, `CODEKAVACH_PROVIDER`, `CODEKAVACH_MODEL`, `CODEKAVACH_OFFLINE`, `CODEKAVACH_JSON`, `CODEKAVACH_QUIET`, `CODEKAVACH_VERBOSE`. A value read from one of them populates the option, so it enters through the validated CLI override layer, not through the settings environment layer.
- E03-16 lists those names and the other single-underscore process variables of E05 in `RESERVED_ENV`, character for character.

**D12 Paths.**
- A relative path in any layer is relative to the project root.
- Models do not resolve paths; `LoadedConfig.resolve_path()` is the only resolver.
- A user-level file that needs a location outside the project uses an absolute or `~/` path.

### Consequences (positive, negative, neutral)

- **E02** keeps the `PrivacyLevel` member order and rank table of D5. Reordering the enum is a change to this record.
- **E05** maps every CLI flag to a dotted settings key through the override layer (E03-17). Global-option variables stay single-underscore names that feed the option, not the environment layer. `init` and `config` are mounted as D11 says.
- **E22** provider adapters call the secret resolver lazily, at the moment of use. They do not store resolved keys, and they accept only references in configuration.
- **E25** treats `privacy.min_level` as a floor and compares levels only through the D5 order. The organisation policy can reject or clamp, never loosen (E03-29, E03-30).
- **E32** (server) adds its own `[server]` section, following the same conventions: references for secrets, tighten-only project input, and the same precedence.
- **E34** stores the GitHub token as a reference (`env:`, `keyring:` or `file:`), never inline (refused by E03-19).
- **E39** containers pass secrets with `file:` references to mounted secret files, or with `env:` references.
- Negative: operators must learn the reference syntax, and trusting a project is an explicit step. Both are deliberate friction.
- Neutral: pydantic-settings is used for the models only; layering and provenance are in the project's own loader (E03-13).

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Decision | Enforced by |
|----------|-------------|
| D2 precedence and the policy lock | E03-43 (full precedence matrix) |
| D3 merge semantics | E03-13 (loader tests) |
| D4 references only | E03-19 (plaintext refusal) and E03-18 (resolver); E03-20 masks values in every output |
| D5 order | E03-04 (exhaustive order tests) and E02-04 |
| D6 tighten-only | E03-25 and E03-26 |
| D7 policy trust | E03-28, E03-29, E03-30 and E03-31 |
| D9 offline loading | E03-44; the socket block in tests (E01-08) |
| D10 versioning | E03-22 |

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Strengthened.
- D4 keeps secret values out of configuration files, snapshots and diagnostics.
- D6 stops an attacker-controlled repository from lowering its own privacy level or redirecting egress, which protects R1 and I1.
- D7 lets an organisation impose floors that no project can undercut.
- D8 keeps the egress guard, ledger and redaction outside the reach of configuration, which protects I4 and principle 7.
- D9 keeps configuration loading outside the scope of I1, because loading opens no connection (tested by E03-44).

I2, I3, I5 and I6 are unchanged; configuration does not touch payloads, the vault or pseudonyms.

## Implementation notes (optional; the only section that may grow after acceptance)

## Links

- `docs/ARCHITECTURE.md` sections 3, 6.1, 6.3, 6.4 and 11; `docs/PLAN.md` sections 2 (R1, R2, R3, R5, R13) and 4 (principles 6 and 7); `AGENTS.md` section 4.
- TOML 1.0 specification: <https://toml.io/en/v1.0.0>
- The Twelve-Factor App, factor III (Config): <https://12factor.net/config>
- XDG Base Directory Specification: <https://specifications.freedesktop.org/basedir-spec/latest/>
- CWE-15 External Control of System or Configuration Setting; CWE-798 Use of Hard-coded Credentials; CWE-312 Cleartext Storage of Sensitive Information.
- Prior art for directory trust: direnv `allow`, Visual Studio Code Workspace Trust, git `safe.directory`.
- ADR-0003 (single egress), ADR-0005 (logging and no-telemetry).
