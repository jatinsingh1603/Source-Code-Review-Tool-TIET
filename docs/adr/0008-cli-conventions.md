# ADR-0008: CLI conventions

| | |
|---|---|
| Status | Proposed |
| Date | 2026-10-04 |
| Deciders | Project maintainers |
| Issue | #160 (E05-01) |
| Affects | `docs/ARCHITECTURE.md` sections 3 and 9.1 (new); `codekavach.cli`; E13, E22, E32, E34, E35 |

## Context and problem statement

`docs/ARCHITECTURE.md` section 3 described the CLI in one line, omitted the groups `plugins`, `demo`, `init` and `completion`, and said nothing about conventions that several epics depend on: the module layout, the exit codes, how global options reach the configuration loader, the JSON envelope, what `--offline` means, and who can approve remote egress. The E05 issues make these decisions; this record puts them in one place with their reasons.

## Decision drivers

- Pipelines, the GitHub Action and hooks act on exit codes and on JSON output, so both are public contracts.
- CLI output and CI logs can leave the client's environment (section 6.4: CI logs outside the trust boundary).
- The scanned repository, including its `codekavach.toml`, is untrusted input (section 6.4: malicious repository content).

## Considered options

- Typer root-callback options only. Rejected: options placed after the subcommand fail.
- BSD `sysexits.h` exit codes. Rejected: the project scope fixes the codes 0 to 4.
- `--offline` forcing privacy level L0. Rejected: a local model inside the trust boundary still benefits from L3 payloads, and the level is a policy matter for E25.
- Consent as a configuration key. Rejected: the scanned repository could grant it.

## Decision outcome

**D1 Layout.** One module per command group directly under `src/codekavach/cli/`: `scan.py`, `report.py`, `privacy.py`, `providers.py`, `vault.py`, `doctor.py`, `sync.py`, `eval_cmd.py`, `demo.py`, `completion.py`, `config.py` (owned by E03) and `plugins.py` (built on the plugin registry of E04-10). Shared infrastructure lives beside them in `app.py`, `console.py`, `exit_codes.py`, `errors.py`, `backends.py`, `options.py`, `context.py`, `logging_setup.py`, `output.py`, `prompts.py`, `progress.py`, `onboarding.py`, `consent.py`, `signals.py` and `term_check.py`; `ledger.py` and `_version.py` already exist as helpers. There is no `commands/` sub-package. Rationale: E03 and E04 already use the flat layout, and one file per group keeps lazy imports simple.

**D2 Entry point.** The console script targets `codekavach.cli.app:main`, which returns an integer. Click runs with `standalone_mode=False`, so one function (`run`) decides the exit code. Rationale: a single place maps every outcome and exception to the contract of D3.

**D3 Exit codes.** 0: completed, nothing at or above the threshold. 1: the command completed and what it checks has problems at or above the threshold (scan findings, a failed `doctor` check, a failed `providers test`, warnings under `config validate --strict`). 2: the command cannot be carried out as invoked (usage, invalid configuration, missing input, a back end not in this build). 3: a privacy control refused (consent absent, a guard refusal that aborts the command, a failed ledger integrity or term check, a locked vault). 4: a defect or unexpected failure. 130: cancelled. Precedence is 4 over 3 over 1 over 0. Rationale: a pipeline can tell "found problems" from "could not run" from "refused for privacy reasons" without parsing text.

**D4 Error rendering.** An unexpected exception prints its type only. The message and the traceback need `--debug`. Rationale: both can quote client code or credentials, and CI logs may be stored outside the client's environment.

**D5 Global options.** They are Click-level options attached to the root and to every leaf command, so they work before and after the subcommand. Settings-backed options are passed to the E03 loader as the CLI layer. The settings environment layer (`CODEKAVACH_<SECTION>__<KEY>`) is owned by E03-16. The global options additionally read the single-underscore variables `CODEKAVACH_PRIVACY_LEVEL`, `CODEKAVACH_PROVIDER`, `CODEKAVACH_MODEL`, `CODEKAVACH_OFFLINE`, `CODEKAVACH_JSON`, `CODEKAVACH_QUIET` and `CODEKAVACH_VERBOSE`, which pass through the same validated CLI layer and are listed in `RESERVED_ENV`. Rationale: one validation path for flags and variables, so privacy floors apply to both.

**D6 `--offline`.** It means no connection to anything outside the machine in this invocation: `llm.allow_remote = false`, the GitHub and MCP integrations are disabled and network probes are skipped. It does not change `privacy.level`. The persistent, stricter form is the `airgapped` profile (E03-24). Rationale: "offline" is a statement about connections, and the level is a separate policy.

**D7 JSON envelope.** `--json` yields exactly one document on stdout with `schema_version`, `codekavach_version`, `command`, `ok`, `exit_code`, `data`, `warnings` and `errors`. Additive changes keep version `"1"`. The serialiser refuses raw code and vault types; findings and snippets are not part of the envelope. Rationale: machine output is the most likely thing to be stored and forwarded, so it carries status and metadata only.

**D8 Consent.** Remote egress requires a per-user consent record (`<user config dir>/consent.json`), an explicit `--accept-egress`, or `CODEKAVACH_ACCEPT_EGRESS=1` for CI, which is an explicit operator action outside the repository. Configuration files cannot grant consent, because the scanned repository's own `codekavach.toml` is untrusted input. The egress guard requires the consent decision from every caller, not only from the CLI. Rationale: the party that approves sending code out must be the operator, not the code being scanned.

**D9 Optional back ends.** Commands reach later epics through `load_backend`. A missing back end is exit 2 with code `backend_unavailable`; commands do not simulate results. Rationale: a simulated result in an audit tool is worse than a clear refusal.

### Consequences (positive, negative, neutral)

- Positive: later epics build on a written contract, and a change that relaxes D4, D6, D7 or D8 is visible in review.
- Negative: exit code 1 covers every completed check with a negative result, not only scan findings; callers that need the difference read `command` and `data` of the JSON envelope.
- Neutral: the layout fixes module names for commands that do not exist yet; their epics create them.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Decision | Where it is implemented or tested |
|---|---|
| D1 | `tests/unit/test_package_layout.py` (expected modules) |
| D2, D3, D4 | #161 (E05-02), #163 (E05-04); `docs/reference/exit-codes.md`; `tests/unit/repo/test_adr_cli.py` compares the table of section 9.1 with `ExitCode` |
| D5, D6 | #164 (E05-05); `docs/reference/cli-global-options.md` |
| D7 | #166 (E05-07); `docs/reference/cli-json-output.md` |
| D8 | #172 (E05-13) for the CLI; the egress guard (E12) for every other caller |
| D9 | `codekavach.cli.backends.load_backend` (E05-02) |

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

- I3 is supported by D4 and D7: error output and machine output are designed not to carry vault contents, raw code or exception text by default.
- I4 is supported by D8 and D3: without consent the command stops with exit code 3 instead of continuing with a weaker path.
- I1, I2, I5 and I6 are unchanged: this record adds no network path and does not change payloads.

D6 covers connections made by CodeKavach itself in that invocation; it is not a statement about third-party plugins.

## Questions for acceptance

1. Is the broadened meaning of exit code 1 (any completed check with a negative result, not only scan findings) acceptable for the GitHub Action (E34)?
2. Should a back end that is not in the build exit 2 (as proposed) or a dedicated code?
3. Is `CODEKAVACH_ACCEPT_EGRESS=1` acceptable as the consent mechanism in CI (D8), or should CI have to pass `--accept-egress` on the command line?
4. Should `--offline` leave `privacy.level` unchanged (D6, as proposed), given that the `airgapped` profile exists for the stricter case?

## Links

- `docs/ARCHITECTURE.md` sections 3, 6.3, 6.4 and 9.1; `docs/PLAN.md` section 4 (principles 2 and 7).
- `docs/reference/exit-codes.md`, `docs/reference/cli-global-options.md`, `docs/reference/cli-json-output.md`.
- [ADR-0006](0006-configuration-layering-secrets-and-trust.md) (configuration layering and trust).
