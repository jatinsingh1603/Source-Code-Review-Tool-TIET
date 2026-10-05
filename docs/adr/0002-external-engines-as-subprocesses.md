# ADR-0002: External engines as subprocesses

| | |
|---|---|
| Status | Accepted |
| Date | 2026-10-05 |
| Deciders | CodeKavach maintainers |
| Issue | #22 |
| Affects | docs/ARCHITECTURE.md sections 2, 6.4 and 8; `codekavach.analysis.engines`; the ruff configuration |

## Context and problem statement

CodeKavach is MIT-licensed and orchestrates third-party analysis engines. Their licences range from permissive to copyleft, and some engines ship rule sets under terms that differ from the engine's own. `docs/ARCHITECTURE.md` section 2 says that external engines are "invoked as subprocesses or containers, results normalised through SARIF", and `AGENTS.md` section 3 says that engines are not imported. The risk register of `docs/PLAN.md` section 8 lists a licence conflict as a high-impact risk, and the threat model of `docs/ARCHITECTURE.md` section 6.4 lists a malicious or compromised engine as an adversary.

An adapter author under time pressure will be tempted to write `import some_engine`. This record states where the boundary is, what crosses it, and what an adapter has to do, so that the adapters of E14 and E15 are built the same way.

## Decision drivers

- Keep the licence of CodeKavach independent of the licence of each engine.
- An engine must be replaceable without touching the pipeline.
- A crashing, hanging or memory-hungry engine must not take the scan down.
- Engines process untrusted repository content and are themselves third-party code inside the trusted boundary.
- The checks the privacy layer depends on must not depend on an optional external program.

## Considered options

1. **Import engines as Python libraries.**
   - For: fastest calls, rich in-process data structures, no installation step beyond a dependency.
   - Against: only possible for engines written in Python; the engine's licence then governs a combined work; an engine fault is a fault of the scan process; the engine shares our memory, our environment variables and our network access.
2. **Run each engine as a subprocess and exchange SARIF or JSON.**
   - For: a separately installed program exchanging data through files or pipes; any implementation language; timeouts and limits per invocation; the engine can be swapped by changing one adapter.
   - Against: process start-up time, an installation burden on the user, version skew between engine releases and adapters, and looser integration than an in-process API.
3. **Run each engine in a container.**
   - For: the engine brings its own runtime; the strongest isolation available without extra tooling (no network, read-only mounts).
   - Against: needs a container runtime on the machine, which a developer laptop or a locked-down CI runner may not have; slower start; image distribution for air-gapped use (E39).
4. **Re-implement all checks natively.**
   - For: no licence question, no installation, full control of privacy behaviour.
   - Against: decades of rule development in the existing engines cannot be rewritten in three months, and coverage would be far below theirs.

## Decision outcome

- **Option 2 by default:** an external engine runs as a subprocess and its results are normalised through SARIF 2.1.0.
- **Option 3** where an engine needs its own runtime or stronger isolation than a process gives.
- **Option 4 only for the native rule engine and the taint engine** (E16, E17), which the privacy layer depends on and which therefore have to exist without any optional program.
- **Option 1 is not used.** No engine package is imported by `codekavach`.

### Adapter boundary rules

Every engine adapter follows these rules.

1. **No import.** The adapter does not import the engine. Engines are not vendored and are not listed in `[project.dependencies]` or in an extra. They are optional and discovered at run time (`codekavach doctor`, E05).
2. **No shell.** The engine is started with an argument vector and `shell=False`. No command line is built by string concatenation.
3. **Timeout.** Every invocation has a timeout derived from the remaining budget of the scan.
4. **Output size limit.** The adapter reads at most a configured number of bytes from the engine and treats more as a failure.
5. **Captured exit status.** The exit status and the error stream are captured. A failure of one engine degrades the scan and is reported in the coverage appendix; it does not abort the scan and is not skipped silently.
6. **Scrubbed environment.** The engine's environment contains no provider API keys, no vault key material and no `GH_TOKEN` or other repository-hosting token. The adapter passes an allow-list of variables, not a copy of its own environment.
7. **No network** for the engine process where the platform allows it, and in every container.
8. **Read-only view of the repository** and a private temporary directory that is removed afterwards.
9. **Telemetry off.** The engine's telemetry is switched off through its documented flag or environment variable; E01-31 keeps the table of these switches.
10. **Version recorded.** Engine name, engine version and rule-pack version are recorded per finding (`provenance`) and in the report appendix "tools and versions" (`docs/ARCHITECTURE.md` section 8).
11. **SARIF in.** The adapter converts the engine's output to SARIF 2.1.0 at the boundary; the pipeline sees SARIF only.

### Licence separation

Running a separately installed program and exchanging data through files or pipes keeps CodeKavach's MIT licence independent of each engine's licence. This is an engineering separation and not legal advice. The licence verdict per engine, including whether it may be used to scan proprietary client code, is a human decision: it is recorded in `docs/research/INSIGHTS.md` and is decided by a person (`needs-human`), not by an adapter author or a coding agent. An engine without a recorded verdict is not enabled by default.

### Consequences (positive, negative, neutral)

- Positive: licences stay separate; engines are optional and replaceable; a failing engine degrades one part of the coverage; the engine has no access to our credentials.
- Negative (costs accepted): process start-up time on every scan; the user has to install engines, and `codekavach doctor` has to explain what is missing; version skew between engine releases and adapters has to be tested; the integration is looser than an in-process API, so some engine features are out of reach.
- Neutral: the ruff configuration allows `subprocess` without a shell (`S603` is ignored) because of this record, while `S602` and `S604` to `S607` stay enabled.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Rule | Enforced by |
|------|-------------|
| No engine package is importable from `codekavach` | An import contract to be added by E14 when the adapter base class lands, with a planted violation in `tests/privacy/test_import_contracts.py` |
| No shell | ruff: `S602` and `S604` to `S607` are enabled in `pyproject.toml`; `tests/unit/repo/test_ruff_config.py` checks that `S602` is reported |
| Timeout, output size limit, captured exit status, degraded scan | Engine sandbox tests of E14: a hanging fake engine, an engine that writes more than the limit, and a crashing engine each leave a completed, degraded scan |
| Scrubbed environment, no network, read-only repository, private temporary directory | Engine sandbox tests of E14 and the hardening tests of E40: a fake engine that prints its environment and tries to open a connection and to write into the repository |
| Telemetry off | The table and the guard of E01-31; a test per adapter that the switch is set |
| Version recorded | Adapter tests of E14 and the report tests of E30 (appendix "tools and versions") |
| Licences | The licence gate of E01-30 for Python dependencies; `docs/research/INSIGHTS.md` for engines |

The tests of E14 and E40 do not exist yet. Those issues are to be checked against this table.

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Unchanged: I1 to I6 are not altered. This record is the design-time control for the "malicious or compromised engine" row of the threat model (`docs/ARCHITECTURE.md` section 6.4).

- Engines run inside the trusted boundary and see raw client code. That is acceptable only because they are local: an engine has no network, no credentials in its environment and a read-only view of the repository, so a compromised engine can read the code it was given but cannot send it anywhere and cannot reach the vault or a provider key.
- An engine that uploads code or metrics by default must have that behaviour switched off by its adapter and verified by a test. If it cannot be switched off, the engine cannot be supported.
- The fail-closed attitude of I4 is extended to engines in the form that fits them: an engine failure degrades the scan and is reported; it is not hidden.
- Engine output is data. It reaches the LLM only through the privacy layer, like any other candidate.

## Implementation notes (optional; the only section that may grow after acceptance)

None yet.

## Links

- `docs/ARCHITECTURE.md` section 2 (External engines row), section 6.4 (threat model), section 8 (appendix: tools and versions).
- `docs/PLAN.md` section 8 (risk: third-party engine licences). `AGENTS.md` section 3.
- ADR-0001 (technology stack), ADR-0003 (single egress), ADR-0005 (no telemetry).
- SARIF 2.1.0 (OASIS). E14 (adapter base and sandbox), E15 (engines per language), E16 and E17 (native rules and taint), E39 (container images), E40 (hardening).
