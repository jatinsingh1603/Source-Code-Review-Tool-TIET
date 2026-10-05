# ADR-0001: Technology stack

| | |
|---|---|
| Status | Accepted |
| Date | 2026-10-05 |
| Deciders | CodeKavach maintainers |
| Issue | #21 |
| Affects | docs/ARCHITECTURE.md section 2; every package of `codekavach`; invariants I1, I2, I3 and I5 |

## Context and problem statement

`docs/ARCHITECTURE.md` section 2 lists the technology choices in a table with one-line reasons. That is enough for a reader who accepts the choices. Contributors, and the examiners of the university project, ask more: why Python and not Go or Rust for a scanner, why tree-sitter and not a compiler front end per language, why an own `LLMProvider` protocol when abstraction libraries exist, why two databases. Without a record the same discussion restarts in every issue.

This record states, for each row of the table, which options were considered, what was chosen, why, and which costs were accepted with the choice. It changes no choice; the table in the architecture document stays the summary.

## Decision drivers

- **Privacy invariants have to be enforceable by tooling**, not by care: a single egress point (I1), sanitised payload types (I2), a local vault (I3) and deterministic pseudonyms (I5) need a type system, import contracts and reproducible builds.
- **Provider neutrality** (requirement R3, principle 6 of `docs/PLAN.md`) and **air-gapped operation** (R5).
- **Eleven target languages** (R6) with one analysis core.
- **Three months and a student team**: familiar, well-documented tools; one core that the CLI, the server and the integrations share.
- **MIT distribution** and scanning of proprietary code: every dependency licence has to be compatible (`AGENTS.md` section 3).

## Considered options

For each concern the options are listed with the chosen one first. The choice and its reasons follow in "Decision outcome".

| Concern | Options considered |
|---------|--------------------|
| Core language | Python 3.12; Go; Rust; TypeScript on Node.js |
| Packaging | uv with `pyproject.toml` and a `src/` layout; Poetry; PDM; pip-tools with setuptools |
| Data models | Pydantic v2; dataclasses with a separate validator; attrs; msgspec |
| CLI | Typer with Rich; Click directly; argparse |
| Parsing | tree-sitter through `tree-sitter-language-pack`; language-native parsers (`ast`, a TypeScript compiler API, JavaParser); a code property graph tool as the core |
| External engines | Subprocesses or containers with SARIF exchange; importing engines as libraries; re-implementing all checks natively (decided in ADR-0002) |
| LLM transport | Own `LLMProvider` protocol with adapters; one abstraction library (LiteLLM) as the core interface; one vendor SDK |
| Local store | SQLite and PostgreSQL through SQLAlchemy 2 with Alembic; SQLite only; flat JSON files; PostgreSQL only |
| Vault cryptography | AES-256-GCM from `cryptography` with keys from the OS keyring, a passphrase (scrypt) or a KMS; a higher-level recipe such as Fernet; libsodium bindings; an own construction |
| Server | FastAPI; Flask; Django |
| Dashboard | React, TypeScript, Vite and Tailwind; server-rendered templates with htmx; Vue or Svelte |
| Reports | Jinja2 with WeasyPrint, docxtpl, XlsxWriter and Pygments; LaTeX; a headless browser for PDF; ReportLab |
| Quality tooling | ruff, mypy in strict mode, pytest, hypothesis, import-linter, pre-commit and GitHub Actions; flake8 with black and isort; pyright; no import contracts |
| Logging | structlog; standard-library `logging`; loguru (decided in ADR-0005) |

## Decision outcome

The choices of `docs/ARCHITECTURE.md` section 2 are confirmed. The reasons and the accepted costs per concern:

### 1. Core language: Python 3.12

- **For.** The security-engine, PII-detection and LLM SDK ecosystems are Python-first, so most integrations need no bridge. Student contributors know the language. Pydantic gives validated models and JSON Schema, which the LLM layer uses as its structured-output contract.
- **Against Go and Rust.** Both would parse a whole repository faster and ship as one binary, but the engines, the PII models and the provider SDKs would have to be reached through subprocesses or foreign-function bridges, and the team would write less of the product in the time available. TypeScript shares the SDK ecosystem only in part and has no equivalent of the Python analysis libraries.
- **Negative consequences.** Slower than Go or Rust for whole-repository work, and the global interpreter lock limits threads that run Python code. Mitigation: the heavy parsing happens in tree-sitter (C), engines run as separate processes, the analyse stage runs its engines concurrently (`docs/ARCHITECTURE.md` section 4), and a performance budget is tracked per stage.

### 2. Packaging: uv, `pyproject.toml`, `src/` layout

- **For.** One tool creates the environment, resolves and locks dependencies and builds the package; `uv.lock` makes installs reproducible, which air-gapped bundles and the determinism of I5 tests rely on. The `src/` layout keeps tests from importing the working tree by accident, so they exercise the installed package.
- **Against the alternatives.** Poetry and PDM do the same job with slower resolution and their own lock formats; pip-tools needs a second tool for environments and a third for building.
- **Negative consequences.** uv is younger than its alternatives and contributors have to install it; the lock file format is specific to uv.

### 3. Data models: Pydantic v2

- **For.** Validation at every boundary, JSON Schema export into `docs/schemas/`, and direct use of the same models as the structured-output contract of the LLM layer (`docs/ARCHITECTURE.md` section 7). Distinct model types for raw and sanitised data let mypy check I2.
- **Against the alternatives.** Dataclasses and attrs need a separate validator and a separate schema generator; msgspec is faster but has a smaller validation vocabulary and no comparable schema tooling for our use.
- **Negative consequences.** Validation costs time on hot paths, so internal loops pass already-validated objects. The models are tied to one library; a major version change of Pydantic is a migration.

### 4. CLI: Typer with Rich

- **For.** Commands are typed functions, so options and help text come from the signature; Rich gives tables and progress output without own terminal code.
- **Against the alternatives.** Click directly means more boilerplate for the same result; argparse has no command tree conventions and no terminal rendering.
- **Negative consequences.** Rich can render tracebacks with local variables, which could print client code, secrets or vault entries on a crash. Pretty exceptions are therefore switched off in `codekavach.cli.app` and must stay off. Typer ships its own copy of Click, so features of upstream Click are not always available (ADR-0008).

### 5. Parsing: tree-sitter through `tree-sitter-language-pack`

- **For.** One API for all eleven target languages of requirement R6, tolerance of incomplete or broken code, and speed.
- **Against the alternatives.** Language-native parsers give exact syntax trees and sometimes types, but each needs its own runtime and its own adapter, eleven times. A code property graph tool as the core would bring data flow for free but makes a heavy external system the centre of the product.
- **Negative consequences.** A concrete syntax tree carries no type information and no name resolution. E07 builds symbols, scopes and imports on top, and the analysis is less exact than a compiler's where types matter.

### 6. External engines: subprocesses or containers, SARIF

- **For.** Licences stay separate, engines are optional and replaceable, and a failing engine cannot take the scan down.
- **Negative consequences.** Process start-up time, an installation burden for the user, and version skew between engines and adapters.
- The options, the boundary rules and the isolation expectations are the subject of ADR-0002.

### 7. LLM transport: own `LLMProvider` protocol

- **For.** Provider neutrality is requirement R3 and principle 6 of `docs/PLAN.md`. The single-egress invariant (ADR-0003) requires that an adapter builds a request and does not send it; an own protocol can say exactly that, and can accept sanitised payload types only.
- **Against the alternatives.** An abstraction library as the core interface sends requests itself and decides which hosts are contacted, which is what I1 forbids outside the transport; a single vendor SDK contradicts R3. LiteLLM, native SDKs, OpenAI-compatible endpoints and Ollama are therefore adapters among several, next to the mock and replay providers.
- **Negative consequences.** The project maintains its own adapters and a conformance suite, and new provider features arrive only when an adapter is written for them.

### 8. Local store: SQLite and PostgreSQL through SQLAlchemy 2, Alembic

- **For.** SQLite needs no setup for the CLI; PostgreSQL serves concurrent users in server mode; one schema definition and one migration history cover both.
- **Against the alternatives.** SQLite only does not serve several writers well; flat files give no queries and no migrations; PostgreSQL only would make a database server a prerequisite of a command-line scan.
- **Negative consequences.** Two dialects have to be tested, and features that only one of them has are off limits.

### 9. Vault cryptography: AES-256-GCM from `cryptography`

- **For.** Standard, audited primitives: authenticated encryption for the vault, and a key that comes from the OS keyring, a passphrase stretched with scrypt, or a KMS. The project writes no cryptographic construction of its own.
- **Against the alternatives.** A recipe such as Fernet is simpler but fixes parameters the vault format wants to choose; libsodium bindings are a further native dependency for the same properties; an own construction is ruled out.
- **Negative consequences.** `cryptography` ships compiled wheels, so an air-gapped installation has to bundle them for each platform (E39). Using a primitive instead of a recipe puts nonce handling in our code, where it has to be tested (E10).

### 10. Server: FastAPI

- **For.** Asynchronous request handling, server-sent events for progress, and an OpenAPI description generated from the same Pydantic models.
- **Against the alternatives.** Flask needs extensions for each of these; Django brings an object-relational mapper and a project structure the core already has.
- **Negative consequences.** Asynchronous code and the synchronous pipeline have to be joined through background workers, which is a place for subtle errors.

### 11. Dashboard: React, TypeScript, Vite, Tailwind

- **For.** Common tools with a large pool of contributors who know them.
- **Against the alternatives.** Server-rendered templates with htmx would avoid a JavaScript build but make the interactive finding views harder; Vue and Svelte are equally capable and less known in the team.
- **Negative consequences.** A second language and build chain in the repository, with its own dependency tree and its own supply-chain exposure.

### 12. Reports: Jinja2 with WeasyPrint, docxtpl, XlsxWriter, Pygments

- **For.** Templates that an auditor can edit, rendering in pure Python code, and a self-contained HTML report.
- **Against the alternatives.** LaTeX gives fine typesetting at the price of a large installation and templates few auditors can change; a headless browser is a heavy runtime dependency and a network-capable component inside the trusted boundary; ReportLab means layout in code instead of templates.
- **Negative consequences.** WeasyPrint needs system libraries (Pango and its dependencies), which Docker images and the devcontainer have to provide (E01-29, E39); where they are missing the PDF renderer is unavailable and the tool has to say so.

### 13. Quality tooling

- **Choice.** ruff, mypy in strict mode, pytest, hypothesis, import-linter, pre-commit and GitHub Actions.
- **For.** Privacy invariants are enforced by tests and import contracts: import-linter and banned-API rules for I1, I2 and I3, property-based tests for the privacy package, mypy for the payload types.
- **Against the alternatives.** flake8 with black and isort is three tools for what ruff does in one; pyright is a capable checker but mypy has the Pydantic plugin the models rely on; leaving out import contracts would leave I1 to code review.
- **Negative consequences.** Strict typing and contracts slow down first contributions, and the checks add minutes to every push.

### 14. Logging

structlog, with events on stderr and a redaction step in the processor chain; no telemetry. The options and reasons are in ADR-0005.

### Supported platforms

Python 3.12 and 3.13. Linux and macOS are tested in CI. Windows is supported through WSL2 or the devcontainer and is not a CI target in v1.0.

### Dependency policy

A runtime dependency must have a licence compatible with MIT distribution (`AGENTS.md` section 3). It is recorded in `RESOURCE.md`, which together with `REFERENCE.md` is where sources are catalogued, and it is added by the first issue that imports it. A dependency that only one interface needs goes into an optional extra; the reserved extras are `server`, `reports`, `providers`, `pii` and `eval`. A dependency must not send telemetry (E01-31). Licence checking is automated by E01-30.

### Consequences (positive, negative, neutral)

- Positive: one language and one set of models from the CLI to the server; the invariants are checkable by tools that already run in CI; no choice ties the product to one LLM vendor or one engine.
- Negative: the costs listed per concern above, of which the most important are the speed of Python for whole-repository work, the absence of type information in the syntax trees, the maintenance of own provider adapters, and system libraries for PDF rendering.
- Neutral: the dashboard is a separate build with its own tooling; it talks to the core only through the API.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Choice | Enforced by |
|--------|-------------|
| Python 3.12 and 3.13 | `requires-python` in `pyproject.toml`; the CI test matrix (both versions on Linux and macOS) |
| uv and the lock file | `make lock-check` in the CI lint job and the `uv-lock` pre-commit hook; CI installs with `uv sync --locked` |
| `src/` layout and package tree | `tests/unit/test_package_layout.py`; the wheel-contents check of the CI build job |
| Pydantic models and schemas | The schema drift check (`python -m codekavach.core.models.export --check`) in CI and pre-commit; mypy with the Pydantic plugin |
| Typer and Rich without pretty exceptions | `pretty_exceptions_enable=False` in `codekavach.cli.app`, with the reason in a comment next to it; the CLI conventions of ADR-0008 and the help snapshots in `tests/unit/cli/snapshots/help/` |
| tree-sitter | The parsing tests of E07, to be added with that epic |
| External engines as processes | ADR-0002; the ruff configuration (`S603` allowed, `S602` and `S604` to `S607` on) |
| Own provider protocol | Import contracts `i1-single-egress` and `i2-llm-no-raw-code`; `tests/privacy/test_i2_static_guard.py`; `tests/privacy/test_import_contracts.py` |
| SQLAlchemy and Alembic | The migration check (`--check-migrations`) in CI and pre-commit; the store tests under `tests/unit/core/store/` |
| Vault cryptography | Import contract `i3-vault-locality`; the vault tests of E10, to be added with that epic |
| Server, dashboard, reports | The tests of E32, E33 and E31, to be added with those epics; the licence gate of E01-30 |
| Quality tooling | The CI jobs `lint`, `typecheck`, `contracts`, `hooks` and `test` of `.github/workflows/ci.yml` |
| No telemetry | `tests/privacy/test_no_telemetry_deps.py`; ADR-0005 |

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Unchanged: this record documents choices already in force and alters no invariant. It states how the stack supports them:

- **I1.** The own `LLMProvider` protocol exists so that adapters build requests and only `codekavach.privacy.egress.transport` sends them. Adopting an abstraction library as the core interface would have moved the sending out of our control.
- **I2.** Raw and sanitised data are distinct Pydantic types, so passing raw code to the LLM layer is a type error under mypy in strict mode, and the import contract and the static guard cover what types do not.
- **I3.** The vault is protected by standard, audited primitives from `cryptography`; the project writes no cryptography of its own.
- **I5.** Locked dependencies, canonical serialisation of the models and deterministic tooling make it possible to test that the same scan salt and the same input give the same pseudonyms.

## Implementation notes (optional; the only section that may grow after acceptance)

None yet.

## Links

- `docs/ARCHITECTURE.md` section 2 (the table this record explains), section 4 (pipeline concurrency) and section 7 (LLM layer).
- `docs/PLAN.md` section 2 (requirements R3, R5, R6) and section 4 (principles 1 and 6).
- ADR-0002 (external engines), ADR-0003 (single egress), ADR-0005 (logging and no telemetry), ADR-0008 (CLI conventions).
- Tools named in this record: uv, Pydantic v2, Typer, Rich, tree-sitter, tree-sitter-language-pack, LiteLLM, SQLAlchemy 2, Alembic, `cryptography`, FastAPI, React, TypeScript, Vite, Tailwind, Jinja2, WeasyPrint, docxtpl, XlsxWriter, Pygments, ruff, mypy, pytest, hypothesis, import-linter, pre-commit, GitHub Actions, structlog. Their sources are catalogued in `RESOURCE.md` and `REFERENCE.md`.
