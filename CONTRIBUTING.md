# Contributing to CodeKavach

Thank you for your interest. This guide takes you from a fresh clone to a passing check and a correctly formed first commit, and tells you which document governs what. It is short on purpose: where a rule lives elsewhere, this page links to it.

## 1. Welcome and scope

CodeKavach is a privacy-preserving, LLM-assisted secure source code review tool. It finds candidate vulnerabilities with deterministic analysis, and sends only sanitised slices of code to a language model for review.

Contributions that are welcome: code, rule packs, support for a language, documentation, evaluation data and bug reports.

What the project does not accept:

- Automatic code fixing, or pull requests against client repositories. Both are out of scope for v1.0 (`docs/PLAN.md` section 3).
- Telemetry of any kind ([ADR-0005](docs/adr/0005-logging-and-no-telemetry.md)).
- Anything that weakens the privacy invariants I1 to I6 (section 8 below).

## 2. Where things are decided

| Document | Decides |
|----------|---------|
| [`docs/PLAN.md`](docs/PLAN.md) | What is built, and when |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The structure; this document is normative |
| [`docs/adr/`](docs/adr/README.md) | Why a significant decision was taken |
| [`AGENTS.md`](AGENTS.md) | How to work an issue, for people and coding agents |
| The [project board](https://github.com/users/jatinsingh1603/projects/1) | The status of the work |

The weekly rhythm is described in [`docs/process/sprint-cadence.md`](docs/process/sprint-cadence.md).

## 3. Set-up

You need Git, `uv` and `make`. Python is installed by `uv`; follow the official documentation of `uv` to install it.

```bash
make setup
make check
```

`make setup` creates the environment and installs the Git hooks. `make check` runs every gate that CI runs: formatting, lint, types, import contracts and the tests. `make help` lists the other targets.

On Windows the supported route is the devcontainer or WSL2 ([ADR-0001](docs/adr/0001-technology-stack.md), "Supported platforms").

**Devcontainer.** Open the repository in VS Code with the Dev Containers extension, or in GitHub Codespaces, and choose "Reopen in Container". The container (`.devcontainer/`) gives you:

- Python 3.12, `uv`, `make`, Git and Node 22;
- the WeasyPrint system libraries;
- `make setup`, run automatically on creation.

The virtual environment lives at `/home/vscode/.venvs/codekavach`, outside the workspace, so the host and the container do not share a `.venv`. The container mounts no host credentials and runs nothing privileged, and editor and tool telemetry are off. Set provider keys inside the container session when you need them. The `Devcontainer` workflow rebuilds the container and runs `make check` in it whenever `.devcontainer/` changes.

## 4. Workflow

- **Core team and coding agents:** pick an issue as described in [`AGENTS.md`](AGENTS.md) section 2 and commit small, focused changes directly to `main`.
- **Outside contributors:** fork the repository, work on a branch and open a pull request against `main`. CI has to pass, and a maintainer merges.

Either way, the change serves an open issue. If none fits, open one first and describe the problem.

## 5. Commit messages

```text
<area>: <imperative summary>

Optional body that says what changed and why.

Refs #<issue>
```

- The areas are `core`, `cli`, `ingest`, `parsing`, `privacy`, `llm`, `engines`, `rules`, `taint`, `risk`, `report`, `api`, `ui`, `github`, `eval`, `docs` and `infra`.
- The subject has at most 72 characters, starts in lower case and has no full stop. `Refs #n` or `Closes #n` stands on a line of its own.
- Commits, issues and documents carry no tool attribution lines and no co-author trailers ([`AGENTS.md`](AGENTS.md) section 5).

Two examples:

```text
privacy: reject payloads that contain vault identifiers
```

```text
cli: add the --strict option to scan

Exits 1 when a stage was degraded.

Refs #169
```

A Git hook checks the message when you commit, and the CI job `commits` checks it again. The checker is `tools/dev/check_commit_msg.py`; run it with `--help` to see the rules.

## 6. Coding standards

- Python 3.12. Every public function has type hints; `ruff` and `mypy --strict` are clean (`make lint`, `make type`).
- Docstrings in Google style.
- British spelling in identifiers and prose: `pseudonymise`, `normalise`, `artefact`, and `licence` as a noun.
- No `print`. Loggers come from `codekavach.core.log` only ([ADR-0005](docs/adr/0005-logging-and-no-telemetry.md)). Do not log code, payloads or secrets.
- Module paths and interface names follow [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 3.
- **Lazy imports keep start-up fast.** The rules:
  1. Package `__init__.py` files import nothing.
  2. A CLI command module imports its implementation inside the command function, not at module top level (`from codekavach.core.pipeline import run_scan  # lazy`).
  3. Optional extras are imported inside the function that needs them, and a missing package raises an error naming the extra, for example `ImportError("PDF reports need the 'reports' extra: pip install 'codekavach[reports]'")`.
  4. Type-only imports go under `if TYPE_CHECKING:`.
  5. Plugin discovery lists entry points and loads a plugin on first use.

  `tests/unit/test_import_budget.py` fails when `import codekavach.cli.app` loads a module from its `HEAVY` list. Run `uv run python tools/dev/importtime_report.py` to see the slowest imports. The CLI side of these rules is in [`docs/process/cli-conventions.md`](docs/process/cli-conventions.md).

## 7. Tests

Tests are part of the change, not a follow-up. The suite has four tiers, each with its marker: `unit`, `integration`, `e2e` and `privacy`. Anything under `codekavach.privacy` is tested with `hypothesis`. Test data uses fake secrets only.

The conventions, the helpers and how to run one tier are in [`tests/README.md`](tests/README.md).

## 8. Privacy invariants

The six invariants I1 to I6 are listed in [`AGENTS.md`](AGENTS.md) section 4 and explained in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 6.3. In one sentence: only the egress transport talks to an LLM endpoint, the LLM layer sees sanitised payloads only, the vault stays local, privacy steps fail closed, pseudonyms are deterministic, and no original identifier, literal or secret appears in a ledger payload.

```bash
make contracts
```

checks the import contracts that enforce part of this.

A change that touches `codekavach.privacy`, `codekavach.llm` or outbound network access must add or update a test that would fail if the invariant broke.

Do not paste client code, real secrets, or vault or ledger content into an issue, a pull request or a test.

## 9. Dependencies

- The licence has to be compatible with MIT distribution ([`AGENTS.md`](AGENTS.md) section 3).
- Add the dependency to the right optional extra or dependency group in `pyproject.toml`, and record a runtime dependency in `RESOURCE.md`.
- Analysis engines are not imported; they run as separate programs ([ADR-0002](docs/adr/0002-external-engines-as-subprocesses.md)).
- No package that sends telemetry.

The reasons are in [ADR-0001](docs/adr/0001-technology-stack.md), "Dependency policy".

`make licences` (and the CI job `licences`) checks the licence of every installed package against `[tool.codekavach.licences]` in `pyproject.toml`. Everything a user installs must be `allowed`. Development-only tools fail only when `denied`. When the gate fails:

- **`denied`** (GPL, AGPL, SSPL and similar): do not add the package; find an alternative.
- **`unknown`**: the metadata does not say which licence applies. Read the licence file the package ships. If the licence is clear, add an entry under `[tool.codekavach.licences.exceptions]` with the licence, the reason and the issue number.
- **`review`** (LGPL, EPL, CDDL and similar): a person decides. Label the issue `needs-human`, name the package and its licence, and record the decision as an exception once it is made.

The gate is an engineering control, not legal advice.

Dependabot opens grouped pull requests every Monday for Python dependencies and GitHub Actions (`.github/dependabot.yml`). They are the exception to direct-to-main work:

- CI has to be green.
- For a runtime dependency, read the upstream changelog first.
- An update can add a transitive dependency, so look at the licence and telemetry checks in the CI result.
- Merge with a merge or squash commit whose subject keeps the `infra:` prefix.
- Do not enable auto-merge for runtime dependencies.

## 10. Changelog and ADRs

A change that a user, operator or integrator can observe adds a fragment under `changelog.d/`, named `<issue>.<type>.md`. The types and the style are in [`changelog.d/README.md`](changelog.d/README.md).

```bash
make changelog-draft
```

prints the upcoming changelog section.

A change that alters the architecture, touches an invariant or an import contract, adds a network destination, or reverses an earlier decision needs an architecture decision record; the full list is in [`docs/adr/README.md`](docs/adr/README.md). Create one with:

```bash
make adr title="Title of decision"
```

After editing documentation, run:

```bash
make docs-check
```

It checks links and anchors without network access.

## 11. Reporting bugs and vulnerabilities

- **Bugs:** open an issue with the template.
- **Vulnerabilities:** report them privately, as described in [`SECURITY.md`](SECURITY.md). A bypass of a privacy invariant is a vulnerability.

Do not paste client code, real secrets, or vault or ledger content into an issue.

## 12. Licensing of contributions

Contributions are accepted under the repository's [MIT licence](LICENSE): what comes in has the licence of what goes out. There is no contributor licence agreement. By contributing you confirm that you have the right to submit the work.

Do not copy code from a source whose licence is incompatible with MIT, and do not paste code that was produced in, or copied out of, a client engagement.

## 13. Conduct

Be respectful and constructive. The project's code of conduct is [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
