# ADR-0004: Changelog and versioning

| | |
|---|---|
| Status | Accepted |
| Date | 2026-10-05 |
| Deciders | CodeKavach maintainers |
| Issue | #33 |
| Affects | `CHANGELOG.md`, `changelog.d/`, `pyproject.toml` (`[tool.towncrier]`, the project version), `AGENTS.md` section 7 |

## Context and problem statement

`AGENTS.md` section 7 makes a changelog entry part of the definition of done for user-visible changes, and the final deliverable is a v1.0 release (`docs/PLAN.md` section 9). The project therefore needs to decide how the changelog is produced and how versions are numbered.

Two facts about this project shape the decision. Commit subjects use area prefixes (`privacy: ...`, `infra: ...`, see `AGENTS.md` section 5), not the types of Conventional Commits. And many contributors, people and coding agents, commit directly to `main` in parallel, without pull requests.

## Decision drivers

- A changelog entry is written for users of the tool, by the person who made the change, at the time of the change.
- Parallel contributors must not collide in one shared file.
- No tooling that needs extra credentials or a pull-request workflow.
- One place for the version number.
- Changes to what leaves the client's machine have to be easy to find in the changelog.

## Considered options

1. **Fragments collected by towncrier.** Each change adds a small file under `changelog.d/`; at release time the files are rendered into `CHANGELOG.md` and removed.
2. **release-please.** Rejected: it derives the changelog from Conventional Commits types, which the project's area-prefixed subjects are not, and it needs a GitHub App or a token to open release pull requests, while the project commits directly to `main`.
3. **A hand-edited `CHANGELOG.md`.** Rejected: with parallel contributors every change touches the same lines at the top of one file, which produces merge conflicts.
4. **A changelog generated from `git log`.** Rejected: commit subjects are written for developers, not for users, and one user-visible change is often several commits.

## Decision outcome

Chosen option: 1, fragments collected by towncrier (MIT licence), in the format of Keep a Changelog 1.1.0.

### Changelog

- `CHANGELOG.md` holds the released sections below a marker line. It is not edited by hand.
- A user-visible change adds one fragment `changelog.d/<issue-number>.<type>.md`, or `changelog.d/+<short-slug>.<type>.md` when there is no issue. The naming and style rules are in `changelog.d/README.md`.
- The six fragment types are the categories of Keep a Changelog: `added`, `changed`, `deprecated`, `removed`, `fixed`, `security`.
- A change to what leaves the client's machine (privacy levels, redaction, egress behaviour) goes under `security` and starts with the word "Privacy:".
- User-visible means: anything a user, operator or integrator can observe. Refactoring, tests, CI and internal documentation need no fragment.
- `make changelog-draft` renders the upcoming section without changing a file. `towncrier build --version X.Y.Z` consumes the fragments and is run only when a release is cut (E39).
- Work done before this record is not back-filled, apart from one fragment for the scaffolding.

### Versioning

The project follows Semantic Versioning 2.0.0, with version strings in the form of PEP 440. The public interface for the purpose of Semantic Versioning is: the command line, the configuration file format, the report and SARIF outputs, the REST API, and the plugin entry-point interfaces.

| Milestone | Version |
|-----------|---------|
| M0 Foundations | `0.1.0.dev0` (no release) |
| M1 Privacy layer MVP + Demo 1 | `0.1.0` |
| M2 to M7 | `0.2.0` to `0.7.0`, one minor version per milestone |
| M8 Hardening and release | `1.0.0` |

Before `1.0.0`, a minor version may break an interface, and each break gets a `changed` or `removed` fragment. The version lives only in `pyproject.toml`. Tags are `vX.Y.Z`.

### Consequences (positive, negative, neutral)

- Positive: no merge conflicts in the changelog; an entry is written while the change is fresh; privacy-relevant changes are grouped under one heading with a fixed first word.
- Negative: one more file per user-visible change, and one more development dependency (towncrier with Jinja2); whether a change needed a fragment cannot be decided mechanically and stays a review point of the definition of done.
- Neutral: cutting releases, tagging and publishing are left to E39.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Rule | Enforced by |
|------|-------------|
| Fragment file names and non-empty fragments | `tools/dev/check_changelog_fragments.py`, run by `make changelog-check` in the CI `lint` job; `tests/unit/tools/test_changelog_fragments.py` |
| The six types | The same test compares the `[tool.towncrier]` types of `pyproject.toml` with the Keep a Changelog categories |
| The configuration renders a Keep a Changelog section | The integration test in the same file runs `towncrier build --draft` on a copy |
| A fragment for each user-visible change | Not mechanical: a line of the definition of done in `AGENTS.md` section 7 |
| One place for the version | `pyproject.toml`; `codekavach --version` reads the installed metadata |

`towncrier check` is not used: it compares against a branch, which says nothing when commits go directly to `main`.

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Unchanged: no invariant is touched. The record makes changes to privacy behaviour visible to users, because they are collected under `security` with the first word "Privacy:". Fragments are public text; they do not describe an unfixed vulnerability in detail and do not contain client names or data.

## Implementation notes (optional; the only section that may grow after acceptance)

None yet.

## Links

- `AGENTS.md` sections 5 and 7. `docs/PLAN.md` section 5 (milestones) and section 9 (deliverables).
- Keep a Changelog 1.1.0; Semantic Versioning 2.0.0; PEP 440; towncrier; release-please (rejected option).
- `changelog.d/README.md`.
