# Tests

Privacy invariants I1 to I6 (`docs/ARCHITECTURE.md` section 6.3) are enforced by tests, so the harness is strict by default: warnings are errors, unknown markers fail collection, and tests that need the network are deselected.

## Tiers

| Tier | Directory | What belongs there |
|------|-----------|--------------------|
| unit | `tests/unit/` | Fast, in-process tests. No subprocess except the interpreter itself, no network |
| integration | `tests/integration/` | Several modules together, the real filesystem, our own CLI as a subprocess |
| e2e | `tests/e2e/` | Full `codekavach` runs against fixtures |
| privacy | `tests/privacy/` | Invariant tests for I1 to I6, property-based where possible |

The tier marker is applied automatically from the directory (`tests/conftest.py`, `tests/support/tiers.py`); do not add it by hand. Top-level test directories that are not tiers (for example `tests/process/` or `tests/perf/`) are collected normally and get no tier marker.

## Markers

| Marker | Meaning |
|--------|---------|
| `unit`, `integration`, `e2e`, `privacy` | Tier, applied automatically |
| `slow` | Takes more than about two seconds; a test that needs more than the 120 s timeout also sets `@pytest.mark.timeout(<seconds>)` |
| `perf` | Performance budget test; part of the default run; limits scale with `CODEKAVACH_PERF_FACTOR`; macOS CI cells deselect it |
| `network` | Needs external network; deselected by default and never run in CI |
| `requires_engine(name)` | Needs an external analysis engine on `PATH`; skipped when absent |

Markers are strict: a misspelt marker fails collection instead of silently deselecting a test.

## Running

```bash
uv run pytest                          # everything except network tests
uv run pytest -m unit                  # one tier (unit, integration, e2e, privacy)
uv run pytest -m "not network and not perf"   # skip performance budgets on a slow machine
uv run pytest -n auto                  # in parallel (pytest-xdist)
uv run pytest --cov --cov-report=term-missing --cov-report=xml --cov-report=html
```

Coverage is switched on explicitly (the Makefile target `cov` and CI do it), never through `addopts`, so single-test and debugger runs stay fast. The floor for the whole package is 85 % branch coverage.

Test order is shuffled by `pytest-randomly`, and tests must not depend on it. The run header prints the seed; reproduce an order with `--randomly-seed=<n>`, or disable shuffling with `-p no:randomly`.

## Directory convention

Inside a tier, tests mirror the source path: `src/codekavach/core/models/location.py` is tested in `tests/unit/core/models/test_location.py`. In addition:

- tests for scripts under `tools/` live in `tests/unit/tools/`;
- tests about repository configuration files (`pyproject.toml`, workflows, CODEOWNERS and similar) live in `tests/unit/repo/`;
- tests of the shared helpers in `tests/support/` live in `tests/unit/support/`.

Every test directory has an `__init__.py` with a one-line docstring, so two files with the same name in different directories never collide. Whoever creates a directory creates its `__init__.py`. Shared helpers are imported from the repository root, for example `from tests.support.tiers import tier_of`.

## Golden files

Expected outputs live in a `golden/` directory next to the test that uses them and are compared byte for byte. The comparison helper arrives with E01-07.

## Test data

Tests hold synthetic values only, never a real credential, not even an expired one (`AGENTS.md` section 3). Secret-shaped values come only from `tests/support/synthetic.py` (E01-07). Small static inputs shared by several tests go in `tests/fixtures/`.

## Warnings

`filterwarnings = ["error"]` turns every warning into a failure. When a third-party deprecation warning appears, add the narrowest possible `ignore:` line in `pyproject.toml` with a comment naming the package and version; never add a blanket ignore.
