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

## Network

The default run cannot open network sockets (`pytest-socket`, `--disable-socket`); Unix domain
sockets stay allowed for event loops and subprocess plumbing.

| Tier | Rule | How |
|------|------|-----|
| unit, privacy | No sockets at all | default `--disable-socket` |
| integration, e2e | Loopback only, and only when declared | `@pytest.mark.allow_hosts(["127.0.0.1", "::1"])` on the test |
| external network | Never in CI; opt-in locally | `@pytest.mark.network`, deselected by `-m "not network"` and skipped unless `CODEKAVACH_TEST_NETWORK=1` |

Limitation: child processes are not covered by `pytest-socket`. `tests/privacy/test_import_purity.py`
therefore also imports every module in a child interpreter with its own socket guard, and E12 adds
a process-level egress test. On Windows, asyncio builds its self-pipe from a loopback socket pair,
so a test that runs an event loop declares `allow_hosts(["127.0.0.1", "::1"])`.

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

## Property-based tests (hypothesis)

Profiles are registered in `tests/conftest.py` and selected with `HYPOTHESIS_PROFILE`; an unknown name stops the run with a usage error.

| Profile | max_examples | deadline | derandomize | Use |
|---------|--------------|----------|-------------|-----|
| `dev` (default) | 50 | 500 ms | no | local runs |
| `ci` | 200 | none | yes | GitHub Actions: reproducible, prints a reproduction blob |
| `nightly` | 2000 | none | no | before a release and in scheduled runs |

`ci` is derandomised so that a privacy regression reproduces on every run and every machine; `nightly` explores new examples. To reproduce a failing example, copy the `@reproduce_failure(...)` decorator that hypothesis prints (the `ci` profile prints it) onto the test, or rerun locally with `HYPOTHESIS_PROFILE=ci`. The example database `.hypothesis/` is not committed.

Shared strategies live in `tests/support/strategies.py`: `identifiers()`, `fake_secrets()` and `nested_json(leaves)`. E02 adds model strategies to the same module and profiles to the same registration; never register a profile name twice.

## Synthetic values

Tests hold synthetic values only, never a real credential, not even an expired one (`AGENTS.md` section 3). Secret-shaped values come only from `tests/support/synthetic.py`:

- the only contiguous secret-shaped literals are the two AWS documentation examples (`AWS_EXAMPLE_ACCESS_KEY_ID`, `AWS_EXAMPLE_SECRET_ACCESS_KEY`);
- every other value is assembled at runtime from prefix fragments with `build_secret(kind, body)` or `example_secret(kind)` (a fixed value per kind), so no token-shaped literal is ever committed;
- values match the detector pattern of their kind in `SECRET_SHAPES` but are not live; formats with a checksum (GitHub tokens) fail it.

Do not paste a token-shaped string into a test; add a kind to `SECRET_SHAPES` instead. Small static inputs shared by several tests go in `tests/fixtures/`.

The `detect-secrets` pre-commit hook compares every commit against the audited `.secrets.baseline` and fails on anything new. If a literal fake secret is truly unavoidable:

1. prefer an inline marker on that line: `# pragma: allowlist secret`; or
2. update the baseline with `uv run detect-secrets scan --baseline .secrets.baseline`, review it with `uv run detect-secrets audit .secrets.baseline` (mark each new entry as not a secret only after checking it), and say so in the commit body.

Never exclude `tests/` or `fixtures/` from the scanner: a real key pasted into a fixture is exactly the accident the hook exists for. The baseline should stay close to empty; a growing baseline is a review signal.

## Golden files

Expected outputs live in a `golden/` directory next to the test that uses them and are compared byte for byte with `tests.support.golden.assert_matches_golden(actual, path)`. Text differences are shown as a unified diff, binary ones by the offset of the first differing byte. To create or update expectations, run the test with `CODEKAVACH_UPDATE_GOLDEN=1` and review the diff before committing. The update is refused when `CI` is set, so a pipeline can never rewrite its own expectations.

## Performance budgets

A `perf` test builds its input outside the timed region, then asserts `measure(fn) <= budget(seconds)` using `tests/support/perf.py` and prints the measured number. `measure` returns the best of three runs; `budget` scales the limit by `CODEKAVACH_PERF_FACTOR` (default 1.0; must be a positive number).

```python
@pytest.mark.perf
def test_load_settings_budget() -> None:
    data = build_input()
    elapsed = measure(lambda: load(data))
    print(f"load: {elapsed * 1000:.1f} ms")
    assert elapsed <= budget(0.05)
```

## Warnings

`filterwarnings = ["error"]` turns every warning into a failure. When a third-party deprecation warning appears, add the narrowest possible `ignore:` line in `pyproject.toml` with a comment naming the package and version; never add a blanket ignore.
