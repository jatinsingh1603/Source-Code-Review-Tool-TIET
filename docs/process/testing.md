# Testing guide

The general test conventions (tiers, markers, synthetic values, golden files, performance budgets) are in [`tests/README.md`](../../tests/README.md). This page collects topic-specific guidance.

## Testing configuration code

Configuration tests must never read the contributor's real configuration, provider keys, keyring or organisation policy. Use the shared helpers instead of touching real paths:

| Helper | Module | Purpose |
|--------|--------|---------|
| `config_sandbox` fixture, `ConfigSandbox` | `tests/support/config.py` | A project root (with `.git`), a user configuration home and an outside directory under `tmp_path`. `write_user()`, `write_project()` and `write_policy()` write the three kinds of file with safe modes; `load()` calls `load_settings(target=root, env=sandbox.env)`. |
| `_isolate_config_env` (autouse) | `tests/support/config.py` | For every test module under a `config` directory: removes `CODEKAVACH_*` and provider variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, ...), redirects `HOME` and `CODEKAVACH_HOME` under `tmp_path`, and empties the system organisation policy paths. `isolate_config_env()` is the same logic for other directories. |
| `memory_keyring` fixture | `tests/support/config.py` | Installs an in-memory keyring backend and restores the previous one; never unlocks the OS keyring. |
| `to_toml()` | `tests/support/config.py` | Writes nested test data as TOML for sandbox files. |
| Strategies | `tests/support/config_strategies.py` | `privacy_levels()`, `trust_tiers()`, `secret_refs()`, `globs()`, `provider_settings()`, `section_dicts(name)`, `settings_dicts()` (always valid) and `layer_sets()` (a user and a project layer). |
| Provider key shapes | `tests/support/synthetic.py` | `example_secret("anthropic_api_key")`, `"openai_project_key"`, `"xai_api_key"` and the earlier kinds; values are assembled at run time and are never live. |

The fixtures are registered through `pytest_plugins` in `tests/conftest.py`.

### Configuration stays offline and fast

Loading configuration is offline (ADR-0006 D9) and runs at the start of every invocation, so three test modules keep it that way:

| Module | What it proves |
|--------|----------------|
| `tests/integration/config/test_offline.py` | `load_settings()` and the seven local `config` commands succeed while `socket.socket`, `create_connection`, `getaddrinfo`, `subprocess.Popen`, `os.system` and `os.posix_spawn` raise. A fresh interpreter that imports and loads `codekavach.config` has none of `keyring`, `cryptography`, `httpx`, `requests`, `urllib3`, `aiohttp`, `litellm`, `anthropic`, `openai`, `boto3` or `google` in `sys.modules`. |
| `tests/unit/config/test_no_telemetry.py` | An `ast` scan of every string constant (docstrings included) under `src/codekavach/config/` finds no URL outside `ALLOWED_HOSTS`, which names each host, its module and the reason. No module imports a network client or credential store at module level; a lazy import inside a function is allowed. |
| `tests/integration/config/test_budget.py` (marker `perf`) | After one warm-up load, the best of 20 `load_settings()` calls on a sandbox with a user file, a project file, a profile and ten environment variables is within `budget(0.05)` seconds. The cumulative `-X importtime` figure of `import codekavach.config` is within `budget(0.4)` seconds. |

Measured at the time of writing: `load_settings()` takes about 5 ms and the package imports in about 360 ms on Windows; roughly 4 ms and 250 ms on Linux. The load budget leaves about ten times headroom. The import budget leaves little (about 1.6 times on Linux), so the test takes the best of three fresh interpreters, and CI relies on its `CODEKAVACH_PERF_FACTOR` of 3.0. A slow laptop that fails only this test needs a factor, not a code change.

`make cov` sets the factor to 3.0 when none is set, because coverage tracing slows the timed code (on a clean Linux machine two budgets failed under `make cov` and passed under `make check`). To relax the budgets locally, set `CODEKAVACH_PERF_FACTOR` (for example `CODEKAVACH_PERF_FACTOR=3`), skip the timing tests with `-m "not perf"` or `CODEKAVACH_SKIP_PERF=1`. The macOS CI cells deselect `perf` tests.

When a budget fails, the cause is almost always an eager import. Find it with `python tools/dev/importtime_report.py --target codekavach.config`, and make the import lazy (inside the function that needs it), as `keys.py` does for `keyring` and `orgpolicy/signature.py` does for `cryptography`.

When a new URL is truly needed in the package, add its host to `ALLOWED_HOSTS` with a reason in the same commit; the telemetry guard then stays a statement of what the package may name.

### The precedence matrix

`tests/integration/config/test_precedence_matrix.py` loads every one of the 64 subsets of the six sources (user file, project file, profile, `CODEKAVACH_*` environment, CLI flags and the organisation policy lock) for a scalar (`scan.max_file_size_kb`), a replaced list (`reporting.formats`) and a union-merged list (`privacy.never_send`), and asserts the winning value and its `Origin`. A test id lists the sources present, for example `scalar-U-P-pr-E-C`, so a failure names the combination. `tests/support/config_matrix.py` holds `build_layers(mask, sandbox, kind)`, which writes the files from `tests/fixtures/config/precedence/` and returns the keywords for `load_settings`.

A locked key must already hold the locked value. In reject mode every subset that contains the lock therefore fails with `CK-CFG-055`, including the lock alone (the default is not the locked value); in clamp mode the locked value wins and the origin is `org-policy`. When you add a layer or change the order, extend `SOURCES` in the helper and the expected order in `expected_winner`; the module is the place that must fail first.
