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
