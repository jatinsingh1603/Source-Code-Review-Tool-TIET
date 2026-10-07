# `codekavach doctor`: the checks

Owning epic: E05 (issues E05-20 and E05-21). Related: invariants I1 and I4 in `docs/ARCHITECTURE.md` section 6.3, `docs/reference/cli-consent.md`, `docs/reference/cli-network-behaviour.md`.

`codekavach doctor` runs a list of checks and prints one row per check with the status `PASS`, `WARN`, `FAIL` or `SKIP`, and a hint for a check that did not pass. It diagnoses and changes nothing. The exit code is 1 when a *required* check failed (with `--strict`, also when any check failed or warned) and 0 otherwise; a missing optional tool is a warning, because the native analysis and the local test doubles work without it. The options are in the [command-line reference](cli.md#codekavach-doctor).

```text
$ codekavach doctor --category providers --probe-providers
PASS  provider:mock:configured       kind mock
PASS  provider:mock:reachable        local mock provider; nothing was sent
WARN  provider:primary:configured    env:ANTHROPIC_API_KEY is not set
SKIP  provider:primary:reachable     consent required
hint  provider:primary:configured    set the variable or change the reference; see `codekavach config key status`
hint  provider:primary:reachable     run `codekavach privacy consent grant --provider primary` on a terminal, or pass --accept-egress
```

Output is pasted into issue trackers, so it holds versions, paths and statuses. It shows no environment variable value and no text of an exception; a crashed check is reported by its exception class (`check crashed: RuntimeError`). A secret reference is shown by name (`env:ANTHROPIC_API_KEY`), as in `codekavach providers list`, and never with a value, a length or a prefix (`tests/unit/cli/test_doctor_external.py`).

## The checks

The first twelve checks do not depend on the settings. The rest are built from the settings when the command starts, so `codekavach doctor --list` shows what would be examined in this project. `Required` means that a failure gives exit code 1. `Network` is `yes` when the check can contact a remote host; see "The provider probe" below.

| Check | Category | Required | Network | What it examines |
|-------|----------|----------|---------|------------------|
| `runtime:python` | runtime | yes | no | The interpreter is Python 3.12 or later. |
| `runtime:package` | runtime | yes | no | The `codekavach` distribution is installed; reports its version and location. |
| `runtime:platform` | runtime | no | no | Operating system, architecture, locale and stdout encoding (UTF-8 expected); the names, not the values, of `CODEKAVACH_*` variables. |
| `config:valid` | config | yes | no | The configuration loads; lists the codes of problems, not their text. |
| `storage:state-dir` | storage | yes | no | The state directory exists and is writable and private, or can be created. |
| `storage:artefacts` | storage | no | no | The artefact store can be read (epic E04). |
| `storage:database` | storage | no | no | The local database is at the newest schema revision (epic E04). |
| `parsing:grammar:python` | parsing | yes | no | The tree-sitter grammar loads (epic E07). |
| `parsing:grammar:javascript` | parsing | yes | no | The tree-sitter grammar loads (epic E07). |
| `secrets:keyring` | secrets | no | no | A usable OS keyring backend exists; no entry is read. |
| `plugins:load` | plugins | no | no | Every allowed plugin loads. |
| `plugins:pipeline` | plugins | no | no | The installed stages resolve into a valid order. |
| `engine:<name>` | engines | no | no | One check per external engine named in `engines.enabled`, `engines.disabled` or `engines.options`, and per installed engine when `engines.enabled` is empty. |
| `provider:<id>:configured` | providers | no | no | One check per enabled provider: its secret reference resolves, by availability only. |
| `provider:<id>:reachable` | providers | no | yes, for a remote provider | One check per enabled provider: a constant probe answers. Runs only with `--probe-providers`. |
| `report:pdf` | report | no | no | The libraries WeasyPrint needs are present. Exists when `reporting.formats` includes `pdf`. |
| `report:fonts` | report | no | no | A font that covers Devanagari is installed. Exists when `reporting.formats` includes `pdf`. |
| `<category>:settings` | engines, providers, report | no | no | A skipped placeholder that replaces the settings-driven checks when the configuration cannot be loaded; `config:valid` says why. |

A check whose back end belongs to an epic that has not landed is `SKIP not available in this build`.

## Engines

`engine:<name>` asks the engine adapter of the plugin registry for its probe. The adapter starts the engine's version command (epic E14), so a `doctor` run can start the engines you enabled, and nothing else. The result is mapped as follows.

| Situation | Status | Summary |
|-----------|--------|---------|
| The engine is switched off (`engines.disabled`, or `engines.options.<id>.enabled = false`) | `SKIP` | `disabled` |
| `engines.enabled` lists other engines | `SKIP` | `not in engines.enabled` |
| Enabled, adapter found, engine runnable | `PASS` | the version and the path or container image |
| Enabled, adapter found, engine absent | `WARN` | `enabled, but not installed`, with the adapter's install hint |
| Enabled, no adapter installed | `WARN` | `enabled, but no adapter for it is installed` |
| Not named, `engines.enabled` empty, engine runnable | `PASS` | as above |
| Not named, `engines.enabled` empty, engine absent | `SKIP` | `not installed`, because nothing asked for it |

`engines.options.<id>.enabled` takes precedence over the two lists, and `engines.disabled` over `engines.enabled`, as in the engine settings. The plugin policy (`plugins.allow_distributions`, `plugins.disable`) applies before an adapter is imported.

## Providers

`provider:<id>:configured` reports `PASS` for the test doubles (`mock`, `replay`), for a provider that needs no credential (for example Ollama), and for a provider whose secret reference resolves. It reports `WARN` for a reference that is not set (`env:NAME is not set`) and for a keyring reference when no keyring backend is available. It is `SKIP` when `llm.enabled = false`. The value is not shown.

### The provider probe

`provider:<id>:reachable` is the only check that can send something to a remote host. It sends the constant probe of the provider adapter through the egress transport (epic E22), and the probe is recorded in the ledger like any other request (invariant I1). The doctor module builds no request and opens no connection itself; `tests/privacy/test_cli_static_imports.py` and the import contract `cli-no-direct-egress` hold it to that. The rules, in the order they are applied:

1. Without `--probe-providers` the check is `SKIP use --probe-providers`, and the probe function is not called.
2. A remote provider under `--offline` is `SKIP offline`. A local provider (`ollama`, or a loopback server whose trust tier is `local`) is probed under `--offline`, because loopback traffic does not leave the machine.
3. With `llm.enabled = false` the check is `SKIP`.
4. The test doubles pass without a probe (`local mock provider; nothing was sent`).
5. A remote provider is `SKIP remote providers are not allowed` when `llm.allow_remote = false`, and `SKIP privacy level L0 sends nothing` at level `L0`.
6. A remote provider needs consent, as for a scan: a stored grant, `--accept-egress`, or `CODEKAVACH_ACCEPT_EGRESS=1`. `doctor` does not ask the question and does not store a grant: without consent the check is `SKIP consent required`, with the command that grants it as hint, and nothing is sent (invariant I4).
7. The probe is called once, with 80 % of `--timeout`. A well-formed answer is `PASS answered in <n> ms`. A failure is `FAIL probe failed: <code>`, where `<code>` is one of `unreachable`, `unauthorised`, `model_not_found`, `rate_limited`, `tls_error`, `timeout` or `bad_response`, with the hint of `codekavach providers test`. The text of the provider's or the transport's error is not shown.

A probe to a paid API costs a few tokens. A failed optional check is reported, and the exit code stays 0 unless `--strict` is given.

`tests/unit/cli/test_doctor_external.py` runs the combinations of `--probe-providers`, remote or local provider, stored grant, flag, variable or no consent, and `--offline`, and counts the calls of a fake probe.

## Reports

`report:pdf` and `report:fonts` exist when `reporting.formats` includes `pdf`. `report:pdf` is `WARN` with a hint for the platform when the libraries are missing (`apt install libpango-1.0-0 libpangoft2-1.0-0` on Linux, `brew install pango` on macOS). `report:fonts` is `WARN` when no font that covers Devanagari is found, because reports for Indian clients can contain such names; its `details` list the fonts that were found.

## For another epic

Epic E14 supplies `adapter.probe(settings)` on the engine adapters, epic E22 supplies `codekavach.llm.providers.probe_provider`, and epic E31 supplies `codekavach.report.render.pdf.probe_pdf_prerequisites()` and `codekavach.report.render.fonts.find_fonts(script)`. The shapes that `doctor` reads are described in the module docstring of `src/codekavach/cli/doctor_checks.py`. A check that is not about settings is registered with `register_check`, as described in the module docstring of `src/codekavach/cli/doctor.py`.
