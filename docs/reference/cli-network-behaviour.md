# Network behaviour of the CLI

Owning epic: E05 (issue E05-32). Related: invariant I1 in `docs/ARCHITECTURE.md` section 6.3, ADR-0003 (single egress).

This page states which `codekavach` commands can use the network, through which component, and how that is tested. It describes what the tests measure; it is not a statement about code that the tests do not reach (see "Limits" below).

## Policy

1. LLM traffic leaves the process through one component only: `codekavach.privacy.egress.transport`. The command layer (`codekavach.cli`) builds no request and opens no connection.
2. CodeKavach has no telemetry, no update check and no crash reporting. No command contacts a CodeKavach or third-party service on its own account.
3. Every command not listed as network-capable below is local: it opens no socket, performs no DNS lookup and starts no program other than those allow-listed for it.

## Commands that can use the network

| Command | When | Component that connects |
|---------|------|-------------------------|
| `codekavach scan` | A remote LLM provider is selected, remote use is allowed and consent was given. Not with `--no-llm`, `--offline`, or a local provider or test double. | `codekavach.privacy.egress.transport` |
| `codekavach providers test` | The tested provider is remote; same conditions as a scan. `mock` and `replay` are local test doubles. | `codekavach.privacy.egress.transport` |
| `codekavach doctor --probe-providers` (planned) | Only when the option is given; not with `--offline`. | `codekavach.privacy.egress.transport` |
| `codekavach sync github` (planned, integrations epic) | Always; it is the purpose of the command. | The named, allow-listed non-LLM transport that the owning epic defines under the ADR-0003 exception procedure |
| SCA advisory database updates (planned, E19) | When an update is requested. | As for `sync github`: the non-LLM transport of the owning epic's ADR-0003 exception |

Dataset downloads for evaluation follow the same rule as advisory updates.

A send to an LLM provider is recorded in the egress ledger (`codekavach privacy ledger show`). `--offline` and `llm.allow_remote = false` refuse remote providers before anything is sent, and the consent gate runs before the first request (`docs/reference/cli-consent.md`).

## Local commands

`--version`, `--help`, `doctor` (without `--probe-providers`), `providers list` (also with `--check-secrets`, which reads the local keyring), `vault status`, `vault rotate`, `vault destroy`, `privacy notice`, `privacy consent ...`, `privacy inspect`, `privacy ledger show`, `privacy ledger verify`, `config ...`, `init`, `report`, and `scan` with `--no-llm`, `--offline` or a local provider.

`scan` may start `git` to read the repository. No other local command starts a program.

## How this is tested

| Test | What it measures |
|------|------------------|
| `tests/privacy/test_cli_no_network.py` | Each listed local command runs with `socket.socket`, `socket.create_connection`, `socket.getaddrinfo` and `ssl.SSLContext.wrap_socket` replaced by functions that record the attempt and raise. The recorded count has to be zero, so an attempt whose exception was swallowed is still seen. `subprocess.Popen` is recorded; a program outside the command's allow-list fails the test. A command whose back end is not built yet exits 2 with `backend_unavailable`. |
| `tests/privacy/test_cli_static_imports.py` | No file under `src/codekavach/cli/` imports `socket`, `ssl`, `http.client`, `urllib.request`, `urllib3`, `httpx`, `requests`, `aiohttp`, `websockets`, `smtplib`, `ftplib`, a provider SDK (`anthropic`, `openai`, `google.generativeai`, `boto3`, `litellm`) or an analytics package (`sentry_sdk`, `posthog`, `segment`, `mixpanel`). This covers code that tests do not execute, such as an error handler. |
| Import contract `cli-no-direct-egress` (`.importlinter`, run by `lint-imports`) | `codekavach.cli` does not import `codekavach.privacy.egress.transport`, `codekavach.llm.providers` or `codekavach.privacy.vault`. The CLI reaches the provider probe and the vault's administrative facade at run time through `codekavach.cli.backends.load_backend`. |
| `tests/privacy/test_no_telemetry_deps.py` | Neither `uv.lock` nor the installed environment contains `sentry-sdk`, `posthog`, `analytics-python`, `mixpanel` or `opentelemetry-exporter-otlp`. An exception needs an ADR. |
| `tests/privacy/test_import_contracts.py` | Each import contract is broken by a planted violation, so the contract is known to detect one. |

The default test run also blocks sockets through `pytest-socket` (`tests/privacy/test_network_blocked.py`).

## Limits

- The dynamic test covers the listed invocations, not every option combination.
- The static checks see `import` statements. They do not see `importlib.import_module`, `__import__`, native extensions or child processes; the socket block and the subprocess record are the runtime controls for those.
- Some provider SDKs and LiteLLM fetch version or pricing data on import or first use. The CLI does not import them (static test). Their behaviour inside the transport and the adapters is for E12 and E22 to test.
- Third-party analysis engines run as external processes (E14); sandboxing them is the concern of E14 and E40, not of this page.
