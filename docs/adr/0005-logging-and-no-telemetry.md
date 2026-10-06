# ADR-0005: Logging and no-telemetry

| | |
|---|---|
| Status | Accepted |
| Date | 2026-09-27 |
| Deciders | CodeKavach maintainers |
| Issue | #24 |
| Affects | docs/ARCHITECTURE.md sections 2 and 3; codekavach.core.log; codekavach.core.no_telemetry; invariants I3 and I4 |

## Context and problem statement

Every pipeline stage needs diagnostics, and CodeKavach handles client source code, secrets and vault mappings. Invariant I3 says vault contents are never logged. Logs are copied into bug reports, CI output and support tickets, so whatever reaches a log line has effectively left the client's control. The architecture names no logging library and no logging module, and it may only be changed through an ADR. Two modules are about to be added under `codekavach.core`: `log/` (E01-20, E01-21) and `no_telemetry.py` (E01-31). Both implement one policy: diagnostics stay on the client's machine and are scrubbed before they are written, and the tool sends no usage data anywhere.

## Decision drivers

- Sensitive values must be removable by a fixed, central step, not by the care of each call site.
- Machine-readable command output on stdout must never be mixed with diagnostics.
- Air-gapped deployments (requirement R5) must work without any outbound traffic from the tool.
- The design must be honest about what automatic scrubbing can and cannot catch.

## Considered options

1. **Standard-library `logging` with a JSON formatter.** No processor chain: redaction would be a `Filter` attached handler by handler, and a handler added later without it bypasses redaction.
2. **loguru.** One global logger and a message-formatting style that encourages interpolated strings, which defeats redaction by key.
3. **structlog** (MIT or Apache-2.0, at the user's choice). Structured by design, with a processor chain in which scrubbing is a fixed step before rendering.

## Decision outcome

Chosen option: 3, structlog.

### 1. Destination

Events go to stderr only. stdout is reserved for command results (JSON, SARIF, report paths), so that `codekavach scan --format json | jq` never meets a log line. The format is human-readable console text on a terminal and JSON otherwise. There are no log files in v1.0; if they are added later they are local, opt-in and readable by the owner only.

### 2. Event style

Event names are `snake_case` constants. Data travels as key-value pairs and is never interpolated into the event string, because redaction by key depends on it.

### 3. What is not logged

File contents, slices, payload text, prompts, model responses, vault entries, secrets and provider keys. Log counts, sizes, durations, hashes (`payload_hash`) and identifiers (`candidate_id`) instead.

### 4. Tracebacks

Local variables are not rendered in any format, including Typer's and Rich's pretty exceptions (E01-01), because locals in a privacy-layer frame are client code, secrets or vault entries.

### 5. Third-party loggers

HTTP client and SDK loggers are held at `WARNING`, because their debug output contains request headers and bodies. The environment switch `CODEKAVACH_LOG_THIRD_PARTY` lifts this for debugging and announces itself with a warning event.

### 6. Redaction

A processor placed directly before rendering scrubs every event by key, by value pattern, by type and by size, and suppresses the event if scrubbing itself fails (fail closed, in the spirit of I4). Its limits, stated plainly: it is a safety net based on keys and patterns; it cannot recognise an arbitrary client identifier or business term; and it is not permission to log sensitive values.

### 7. No telemetry

CodeKavach contains no usage analytics, crash reporting, update checks or remote log handlers, in any deployment mode. This is a design rule with named checks:

- dependencies that ship analytics or crash-reporting clients are rejected by a lockfile check (`make telemetry-check`, E01-31);
- documented opt-out variables for third-party tools are set when the process starts (`codekavach.core.no_telemetry`, E01-31);
- network client imports are confined to the egress transport by the import contracts (E01-14, ADR-0003);
- sockets are blocked in the test process (E01-08).

It does not cover the behaviour of a third-party engine beyond its documented switch; ADR-0002 handles that by running engines without network access.

### 8. Placement

`codekavach.core.log` (a package with `config.py` and `redaction.py`) and `codekavach.core.no_telemetry` (a module). They sit in `core` because every package uses them and they import nothing else from `codekavach`. Only `codekavach.core.log` may call `logging.getLogger` or `structlog.get_logger`; everything else calls `codekavach.core.log.get_logger` (enforced with ruff `TID251` by E01-20). The implementing issues add both names to the forbidden list of the `core-models-independent` import contract.

### Reserved names

- Environment variables: `CODEKAVACH_LOG_LEVEL`, `CODEKAVACH_LOG_FORMAT`, `CODEKAVACH_LOG_THIRD_PARTY`.
- Configuration keys: `logging.level`, `logging.format` (E03).
- Command-line options: `--log-level`, `--log-format` (E05).

### Consequences (positive, negative, neutral)

- Positive: one place to scrub, one place to configure; stdout stays machine-readable; air-gapped use needs no special mode.
- Negative: contributors must use key-value events and `get_logger` rather than familiar `logging` idioms; debugging third-party HTTP traffic needs an explicit switch.
- Neutral: a runtime dependency (structlog) is added by E01-20; its licence is compatible with MIT distribution.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

- `tests/unit/core/log/test_config.py` (E01-20): destination, formats, third-party levels, no locals in tracebacks.
- `tests/unit/core/log/test_redaction.py` and `tests/privacy/test_log_redaction_properties.py` (E01-21): scrubbing by key, pattern, type and size; fail-closed suppression.
- `tools/dev/check_no_telemetry.py` with `make telemetry-check` (E01-31).
- ruff `T20` (no `print`) and `TID251` (no direct `logging.getLogger` or `structlog.get_logger` outside `codekavach.core.log`).

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Supports I3: vault contents and other sensitive values are not logged, and a central redaction step scrubs what slips through by key, pattern, type and size. Extends the fail-closed attitude of I4 to diagnostics: an event that cannot be scrubbed is suppressed. I1 is unaffected because logging performs no network access. The redaction step is a safety net for known keys and recognisable patterns only; it does not detect arbitrary client identifiers or business terms, so the rule "do not log sensitive values" remains the primary control. No invariant is changed.

## Implementation notes (optional; the only section that may grow after acceptance)

### Redaction

Implemented by `codekavach.core.log.redaction.RedactionProcessor` (E01-21). It sits in the
redaction slot of the processor chain, so both structlog events and standard-library records go
through it, and it builds a new structure without mutating the caller's objects.

- Sensitive keys: after lower-casing and removing `_` and `-`, any key containing `password`,
  `passwd`, `passphrase`, `secret`, `token`, `apikey`, `authorization`, `cookie`, `credential`,
  `privatekey`, `vaultkey`, `salt` or `signature` has its string or bytes value replaced by
  `<redacted>`. Keys ending in `_count(s)`, `_estimate`, `_tokens`, `_len`, `_id` or `_ms` are
  exempt, and so are numbers, booleans and `None`.
- Code keys (`code`, `source`, `snippet`, `slice`, `text`, `payload`, `content`, `body`, `prompt`,
  `response`, `completion`, `original`, `mapping`, `literal`, `identifier`) are reduced to
  `<code:len=N>` or `<code:items=N>`.
- Patterns, replaced by `<redacted:NAME>` in every string: `aws_access_key`, `github_token`,
  `llm_api_key`, `google_api_key`, `slack_token`, `jwt`, `private_key`, `bearer`,
  `basic_auth_url` and `assignment` (for `password=`, `token:` and similar, the key is kept), plus
  `validation_input` (Pydantic's `input_value=...`). Other components add patterns with
  `register_pattern(name, pattern)`.
- Limits: strings over 2048 characters become `<str:len=N>`, text over 5 lines becomes
  `<text:lines=N>`, bytes become `<bytes:len=N>`, `SecretStr` and `SecretBytes` become
  `<redacted>`, and nesting deeper than 8 levels becomes `<nested>`. Tracebacks (`exception`,
  `stack`, `stack_info`) are exempt from the length and line rules, but they are cut at 32768
  characters and still scrubbed.
- Fail closed: if redaction raises, the event is replaced by
  `{"event": "log_event_suppressed", "reason": "redaction_error", "level": ...}`.
- Not covered: client names, identifiers and business terms that look like ordinary words.
  Payload protection belongs to the egress guard (E12), not to this processor.
- Tests: `tests/unit/core/log/test_redaction.py`,
  `tests/privacy/test_log_redaction_properties.py` and
  `tests/unit/core/log/test_redaction_budget.py` (the median cost per event is about 50 µs, and
  the budget is 0.5 ms).

### Dependencies and child processes

Implemented by E01-31. CodeKavach's own code sends nothing; this part covers what it depends on and what it launches.

**Deny list for dependencies.** `tools/dev/check_no_telemetry.py` (`make telemetry-check`, CI `lint` job) reads every `[[package]]` in `uv.lock`, which covers the whole resolution: every extra and group, on every platform. It fails when a PEP 503 normalised name matches `[tool.codekavach.telemetry] deny` in `pyproject.toml`.

- The list names error-reporting, product-analytics and APM agents: Sentry, PostHog, Segment, Mixpanel, Amplitude, RudderStack, Scarf, Bugsnag, Rollbar, New Relic, Datadog, Honeycomb, Logfire, Google Analytics, Statsig and LaunchDarkly.
- It also denies `opentelemetry-exporter-*`. OpenTelemetry API and SDK packages are not denied, because libraries depend on them without sending anything; the exporters are what ship data off the machine.
- An exception needs a `reason` (why the package is present and how it is kept silent), a `verified_by` test and an `approved_in` reference, or the check fails.
- The check fails closed on an unparseable lockfile or a malformed policy.

**Opt-out variables.** `codekavach.core.no_telemetry.OPT_OUT_ENV`, set by `apply_opt_outs()` as the first statement of the CLI's `main()`. Values a user set deliberately are kept, and child processes inherit the variables.

| Variable | Value | Silences |
|----------|-------|----------|
| `DO_NOT_TRACK` | `1` | tools that honour the cross-tool convention |
| `HF_HUB_DISABLE_TELEMETRY` | `1` | Hugging Face Hub client (E08, E22) |
| `SEMGREP_SEND_METRICS` | `off` | Semgrep as an external engine (E15) |
| `DOTNET_CLI_TELEMETRY_OPTOUT` | `1` | .NET command-line tools used by C# engines (E15) |
| `SCARF_NO_ANALYTICS` | `true` | packages that embed Scarf install analytics |
| `CHECKPOINT_DISABLE` | `1` | HashiCorp version and usage checks (IaC engines, E20) |

Later epics extend the table when they add a tool with such a switch, naming the tool and the epic and confirming the variable in the tool's own documentation. Library users and the server (E32) call `apply_opt_outs()` at start-up themselves, because importing the package changes nothing. Tests: `tests/unit/tools/test_check_no_telemetry.py` and `tests/unit/core/test_no_telemetry.py`.

## Links

- `docs/ARCHITECTURE.md` preamble, sections 2, 3, 6.3 (I3, I4) and 6.4 (insider with log access)
- `docs/PLAN.md` section 2 (R1, R5) and section 4 (principles 2 and 7)
- ADR-0002 (external engines as subprocesses), ADR-0003 (single egress)
- structlog; Python `logging`; loguru (rejected option); CWE-532 (insertion of sensitive information into log file)
