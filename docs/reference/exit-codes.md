# Exit codes

Every `codekavach` invocation ends with exactly one of these exit codes. They are a public
contract: pipelines, the GitHub Action and the pre-commit hook act on them. The table below is the
text that `codekavach --help` prints as its epilog; a test keeps the two identical.

```text
Exit codes:
  0    OK             completed; nothing at or above the threshold
  1    FINDINGS       completed; problems at or above the threshold
  2    USAGE          cannot run as invoked (options, configuration, input, missing back end)
  3    PRIVACY_BLOCK  a privacy control refused the operation
  4    INTERNAL       unexpected failure inside CodeKavach
  130  CANCELLED      interrupted by the user
Precedence at the end of a command: 4 over 3 over 1 over 0; 2 only before work starts.
```

## Meaning

| Code | Name | When |
|---|---|---|
| 0 | `OK` | The command completed and found nothing at or above its threshold. |
| 1 | `FINDINGS` | `scan` found a finding at or above `--fail-on`; `doctor` has a failed required check (or a warning under `--strict`); `providers test` found an unreachable provider or rejected credentials; `config validate --strict` has warnings. |
| 2 | `USAGE` | Unknown option or bad value, invalid or untrusted configuration, missing input, contradictory flags, or a back end that this build does not contain (`backend_unavailable`). |
| 3 | `PRIVACY_BLOCK` | A privacy control refused the operation: no consent for remote egress, an egress guard refusal, a broken ledger chain or payload mismatch, a listed term found in a ledger payload, or a vault that cannot be unlocked. |
| 4 | `INTERNAL` | A defect or an unexpected environment failure inside CodeKavach. The message names the exception type only; run again with `--debug` for a traceback on stderr. |
| 130 | `CANCELLED` | Interrupted by the user (128 + SIGINT). Outside the 0 to 4 outcome contract so that CI can tell an interrupted run from a completed one. |

When several conditions hold at the end of a command, the most severe code wins: 4 over 3 over 1
over 0. Code 2 can only arise before any work starts.

Diagnostics go to stderr as `error[<code>]: <message>`, optionally followed by `hint: ...`.
Unexpected errors print the exception type only, because exception messages and tracebacks can
quote client code, file paths or credentials.

## CI examples

GitHub Actions: keep the job green when findings are reported (code 1), fail on everything else.

```yaml
- name: CodeKavach scan
  id: scan
  run: codekavach scan . --fail-on high
  continue-on-error: true
- name: Fail on errors other than findings
  if: steps.scan.outcome == 'failure'
  run: |
    code="${{ steps.scan.outputs.exit_code }}"
    test "$code" = "1"
```

Shell:

```sh
codekavach scan . --fail-on high
case $? in
  0) echo "clean" ;;
  1) echo "findings at or above the threshold" ;;
  2) echo "usage or configuration problem"; exit 2 ;;
  3) echo "blocked by a privacy control"; exit 3 ;;
  130) echo "cancelled"; exit 130 ;;
  *) echo "internal error"; exit 4 ;;
esac
```
