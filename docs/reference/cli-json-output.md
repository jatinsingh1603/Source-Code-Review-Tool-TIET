# JSON output (`--json`)

With `--json`, every command writes exactly one JSON document to stdout: the envelope below, as a
single line followed by a newline. Everything else (progress, warnings for people, diagnostics)
goes to stderr. The schema is `docs/schemas/cli/envelope.schema.json`.

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | `"1"` | Version of this envelope. |
| `codekavach_version` | string | Version of the tool that wrote it. |
| `command` | string | The command path without the program name, for example `privacy ledger verify`. |
| `ok` | boolean | `true` exactly when `exit_code` is 0. |
| `exit_code` | integer | The process exit code (see `exit-codes.md`); the process exit code stays authoritative. |
| `data` | any JSON | The command's result; each command documents its own object. `null` when it produced none. |
| `warnings` | list | `{"code", "message", "hint"}` objects. |
| `errors` | list | At most one `{"code", "message", "hint"}` object per raised error; `usage` for command-line errors. |

A scan that finds a high-severity issue has `ok: false`, `exit_code: 1` and empty `errors`;
consumers tell "completed with findings" from "failed" by `exit_code`.

## Example

`codekavach doctor --json` with a failing check:

```json
{"schema_version":"1","codekavach_version":"0.1.0","command":"doctor","ok":false,"exit_code":1,"data":{"checks":[{"name":"grammar:python","status":"fail"}]},"warnings":[],"errors":[]}
```

## Stability

- `schema_version` stays `"1"` while changes are additive (new keys). Removing or retyping a key
  requires `"2"`.
- Consumers must ignore keys they do not know.
- `--quiet` has no effect in JSON mode: the envelope is already the whole output.

## What never appears

The envelope is built through one serialisation function that refuses raw client code
(`RawCode`, `CodeSlice`) and anything from the vault, and refuses sanitised text unless a command
explicitly asks for it (only `privacy inspect` does). Machine output is copied into CI logs and
issue comments, so these types are refused before conversion to JSON, where the wrappers would
otherwise turn into plain strings.
