# Consent for remote egress

CodeKavach does not contact a remote LLM provider until a person has approved it for that provider and privacy level. `codekavach scan` checks this before the pipeline starts, so a refused run does no work and sends nothing.

## When consent is needed

Consent is needed when the selected provider is remote. It is not needed, and the store is not read, when:

- the LLM is disabled (`--no-llm`, `llm.enabled = false`);
- the provider is local: kinds `mock` and `replay`, or a provider whose trust tier is `local` (for example Ollama on a loopback address);
- the run is `--offline`;
- the effective privacy level is `L0`.

## How consent is given

In this order:

1. **Stored grant.** A grant recorded earlier covers the run (see matching below).
2. **`--accept-egress`.** Approves this invocation; nothing is stored.
3. **`CODEKAVACH_ACCEPT_EGRESS=1`.** Approves this process; nothing is stored. Only the exact value `1` counts.
4. **Question on a terminal.** `scan` shows the provider, host, model and level and what a payload still discloses, and asks `Send sanitised payloads to <provider> (<host>) at level <Lx>? [y/N]`. Answering yes stores a grant.

Otherwise the run stops with exit code 3:

```text
error[consent_required]: remote provider 'primary' has not been approved for level L3
hint: run 'codekavach privacy consent grant --provider primary' on a terminal, or pass --accept-egress for this run
```

A scan that proceeds prints `remote egress to <provider> accepted via <source>` on stderr, where the source is `stored`, `flag` or `env`. The scan manifest records the source as `consent_source` (`user-file`, `flag`, `env` or `none`).

## What cannot give consent

Configuration files cannot. A key in `codekavach.toml` would be controlled by the repository being scanned, which is untrusted input. Consent comes only from the user's own state file, a flag typed for the invocation, or an environment variable of the process.

## The store

`<user config dir>/consent.json` (under `CODEKAVACH_HOME` when set), mode `0600`, replaced atomically:

```json
{"version": 1, "grants": [
  {"provider_id": "primary", "kind": "anthropic", "host": null, "trust_tier": "public",
   "level": "L3", "granted_at": "2026-10-01T09:14:03Z", "codekavach_version": "0.1.0"}
]}
```

It holds provider metadata and timestamps only. `host` is the host of the provider's `base_url`, or `null` when none is configured.

A grant covers a run when the provider id, kind, host and trust tier are equal and the requested level is at least as strict as the granted one, in the order L1, L2, L3, L4, L0. A grant at L3 covers L3 and L4; a later run at L2 asks again, and so does a provider whose host or kind changed.

A store that cannot be read, is malformed or has an unknown version counts as empty.

## Commands

| Command | Effect |
|---|---|
| `codekavach privacy consent status` | Lists the grants and the path of the store. With `--json`: `data = {"grants": [...], "path": "..."}` |
| `codekavach privacy consent grant --provider ID [--level Lx] [--yes]` | Shows the same summary and question and stores a grant. `--yes` approves without asking |
| `codekavach privacy consent revoke --provider ID` | Removes the grants of that provider |
| `codekavach privacy consent revoke --all` | Removes every grant; the store becomes `{"version": 1, "grants": []}` |

## CI

A pipeline has no terminal, so it gets consent from its own definition:

```yaml
- name: CodeKavach scan
  run: codekavach scan . --profile ci
  env:
    CODEKAVACH_ACCEPT_EGRESS: "1"
```

Set the variable deliberately in the pipeline definition, not in a file inside the repository that the scan reads.

## Relationship to the egress guard

The gate is an accountability control of the CLI. It does not replace the egress guard: every send still needs a ticket from the guard, and the guard requires the consent decision from every caller.
