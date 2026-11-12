# REST API server (`codekavach serve`)

The server runs the same pipeline as `codekavach scan`, keeps projects, scans, findings and their
triage in a SQLite database, and serves the web dashboard. Owning epic: E32 (issues #268, #269,
#270).

## Running it

```bash
uv sync --extra server --extra reports
uv run codekavach serve --host 127.0.0.1 --port 8080
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--host` | `127.0.0.1` | Address to listen on. Use `0.0.0.0` only inside a container. |
| `--port` | `8080` | Port. |
| `--data-dir` | `$CODEKAVACH_SERVER_DATA_DIR` or the platform data directory plus `server` | Database, scan workspaces, uploads, the vault passphrase file. |
| `--ui-dir` | `ui/dist` of the checkout when built | The dashboard served at `/` (single-page fallback). Without it `/` explains how to build it. |
| `--workers` | `2` | Scans that may run at the same time; the rest wait as `queued`. |
| `--print-openapi` | | Print the OpenAPI document and exit. |

On first start the server creates the user `admin` with the password from
`CODEKAVACH_ADMIN_PASSWORD` (default `kavach-admin`, printed at start; change it under Users) and
the project **KavachBank (sample)** (source type `sample`, `fixtures/kavachbank`). Interactive API
documentation is at `/api/docs`.

Environment:

| Variable | Effect |
|----------|--------|
| `CODEKAVACH_ADMIN_PASSWORD` | Password of the first `admin` account. |
| `CODEKAVACH_DEV=1` | Allow the Vite dev server (`http://localhost:5173`) through CORS. CORS is off otherwise. |
| `CODEKAVACH_SERVER_DATA_DIR` | Default of `--data-dir`. |
| `CODEKAVACH_<SECTION>__<KEY>` | Passed to every scan's configuration, as for the CLI (providers, vault key source). |
| `CODEKAVACH_AGENTROUTER_API_KEY` and other provider key variables | Read by the provider adapters when a scan uses them; the server stores only references. |

To scan with the AgentRouter gateway (OpenAI Responses API, model `gpt-5.6-sol`), either export
`CODEKAVACH_AGENTROUTER_API_KEY` before starting the server or store a reference in the settings:

```bash
curl -s -X PUT localhost:8080/api/v1/settings -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"provider_key_refs": {"agentrouter": "file:/path/to/agentrouter.key"}}'
```

then start a scan with `{"provider": "agentrouter", "send": true}`.

## Authentication and roles

`POST /api/v1/auth/login {username, password}` returns `{token, user}`. Send the token as
`Authorization: Bearer <token>`. `EventSource` and download links that cannot send headers may pass
`?access_token=<token>`. Tokens expire after 12 hours and are revoked by `POST /auth/logout`, by a
role or password change and by deactivating the user. Passwords are hashed with scrypt; login is
limited per client address and per user name and answers an unknown user and a wrong password the
same way.

| Permission | admin | auditor | developer | viewer |
|------------|:-----:|:-------:|:---------:|:------:|
| read projects, scans, findings, stats | yes | yes | yes | yes |
| download reports | yes | yes | yes | yes |
| create and change projects, start and cancel scans, triage findings | yes | yes | yes | no |
| privacy summary, ledger entries, ledger verification | yes | yes | yes | no |
| original-versus-sent pair of a ledger entry (`/ledger/{seq}`) | yes | yes | no | no |
| audit log | yes | yes | no | no |
| users, settings, policy | yes | no | no | no |

Every denial, every login and every read of an original-versus-sent pair is written to a
hash-chained audit log (`GET /api/v1/audit` reports whether the chain is intact).

## Endpoints

All paths are below `/api/v1`. Errors have the body
`{"ok": false, "error": {"code", "message", "hint"}, "detail", "request_id"}`.

| Method and path | Purpose |
|-----------------|---------|
| `GET /health`, `GET /version` | Liveness and version (no token). |
| `POST /auth/login`, `GET /auth/me`, `POST /auth/logout` | Session. |
| `GET /stats` | Projects, scans, findings by severity of each project's latest scan, open findings, last scan, trend. |
| `GET /projects`, `POST /projects` | List and create. Source `{type: sample\|path\|git\|upload, path?, url?, ref?}`. |
| `GET/PATCH/DELETE /projects/{id}` | Read, rename or re-point, delete with its scans. |
| `POST /projects/{id}/upload` | Multipart `file`: a zip or tar archive, checked before it is kept. |
| `POST /projects/{id}/scans` | `{privacy_level, provider, model?, send, rules?}`; returns the queued scan. |
| `GET /scans?project_id=`, `GET /scans/{id}`, `DELETE /scans/{id}` | Scan status: `queued`, `running`, `completed`, `failed`, `cancelled`; `stage`, `progress`, counts by severity. |
| `GET /scans/{id}/events` | Server-sent events `stage`, `progress`, `log`, `finding`, `done`; resumes after `Last-Event-ID`. `GET /scans/{id}/log` returns the same events as JSON. |
| `POST /scans/{id}/cancel` | Cancel a queued or running scan. |
| `GET /scans/{id}/findings?severity=&status=&cwe=&q=&engine=&path=` | Findings, most severe first. |
| `GET /findings/{id}`, `PATCH /findings/{id}`, `GET /findings/{id}/history` | Detail (code with line numbers, taint path, LLM verdict, CVSS, compliance), triage (`status`, `assignee`, `comment`), history. |
| `GET /scans/{id}/privacy` | Level, payloads, blocked, placeholders by type, pseudonyms, tokens sent, chain state, zero-leak check, attestation text. |
| `GET /scans/{id}/ledger`, `GET /scans/{id}/ledger/{seq}`, `POST /scans/{id}/ledger/verify` | Egress ledger entries; one entry with `payload_text`, `original_text` and change `markup`; chain and payload verification. |
| `GET /scans/{id}/reports`, `GET /scans/{id}/reports/{fmt}` | Formats of the installed renderers; download (`?inline=1` to view an HTML report in the dashboard). Reports are rendered again after triage changes. |
| `GET /providers`, `POST /providers/{id}/test` | Configured LLM providers (keys as references only; the `agentrouter` preset is always listed). The test sends one constant synthetic payload through the egress guard, ledger and transport and returns `{ok, latency_ms, model, message}`. |
| `GET/PUT /settings` | Default provider, model and privacy level, `send_by_default`, organisation name, report title and classification, `provider_key_refs` (provider id to an `env:`, `file:` or `keyring:` reference; a literal key is refused with `key_not_reference`). |
| `GET/PUT /policy` | The privacy policy (`codekavach.policy.toml`) applied to every server scan, validated before it is saved. |
| `GET/POST /users`, `PATCH/DELETE /users/{id}` | User administration. |
| `GET /audit` | Audit events and chain state. |
| `POST /scans/{id}/sync/github` | `{repo, token_ref, dry_run}`: plan or apply the GitHub issue sync; the token only as a reference such as `env:GITHUB_TOKEN`. |

## How a scan runs

1. The source is materialised into `<data-dir>/scans/<scan id>/src`: the sample and local paths are
   copied without `.git`, dependencies and symbolic links; an upload is extracted with checks for
   path traversal, absolute names, links, special files, entry count, total size and compression
   ratio (each refused with its own code, for example `archive_path_traversal`); a git URL must be
   https, carry no credentials, name an allow-listed host (`github.com`, `gitlab.com`,
   `bitbucket.org`) that resolves only to public addresses, and is cloned with depth 1, no
   submodules, no hooks and no symbolic links.
2. The configuration is loaded as for `codekavach scan`, with the scan's privacy level, provider
   and model as overrides, and the server's policy document copied into the source root when the
   project has none.
3. `run_scan` runs the real pipeline in a worker thread with a cancellation token. With `send`
   false, payloads are prepared and recorded in the ledger but not sent. With a remote provider and
   `send` true, the request carries the operator's consent; the egress guard still decides per
   payload what may leave.
4. Findings are stored with their triage state, the privacy summary is computed from the ledger
   (chain walk, payload re-hash, the zero-leak search for the sample's listed terms), and the HTML,
   JSON and SARIF reports are rendered when those renderers are installed; other formats render on
   first download.

The server itself opens no connection to a model: only the pipeline's egress transport does (I1).
The server code does not open the vault; the original side of a ledger pair is the code slice the
pipeline stored for that candidate.

## Known limits

- Single organisation: no tenants, no OIDC; local accounts only.
- Scans run in threads of the server process, not in separate child processes with resource
  limits; a server restart marks running scans `failed` (`server_restarted`).
- The database is SQLite; PostgreSQL and Alembic migrations for the server tables are not
  implemented.
- `markup` marks replaced spans on the payload side only.
