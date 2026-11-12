# Admin guide

For the person who deploys CodeKavach for a team, manages accounts and sets what may leave the organisation. Day-to-day use is in the [User guide](user-guide.md); reading reports is in the [Auditor guide](auditor-guide.md).

## 1. Deploy with Docker Compose

The dashboard, the REST API (`/api/v1`) and the CLI ship as one image listening on port 8080, with all state under `/data`, running as an unprivileged user on a read-only root filesystem.

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET.git codekavach
$ cd codekavach
$ cp .env.example .env && chmod 600 .env
$ $EDITOR .env
$ docker compose up -d --build
$ docker compose ps                                  # wait for (healthy)
$ curl -s http://127.0.0.1:8080/api/v1/health
```

`.env` holds:

| Variable | Kind | Meaning |
|----------|------|---------|
| `CODEKAVACH_ADMIN_PASSWORD` | value | Password of the first `admin` account. Default `kavach-admin`: change it. |
| `CODEKAVACH_AGENTROUTER_API_KEY` | secret | Key for the `agentrouter` provider. Empty keeps the stack offline. |
| `CODEKAVACH_VAULT_PASSPHRASE` | secret | Derives the key of the pseudonym vault. Keep it: changing it makes existing vaults unreadable. |
| `CODEKAVACH_BIND`, `CODEKAVACH_PORT` | value | Where the dashboard listens on the host. The default `127.0.0.1:8080` is reachable from this machine only; use `0.0.0.0` to expose it on the LAN, and then put TLS in front of it. |
| `CODEKAVACH_IMAGE` | value | Image tag compose builds and runs. |

Never commit `.env`. The image build context excludes it, state directories, vaults and key files.

**Data and backups.** The named volume mounted at `/data` holds the database (users, projects, scans, findings, triage, audit log), scan workspaces, uploads and the vault. Back it up as one unit; restoring the database without the vault loses the ability to restore pseudonyms for old scans.

**Upgrading.** Pull, then `docker compose up -d --build`.

Other deployments: a Helm chart (`deploy/helm`), an air-gapped bundle, a compose profile with a local Ollama model (`--profile local-llm`) and a network-less profile (`--profile airgapped`). See [Deployment](deploy.md).

### Without Docker

```console
$ uv sync --extra server --extra reports
$ CODEKAVACH_ADMIN_PASSWORD=... uv run codekavach serve --host 127.0.0.1 --port 8080
```

Build the dashboard once with `cd ui && npm ci && npm run build`; `serve` finds `ui/dist` in a checkout, or take `--ui-dir`. Interactive API documentation is at `/api/docs`.

## 2. Users and roles

The first start creates `admin`. Create further accounts under **Admin, Users** (or `POST /api/v1/users`).

| Role | Can do |
|------|--------|
| **admin** | Everything: users, settings, policy, providers, plus all below. |
| **auditor** | Projects, scans and triage; privacy summary, ledger and ledger verification; the original-versus-sent pair of a ledger entry; the audit log. |
| **developer** | Projects, scans and triage; privacy summary and ledger metadata. Not the original-versus-sent pair. |
| **viewer** | Read projects, scans, findings and statistics; download reports. |

Sessions use bearer tokens that expire after 12 hours and are revoked on logout, on a role or password change and when a user is deactivated. Passwords are stored as scrypt hashes. Login is rate limited per client address and per user name. Every login, every denial and every read of an original-versus-sent pair is written to a hash-chained audit log, which only admins and auditors can read.

Give the original-versus-sent pair only to people who are allowed to see the original code, since it displays it next to what was sent.

## 3. Policy

Two layers decide what may leave.

**Organisation policy** (`policy.toml`, signed or pinned by the security team) constrains the tool's configuration for everyone: a minimum privacy level, a minimum level per provider trust tier, globs that are never prepared for egress, which provider kinds, ids and hosts are allowed, whether the GitHub integration is allowed. It can reject or clamp a value; it cannot loosen one. See the [organisation policy guide](../configuration/organisation-policy.md) and the examples `docs/examples/policy.bank-strict.toml` and `policy.minimal.toml`.

**Project privacy policy** (`codekavach.policy.toml`, edited under **Settings, Privacy policy**) sets levels per path, per language, per rule or CWE, and per classification tag such as `pci`; a file can only tighten what the organisation set, and `never_send = true` overrides every level. See [Privacy levels, policy and score](../privacy/policy-levels-score.md). `codekavach privacy explain <file>` shows which rule decided.

Recommended starting point for a regulated organisation: minimum level L3, public providers at L4, `never_send` for key material and anything under a hardware-security-module path, `llm.allow_remote = false` for the most sensitive repositories, and a local model for those.

## 4. Providers

Open **Settings, Providers** to see every provider, whether it is configured, its default model, and whether it runs locally. **Test** sends a tiny request through the egress path and reports success, latency and the model that answered. The [Provider guide](providers.md) covers each one.

Rules of thumb:

- A hosted provider needs a key and consent to send. The key is read from an environment variable or file reference; the server stores references, not keys.
- `mock` and `replay` answer on the machine and send nothing. Use them for demonstrations and for checking the pipeline.
- A provider's trust tier sets the minimum privacy level it may receive.

## 5. Organisation settings and reports

**Settings** holds the organisation name printed on reports, default provider, model and privacy level for new scans. Reports are rendered on the server (HTML, PDF, DOCX, SARIF, JSON, CSV, XLSX, Markdown). The PDF renderer needs the report libraries that the image includes; a checkout needs `--extra reports`.

## 6. GitHub integration

A scan's findings can be synced to issues in the client's repository: `POST /api/v1/scans/{id}/sync/github` with `{repo, token_ref, dry_run}` (the dashboard has a dialog for it). The token is passed as a reference, never stored. Run with `dry_run` first: it returns the issues that would be created, updated and closed. The repository also ships a GitHub Action and a review workflow that uploads SARIF.

## 7. Operations checklist

- [ ] `CODEKAVACH_ADMIN_PASSWORD` changed; default account password rotated.
- [ ] `CODEKAVACH_VAULT_PASSPHRASE` set, stored in a password manager and included in the disaster-recovery plan.
- [ ] Dashboard reachable only through TLS if it is not bound to localhost.
- [ ] Organisation policy in place; minimum level agreed with the security team.
- [ ] Provider keys stored as secrets, not in the repository or in screenshots.
- [ ] `/data` backed up; a restore was rehearsed.
- [ ] Auditors can open **Egress ledger** and **Verify** passes.
- [ ] `docker compose ps` is healthy; `/api/v1/health` is monitored.
