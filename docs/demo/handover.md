# Hand-over checklist

What the Thapar team receives at the end of the demo, how to run it, what to change before anyone else can reach it, and how to rotate every credential.

## What you receive

- [ ] The repository: `https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET` (public). Admin rights on it are transferred or shared by the owner during the call; confirm who has them.
- [ ] A tagged release with the wheel, the sdist, the `.vsix`, a sample report and `SHA256SUMS` (Releases page). Verify with `sha256sum -c SHA256SUMS --ignore-missing`.
- [ ] The server image on GHCR (published by the release workflow), plus `docker-compose.yml` and the Helm chart in `deploy/`.
- [ ] Runbooks: this directory. Start with [`README.md`](README.md); install paths are in [`install.md`](install.md).
- [ ] The sample projects and their ground truth: `fixtures/kavachbank`, `fixtures/demo-ledgerly`, `fixtures/demo-shopfront`. Synthetic and deliberately vulnerable; never deploy them.
- [ ] Documentation: `README.md` (including "Known limits"), `docs/ARCHITECTURE.md`, `docs/PLAN.md`, the ADRs in `docs/adr/`, `AGENTS.md` for contributors.
- [ ] The open issues and the risk log (`docs/status/risk-log.md`): what is not finished.
- [ ] No API key. We do not hand over our model key; you use your own.

## Run it

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET && cd Source-Code-Review-Tool-TIET
$ cp .env.example .env              # then edit .env as described below; it is git-ignored
$ docker compose up -d --build      # dashboard and API on http://127.0.0.1:8080
$ docker compose exec codekavach codekavach --version
```

Without Docker: `uv sync --all-extras` and `uv run codekavach serve` (dashboard and API), or `uv run codekavach scan <path>` for the command line. Optional: seed the sample data with `uv run python scripts/seed_demo.py`. Verify the install with `uv run codekavach demo --out demo-out`; it must print `zero_leak_passed  True`.

## Credentials to change before first real use

| Credential | Where | Default | What to do |
|------------|-------|---------|------------|
| Dashboard admin password | `CODEKAVACH_ADMIN_PASSWORD` in `.env` | `kavach-admin` (a published default) | Change it before the port is reachable by anyone else; then recreate the container. Do not expose the port on a LAN with the default. |
| Vault passphrase | `CODEKAVACH_VAULT_PASSPHRASE` in `.env` | `change-me-vault-passphrase` | Set a long random value. It derives the key of the pseudonym vault. See rotation. |
| Model API key | `CODEKAVACH_AGENTROUTER_API_KEY` (or the key of whichever provider you configure) in `.env` | empty | Use your own key. Never commit `.env`. |
| GitHub Action key | Repository secret `CODEKAVACH_LLM_API_KEY` | not set | Add it under Settings, Secrets and variables, Actions, if you want a real model in CI. Without it the Action uses the mock provider. |
| Bind address | `CODEKAVACH_BIND` | `127.0.0.1` | Leave it for single-user use. Put a reverse proxy with TLS in front before using `0.0.0.0`. |

## Rotating keys

- **Model key.** Create a new key at the provider, put it in `.env`, run `docker compose up -d` to recreate the container, run a one-file scan with the real provider, then revoke the old key at the provider. If a key was ever pasted into a chat, a log or a commit, treat it as leaked: revoke first, then replace.
- **GitHub secret.** Settings, Secrets and variables, Actions: update `CODEKAVACH_LLM_API_KEY`. Secrets are write-only, so re-enter the value; re-run the workflow to confirm.
- **Admin password.** Edit `.env`, recreate the container. Whether an existing account's stored password is replaced or only the first-start default changes depends on the server build: after the change, log in with the new password and, if the old one still works, change it from the dashboard's account page or delete the data volume (`docker compose down -v`, which deletes all scans).
- **Vault passphrase.** Changing it makes existing vaults unreadable, which means old scans can no longer restore real names into findings. Plan it: finish and export the reports you need (they contain the restored names), then change the passphrase, and treat earlier scans as archived. There is no recovery without the old passphrase.
- **GitHub token used by the integrations.** Use a fine-grained token with only the permissions the integration needs, and replace it by creating the new one, updating where it is used, then deleting the old one.

## Before you go live

- [ ] Default admin password and vault passphrase replaced.
- [ ] `.env` is not in git: `git status` shows it untracked or ignored.
- [ ] `git log -p | grep -i "api_key"` shows no real key (a synthetic fixture value is fine).
- [ ] Privacy policy configured: the floor level, `never-send` paths and which providers are approved (`docs/configuration/organisation-policy.md`).
- [ ] The first real scan was done at a conservative level (L3) and the inspection page was read by a person.
- [ ] You know what is not protected: read "Known limits" in the README and tell your users.

## Support after the call

Open issues in the repository; state the CLI version, the command, the error code and, if you can, the output of `codekavach doctor`. Do not paste code from a confidential project, keys or ledger payloads into an issue.
