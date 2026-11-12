# Demo 2 runbook: the dashboard

Owning epic: E39 (issue E39-02). The session plan and the questions to expect are in the [demo hub](README.md); the offline one-command demo is [`DEMO1.md`](DEMO1.md). This page is the hands-on script for the web dashboard, from a fresh laptop to a downloaded audit report.

## 1. Set up on a fresh laptop (10 minutes, do it the day before)

Needs Docker with the compose plugin and git. Nothing else: Python, Node and the PDF libraries are inside the image.

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET.git codekavach
$ cd codekavach
$ cp .env.example .env
$ chmod 600 .env
```

Edit `.env`:

- `CODEKAVACH_ADMIN_PASSWORD`: the dashboard password for `admin`.
- `CODEKAVACH_AGENTROUTER_API_KEY`: the AgentRouter key, pasted from the password manager. Do this with the screen not shared. Leave it empty for an offline demo.
- `CODEKAVACH_VAULT_PASSPHRASE`: any long random string.

```console
$ docker compose up -d --build       # first build: a few minutes
$ docker compose ps                  # wait for "(healthy)"
$ curl -s http://127.0.0.1:8080/api/v1/health
```

If `ps` stays at `(health: starting)` for more than a minute, run `docker compose logs codekavach` and read the last lines.

## 2. Log in

Open `http://127.0.0.1:8080`. Log in as `admin` with the password from `.env` (default `kavach-admin`; the server also prints it in its log at first start). The Overview shows the project count, open findings by severity and the trend across scans.

The project **KavachBank (sample)** is created on first start from `fixtures/kavachbank`, a small banking application with planted vulnerabilities and planted secrets. Its ground truth is in `fixtures/kavachbank/ground-truth/manifest.yaml`.

## 3. Check the model before you need it

Settings, then Providers: press **Test** next to `agentrouter`. It should answer `ok` with a latency of a few seconds and the model `gpt-5.6-sol`. If it fails, do not debug in front of the audience; use the fallback (section 8).

## 4. Scan the sample with the real model

1. Projects, **KavachBank (sample)**, **New scan**.
2. Privacy level **L3** (the default: slices around each candidate, secrets as typed placeholders, identifiers pseudonymised).
3. Provider `agentrouter`, model `gpt-5.6-sol`, **Send to provider** on.
4. Start. The scan page streams the stages (ingest, parse, rules, taint, engines, privacy, LLM review, restore, rate) with progress and a log, and findings appear as they are confirmed. A scan of the sample takes a minute or two; each model call takes about four seconds.

Say while it runs: the deterministic engines (own rules, taint, Opengrep, Bandit) find the candidates; the model only reviews a sanitised slice of each one and says whether it is exploitable and why.

## 5. Walk through the findings

Open the scan's findings. Filter by severity **critical** and **high**. Open one SQL injection or command injection finding and show, top to bottom:

- The code snippet with line numbers, on the real file and line, with the real identifiers. The payloads sent to the model carried pseudonyms instead of these names (the ledger in the Privacy view shows each payload); the real names were restored locally from the vault.
- The taint path: source, steps, sink.
- The LLM verdict: vulnerable or not, confidence, reasoning, impact and remediation, with the provider and model that produced it.
- The classification: CWE, OWASP Top 10, ASVS, CAPEC, CVSS 4.0 and 3.1 vectors with scores, likelihood and impact, and the compliance clauses.
- Status workflow: mark one finding **confirmed** and one **false positive** with a comment, then show its history.

## 6. Privacy Centre

Open the scan's Privacy view:

- Level, payloads sent, payloads blocked by the guard, placeholders by type, pseudonyms, tokens sent.
- **Zero-leak check**: how many listed terms were searched in every payload and how many occurrences were found (expected 0). Say what it does not cover: it is verbatim only, and the shape of the code still leaves (see the hub's questions).
- **Ledger**: the hash-chained list of every payload. Open one entry: original on the left, the exact payload on the right, secrets (red), personal data, renamed identifiers (blue) and literals marked. Press **Verify chain** and show it passes.
- The attestation text that goes into the report.

## 7. Reports

From the scan, Reports: download **PDF** and open it (executive summary, risk matrix, findings with evidence and remediation, privacy attestation). Mention the other formats: HTML, SARIF (for GitHub code scanning), JSON, CSV, XLSX, Markdown and DOCX. Reports contain client code: keep them with the classification of the code.

## 8. Fallback when the network or the key fails

Say what you are doing, then go down one rung at a time:

1. **Replay**: new scan with provider `replay`. It answers from recorded responses in `fixtures/kavachbank/cassettes/`; no network. Say it is a recording.
2. **Mock**: provider `mock`. Local and deterministic, no key; the ledger shows what would have been sent.
3. **CLI**: `docker compose exec codekavach codekavach demo --out /data/demo-out`, then copy the report out with `docker compose cp codekavach:/data/demo-out/report.pdf .`.

To run the whole stack without any network, see the `airgapped` profile in [`docs/guide/deploy.md`](../guide/deploy.md#no-network-at-all-profile-airgapped).

## 9. Afterwards

```console
$ docker compose down          # keeps the data volume
$ docker compose down -v       # also deletes scans, vaults, ledgers and reports
```

Remove the key from `.env` if the laptop is shared. The hand-over package is the repository plus [`docs/guide/install.md`](../guide/install.md) and [`docs/guide/deploy.md`](../guide/deploy.md).
