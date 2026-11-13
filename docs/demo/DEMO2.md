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
- `CODEKAVACH_VAULT_PASSPHRASE`: leave empty; the server generates one in its data volume.

```console
$ docker compose up -d --build       # first build: a few minutes
$ docker compose ps                  # wait for "(healthy)"
$ curl -s http://127.0.0.1:8080/api/v1/health
```

If `ps` stays at `(health: starting)` for more than a minute, run `docker compose logs codekavach` and read the last lines.

## 2. Log in

Open `http://127.0.0.1:8080`. Log in as `admin` with the password from `.env` (default `kavach-admin`; the server also prints it in its log at first start). The Overview shows open findings by severity, the privacy score, bytes egressed, the zero-leak check, the trend across scans, the risk matrix, the OWASP heatmap and the privacy guard status. Choose the project in the first pill of the top bar.

The project **KavachBank (sample)** is created on first start from `fixtures/kavachbank`, a small banking application with planted vulnerabilities and planted secrets. Its ground truth is in `fixtures/kavachbank/ground-truth/manifest.yaml`.

## 3. Check the model before you need it

Providers (side navigation, under Deliver): press **Run health checks**; the `agentrouter` card shows its status, with the latency in the tooltip. It should answer `ok` with a latency of a few seconds and the model `gpt-5.6-sol`. If it fails, do not debug in front of the audience; use the fallback (section 8).

## 4. Scan the sample with the real model

1. With **KavachBank (sample)** selected in the top bar, Overview, **New scan**.
2. Privacy level **L3** (the default: slices around each candidate, secrets as typed placeholders, identifiers pseudonymised).
3. Provider `agentrouter`, model `gpt-5.6-sol`, **No-send (dry run)** off.
4. **Start scan**. The live view shows the nine-stage pipeline with counts, the egress meter (payloads, bytes, secrets, listed terms) and the streaming log. Leave **Model review** at "Quick · the 8 most severe candidates". The deterministic stages take seconds; the gateway then answers one request at a time, about one to two minutes each, so the scan takes about 15 minutes (timings in [the hub](README.md#real-model-timings)). Each verdict appears in the log as it lands.

Say while it runs: the deterministic engines (own rules, taint, Opengrep, Bandit) find the candidates; the model only reviews a sanitised slice of each one and says whether it is exploitable and why.

## 5. Walk through the findings

Press **Open findings**. Pick the **Critical and high** view. Open one SQL injection or command injection finding and show, top to bottom:

- The tabs **What the LLM saw** (the pseudonymised payload) and **Real code** (the real file and line, kept local); **Inspect side by side** opens Privacy Inspect. The real names were restored locally from the vault.
- The taint path: source, steps, sink.
- The LLM verdict: vulnerable or not, confidence, reasoning, impact and remediation, with the provider and model that produced it.
- The classification: CWE, OWASP Top 10, ASVS, CAPEC, CVSS 4.0 and 3.1 vectors with scores, likelihood and impact, and the compliance clauses.
- Status workflow: change the status in Details, add a comment, and show the Activity timeline.

## 6. Privacy Centre

Open **Privacy Centre**, then **Privacy Inspect** and **Egress Ledger** from the side navigation:

- Privacy Centre: the privacy score and its parts, exposure budgets, the invariant suite, policy decisions and the explanation for one file, and the attestation (Download PDF or JSON).
- **Zero-leak check**: how many listed terms were searched in every payload and how many occurrences were found (expected 0). Say what it does not cover: it is verbatim only, and the shape of the code still leaves (see the hub's questions).
- **Privacy Inspect**: original on the left, the exact payload on the right, secrets (red), renamed identifiers (blue) and generalised literals marked.
- **Egress Ledger**: the hash-chained list of every payload. Select a record to see it; press **Verify again** and show it passes.
- The attestation text that goes into the report.

## 7. Reports

Reports: pick the formats in the builder, press **Generate report** and open the **PDF** (executive summary, risk matrix, findings with evidence and remediation, privacy attestation). Mention the other formats: HTML, SARIF (for GitHub code scanning), JSON, CSV, XLSX, Markdown and DOCX. Reports contain client code: keep them with the classification of the code.

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
