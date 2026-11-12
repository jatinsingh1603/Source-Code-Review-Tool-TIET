# User guide

This guide takes you from nothing installed to a downloaded audit report. It covers the dashboard, which is how most people use CodeKavach, and the command line, which does the same work in a terminal or a CI job.

CodeKavach reviews source code for security problems with the help of a large language model (LLM) while keeping secrets and personal data on your machine, and measuring how much of your business logic is shown to the model.

## 1. Install

You need one of two things.

**Docker (recommended for the dashboard).** Docker with the compose plugin and git.

```console
$ git clone https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET.git codekavach
$ cd codekavach
$ cp .env.example .env          # set CODEKAVACH_ADMIN_PASSWORD
$ docker compose up -d --build
$ docker compose ps             # wait for (healthy)
```

Open <http://127.0.0.1:8080> and log in as `admin` with the password from `.env`. If you did not set one, the default is `kavach-admin`; change it under **Admin, Users** after the first login.

**uv (command line, or the server from a checkout).** [uv](https://docs.astral.sh/uv/) installs Python 3.12 for you.

```console
$ uv sync --all-extras
$ uv run codekavach --version
$ uv run codekavach doctor              # checks your setup, prints what to fix
$ uv run codekavach serve --host 127.0.0.1 --port 8080   # dashboard and API
```

Longer instructions, including the air-gapped bundle, are in [Installation](install.md) and [Deployment](deploy.md).

## 2. Your first scan, offline

The fastest way to see the whole product is the offline demo. It scans the bundled **KavachBank** sample with the built-in `mock` provider, so nothing leaves your machine and no key is needed.

```console
$ uv run codekavach demo --out demo-out
```

It writes an HTML and PDF report, a side-by-side page of what would have been sent to a model, and a ledger verification. Open `demo-out/report.html`.

## 3. Your first scan, in the dashboard

1. **Log in.** The Overview shows projects, scans, open findings by severity and a trend.
2. **Pick a project.** *KavachBank (sample)* is created on first start. To add your own, choose **New project** and give a name and a source: a path on the server, a git URL and ref, or an uploaded zip or tar archive.
3. **Start a scan.** Open the project and choose **New scan**. Set:
    - **Privacy level**: L0 to L4 (see section 5). L3 is the default.
    - **Provider and model**: `mock` and `replay` run offline. `agentrouter`, `openai`, `anthropic` and others send data to a hosted model and need a key (see the [Provider guide](providers.md)).
    - **Send**: when off, the scan prepares everything and records what *would* be sent, but sends nothing. Use this first on a real project.

    The wizard shows an **egress preview**: the exact payloads that will leave. Read it before you confirm.
4. **Watch it run.** The live view shows the stages (ingest, parse, analyse, privacy-prepare, llm-review, restore, rate), a progress bar and a log. You can cancel at any time.
5. **Read the findings.** When the scan completes, open **Findings**.

## 4. Dashboard tour

| Screen | What it is for |
|--------|----------------|
| **Overview** | Projects, scans, open findings by severity, trend over time, recent scans. |
| **Projects** | Add, edit and delete projects; start scans. |
| **Scans** | Every run with status, privacy level, provider, model and counts. |
| **Findings** | The list for one scan. Filter by severity, status, CWE and free text. Select several to triage in bulk. |
| **Finding detail** | The code with line numbers, the taint path from source to sink, the model's verdict and reasoning, impact, remediation, CVSS vectors, CWE, OWASP and compliance mappings, and the history of status changes. Three tabs: what the model saw, the real code, and the reasoning. |
| **Privacy Centre** | The privacy posture of one scan: level, payloads sent and blocked, placeholders by type, tokens sent, ledger chain state, the zero-leak check and the attestation text. |
| **Egress ledger** | Every request that left (or was blocked), in order, hash-chained. Open an entry to see the original code and the exact text sent, side by side, with the changes marked as secret, personal data, identifier or literal. **Verify** re-checks the chain. |
| **Reports** | Download the audit report in each format. |
| **Settings** | Providers (with a **Test** button), the privacy policy editor, organisation name for reports, defaults. |
| **Admin, Users** | Accounts and roles (admin only). |

Roles: **admin** does everything; **auditor** and **developer** scan and triage, and an auditor also sees the original-versus-sent pair; **viewer** reads results and downloads reports.

### Triage

On a finding, set the status: **open**, **confirmed**, **false positive**, **accepted risk** or **fixed**, add a comment and assign it. Every change is kept in the finding's history with who and when. A finding the model judged not vulnerable stays visible with its reasoning, so a human can overrule it.

## 5. Privacy levels

| Level | What leaves the machine |
|-------|-------------------------|
| **L0** | Nothing. Deterministic engines and local models only. |
| **L1** | Code with secrets and personal data replaced by typed placeholders. Names and structure are unchanged. |
| **L2** | L1, plus identifiers pseudonymised (`fn_3`, `param_1`). |
| **L3** (default) | L2, but only the smallest slice of code that explains the finding. No whole files, no comments or domain words. |
| **L4** | No code: abstract data-flow facts and questions only. |

Higher means less disclosed and usually a little less context for the model. Pick the highest level that still gives you useful findings; the [whitepaper](whitepaper.md) explains the trade-off and the evaluation measures it. Whatever the level, secrets and personal data are redacted and an **egress guard** blocks any payload that still contains a recorded secret, a listed business term or a known original identifier.

You can lower nothing below the **minimum level** set by your organisation's policy. Paths can be given a stricter level, or `never-send`, in the policy (Settings, Privacy policy).

## 6. Reports

Open **Reports** for a scan and download any format:

| Format | Use |
|--------|-----|
| **HTML** | Read in a browser; self-contained. |
| **PDF** | The deliverable for a client or committee. |
| **DOCX** | Edit before delivery. |
| **SARIF** | Upload to GitHub code scanning or another SARIF viewer. |
| **JSON** | Machine-readable, for your own tooling. |
| **CSV / XLSX** | Triage in a spreadsheet. |
| **Markdown** | Paste into a ticket or pull request. |

The report is laid out like a professional audit: executive summary, scope and methodology, risk matrix, evidence-backed findings with impact and remediation, compliance mapping, and a privacy attestation. See the [Auditor guide](auditor-guide.md) for how to read it.

From the command line:

```console
$ uv run codekavach scan ./myproject --privacy-level L3 --provider mock --format html --format sarif
$ uv run codekavach report --scan latest --format pdf --org "Your Org" --client "Client Name"
```

## 7. The command line

```console
$ uv run codekavach init                          # write a starter codekavach.toml
$ uv run codekavach scan . --privacy-level L3 --provider agentrouter --accept-egress
$ uv run codekavach privacy inspect --scan latest # see original and sent, side by side
$ uv run codekavach privacy score --scan latest
$ uv run codekavach privacy ledger verify         # check the egress ledger
$ uv run codekavach report --scan latest --format html,pdf
$ uv run codekavach providers list
```

The exit code of `scan` reflects the `fail_on` severity gate, which makes it usable in CI. Every command and option is in the [command-line reference](../reference/cli.md); the long form of this section is the [CLI guide](cli.md).

## 8. Troubleshooting

| Symptom | What to do |
|---------|------------|
| Dashboard does not load | `docker compose ps` should say `(healthy)`; read `docker compose logs codekavach`. |
| Provider **Test** fails | Check the key variable is set in `.env` and the container was recreated (`docker compose up -d`). Use `mock` meanwhile. |
| Scan finishes with 0 payloads sent | The scan ran with **Send** off, or the egress guard blocked the payloads; see the Privacy Centre for the blocked count and reason. |
| A payload is blocked | A recorded secret, listed domain term or original identifier was found in it. This is the guard working. Raise the level or add the path to `never-send`. |
| Findings look noisy | Triage the noise as **false positive** with a comment, so the report records why. Findings the model judged not vulnerable keep its reasoning for you to check. |
