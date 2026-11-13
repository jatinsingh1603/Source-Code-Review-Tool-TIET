# Demo day hub

Everything for the demo to the Head of Department of Cyber Security (Thapar) and the guest from Australia, and for the hand-over on the same call. One page to run the session from; one page per surface behind it.

Audience: security people. They will probe the privacy claim harder than anything else, so the session is built around it. Never claim more than [Known limits](../../README.md#known-limits) allows.

## Runbooks

| Surface | Runbook | Owner |
|---------|---------|-------|
| Offline first demo (one command, mock provider) | [`DEMO1.md`](DEMO1.md) | core |
| Install every way | [`install.md`](install.md) | infra |
| Docker, compose, Helm; the dashboard in a container | [`docker.md`](docker.md), [`DEMO2.md`](DEMO2.md) | deploy |
| Command line | [`cli.md`](cli.md) | cli |
| CI and GitHub Action | [`ci.md`](ci.md), [`github-actions.md`](github-actions.md) | integrations |
| VS Code | [`vscode.md`](vscode.md) | integrations |
| Hand-over | [`handover.md`](handover.md) | hub |
| Seed data for the dashboard | [Seeding the dashboard](#seeding-the-dashboard) | hub |

Install guides: [`docs/guide/install.md`](../guide/install.md) and [`docs/guide/deploy.md`](../guide/deploy.md).

## Agenda (about 30 minutes)

| Min | Part | What to show | Say |
|-----|------|--------------|-----|
| 0-3 | The problem | One slide or the README intro | Reviewing code with an LLM is useful, and sending the code to a provider is exactly what a bank, a defence contractor or a university lab cannot do. We build the review so the provider never sees what it does not need to. |
| 3-7 | The privacy approach | Levels table (below), then `codekavach privacy inspect` page | Five levels, L0 to L4. L3 is the default. Show what leaves the machine, not a promise about it. |
| 7-15 | Live dashboard scan, real model (start it at minute 3, before the privacy slides, and come back to it: a quick review of 8 candidates took 14 min 37 s on 13 Nov; see [Real-model timings](#real-model-timings)) ([`DEMO2.md`](DEMO2.md) sections 3 to 5) | Dashboard: start a scan of the KavachBank project at L3 with the `agentrouter` provider, Model review "Quick · the 8 most severe candidates"; verdicts appear in the log one by one | The findings carry the real file, line and name, although the model only saw pseudonyms; the mapping is restored locally from the vault. |
| 15-20 | Privacy Centre ([`DEMO2.md`](DEMO2.md) section 6) | Side by side (original vs payload), the egress ledger, the zero-leak check | The ledger is hash-chained: every payload that was sent, or blocked, is recorded. The check shows listed terms do not occur verbatim in any payload. Then state what it does not show (see questions). |
| 20-23 | Report ([`DEMO2.md`](DEMO2.md) section 7) | Open the PDF from the dashboard or `codekavach report` | Audit-style: executive summary, risk matrix, evidence, remediation, privacy attestation. Also SARIF, JSON, CSV, XLSX, Markdown, DOCX. |
| 23-26 | CI and VS Code ([`github-actions.md`](github-actions.md), [`vscode.md`](vscode.md)) | A finished GitHub Actions run with its Security-tab alerts; the extension showing the same findings in the editor | Same core everywhere. GitHub-hosted runs use the mock provider: no key, nothing leaves the runner. |
| 26-28 | Docker hand-over ([`docker.md`](docker.md)) | `docker compose up -d`, dashboard on port 8080 | This is what you receive. See [`handover.md`](handover.md). |
| 28-30 | Q&A | The questions below | Answer plainly; "not measured yet" is an acceptable answer. |

### Levels in one table

| Level | What the provider receives | Default |
|-------|----------------------------|---------|
| L0 | Nothing. Deterministic engines and a local model only | |
| L1 | Code with secrets and personal data replaced by typed placeholders | |
| L2 | L1 plus consistent pseudonyms for identifiers | |
| L3 | L2, cut down to the minimal slice around the finding | yes |
| L4 | Abstract data-flow facts only, no code (not delivered in every build; it fails closed) | |

What "leaves the machine" at L2 and L3: the control flow of the slice, the shape of string literals and the names of public library APIs. State it before anyone asks.

## Pre-flight checklist

Do this the day before and again 30 minutes before. Tick each item; if one fails, go to the ladder.

- [ ] `git pull` on the demo machine; `uv sync --all-extras`; `uv run codekavach --version` works.
- [ ] `uv run codekavach demo --out demo-out` exits 0 and prints `zero_leak_passed  True` (works offline).
- [ ] Dashboard up: `docker compose up -d` (or `uv run codekavach serve`), then open `http://127.0.0.1:8080`, log in as `admin`.
- [ ] Dashboard seeded: `uv run python scripts/seed_demo.py` has been run once; the Overview shows several scans and a Privacy Centre that is not empty (see "Seeding the dashboard").
- [ ] Privacy guard status recorded: the Overview's "Privacy guard status" card reads "not recorded" for I1, I2, I3 and I5 until the invariant suite has been run once into the server's data directory: `uv run pytest -m privacy --junitxml=<data-dir>/invariants/junit.xml` (about two minutes; `<data-dir>` is the `--data-dir` of `codekavach serve`). With Docker, run it on the host and copy the file into the volume: `uv run pytest -m privacy --junitxml=junit.xml && docker compose exec codekavach mkdir -p /data/invariants && docker compose cp junit.xml codekavach:/data/invariants/junit.xml`. The Privacy Centre's "Invariant suite" card then shows the run time and the test count (about 400). Re-run it after `git pull`; a failing test shows as "Fail" on the card.
- [ ] Restart the server after every `git pull` (`docker compose up -d --build`, or stop and start `codekavach serve`): a server left running on old code with new report templates fails to render HTML and PDF reports.
- [ ] Real model reachable: **Providers** in the sidebar, **Run health checks**; the `agentrouter` card turns **Healthy** with its latency (hover it for the message). It shows **Key missing** when the key is not in the environment, and is then not called. The key lives in `.env` (`CODEKAVACH_AGENTROUTER_API_KEY`), never in a file that is committed; do not show it on screen.
- [ ] `report.pdf` opens (needs the Pango libraries; see `DEMO1.md`).
- [ ] The latest GitHub Actions run of the demo workflow is green; the Security tab has alerts. Check in the browser; do not rely on memory.
- [ ] VS Code with the extension installed and the KavachBank folder open.
- [ ] Network: wired or hotspot as backup; the offline demo is the safety net.
- [ ] Terminal font large; notifications off; browser zoom 125 percent; secrets (`.env`, key files) not visible in any open tab or file tree.
- [ ] Two terminals ready: one in the repository, one for Docker.

## Seeding the dashboard

A dashboard with history is more convincing than an empty one. With the server running (`docker compose up -d` or `uv run codekavach serve`), from a checkout:

```console
$ export CODEKAVACH_ADMIN_PASSWORD=...          # the admin password from .env; omit for the default
$ uv run python scripts/seed_demo.py            # about two minutes; add --url http://host:8080 for another address
KavachBank (sample)
  KavachBank at L1: completed, 66 findings (19 critical, 26 high), 29 payloads, 0 blocked
  ...
done: 3 projects, 8 scans, 80 findings, 76 still open
```

It uses only the REST API (so it works against a container), the offline `mock` provider (no key, nothing leaves the machine) and real scans. It creates:

| Project | Scans | What it shows |
|---------|-------|---------------|
| KavachBank (sample) | L1, L2, L3 | The same code at three levels: detection does not change with the level, what the provider would receive does (compare the Privacy Centre of each scan). 4 findings confirmed, 2 accepted risk. |
| Ledgerly (demo), Python, `fixtures/demo-ledgerly` | L2, then L3 after three flaws are fixed in the uploaded code | A falling trend: the re-scan no longer reports the SQL injection, the unsafe YAML load and the debug flag; those findings are marked **fixed**. |
| Shopfront (demo), Node, `fixtures/demo-shopfront` | L3, L0, then L3 after fixes | An L0 scan with **zero payloads** (nothing leaves the machine) between two L3 scans; findings on the safe code (the ground-truth negative control) are marked **false positive**. |

Nothing is typed into the database. Findings, counts, payloads, the ledger and the zero-leak result are the output of the scans; only the triage statuses are the script's choice, applied through the same API a reviewer uses. Run it twice and it skips projects that already have scans (`--again` repeats). With Docker, use it instead of `scripts/demo-docker.sh --seed`, which runs a single sample scan: once KavachBank has that scan, this script skips it unless you add `--again`. Run it the day before, not in front of the audience, and check the Overview, a Privacy Centre page and one report afterwards.

Honest notes for the presenter, as observed with the engines of the day:

- The sample projects are small and synthetic, with ground truth in `fixtures/*/ground-truth/manifest.yaml`. The scanner finds most planted flaws, but not all, and it flags the safe code in Shopfront. That is a true statement about detection quality on small samples, and a good moment to show triage. Do not present it as a benchmark; `codekavach eval` is the benchmark.
- L4 is not seeded: it is not delivered in every build and fails closed. A scan started at L4 completes with zero payloads and every candidate withheld; the scan form, the ledger, Inspect and the Privacy Centre all say so. Show it only as "fails closed", never as working L4.
- Evaluation shows bundled sample results (marked "Sample results") until **Run benchmark** is pressed. A run takes about a minute with the mock provider and replaces the sample, including its AgentRouter row, with this server's mock-only figures, where the model review does not change F1. Decide before the session which one you want on screen.
- The first PDF of a scan takes up to a minute to render on a laptop (later downloads are instant). Download the PDF of the scan you will show once before the session.
- Scans with the mock provider say so in the summary: the ledger shows what **would** have been sent.

## Real-model timings

Measured on 13 Nov 2026 from the dashboard (WSL laptop, KavachBank sample, L3, `agentrouter` / `gpt-5.6-sol`, Model review "Quick · the 8 most severe candidates"). The gateway answers one request at a time per key and reasons at length, so the time is almost all model time.

| Step | Time |
|------|------|
| New scan, **Test provider** | 15.7 s |
| Deterministic stages (ingest to privacy layer, 29 files, 59 findings) | 7 s |
| First verdict in the live log, after **Start scan** | 81 s |
| Each further verdict | 23 s to 3 min 51 s (about 1 min 50 s on average) |
| Model stage, 8 verdicts | 14 min 25 s |
| Whole scan | 14 min 37 s |
| **Review with model** on one finding page, first time | 53 s |
| The same finding reviewed again (answered from the scan's cache, no egress, no ledger entry) | 2.6 s |

What this means on the day:

- Start the real scan early (minute 3) and talk over it; the verdicts stream into the log as they arrive. If time is short, open a real scan run before the session instead and say so.
- A new scan of the same code is **not** answered from the cache: every server scan gets a fresh pseudonym salt (less linkability between scans), so its payloads differ and the model is asked again. Only a repeated **Review with model** on the same finding is served from the cache.
- Candidates beyond the eight keep their deterministic evidence; open any of them and press **Review with model** (auditor or admin) to ask about that one finding live, in about a minute.

## Fallback ladder

Go down one rung at a time, and say what you did ("the network is slow, so I will replay a recorded model run"). Do not hide a rung from the audience.

1. **Real model** (`agentrouter`, model `gpt-5.6-sol`). Needs network and the key in the environment.
2. **A real-model scan run before the session.** Open it from **Scans** (provider `agentrouter`): its verdicts, ledger and report are real; say when it was run. The `replay` provider is not offered in the dashboard (every dashboard scan gets a fresh pseudonym salt, so recorded answers would not match); it backs the offline CLI demo only (see [`DEMO1.md`](DEMO1.md)).
3. **Mock provider.** Deterministic, local, no key. The ledger then shows what would have been sent. This is the default for `codekavach demo`.
4. **Recorded artefacts.** The sample report from the latest release (`codekavach-sample-report.zip`), the last green Actions run and the screenshots you took during rehearsal. Open them and narrate.

## Likely questions from a security HOD

**Can the provider reconstruct my business logic from what it receives?** Partly, and we measure it rather than deny it. At L3 the provider sees a slice with pseudonymised names and no comments or string contents, but the control flow and the shape of literals remain, and so do public API names, which can hint at the stack and the domain. The leak check is verbatim only. How much an adversary can reconstruct (identifier recovery, summarising the logic, re-assembling slices, identifying the project) is what `codekavach eval leakage` measures; until those numbers are published, treat the protection as a hypothesis under test. For paths that must never be disclosed, use L4, L0 or `never-send`. See "Known limits" in the README.

**What exactly leaves the machine?** Only what the egress ledger records, and you can read it: `codekavach privacy ledger`. Each entry has the payload hash, the level and the provider. A payload the guard blocks is recorded as blocked. With the mock and replay providers nothing is transmitted at all.

**What if the model is malicious or compromised?** It never receives secrets (typed placeholders), real identifiers (pseudonyms) or whole files at L3. A model can still return a wrong or manipulated answer; findings are candidates that carry evidence and pass schema validation and prompt-injection defences, and the deterministic engines do not depend on the model. Treat model output as untrusted input.

**Where is the mapping from pseudonyms to real names kept?** In the local vault, encrypted, in the scan state directory; it is never sent. Losing the passphrase makes old vaults unreadable.

**Does the tool find real vulnerabilities, or only the planted ones?** Both are the point of the evaluation harness (`codekavach eval`), which compares findings with labelled ground truth at each level. The sample applications are planted on purpose so that the demo has a known answer. We do not claim a detection rate on real code beyond what `eval` has measured; show the numbers it has, not the ones we would like.

**How do you handle false positives?** Findings carry a status the reviewer sets in the dashboard (confirmed, false positive, fixed); the evidence and the data-flow path are shown so the reviewer can decide quickly.

**Is the zero-leak proof a proof?** It proves one narrow thing: no recorded original identifier, literal, secret or listed term of four or more characters occurs verbatim in any stored payload. It does not prove no meaning can be inferred, and it cannot find a term nobody listed.

**Can we run it without any cloud?** Yes. L0 with a local model (Ollama) or the deterministic engines only, in the air-gapped compose profile.

**What does it cost to run?** The software is free to run. Model cost depends on the provider and level; L3 sends slices, not files, so it is the cheapest of the code-sending levels. Do not quote a figure you have not measured.

**What data does the dashboard store?** Scan results, findings, ledger entries and reports in its own database and volume, on your machine. Nothing is sent to us.

**What is not finished?** Say it: check `docs/status/` and the changelog on the day. Anything marked unfinished there is not to be demonstrated as working.

## After the session

Stop the stack (`docker compose down`), delete `demo-out/` if the machine is shared (the inspection page holds the fixture's code), and hand over using [`handover.md`](handover.md).
