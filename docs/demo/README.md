# Demo day hub

Everything for the demo to the Head of Department of Cyber Security (Thapar) and the guest from Australia, and for the hand-over on the same call. One page to run the session from; one page per surface behind it.

Audience: security people. They will probe the privacy claim harder than anything else, so the session is built around it. Never claim more than [Known limits](../../README.md#known-limits) allows.

## Hosted demo (no install)

<https://jatinsingh1603.github.io/Source-Code-Review-Tool-TIET/> is the dashboard published to GitHub Pages in mock mode, for anyone who wants to look before or after the session. It is a static site: every API call is answered in the browser from synthetic sample data (`ui/src/mock`), so nothing is scanned and nothing is sent anywhere. A strip at the top of each page says so and links to [`install.md`](install.md). Sign in as `admin` / `kavach-admin` (or `auditor`, `developer`, `viewer` with `kavach-<role>`), or choose **Try the offline demo**. **Sign in with Google** there is a demo sign-in: it shows the sample data under your own name and needs `https://jatinsingh1603.github.io` among the OAuth client's authorised JavaScript origins. Google sign-in on a real server is optional and off by default ([`deploy.md`](../guide/deploy.md#google-sign-in)). The [Pages workflow](../../.github/workflows/pages.yml) republishes it on every push to `main` that changes `ui/`.

| | Hosted demo (GitHub Pages) | Docker or local install |
|---|---|---|
| Overview, findings, finding detail, triage | Yes, on sample data | Yes, on your scans |
| Privacy Centre, side by side, egress ledger, verify | Yes, on sample data | Yes |
| Start a scan | Simulated stage by stage over the sample project; an uploaded archive is not read | Real engines, real model or the mock provider |
| Reports | HTML, SARIF, JSON, CSV and Markdown, built from the sample data; PDF, Word, Excel and delta reports say they need the server | Every format |
| GitHub issue sync | Preview (dry run) only; creating issues says it needs the server | Real, with a GitHub token |
| Providers, admin, users, settings, policy | Sample responses; changes last until the page is reloaded | Real |
| CLI, GitHub Action, VS Code | No | Yes |

For the session itself use the Docker or local install: the hosted demo shows the interface, not the privacy layer at work.

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
| 7-15 | Live dashboard scan, real model, then the full real-model scan made before the session (the live review of 3 candidates took 2 min 4 s on 13 Nov; see [Real-model timings](#real-model-timings)) ([`DEMO2.md`](DEMO2.md) sections 3 to 5) | Dashboard: start a scan of the KavachBank project at L3 with the `agentrouter` provider, Model review "Live demo · the 3 most severe candidates"; the three verdicts (command injection, unsafe deserialisation, SQL injection) appear in the log one by one. Then open the pre-run scan (every candidate reviewed) from **Scans** for the findings walk-through | The findings carry the real file, line and name, although the model only saw pseudonyms; the mapping is restored locally from the vault. |
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
- [ ] Privacy guard status recorded: the Overview's "Privacy guard status" card reads "not recorded" for I1, I2, I3 and I5 until the invariant suite has been run once into the server's data directory: `uv sync --all-extras` first (without the server extras four test modules fail to import), then `uv run pytest -m privacy --junitxml=<data-dir>/invariants/junit.xml` (two to six minutes; `<data-dir>` is the `--data-dir` of `codekavach serve`). With Docker, run it on the host and copy the file into the volume: `uv run pytest -m privacy --junitxml=junit.xml && docker compose exec codekavach mkdir -p /data/invariants && docker compose cp junit.xml codekavach:/data/invariants/junit.xml`. The Privacy Centre's "Invariant suite" card then shows when the file was copied in and the number of tests behind the six invariants (412 on 14 Nov; pytest itself reports 556 passed, because some privacy tests back no single invariant). Say "412 tests behind I1 to I6" if asked. Re-run it after `git pull`; a failing test shows as "Fail" on the card. A busy laptop no longer fails a property test for drawing inputs slowly (the suite skips Hypothesis's timing check), but check the card reads Pass for all six before the call.
- [ ] Restart the server after every `git pull` (`docker compose up -d --build`, or stop and start `codekavach serve`): a server left running on old code with new report templates fails to render HTML and PDF reports.
- [ ] Real model reachable: **Providers** in the sidebar, **Run health checks**; the `agentrouter` card turns **Healthy** with its latency (hover it for the message). It shows **Key missing** when the key is not in the environment, and is then not called. The key lives in `.env` (`CODEKAVACH_AGENTROUTER_API_KEY`), never in a file that is committed; do not show it on screen.
- [ ] Pre-run real-model scan in place: a completed KavachBank scan at L3 with `agentrouter` and Model review "Every candidate" (about 15 minutes; see [Making the pre-run real-model scan](#making-the-pre-run-real-model-scan)), its ledger verified and its PDF downloaded once. Settings, Default provider: `agentrouter`.
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
$ uv run python scripts/seed_demo.py            # two to five minutes; add --url http://host:8080 for another address
KavachBank (sample)
  KavachBank at L1: completed, 59 findings (11 critical, 26 high), 14 payloads, 0 blocked
  ...
done: 3 projects, 8 scans, 69 findings, 65 still open
```

The totals depend on which external engines the server has, not on chance: the run above (14 Nov, after secrets were rated by type) had no external engine (Opengrep, Bandit, ESLint), as on a fresh laptop or in the container; each scan log then says "No external engine ... is installed". KavachBank's 59 are 11 critical, 26 high, 16 medium and 6 low. With Bandit installed the same script reported 66 findings and 18 payloads before that change; its critical count is lower now (Bandit's own hits are unchanged, the secrets engine's are re-rated), and it has not been re-measured. Rehearse the numbers on the demo machine itself.

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
- Triage survives a re-scan. When the live scan of KavachBank finishes, its unchanged findings keep the seeded decisions (4 confirmed, 2 accepted risk), so the Overview still reads 57 open, not 59 (64 of 66 with Bandit), and each carried finding's Activity says "Kept the reviewer's decision from SCN-...". A finding marked **fixed** that comes back opens again (a regression). Say this if asked "what happens to my false positives on the next scan".
- The PDF's executive summary counts every finding of the scan and then says how many remain open ("59 findings ... 57 remain open; two were closed by the reviewers"); the Overview shows the open count. Both are right; point at the second sentence if the numbers are compared.
- The live log and the findings table agree on the model's confidence: a vulnerable verdict with low or medium confidence reads "vulnerable per the model, medium confidence: needs review" (the model's own word) in the log and **Needs review** in the table. The mock provider gives varied confidences, so a mock scan shows a mix. The real model does not always answer "high": on 14 Nov it answered medium on all three live-demo verdicts (the table shows 0.60), where on 13 Nov it had answered high. Say "the model flags it, a reviewer confirms it" rather than promising "confirmed".
- The severity in a verdict line of the live log is the candidate's before risk rating: on 14 Nov the log read "CWE-502 (high)" and "CWE-89 (high)" and the findings table then shows both Critical. The table and the report carry the final rating.
- The Findings filter menus count within the selected tab: under **All open** the Severity menu says Low 4, not 6 (the two accepted-risk findings, among them the Razorpay key ID, are under **Suppressed** and **All**).
- The Findings trend counts every finding each scan reported, by severity (59 per KavachBank scan); the Open findings card counts what is still open (57). Bars are labelled by the scan's start time, as in Recent scans.
- Findings without a model verdict show the weakness's impact statement (the same text as the report), not a CVSS line. Taint and secret findings read in words: "Data from a request parameter reaches an SQL query (cur.execute)", "Hard-coded credential: AWS access key". Search for **SQL query**, not "sql sink", to open the SQL injection finding.
- Bandit findings read in words too ("A subprocess call runs its command through a shell (shell=True).", "Possible hard-coded password."). A project scanned before 14 Nov keeps Bandit's own wording ("subprocess call with shell=True identified, security issue.") on its old scans until it is scanned again; seed on a fresh volume, or re-scan each project once, after updating.
- The attestation in the Privacy Centre gives payload bytes (the code slices) and prompt tokens, which include the fixed review instructions sent with every slice. On a fresh seed with no external engine (14 Nov) KavachBank's L3 scan reads 14 payloads, 3,865 B and 27,363 prompt tokens (L2: 18,306 B and 31,245 tokens; L1: 19,622 B and 31,576 tokens, whole files); a run with Bandit installed sends more payloads and was about 6.5 KB and 35,500 tokens. If asked why tokens exceed bytes, that is the reason; the report's privacy annex splits them into prompt and completion tokens.
- The live log names every stage in words ("Scanning for secrets done in 362 ms", "Checking dependencies against OSV done in 398 ms"); it no longer shows internal names such as `analyse-secrets`. An L0 scan opens with "no model review: nothing is sent to a model (local engines only)". Shopfront's seeded L0 scan was made on a fresh volume, so it has the new wording; a volume seeded before 14 Nov keeps "payloads sent" in that old log.
- Mean time to remediate on Ledgerly and Shopfront reads "1 min": the seed script fixes those findings with a re-scan a few seconds later. Say so if asked; it is the seed, not a claim about a team. Real fixes over days read in days.
- The admin audit log names scans as the rest of the dashboard does (`SCN-AD99A5 #35` = payload 35 of that scan); hover a target for the internal id. Action names (`privacy.read_original`) stay as they are, as in the design.
- On a phone (390 px) the Overview trend shows only its first and last labels; the other scan times are in Recent scans below it. On a laptop every bar is labelled.
- `codekavach demo` (air-gapped profile) no longer prints an empty `state_dir` line at the end; the table ends with the note about the mock provider.
- Hard-coded secrets are rated by what they give an attacker, not all as Critical 9.1: the private key, AWS secret key, connection string and Razorpay key secrets are Critical (CVSS 9.3), the AWS access key id High (8.3), the two low-entropy generic passwords Medium (6.3), and the Razorpay key ID, a public identifier shipped to browsers, Low (2.0). The finding page says "representative ... vector matching the engine's rating of this secret instance". The report and every export carry the same severity and score. If asked: the severity comes from the detector's type and confidence, not from a model.
- A report of a mock scan says so in its executive summary: "No language model reviewed the code: the run used the offline mock provider ...". The mock's placeholder impact and remediation text no longer appear in the report; the library text does. Detailed findings still show "Model assessment: ... (mock-1)", labelled as the mock's.
- Every export names the dashboard scan id: the JSON `scan.reference`, a `scan_id` column in the CSV and XLSX, `scan_reference` in the SARIF run properties and in the integrity manifest (beside the pipeline id `scan_...`).
- Saving a policy under **Privacy**, **Policy** no longer adds a file to the scanned code: the next scan of KavachBank still reads 29 files and no TOML. The policy stays in the server's data directory and wins over any `codekavach.policy.toml` the project ships; a never-send rule on `services/web/**` shows in the scan log as "11 candidates not sent to the model: the privacy policy keeps their files local ...", followed by how many of them are code findings (the kind sent as a payload) and how many are secrets, dependencies or configuration. The code-finding number is the drop in payloads: a never-send rule on `services/api/**` read "23 candidates ... 9 are code findings ...; 14 are secret, dependency or configuration findings" while payloads fell from 14 to 5 (14 Nov).
- On a phone (760 px and narrower) the sidebar is a drawer behind the menu button at the left of the top bar; it closes on a link, on Escape, on the scrim or on its close button.
- **Admin**, **Invite user** shows every field error at once (username, email, password), each under its field, with a count above the buttons.
- **Review with model** on a finding the scan could not send reads "Nothing was sent" and says why: in a never-send path, "the privacy policy keeps this finding's file local (a never-send path)"; in an L4 scan, "the scan is at L4, which this build does not deliver, so it fails closed". No ledger entry is written in either case.
- Time zone and date form (**Settings**, Language and region) belong to the user, not the browser: they follow the user to another browser and do not change what another user sees on a shared one. With the ISO form the Overview's short dates read `11-15`. Reports, exports and the ledger verification file state times in UTC ("Generated 2026-11-14 13:30 UTC"), whatever the reader chose; the dashboard converts.
- The delta report's **Still present** counts every finding detected again, triaged or not; under it the tile reads "55 open · 4 closed by triage" when reviewers have closed some, which matches the Overview's open count.
- The Findings sort (for example **Conf.**) is part of the address, so Back from a finding returns to the same sorted page. Rows without a confidence or CVSS stay at the end in both directions.
- Refusals name the role they need, in toasts as well as on pages: "Your role (Viewer) cannot do this: it needs the Admin role. Ask an administrator if you need access." A viewer sees no Privacy section, no scan launch, no triage, no **Review with model**, and no **Open ledger** on a scan page; **Run benchmark** is disabled for every role but Admin.
- The Word report opens with its Contents filled in (section titles); Word adds page numbers when its fields are updated (select all, then F9). The XLSX prints one page wide in landscape, the heading row repeated (16 pages for KavachBank, down from 166). Its Owner column is left blank for the client's tracker, and its due dates count from the report's generation time, not from the scan.
- **Review with model** on a finding sends one more payload into that scan's ledger after the scan finished. The scan's attestation describes the scan run and keeps its figures; the Privacy Centre now says under Payloads "Not included: 2 more sent later by Review with model on findings of this scan (408 B, 3,894 prompt tokens); they are in this scan's ledger", so the ledger's 5 sent payloads and the attestation's 3 no longer look like a contradiction (14 Nov, live-demo scan plus two reviews).
- The scan form refuses L2 or L1 with `agentrouter` ("needs L3 or stricter", public trust tier). A scan started through the API at L2 still runs, and every payload is prepared at L3; its log now says so ("Provider agentrouter (public tier) needs L3 or stricter: payloads are prepared at L3, not L2"), and the Privacy Centre's Levels used reads L3. A word-by-word check of those payloads against the originals found no project identifier, table name or comment text; what remained were public API names (`subprocess.run`, `pickle.loads`, `cursor`), SQL keywords and short literal words such as `zip` (14 Nov).
- Ctrl+C on `codekavach serve` while a scan runs and a dashboard tab is open now stops the server in 6 to 7 seconds (it used to wait for the scan to finish). That scan ends **Failed**: "The server was stopped while this scan was running ... Start it again with Run again"; a server that was killed outright gives the same message on its next start. An open scan page shows "The CodeKavach server could not be reached" while it is down and the failed scan as soon as it is back, without a reload. Do not restart the server during the live scan.
- A session that ends (sign-out in another tab, or a revoked token) takes the next click to the sign-in page with "Your session has ended. Sign in again; you will return to the page you were on"; a **Start scan** clicked with an ended session starts nothing.
- Large projects: this repository's own `src/` (694 files, 123,162 lines, 616 of them Python) added as a local-path project scans at L3 with mock in 1 min 51 s on the server (135 findings, 15 payloads, 2 blocked by the egress guard). It took 27 minutes before the 14 Nov fixes to slicing and taint analysis. Findings paging, filters and the finding page answer in under a second; the first PDF, Word, SARIF and JSON of that scan took 71 s, almost all of it the PDF.
- The Findings filter menus (Severity, CWE, OWASP and the rest) and the Egress Ledger status filter apply when you click an option's text; before 14 Nov a click on the text in Chromium or Edge closed the menu and changed nothing, so only the small box worked. **Export CSV** on Findings exports the rows the view shows (11 rows with Critical ticked, saved as `...-view.csv`); with nothing filtered under **All** it is the whole scan.
- **Run benchmark** on this server (14 Nov, mock, about 40 s) gave identifier recovery L2 7.4%, L3 8.3%, L4 0%, and F1 0.87 for every arm. If asked why L3 is not lower than L2: the rate is the share of identifiers defined in the files the payloads touch, and L3 touches fewer files, so the two rates have different denominators. Do not read it as "L3 leaks more"; the absolute counts are in the output of `codekavach eval leakage` if someone presses. The Privacy Centre's Leakage evaluation card shows the same run once it has been made.
- Findings for a CORS wildcard, debug mode, a deprecated TLS version and unencrypted storage carry their own fix ("Replace the wildcard with an explicit list of the origins ...") from scans made after 14 Nov; scans made before keep the old family text (cookie and session advice for CORS, password hashing for TLS). Seed on a fresh volume or re-scan once. The PDF roadmap header reads PRIORITY on one line.
- **Settings**, Notifications: the In app switches decide what the bell shows (finished and failed scans, findings assigned to you). Assigning a finding to yourself also puts it on your bell. This build raises no Critical-finding or ledger alerts and sends no e-mail; the page says so.
- **New scan**, Mode **Diff** is greyed out in the dashboard ("Not in this build"). A diff scan is a command-line feature: `codekavach scan . --diff-since HEAD~1` (or a branch, tag, commit or earlier scan id) scans only the changed files; on a copy of Ledgerly with one changed file it reported 4 findings instead of 9.
- The live log of a quick review counts only what the limit held back. For KavachBank with "Live demo · the 3 most severe candidates" (mock, 14 Nov) it reads "11 candidates kept their deterministic evidence ... (review limit)" and "45 candidates not sent to the model: no code slice to send"; 3 + 11 + 45 = 59. Before 14 Nov the same scan read 42 and 14, because dependency and configuration findings, which have no slice at any limit, were counted as held back. If asked "how many did the model not see": 11 code findings, each of which **Review with model** can send from its page.
- **Settings**, Organisation defaults: switching the default provider back from `agentrouter` to Mock (rung 3 of the fallback ladder) now clears the default model; before 14 Nov every later Mock scan recorded `gpt-5.6-sol` as its model in the scan settings, the ledger and the attestation. A server that was switched before this fix keeps the stale model until **Save defaults** is pressed once with Mock selected. The form also refuses a default level the default provider refuses (AgentRouter at L2 shows "needs L3 or stricter" and keeps **Save defaults** off).
- A Viewer or Developer who opens a finding, the Demo page or a ledger record sees "needs the Auditor role, because it shows original code or payload text" without a request being refused, so the **Admin**, Audit log no longer fills with "denied" lines for them. A denied line there now means someone asked for something on purpose (through the API, for example). Admin and Auditor views of a payload are logged as `privacy.read_original`, as before.
- A **Reports** link to a scan that is gone or not finished (`/reports?scan=...`, for example a bookmark from a deleted volume) reads "No report for SCN-..." with **Use the latest scan**; before 15 Nov it hid the report builder without a word. The Overview's OWASP card no longer flashes "Top 10:2025" while loading; the seeded findings carry the 2021 edition, so it reads "OWASP Top 10:2021 coverage". Findings, Egress Ledger, Privacy Centre and Privacy Inspect likewise show a placeholder while the scan list loads; before 15 Nov they could say "No findings yet" or "No scans yet" for a moment on a seeded server.
- A finding can be found by the id the dashboard shows: type `F-2HJTV2` (all six characters) in the search box (Ctrl+K) or the Findings filter. Before 15 Nov only the six characters without `F-` matched. Search covers the latest scan of the selected project; type a project name to open another.

## Real-model timings

Measured on 13 Nov 2026 from the dashboard in Chromium (WSL laptop, `codekavach serve`, KavachBank sample, 29 files, 59 findings, L3, `agentrouter` / `gpt-5.6-sol`). The gateway answers one request at a time per key and reasons at length, so the time is almost all model time, and it varies: the same request took 17 s in one run and over 5 minutes in another.

| Step | Live demo · 3 candidates | Quick · 8 candidates | Every candidate (14 payloads) |
|------|------|------|------|
| **Test provider** in the scan form | 14.2 s | 11.5 s | 11.5 s |
| Deterministic stages (ingest to privacy layer) | 2 s | 3 s | 10 s |
| First verdict in the live log, after **Start scan** | 81 s | 35 s | 38 s |
| Verdicts, seconds after **Start scan** | 81, 98, 121 | 35, 54, 89, 122, 211, 228, 357, 407 | 38, 59, 85, 111, 163, 227, 562, 591, 638, 743, 769, 822, 836, 893 |
| Model stage | 1 min 58 s | 6 min 44 s | 14 min 43 s |
| Whole scan | **2 min 4 s** | 6 min 49 s | 14 min 58 s |
| Reviewed by the model | CWE-78, CWE-502, CWE-89 (all critical, all confirmed) | the three above, then CWE-639, CWE-862, CWE-327, CWE-22 twice | every candidate with a code slice; the rest (secrets, dependencies, configuration) keep their deterministic evidence |
| Payloads sent / blocked | 3 / 0 | 8 / 0 | 14 / 0 |
| Ledger **Verify again** | chain intact, 6 records | chain intact, 16 records | chain intact, 30 records |
| Zero-leak check | passed, 0 of 31 listed terms | passed, 0 of 31 | passed, 0 of 31 |

| Finding page (high, SSRF in `payments.js`, from the 8-candidate scan) | Time |
|------|------|
| **Review with model**, first time (the gateway failed once and the request was retried; the ledger shows "No response" then "Sent") | 81.5 s |
| **Review again** on the same finding (answered from the scan's cache, no egress, no ledger entry) | 1.7 s |

What this means on the day:

- **Re-measured 14 Nov from Edge**, same set-up: Test provider 15.9 s; verdicts at 39, 62 and 95 s after **Start scan** (CWE-78, CWE-502, CWE-89, all "vulnerable", medium confidence); whole scan 2 min 4 s; 3 payloads, 0 blocked, chain intact (6 records), zero-leak passed (0 of 31), 5,857 prompt tokens and 654 B, matching the ledger entry by entry. **Review with model** on two more findings took 106 s (SSRF in `payments.js`: Needs review, 0.60) and 112 s (path traversal in `exporter.js`: Confirmed, 0.85); about 30 s of each is the local pipeline run before the request is sent, and a large scan was running at the same time.
- **Live: "Live demo · the 3 most severe candidates".** It finished in about two minutes; even with the slowest gateway answers seen today it stays under four. Eight candidates took almost seven minutes and are not safe to wait for on stage. Start it, explain the pipeline and the egress meter while it runs, and read the three verdicts out as they land.
- **Pre-run: "Every candidate"**, made before the call (below). Use it for the findings walk-through, the Privacy Centre, the ledger and the report: it has a model verdict on all 14 candidates that can be sent, not only the top three.
- A new scan of the same code is **not** answered from the cache: every server scan gets a fresh pseudonym salt (less linkability between scans), so its payloads differ and the model is asked again. Only a repeated **Review with model** on the same finding is served from the cache.
- Candidates beyond the limit keep their deterministic evidence; open any of them and press **Review with model** (auditor or admin) to ask about that one finding live, in about a minute (longer when the gateway retries).
- The pill in the top bar reads "Offline · air-gapped" whenever the default provider is `mock`, also next to a finished real-model scan. Set **Settings**, Default provider, to `agentrouter` before the call so the pill and the scan form match what you show; the pill goes as soon as **Save defaults** is pressed (it used to linger for up to 30 seconds).

### Making the pre-run real-model scan

Do it the day before or at least 30 minutes before the call, on the machine and the data directory (or Docker volume) you will present from; it takes about 15 minutes and needs no attention.

1. Server up with the key in its environment (`.env` for Docker; `CODEKAVACH_AGENTROUTER_API_KEY` or `CODEKAVACH_AGENTROUTER_API_KEY_FILE` for `codekavach serve`) and the dashboard seeded.
2. **Providers**, **Run health checks**: `agentrouter` is **Healthy**.
3. KavachBank (sample), **New scan**: L3, provider `agentrouter`, model `gpt-5.6-sol`, Model review **Every candidate**, No-send off, **Start scan**.
4. When it says **Completed**, open the ledger and press **Verify again** (chain intact, zero-leak passed), and download its PDF report once so the first render is not on stage.
5. Note the scan id (for example `SCN-BD2984`) and the time it ran; you will say both when you open it. Do not restart the server with another vault passphrase or data directory, or the scan's vault becomes unreadable.

## Fallback ladder

Go down one rung at a time, and say what you did ("the network is slow, so I will replay a recorded model run"). Do not hide a rung from the audience.

1. **Real model** (`agentrouter`, model `gpt-5.6-sol`). Needs network and the key in the environment.
2. **A real-model scan run before the session** (see [Making the pre-run real-model scan](#making-the-pre-run-real-model-scan)). Open it from **Scans** (provider `agentrouter`): its verdicts, ledger and report are real; say when it was run. The `replay` provider is not offered in the dashboard (every dashboard scan gets a fresh pseudonym salt, so recorded answers would not match); it backs the offline CLI demo only (see [`DEMO1.md`](DEMO1.md)).
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

**Can someone with access to the server rewrite the ledger?** Yes, and say so. The hash chain is tamper-evident, not tamper-proof: an edited, inserted, removed or reordered entry is detected, but the hashes are not keyed and nothing outside the scan's directory anchors the chain, so someone who can write to that directory can cut entries off the end or recompute every hash, and verification still passes. The check is the head hash printed in the report and the verification file: keep it somewhere the server's operator cannot change. External anchoring is future work. Step 8 of the terminal demo prints "the log cannot be edited unnoticed"; read that as "an edit to a recorded entry is detected".

**Can we run it without any cloud?** Yes. L0 with a local model (Ollama) or the deterministic engines only, in the air-gapped compose profile.

**What does it cost to run?** The software is free to run. Model cost depends on the provider and level; L3 sends slices, not files, so it is the cheapest of the code-sending levels. Do not quote a figure you have not measured.

**What data does the dashboard store?** Scan results, findings, ledger entries and reports in its own database and volume, on your machine. Nothing is sent to us.

**What is not finished?** Say it: check `docs/status/` and the changelog on the day. Anything marked unfinished there is not to be demonstrated as working.

## After the session

Stop the stack (`docker compose down`), delete `demo-out/` if the machine is shared (the inspection page holds the fixture's code), and hand over using [`handover.md`](handover.md).
