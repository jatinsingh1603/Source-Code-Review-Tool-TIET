# Walkthrough: a review from scan to signed-off report

The workflow a reviewer follows in the dashboard, end to end: check the provider, scan a project, read and triage the findings, check what left the machine, and produce the report. It uses the bundled sample project KavachBank so that every step can be repeated on a fresh installation; the steps are the same for your own project.

Before you start: CodeKavach is installed and you can sign in ([Quickstart](quickstart.md)). The same workflow in a terminal is the [command-line tour](cli-tour.md).

## 1. Choose the project

Sign in and pick the project in the first pill of the top bar. The Overview then shows that project: open findings by severity, the privacy score, bytes sent, the zero-leak check, the trend across scans, the risk matrix, the OWASP coverage and the privacy guard status.

**KavachBank (sample)** is a small banking application with planted vulnerabilities and planted, synthetic secrets (`fixtures/kavachbank`). Its answer key is `fixtures/kavachbank/ground-truth/manifest.yaml`. To review your own code, add it under **Projects**, **New project**: a path on the server, a git URL and ref, or an uploaded zip or tar archive.

## 2. Check the provider before you need it

Open **Providers** and press **Run health checks**. Each configured provider is asked a constant question that contains no code; its card shows **Healthy** with the latency, or the error. A provider whose key is not in the server's environment shows **Key missing** and is not called.

Without a key, use the `mock` provider. It answers on the machine and opens no connection, so the whole workflow can be followed offline; the ledger then records what would have been sent, and the scan summary and the report say that no language model reviewed the code.

## 3. Start a scan

1. With the project selected, **Overview**, **New scan**.
2. **Privacy level**: L3 is the default (a minimal slice around each candidate, secrets as typed placeholders, identifiers pseudonymised). The form states in plain language what leaves the machine at the chosen level. A provider with a public trust tier refuses L1 and L2 ("needs L3 or stricter").
3. **Provider and model**: the default provider, or another configured one. **Test provider** runs the same probe as the health check.
4. **Model review**: how many candidates the model reviews. A limit sends only the most severe candidates and is the quick way to a first result; **Every candidate** reviews all that can be sent. Candidates beyond the limit keep their deterministic evidence and can be sent one at a time later (step 5).
5. **No-send (dry run)**: when on, the scan prepares every payload and records it in the ledger, and sends nothing. Use it for the first scan of a project you have not scanned before, and read the payloads before you send any.
6. **Start scan**.

The live view shows the pipeline stage by stage with counts, the egress meter (payloads, bytes, secrets replaced, listed terms) and a log in plain words. The deterministic stages take seconds. The model stage takes as long as the provider needs; verdicts appear in the log one by one. Do not restart the server while a scan runs: the scan ends as **Failed** and has to be started again with **Run again**.

What the log tells you besides progress:

- Which external engines ran. Opengrep, Bandit and ESLint are optional; the log says when none is installed, and the number of findings depends on which are present.
- How many candidates were not sent and why: held back by the review limit, kept local by a `never-send` rule, or without a code slice to send (secrets, dependencies and configuration findings are never sent as payloads).
- At L0: "no model review: nothing is sent to a model (local engines only)".

## 4. Read and triage the findings

Press **Open findings** and pick the **Critical and high** view. Filters (severity, status, CWE, OWASP, free text) and the sort order are part of the address, so a view can be bookmarked or shared, and **Back** from a finding returns to the same page. A finding can be found by the id the dashboard shows: type `F-` and its six characters into the search box (Ctrl+K).

Open a finding. From top to bottom:

- **What the LLM saw** and **Real code**: the pseudonymised payload, and the real file and line, which stay on the machine. The real names were restored locally from the vault. **Inspect side by side** opens Privacy Inspect for this finding.
- The taint path: source, intermediate steps, sink.
- The model's verdict, when the finding was reviewed: vulnerable or not, confidence, reasoning, impact and remediation, with the provider and model that produced it. A finding the model did not review shows the weakness's impact statement instead.
- The classification: CWE, OWASP Top 10, ASVS, CAPEC, CVSS 4.0 and 3.1 vectors with scores, likelihood and impact, and the compliance clauses.
- **Details**: set the status (open, confirmed, false positive, accepted risk, fixed), assign the finding and add a comment. The **Activity** timeline keeps every change with who and when.

How much to trust a verdict: the deterministic evidence (the code, the path, the engine) is the evidence; the model's text is advice. A "vulnerable" verdict with low or medium confidence is shown as **Needs review**. See the [auditor guide](auditor-guide.md#how-much-to-trust-a-finding).

## 5. Ask the model about one more finding

On a finding the scan did not send (it was beyond the review limit), an auditor or administrator can press **Review with model**. One more payload is prepared, checked by the egress guard, recorded in that scan's ledger and sent. The Privacy Centre lists such later reviews separately from the scan's own attestation, so the ledger and the attestation agree.

When nothing can be sent, the button says so and why: the finding's file is in a `never-send` path, or the scan ran at L4, which this release does not deliver. No ledger entry is written in either case.

## 6. Check what left the machine

Three pages under **Privacy**:

- **Privacy Centre**: the privacy score and its parts, exposure budgets, the invariant suite, policy decisions with the explanation for one file, and the attestation (download as PDF or JSON).
- **Privacy Inspect**: the original on the left, the exact payload on the right, with secrets, renamed identifiers and generalised literals marked. This page shows original code, so it needs the auditor or administrator role.
- **Egress Ledger**: the hash-chained list of every payload, sent or blocked. Select a record to read it. **Verify again** recomputes the chain and the payload hashes and repeats the zero-leak check.

What to look for:

1. The ledger chain is intact and the number of records matches the scan (two records per sent payload: the request and its outcome).
2. The **zero-leak check** passed: it reports how many listed terms were searched in every payload and how many occurrences were found. The expected number is 0.
3. Blocked payloads: each one is a candidate the model did not see. Read why it was blocked.
4. Note the ledger head hash. It is printed in the report; keep a copy outside the server.

What these checks do not show: the zero-leak check is a verbatim search, and the shape of the code (control flow, literal skeletons, public API names) still leaves at L2 and L3. The chain is tamper-evident, not tamper-proof. Both limits are explained in the [auditor guide](auditor-guide.md#what-the-attestation-does-not-say) and the [questions and answers](faq.md#evidence-and-storage).

## 7. Produce the report

Open **Reports**, pick the formats in the builder (PDF, DOCX, SARIF and JSON are on by default) and press **Generate report**. Each format is saved as its own download; the browser may ask once to allow several downloads from this site.

| Format | Use |
|--------|-----|
| PDF | The deliverable: executive summary, scope and methodology, risk matrix, findings with evidence and remediation, compliance mapping, privacy attestation |
| DOCX | The same sections, for editing before delivery. Word fills in the page numbers of the contents when its fields are updated (select all, then F9) |
| HTML | Self-contained, searchable, loads nothing from the network |
| SARIF | GitHub code scanning and other SARIF viewers |
| JSON, CSV, XLSX | Your own tooling and trackers. The XLSX leaves the Owner column blank for your tracker and counts due dates from the report's generation time |
| Markdown | A summary for a ticket or pull request |

The first PDF of a scan can take up to a minute to render; later downloads are immediate. Reports state times in UTC, whatever time zone the reader chose in the dashboard. Every export names the scan id the dashboard shows (`SCN-...`). Reports contain code from the scanned project: keep them with the classification of that code.

To compare two scans, choose an earlier scan under **Baseline for delta** on the Reports page and press **Download delta report**: one HTML file with the new, still-present and fixed findings, matched by fingerprint.

Then sign off with the checklist in the [auditor guide](auditor-guide.md#6-sign-off-checklist).

## 8. Scan again after fixes

Start another scan of the same project when the code has changed. Unchanged findings keep their triage decisions (confirmed, false positive, accepted risk), and their Activity names the scan the decision was carried from. A finding that the new scan no longer reports is listed as fixed in the delta report; mark it **fixed** on the earlier scan to record the decision. A finding that was marked fixed and is reported again opens again. The Overview trend shows every scan of the project, and mean time to remediate is measured from the time a finding was first reported to the time it was marked fixed.

From a terminal or a pipeline, `codekavach scan . --diff-since <ref>` scans only the files changed since a branch, tag, commit or earlier scan. The dashboard does not offer diff scans in this release.

## How long a model review takes

The deterministic stages take seconds on the sample. The model stage is almost entirely the provider's response time. The figures below were measured on 13 November 2026 from the dashboard on a laptop (`codekavach serve`, KavachBank, 29 files, 59 findings, L3) with the `agentrouter` provider and the model `gpt-5.6-sol`, a gateway that answers one request at a time per key. They are one day's measurements, not a service level: the same request took 17 seconds in one run and over 5 minutes in another.

| Step | 3 most severe candidates | 8 most severe candidates | Every candidate (14 payloads) |
|------|------|------|------|
| **Test provider** in the scan form | 14.2 s | 11.5 s | 11.5 s |
| Deterministic stages (ingest to privacy layer) | 2 s | 3 s | 10 s |
| First verdict in the live log, after **Start scan** | 81 s | 35 s | 38 s |
| Model stage | 1 min 58 s | 6 min 44 s | 14 min 43 s |
| Whole scan | 2 min 4 s | 6 min 49 s | 14 min 58 s |
| Payloads sent / blocked | 3 / 0 | 8 / 0 | 14 / 0 |
| Ledger **Verify again** | chain intact, 6 records | chain intact, 16 records | chain intact, 30 records |
| Zero-leak check | passed, 0 of 31 listed terms | passed, 0 of 31 | passed, 0 of 31 |

**Review with model** on a single finding took 81.5 seconds the first time (the gateway failed once and the request was retried; the ledger shows "No response" and then "Sent") and 1.7 seconds when repeated, because the repeat is answered from the scan's cache.

With the `mock` provider the same scan completes in well under a minute. On a larger code base (694 files, 123,162 lines, mostly Python, added as a local-path project) a scan at L3 with `mock` took 1 minute 51 seconds; the first PDF, Word, SARIF and JSON of that scan took 71 seconds, almost all of it the PDF.
