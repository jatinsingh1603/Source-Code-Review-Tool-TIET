# Web dashboard

The dashboard is the browser front end of `codekavach serve`. It is a static single-page application built from `ui/` into `ui/dist`, which the server serves at `/` with a fallback to `index.html` for client-side routes. Everything it shows comes from the REST API under `/api/v1`; it has no data of its own. Developer notes are in [`ui/README.md`](../../ui/README.md).

## Running it

```bash
(cd ui && npm ci && npm run build)
uv run codekavach serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080` and sign in as `admin` with the password printed at start-up (`CODEKAVACH_ADMIN_PASSWORD`, default `kavach-admin`). A project called "KavachBank (sample)" exists on first start. To use the real model, set `CODEKAVACH_AGENTROUTER_API_KEY` (or configure a key file reference) before starting the server and choose the AgentRouter provider in the new scan wizard; the Mock and Replay providers work offline.

For a demonstration without a server, `npm run dev:mock` (or any page opened with `?mock`) runs the dashboard on built-in sample data and says so in a banner.

## Roles and navigation

Navigation is filtered by role for presentation; the server enforces every permission.

| Role | Sees |
|---|---|
| admin | Everything, including Users and editing settings and policy |
| auditor | Everything a developer sees, plus original code next to each payload in the Privacy Centre |
| developer | Projects, scans, findings and triage, the Privacy Centre ledger without original code, reports, GitHub sync |
| viewer | Overview, projects, scans, findings (read only) and reports |

A user who opens a page their role does not allow sees an "Access denied" page naming the role required.

## A demonstration walk-through

1. **Overview.** Open findings by severity, the trend over completed scans, recent scans, and the privacy posture of the latest scan of the selected project (project switcher in the top bar).
2. **New scan.** From a project, choose the privacy level. The egress preview states in plain language what leaves the machine at that level, what is removed and what remains visible to the provider. Pick the provider and model, test the connection (the probe itself is recorded in the ledger), and decide whether payloads are sent or only prepared.
3. **Live scan.** The stage stepper, progress bar and log follow the server's event stream. Events carry stage names, counts and codes only, never source code. If the stream drops, the page reconnects with `Last-Event-ID` and, after three failures, polls the scan summary every five seconds.
4. **Findings.** Filter by severity, status, CWE and free text; the filters live in the URL so a view can be shared. Select findings to change their status in bulk. A finding the model judged not exploitable stays in the list, down-ranked and annotated; no interface path deletes a finding.
5. **Finding detail.** Code evidence with the affected lines highlighted (secrets masked by the server), the source-to-sink data flow, the model verdict with its reasoning, CVSS v4.0 and v3.1 vectors and scores, OWASP, CWE, ASVS, CAPEC and compliance mappings, remediation and references, and triage with a comment and history.
6. **Privacy Centre.** The attestation for the scan, placeholder counts by type, the egress ledger with each entry's hashes and outcome, a re-verification of the hash chain, and for any entry the original code (which stays local) next to the exact payload the provider received, with secrets, personal data, identifiers and literals marked. The pseudonym mapping is never shown or exported.
7. **Reports.** Download HTML, PDF, Word, Excel, SARIF, JSON, CSV or Markdown, and preview the HTML report inline. GitHub issue sync is available from Findings and Reports, with a dry run first.

## Triage vocabulary

| Status | Meaning |
|---|---|
| Open | Reported, not yet reviewed |
| Confirmed | A reviewer agrees it is a real issue |
| False positive | Not a real issue; a reason is required |
| Accepted risk | Real, but accepted; a reason is required |
| Fixed | Remediated |

## Rendering rules

Finding titles, descriptions, remediation and model reasoning are influenced by the scanned code and written by a model, so the dashboard renders them as text only: no `dangerouslySetInnerHTML`, no Markdown rendering, no automatic links in model text and no remote images or fonts. Reports are previewed in a sandboxed iframe without scripts.
