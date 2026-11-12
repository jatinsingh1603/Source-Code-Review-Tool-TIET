# Screen specifications

One section per screen of the approved design ([`codekavach-dashboard.html`](codekavach-dashboard.html); open it and pick a screen in the bottom-right "Screen" menu). Each section gives the route, the layout from top to bottom, the exact copy, the interactions, the states, and the data each element needs, mapped to the REST API (`/api/v1`, bearer auth). Component markup is in [COMPONENTS.md](COMPONENTS.md); styles in [components.css](components.css) and [tokens.css](tokens.css).

Conventions:

- **API** names an endpoint of the current contract and the field used, for example `GET /scans/{id}/privacy → zero_leak.checked`. Field names follow `ui/src/api/types.ts`.
- **NEW** marks data the contract does not provide yet. Each one is collected in [API gaps](#api-gaps) at the end. Until it exists, render the element from mock data or hide it, but keep its place in the layout.
- Copy in quotes is exact. Numbers, names, hashes and dates are demo data: render them from the API. Names, emails and hosts in the design are fictional; the AWS key is AWS's documented example key.
- Dates: `12 Nov 2026, 10:42 IST` long form; `12 Nov, 10:42` in tables; times `10:43:41`. Numbers use thousands separators (`2,486`). Byte sizes `412.6 KB`, `2,914 B`. British English.

## Contents

- [Shared: app shell, routes, icons, logo, states](#shared)
- [00 Design system board](#00-design-system-board)
- [01 Sitemap and demo flow](#01-sitemap-and-demo-flow)
- [02 How it works](#02-how-it-works)
- [03 Demo mode](#03-demo-mode)
- [04 Login (landing hero)](#04-login-landing-hero)
- [05 Set up a project (onboarding)](#05-set-up-a-project-onboarding)
- [06 Overview](#06-overview)
- [07 Scan launch and live progress](#07-scan-launch-and-live-progress)
- [08 Findings](#08-findings)
- [09 Finding detail](#09-finding-detail)
- [10 Privacy Inspect](#10-privacy-inspect)
- [11 Privacy Centre](#11-privacy-centre)
- [12 Egress Ledger](#12-egress-ledger)
- [13 Privacy policy](#13-privacy-policy)
- [14 Providers](#14-providers)
- [15 Reports](#15-reports)
- [16 Integrations](#16-integrations)
- [17 Evaluation](#17-evaluation)
- [18 Admin](#18-admin)
- [19 Settings](#19-settings)
- [API gaps](#api-gaps)

---

## Shared

### Routes

| Screen | Route | Notes |
|---|---|---|
| Login | `/login` | outside the shell |
| Overview | `/` | |
| Projects list | `/projects` | not drawn; reuse the Overview "Recent scans" table pattern |
| Set up a project | `/projects/new` | wizard, `?step=1..5` |
| Project detail | `/projects/:id` | not drawn |
| Scan launch | `/projects/:id/scan` | the left form of the live view, unlocked |
| Scans list | `/scans` | not drawn; Overview "Recent scans" table, full width |
| Scan live view | `/scans/:id` | |
| Findings | `/findings` | `?scan=&view=&severity=&cwe=&status=&q=` |
| Finding detail | `/findings/:id` | `?tab=saw|real|reason` |
| Privacy Centre | `/privacy` | current project's latest scan; `?scan=` |
| Privacy Inspect | `/privacy/inspect/:scanId/:seq` | `?level=1..4`; nav link opens the latest payload |
| Egress Ledger | `/privacy/ledger` | `?scan=&seq=` (selected record) |
| Privacy policy | `/privacy/policy` | |
| Reports | `/reports` | `?scan=` |
| Integrations | `/integrations` | |
| Providers | `/providers` | |
| Evaluation | `/evaluation` | |
| Admin | `/admin` | tabs as `/admin/users` (default), `/admin/orgs`, `/admin/tokens`, `/admin/keys`, `/admin/audit`, `/admin/retention`, `/admin/health` |
| Settings | `/settings` | sections as anchors `#profile`, `#appearance`, `#notifications`, `#tokens`, `#language` |
| Demo mode | `/demo` | |
| How it works | `/how-it-works` | |
| Design system board | `/design` | development builds only |

Role access (from the sitemap): **Admin** everything. **Auditor** findings, privacy, ledger, reports (read and triage). **Developer** findings assigned to them, integrations, settings. **Viewer** read-only dashboards and reports. Hide nav items a role cannot open.

### App shell

Every screen except Login, the design system board and the sitemap uses the shell in [COMPONENTS.md §1](COMPONENTS.md#1-app-shell): side nav (Overview, Projects, Scans, Findings; "Privacy": Privacy Centre, Privacy Inspect (sub-item), Egress Ledger, Policy; "Deliver": Reports, Integrations, Providers; "Organisation": Evaluation, Admin, Settings), footer (Demo mode, How it works, version · organisation), top bar (project pill, level pill, network pill, provider pill, search with ⌘K, notifications, user).

Shell data:

| Element | Source |
|---|---|
| Project pill and switcher | `GET /projects → name`; current project in app state |
| Level pill | latest scan `privacy_level` or `GET /settings → default_privacy_level`; label from the level table in COMPONENTS.md §7 |
| Network pill "Offline · air-gapped" | **NEW** network posture (suggest `GET /health → network: "offline" | "online"`) |
| Provider pill | `GET /settings → default_provider`, name from `GET /providers` |
| Search / ⌘K palette | findings by title, file, id: `GET /scans/{id}/findings?q=`; scans by id: `GET /scans`; actions are static |
| Notifications bell, unread count | **NEW** `GET /notifications` (event, read flag); events listed in Settings → Notifications |
| User name, role, initials | `GET /auth/me → display_name, role` |
| Footer version · organisation | `GET /version → version`, `GET /settings → org_name` |

Active nav item per screen: Overview → Overview; Onboarding → Projects; Scan live → Scans; Findings and Finding detail → Findings; Privacy Inspect → Privacy Inspect (sub-item); others → their own item. Demo mode and How it works highlight their footer button instead.

### Icons

Inline SVG, no icon font or library. Every icon is `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">…</svg>`: 16 px, `fill:none`, `stroke:currentColor`, stroke width 1.6, round caps and joins (`.ico.lg` is 20 px). Icons take the text colour of their parent. Names below are ours; the shapes are the design's.

| Name | Used for | Inner markup |
|---|---|---|
| `grid` | Overview | `<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/>` |
| `folder` | Projects, project pill | `<path d="M3 7h6l2 2h10v10H3z"/>` |
| `gauge` | Scans | `<circle cx="12" cy="12" r="9"/><path d="M12 12l6-6"/>` |
| `flag` | Findings | `<path d="M5 21V4h11l-2 4 2 4H5"/>` |
| `shield` | Privacy Centre, level pill | `<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>` |
| `lines` | Egress Ledger, ledger chip | `<path d="M4 6h16M4 12h16M4 18h10"/>` |
| `sliders` | Policy | `<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>` |
| `doc` | Reports | `<path d="M6 3h9l4 4v14H6zM14 3v5h5"/>` |
| `plug` | Integrations | `<path d="M9 3v5M15 3v5M7 8h10v4a5 5 0 0 1-10 0zM12 17v4"/>` |
| `chip` | Providers, provider pill | `<path d="M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>` |
| `bars` | Evaluation | `<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>` |
| `users` | Admin | `<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 3-5 6-5s6 2 6 5M16 5a3 3 0 0 1 0 6M21 20c0-2-1.5-4-4-4.6"/>` |
| `cog` | Settings | `<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>` |
| `play` | Demo mode, run demo | `<path d="M8 5v14l11-7z"/>` |
| `search` | search, palette | `<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>` |
| `bell` | notifications | `<path d="M6 16v-5a6 6 0 0 1 12 0v5l2 2H4zM10 21h4"/>` |
| `chevron-down` | pill and filter dropdowns | `<path d="M6 9l6 6 6-6"/>` |
| `arrow-right` | "more" links, taint edges, pagination | `<path d="M5 12h14M13 6l6 6-6 6"/>` |
| `arrow-up-right` | external links | `<path d="M7 17L17 7M9 7h8v8"/>` |
| `arrow-up` | KPI delta up | `<path d="M12 19V5M6 11l6-6 6 6"/>` (12×12) |
| `arrow-down` | KPI delta down, "Load more" | `<path d="M12 5v14M6 13l6 6 6-6"/>` (12×12 in KPIs) |
| `flow-right` | How it works, local row | `<path d="M4 12h15M14 7l5 5-5 5"/>` |
| `flow-left` | How it works, return row | `<path d="M20 12H5M10 7l-5 5 5 5"/>` |
| `copy` | copy hash (13 px) | `<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>` |
| `lock` | vault, "what stays local" | `<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>` |
| `lock-wide` | SSO button | `<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>` |
| `info` | info banner | `<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>` |
| `close` | close record panel | `<path d="M6 6l12 12M18 6L6 18"/>` |

### Logo

Four lines of code: three ink bars stay on the machine, one short blue segment is the minimal slice that leaves (the privacy model at L3). Minimum size 16 px; clear space one line height. Sizes used: 26 px in the side nav (`.logo`), 32 px on Login, 72 px on the design board.

```html
<svg class="logo" viewBox="0 0 28 28" aria-hidden="true">
  <rect x="3"  y="5"  width="22" height="3" rx="1" style="fill:var(--text)"/>
  <rect x="7"  y="11" width="10" height="3" rx="1" style="fill:var(--text)"/>
  <rect x="19" y="11" width="6"  height="3" rx="1" style="fill:var(--accent)"/>
  <rect x="7"  y="17" width="15" height="3" rx="1" style="fill:var(--text)"/>
  <rect x="3"  y="23" width="13" height="3" rx="1" style="fill:var(--text)"/>
</svg>
```

On an ink background: the four ink bars become `#FFFFFF` and the blue segment `#6E95F5` (`--logo-accent-on-dark`). Word mark: "CodeKavach", IBM Plex Sans 600 15 px (side nav), 700 20 px (login), 600 40 px / -0.025em (board). Sub-line in the side nav: "कवच · secure code review" (`.brand-sub`, Noto Sans Devanagari 11 px). Board tag line: "कवच · armour for source code review".

### States

Every screen ships with loading (skeleton bars), empty and error states (sitemap note), drawn once on the design board ([COMPONENTS.md §22](COMPONENTS.md#22-states-skeleton-empty-error)). Use them per card or table, not as a full-page spinner:

- Loading: three `.skel` bars (60%, 100%, 80%) in each card; skeleton rows in tables.
- Empty: `.empty` with a bold title, one `sm` sentence and a `.more` action. Copy per screen is given below where the design implies one; otherwise "No {things} yet" + one sentence + the obvious action.
- Error: `.banner.bad.sm` with what failed and what happened as a result. Privacy failures say the request was aborted and nothing was sent (I4).

---

## 00 Design system board

Route `/design` (development only). No shell; `.ck` wrapper with `padding:56px 64px 72px`, column gap 40.

1. Header: overline "CodeKavach · design system v1.0"; 72 px logo + "CodeKavach" (40 px) + "कवच · armour for source code review"; right paragraph "The mark is four lines of code. Three stay dark: they never leave the machine. One short blue segment is the minimal slice that does. The logo is the product's privacy model at L3."; lock-ups on light and on ink; "Minimum size 16 px · clear space = one line height".
2. "Colour": seven swatches (Canvas #F6F7F9, Surface #FFFFFF, Subtle #F0F2F5, Line #D0D5DD, Muted #475467, Ink #101828, Blue #1D4ED8) and "One accent. Ink for primary actions, blue for links, selection and data. Colour is reserved for severity; everything else is greyscale."
3. Three cards: "Severity" ("A different marker shape per level, so it still reads in greyscale.", five `.sev`, four `.cvss` 9.3/8.2/6.3/2.7 v4.0); "Privacy levels" ("Neutral, never a severity colour. Bars show protection: more filled bars, less leaves.", L0, L4, L3, L2, L1 rows with captions); "Diff markers and verdicts" (redacted secret, renamed identifier, `// <comment generalised>`, four verdicts).
4. Two cards: "Typography · IBM Plex" (28/500 "43 open findings", 22/600 "Page title, 22 semibold", 14/600 "Section title, 14 semibold", body "Body 14 regular. British English throughout: organisation, pseudonymise, behaviour.", overline "Overline 11 · uppercase", mono 13 "Plex Mono 13 · cursor.execute(sql)  # CWE-89"); "Buttons and inputs" (Run scan, Export, Cancel, Purge vault, "View all findings →"; Repository input, Provider select; switch "No-send (dry run)", checkbox "Opengrep", segmented L3/L2/L4).
5. Three cards: "Privacy invariants" (CI run 12 Nov, 10:31; I1, I4, I6 rows; hash chip + CWE-89, A05:2025, CAPEC-66 tags); KPI "Bytes egressed, this scan" with sparkline and toast "Ledger chain verified"; "States" (skeleton, empty "No findings yet", error banner).
6. "Pipeline stepper" with "Underline: ink when done, blue when running. Remote stage labelled in orange text." (stage 04 running).
7. Two cards: "Taint path" + "Code viewer"; "Breadcrumb, tabs, table" + risk matrix row + heatmap ramp.
8. "Command palette · ⌘K".
9. Footer: "Principles: flat surfaces, 1 px lines, no shadows or gradients, one accent, arrows for navigation, words instead of tick marks."

Data: none (static reference).

## 01 Sitemap and demo flow

Not a product screen; it documents navigation. Demo story (offline, Mock provider): 1 Login → 2 Demo mode → 3 Live scan → 4 Findings → 5 Finding detail → 6 Privacy Inspect → 7 Egress Ledger → 8 Audit report. Information architecture under the app shell (sidebar, top bar, ⌘K): **Home** (Overview, Demo mode, How it works), **Scanning** (Projects · onboarding, Scan launch, Live progress), **Findings** (Findings list, Finding detail, Bulk triage), **Privacy** (Privacy Centre, Privacy Inspect, Egress Ledger, Policy editor), **Deliver** (Reports · builder, Integrations, Providers), **Organisation** (Evaluation, Admin, Settings, Login · tenant). Role access note as in [Routes](#routes).

## 02 How it works

Route `/how-it-works`. Shell; footer "How it works" active.

1. Header: crumb "CodeKavach / How it works"; h1 "How CodeKavach works"; muted paragraph (max 760 px) "Heavy analysis stays on your machine. Only a minimal, sanitised slice crosses the boundary, every outbound byte is written to the egress ledger, and verdicts are mapped back using a vault that never leaves."; primary button `play` "Run KavachBank demo" → `/demo`.
2. Card (padding 24) holding a three-column diagram (`grid-template-columns: minmax(0,1fr) 170px 230px`, horizontally scrollable):
   - Left, "Your machine · local" (`.sec-h`) / "code, vault and ledger never leave": `surface-2` panel, radius 14 0 0 14. Row 1 (`flow-right` arrows): `.stand` 01 "Ingest & parse" ("ASTs, symbols, call graph"), 02 "Deterministic analysis" ("SAST, secrets, SCA, IaC, taint"), 03 "Candidate findings" ("source-to-sink paths, hits"). Rule. Row 2 (`flow-left` arrows): 09 "Issue sync" ("GitHub issues, Kanban"), 08 "Audit report" ("PDF, DOCX, SARIF, JSON"), 07 "Risk rating" ("CWE, OWASP, CVSS 4.0"). Chips: `lock` "Vault · pseudonym map", `lines` "Egress ledger · hash-chained".
   - Middle, "Boundary": `--priv-bg` with `--priv` top and bottom borders. "04 · OUTBOUND" / "Privacy layer" / "redact → slice → pseudonymise → leak check → ledger"; "THE ARMOUR" (priv colour, 600, 0.06em); "06 · INBOUND" / "De-pseudonymise" / "verdicts mapped back from the local vault".
   - Right, "Remote · or self-hosted" (overline in `--high`): dashed border panel. `.stand` 05 "LLM reasoning" ("Claude, OpenAI, Gemini, Grok, Bedrock, Azure, or Qwen, DeepSeek, Llama via Ollama / vLLM"); "Receives only the sanitised slice. Returns a verdict, rationale and exploit scenario in pseudonyms."; note "At **L0** this column is empty: a local model or deterministic engines only."
3. `.g-3`: card "What crosses the boundary" ("At the default L3: the minimal vulnerability-relevant slice, with secrets and PII redacted and identifiers, strings and comments pseudonymised. No whole files." + `.btn.sm` "Open Privacy Inspect"); card "How it is measured" ("Every payload is hashed, checked against the listed-term set and appended to a hash-chained ledger. The chain can be verified offline at any time." + "Open Egress Ledger"); `.note` "**What this does not cover.**" list: "Control flow, literal shapes and public API names stay visible at L2 and L3." / "The leak check is verbatim only; paraphrase or encoding is out of scope." / "CodeKavach measures disclosure. It does not claim zero disclosure."

Data: static. Provider list may be built from `GET /providers → name`.

## 03 Demo mode

Route `/demo`. Shell; footer "Demo mode" button highlighted (accent border and soft background).

1. Card (padding 32, items start, gap 16): overline "Demo mode · offline"; h1 28/650 "Run the KavachBank demo"; muted (max 620) "Runs the full 9-stage pipeline on the synthetic KavachBank sample: Python and JavaScript, planted vulnerabilities, fake secrets and an interest and fee engine. Fully offline with the Mock provider. No API key needed."; `.btn.pri.xl` with `play` (20 px) "Run KavachBank demo"; chips "Privacy level L3", "Mock provider", "486 files", "about 90 seconds".
2. `.banner.info` with `info` icon: "**Mock provider:** the ledger shows what *would* have been sent. Nothing left this laptop."
3. Row: h2 16/600 "Last demo run · 12 Nov 2026, 10:42 IST"; right `.st` green dot "Completed in 1 min 27 s".
4. `.g-4` of four link cards (overline + `arrow-right` faint at the right):
   - "Findings" → `/findings`: 30/650 "43"; severity row c 3, h 9, m 14, l 11, i 6; sub "SQL injection, command injection, SSRF and 2 planted secrets confirmed."
   - "Inspect" → Privacy Inspect: "11 <small>of 34 lines</small>"; `.bar.priv` 32%; "See exactly what the model saw for KB-2026-0012, side by side with the real code."
   - "Ledger verified" → Egress Ledger: "142 <small>records</small>" (weight 500); chips fixed "chain ok", "hashes ok", "0 terms"; "0 listed terms found verbatim across 412.6 KB of payloads."
   - "Report" → Reports: "KB-AR-014"; tags PDF, SARIF, DOCX; "Audit report with executive summary, risk matrix and privacy attestation."

Interactions: "Run KavachBank demo" creates (or reuses) the sample project and starts a scan, then navigates to `/scans/{id}`.

Data:

| Element | Source |
|---|---|
| Run demo | `POST /projects {name:"kavachbank-core", source:{type:"sample"}}` (or find it in `GET /projects`), then `POST /projects/{id}/scans {privacy_level:"L3", provider:"mock", send:false}` |
| Chips (files, duration estimate) | `Project.files`; "about 90 seconds" static or **NEW** estimate |
| Last demo run header | latest scan of the sample project: `GET /scans?project_id=` → `started_at`, `finished_at`, `status` |
| Findings card | `Scan.counts` (total and per severity); headline sentence: static or **NEW** summary |
| Inspect card | `GET /scans/{id}/ledger/{seq}` for the headline finding: lines sent vs original. **NEW** `lines_sent`, `lines_total` on the ledger entry (or count from `payload_text`/`original_text`) |
| Ledger card | `GET /scans/{id}/privacy → payloads, chain_ok, zero_leak`; bytes: **NEW** `bytes_sent` (contract has `tokens_sent` only) |
| Report card | `GET /scans/{id}/reports → format` list; report id **NEW** (see Reports) |

Empty: before any demo run, hide rows 3 and 4. Loading: skeleton in the four cards while a run is in progress, with a link to the live view.

## 04 Login (landing hero)

Route `/login`. No shell. `.ck` flex, wraps, min-height 900 (use `100vh`).

Left panel (flex 1 1 520, padding 56, white, right border, space-between):

1. Logo 32 px + "CodeKavach" 20/700 + "कवच" (Devanagari, muted).
2. Hero (max 560, gap 20): h1 36/650/-0.025em "Get an LLM security review. Keep secrets and personal data local."; muted 16 px "Minimise and measure the business logic you disclose. Every byte that leaves is hashed, checked and written to a tamper-evident ledger."; three `.guard` rows: L3 "Minimal slice by default. No whole files." / I4 "Any privacy-step failure aborts the request." / I6 "Ledger payloads checked for listed terms of 4+ characters." (no Pass label).
3. Foot, xs faint: "OWASP Code Review Guide · ASVS · CWE · CVSS 4.0 · SARIF 2.1.0 · NIST SSDF".

Right panel (flex 1 1 440, centred, padding 48/24): card form (max 420, padding 28, gap 16):

1. h2 20/650 "Sign in"; sub "Choose your organisation to continue."
2. Select "Organisation": "Demo Organisation · demo.codekavach.local", "KavachBank Security".
3. Primary full-width button `lock-wide` "Continue with SSO (SAML / OIDC)".
4. Divider "or local account".
5. "Email" input, "Password" input.
6. Row: checkbox "Remember this device"; link `sm acc` "Forgot password?".
7. Outline full-width "Sign in".
8. Rule; ghost full-width `play` "Try the offline demo, no account needed" → `/demo`.
9. xs faint centred "Running air-gapped. No telemetry leaves this machine."

Interactions: Sign in → `POST /auth/login {username, password}` → store `token`, go to `/` (or the `next` route). Errors: `.banner.bad.sm` above the button, "Email or password is incorrect." SSO and organisation choice are **NEW** (no tenants or SSO in the contract): show the SSO button disabled with a title, or hide it, until the API supports it. Demo link works without a token only if the API allows an anonymous demo session (**NEW**); otherwise it signs in with the demo account.

## 05 Set up a project (onboarding)

Route `/projects/new` (`?step=`). Shell, nav "Projects" active. Content max-width 1180. Top-bar pill 1 reads "New project"; the level pill follows the level chosen in step 3.

Header: crumb "Projects / New project"; h1 "Set up a project"; right `.sub` "Step {n} of 5".

Stepper `.steps`: "1 Connect repository", "2 Detect inventory", "3 Privacy level", "4 Provider", "5 Consent and launch". Steps are clickable.

**Step 1, Connect a repository** (card, padding 24): h2 16 "Connect a repository" + sub "The code is read in place. Nothing is uploaded at this step."; `.g-4` of `.lvlcard`: "Local path" / "A folder on this machine" (selected), "Git URL" / "SSH or HTTPS, cloned locally", "Archive upload" / ".zip or .tar.gz", "GitHub" / "Via the GitHub App"; `.g-2` "Folder" (mono, `/srv/repos/kavachbank-core`) and "Project name"; "Branch" (mono, `main · 9f3c2e1`).

**Step 2, Detect inventory** (`.g-side`): card "Languages and inventory" + sub "486 files · 81,627 lines"; table Language / Files / Lines / Share (200 px `.bar`) / Support (`chip fixed` "Full" or `chip` "Emerging"): Python, JavaScript, Java, Go, "IaC · Terraform, YAML". Right card "Engines available": checkboxes "Opengrep · SAST", "Bandit · Python", "ESLint security · JavaScript", "Secrets scanner", "SCA · OSV database (offline mirror)", "IaC checks", "Taint engine".

**Step 3, Privacy level** (default step in the design): grid of five `.lvlcard` (min 180): L0 "Local only" / "Nothing leaves. Local model or deterministic engines."; L1 "Redacted" / "Code with secrets and PII redacted."; L2 "Pseudonymised" / "L1, plus identifiers, strings and comments renamed."; "L3 · default" "Minimal slice" / "L2, but only the vulnerability-relevant slice."; L4 "Facts only" / "No code. Abstract data-flow facts and questions." Below, `.g-2`: card with `--high` border, `arrow-right` in high colour, "What leaves at {L}"; card with `--ok` border, `lock` in ok colour, "What stays local". Texts per level (lines separated by line breaks):

| Level | What leaves | What stays local |
|---|---|---|
| L0 | Nothing. No network connection is opened. | All code, secrets, identifiers and comments. / Vault and ledger. |
| L1 | Source files with secrets and PII replaced by typed placeholders. / Real identifiers, strings and comments. | Secret values and PII. / Vault and ledger. |
| L2 | Source files with identifiers, strings and comments pseudonymised. / Control flow and literal shapes. | Secrets, PII, real names and business terms. / Vault mapping pseudonyms back. |
| L3 | Only the lines on the source-to-sink slice, pseudonymised. / Control flow and public API names in that slice. | Whole files, secrets, PII, real names and business terms. / Everything outside the slice. |
| L4 | Abstract data-flow facts and questions. No code. | All source code, names and literals. / Vault and ledger. |

Then `.note`: "**What this does not cover.** At L2 and L3, control flow, literal shapes and public API names are still visible to the model. The leak check is verbatim only." Levels below the organisation floor are disabled (from `GET /policy`).

**Step 4, Provider** (`.g-3` of `.lvlcard`, each with `.provlogo` and a chip): M "Mock" `chip fixed` "Default" / "Offline · no key. Deterministic verdicts for demos and CI."; R "Replay" "Offline" / "Replays recorded verdicts. No key."; L "Ollama / vLLM" "Self-hosted" / "Qwen, DeepSeek, GLM, Kimi, Llama on your hardware."; A "Anthropic Claude" "BYO key" / "Key reference: env:ANTHROPIC_API_KEY"; O "OpenAI · Azure OpenAI" "BYO key" / "Key reference: keyring:openai"; G "Gemini · Grok · Bedrock" "BYO key" / "Key reference: file:/etc/kavach/keys".

**Step 5, Review and consent** (`.g-side`): card h2 "Review and consent"; `.dl`: Repository (mono "kavachbank-core · main · 9f3c2e1"), Privacy level (`.lvl` "L3 · Minimal slice"), Provider "Mock (offline) · no key", Engines "Opengrep, Bandit, ESLint, Secrets, SCA, IaC, Taint", Policy "Bank strict · floor L2 · config/** never-send"; consent checkbox (top-aligned) "I understand that sanitised slices may be sent to the selected provider and that every payload is recorded in the egress ledger."; switch "No-send (dry run): build payloads, send nothing". Right `.note` "**Before you launch.**" list: "Secrets are redacted before anything is sliced." / "If any privacy step fails, the request is aborted (I4)." / "You can inspect every payload afterwards."

Footer row: ghost "Back"; right "Save and exit" (→ `/`) and primary "Continue" (steps 1 to 4) or "Launch scan" (step 5). Launch is disabled until consent is ticked (unless level is L0 or dry run).

Data:

| Element | Source |
|---|---|
| Source type, folder, Git URL, name, branch | `POST /projects {name, source:{type:"path"|"git"|"upload", path, url, ref}}`; archive: `POST /projects/{id}/upload`; GitHub App: **NEW** |
| Inventory table, totals | `Project.files`, `Project.languages`; per-language files, lines, support level **NEW** (`GET /projects/{id}` inventory) |
| Engines available | **NEW** engine list with install status (also used by Admin → System health); send selection as `ScanCreate.rules` or **NEW** `engines` |
| Level cards, floor | `GET /settings → default_privacy_level`, `GET /policy` (floor) |
| Provider cards | `GET /providers → name, kind, local, configured, default_model`; key reference text **NEW** (`key_ref`) |
| Policy line in review | `GET /policy` (name, floor, never-send rules) |
| Launch | `POST /projects/{id}/scans {privacy_level, provider, model, send: !dryRun}` → navigate to `/scans/{id}` |
| Save and exit | project is saved after step 1; draft wizard state **NEW** or client-only |

## 06 Overview

Route `/`. Shell, "Overview" active.

1. Header: crumb "kavachbank-core / Overview"; h1 "Overview"; right `.sub` "Last scan <mono>SCN-0142</mono> · 12 Nov 2026, 10:42 IST" + primary "New scan" (→ `/projects/:id/scan`).
2. KPI strip (card padding 0, six cells, min 190):
   - "Open findings" → `/findings`: "43"; detail severity markers c 3, h 9, m 14, l 17.
   - "Privacy score" → `/privacy`: "86 <small>/ 100</small>"; `.k-d.down` `arrow-up` "3 pts vs last scan".
   - "Bytes egressed, this scan" → ledger: "412.6 <small>KB</small>"; "142 payloads · 0.5% of repo".
   - "Zero-leak check" → ledger: "0 <small>terms found</small>"; "2,486 listed terms, verbatim".
   - "Last scan": "10:42"; "12 Nov · 1 min 27 s · main".
   - "Mean time to remediate": "4.2 <small>days</small>"; `.k-d.down` `arrow-down` "0.8 days in 30 days".
3. `.g-side`: card "Findings trend" / "Open findings by severity, last 12 weeks" + legend (Critical, High, Medium, "Low and info"), `.vbars` 12 weekly columns with aria-label "Open findings fell from 58 to 43 over 12 weeks", x labels "24 Aug, 31, 7 Sep, 14, 21, 28, 5 Oct, 12, 19, 26, 2 Nov, 9". Right card "Risk matrix" / "Likelihood × impact, open findings": `.rm` 5×5 with counts, axis captions "Likelihood ↑" / "Impact →".
4. `.g-side`: card "OWASP Top 10:2025 coverage" / "Findings per category and detection source" + `.more` "Open findings": heatmap rows A01 to A10 ("A01 Broken Access Control", "A02 Security Misconfiguration", "A03 Supply Chain Failures", "A04 Cryptographic Failures", "A05 Injection", "A06 Insecure Design", "A07 Authentication Failures", "A08 Integrity Failures", "A09 Logging and Alerting", "A10 Exceptional Conditions"), columns SAST, Secrets, SCA, IaC, Taint, LLM. Right stack: card "Top CWEs" (six labelled bars: CWE-89 SQL injection 7, CWE-79 Cross-site scripting 5, CWE-798 Hardcoded credentials 4, CWE-328 Weak hash 3, CWE-22 Path traversal 3, CWE-918 SSRF 2; width relative to the top value); card "Privacy guard status" + `.more` "Details" → `/privacy`: guards I1 "Single transport module", I2 "Sanitised payloads only", I3 "Vault never logged or exported", I4 "Fail closed on privacy error", I5 "Deterministic pseudonyms per salt", I6 "No listed term in ledger payloads", each "Pass".
5. "Recent scans" (14/600) + `.more` "All scans" → `/scans`. Table: Scan (mono link) / Target (mono sm, "main · 9f3c2e1", "diff · feature/fee-engine") / Level (`.lvl`) / Provider / Findings (num) / Payloads (num) / Status (`.st`: ok "Completed", bad "Aborted · I4 slicer error", acc "Running", grey "Queued", bad "Failed", grey "Cancelled") / Started.

Interactions: KPI cells and heatmap cells link to filtered findings (`/findings?owasp=A05&engine=taint`), matrix cells to `/findings?likelihood=&impact=`.

Data:

| Element | Source |
|---|---|
| Last scan line | `GET /stats → last_scan (id, started_at)` |
| Open findings + severity | `GET /stats → open_findings, findings_by_severity` |
| Privacy score + delta | `GET /scans/{last}/privacy → privacy_score`; delta needs the previous scan's privacy (second call) |
| Bytes egressed, payloads, % of repo | `GET /scans/{last}/privacy → payloads`; bytes **NEW** `bytes_sent`; repo size **NEW** `repo_bytes` |
| Zero-leak | `GET /scans/{last}/privacy → zero_leak.occurrences, zero_leak.checked` |
| Last scan time, duration, branch | `Scan.started_at, finished_at`, `Project.source.ref` |
| Mean time to remediate | **NEW** (`GET /stats → mttr_days, mttr_delta_days`) |
| Findings trend | `GET /stats → trend[] {date, critical, high, medium, low}` (info is missing from `TrendPoint`: **NEW** `info`, or plot low only) |
| Risk matrix | **NEW** counts by likelihood × impact (`Finding.likelihood`, `Finding.impact` exist per finding; aggregate client-side from `GET /scans/{id}/findings` if needed) |
| OWASP heatmap | aggregate `Finding.owasp` × `Finding.engine` client-side, or **NEW** `GET /stats → owasp_by_engine` |
| Top CWEs | aggregate `Finding.cwe`, `cwe_name` client-side, or **NEW** `GET /stats → top_cwes` |
| Privacy guard status (I1 to I6) | **NEW** invariant suite results (`GET /health → invariants[] {id, title, passed, run_at, tests}`) |
| Recent scans | `GET /scans?limit=5 → id, privacy_level, provider, model, counts, status, error, started_at`; target text from `Project.source.ref` and scan mode **NEW** (`mode: branch|diff`, `ref`); payload count **NEW** `Scan.payloads` |

Empty (no scans yet): replace sections 2 to 5 with `.empty` "No scans yet" / "Run a scan to see results here." / "Run a scan →", plus a link to Demo mode.

## 07 Scan launch and live progress

Route `/scans/:id` (live view). The same left form, editable, is the launch page `/projects/:id/scan`. Shell, "Scans" active.

1. Header: crumb "kavachbank-core / Scans / SCN-0143"; h1 "Scan SCN-0143" + `.st.sm` with `dot acc` "Running" (margin-left 8); right `.sub.mono` "00:58 elapsed · about 31 s left" + `.btn.danger` "Cancel scan".
2. `.g-side-l`:
   - Left form card "Launch settings" + xs faint "locked while running": "Target" select; "Mode" `.seg` Branch / Diff; "Branch" (mono); "Privacy level" ("L3 · Minimal slice (default)"); two-up "Provider" ("Mock") and "Model" ("mock-reasoner-1"); "Engines" checkboxes Opengrep, Bandit, ESLint security, "Secrets · SCA · IaC", Taint engine; rule; switch "No-send (dry run)". On the launch page the form ends with a primary "Start scan" button (not drawn; use `.btn.pri`).
   - Right stack:
     - Card "Pipeline" + sub "Stage 5 of 9 · 68%"; `.bar` 68%; pipeline stepper with counts: 01 "486 files", 02 "1,284 hits", 03 "187 cand.", 04 "142 slices", 05 running "94 / 142 sent", 06 running "91 verdicts", 07 "waiting", 08 "waiting", 09 "off".
     - Card "Egress meter" / "What has left so far, checked as it leaves" + `.more` "Open ledger": boxed KPI strip "Payloads" "94 <small>/ 142</small>", "Bytes out" "271.4 <small>KB</small>", "Secrets in payloads" "0" / "94 of 94 checked", "Domain terms in payloads" "0" / "2,486 listed terms"; then row "Exposure budget for this scan" / mono "271.4 / 600 KB" and an ink `.bar` 45%.
     - Card "Log" + xs faint "streaming" + `.btn.sm` "Download log": `.console` (format in COMPONENTS.md §21).

Interactions: subscribe to `GET /scans/{id}/events` (SSE) on mount. Cancel → confirm, then `POST /scans/{id}/cancel`. When `done` arrives: header status becomes "Completed" (ok dot) and the elapsed text becomes "Completed in 1 min 27 s"; show a toast and links to Findings and the ledger. Download log saves the console buffer.

Data:

| Element | Source |
|---|---|
| Header id, status, elapsed | `GET /scans/{id} → status, started_at`; remaining time **NEW** (`eta_seconds`) or omit |
| Launch settings | `Scan.privacy_level, provider, model, send`; target `Project.name`; mode/branch **NEW** (`mode`, `ref`); engines **NEW** |
| Pipeline stage states | SSE `stage {name, status}`; stage names map to the nine stages (`ingest`, `analyse`, `candidates`, `privacy`, `llm`, `depseudonymise`, `risk`, `report`, `sync`); per-stage counts **NEW** (add `count`, `total` to `stage` events) |
| Overall bar and "Stage n of 9 · p%" | SSE `progress {percent}`; initial `Scan.progress`, `Scan.stage` |
| Egress meter | live: **NEW** SSE `egress {payloads, total, bytes, secrets_checked, terms_found}`; after the scan: `GET /scans/{id}/privacy` |
| Exposure budget | **NEW** budget (`GET /policy` or `/settings`: `budget_scan_bytes`) |
| Log lines | SSE `log {level, message}` (+ `finding` events as verdict lines); timestamps **NEW** in the event or stamp client-side |
| Cancel | `POST /scans/{id}/cancel` |

States: queued (all stages `wait`, "Queued" grey dot, Cancel enabled); failed (banner bad with `Scan.error`, e.g. "Privacy step failed. Request aborted under I4. Nothing was sent."); cancelled (grey "Cancelled").

## 08 Findings

Route `/findings`. Shell, "Findings" active.

1. Header: crumb "kavachbank-core / Findings"; h1 "Findings"; right `.sub` "Scan SCN-0142 compared with baseline SCN-0140" + "Export CSV" + "Upload SARIF".
2. Saved-view tabs: "All open 43", "Critical and high 12", "New since baseline 5", "Needs review 4", "Assigned to me 6", "Suppressed 3", "+ Save view".
3. Filter row: search (white background, max 300) "Filter by title, file or ID"; `.btn.sm` dropdowns with `chevron-down`: "Severity: Critical, High", "CWE", "OWASP", "Engine", "Language", "Status", "Verdict", "Privacy level"; ghost "Clear".
4. Bulk bar (only while rows are selected): "**2 selected**" + "Assign", "Suppress with reason", "Mark false positive", "Sync to GitHub".
5. Table columns: checkbox / Severity (`.sev` with word) / Finding (title link + "KB-… · New|Unchanged|Fixed in branch") / CWE / OWASP (e.g. "A05") / CVSS 4.0 (`.cvss` box only) / Location (mono xs `path:line`) / Engines ("Opengrep, Taint <faint>· merged from 2</faint>") / LLM verdict (`.vd`) / Conf. (num, 2 decimals) / Status ("Open", "In progress", "Triage", faint "Suppressed") / Assignee (`.avatar.sm` or faint "Unassigned"). Selected rows `tr.sel`. Sorted by severity, then CVSS.
6. Footer: "Showing 1-12 of 43" + "Previous" (disabled) / "Next →".

Interactions: tabs and filters update the query string. Row title → `/findings/:id`. Select-all checkbox. Bulk actions: Assign → user picker then `PATCH /findings/{id} {assignee}` per row; Suppress with reason → dialog with reason text, `PATCH {status:"accepted_risk", comment}`; Mark false positive → `PATCH {status:"false_positive"}`; Sync to GitHub → `POST /scans/{id}/sync/github {repo, token_ref, dry_run}` (show a preview of `items` first). Export CSV → `GET /scans/{id}/reports/csv`. Upload SARIF → **NEW** (no import endpoint).

Data:

| Element | Source |
|---|---|
| Rows | `GET /scans/{id}/findings?severity=&status=&cwe=&q=` → `Finding` |
| Severity, title, id | `severity`, `title`, `id` |
| New / Unchanged / Fixed in branch | **NEW** baseline comparison (`baseline_state`, with `?baseline=` scan id) |
| CWE, OWASP, CVSS | `cwe`, `owasp`, `cvss4_score` |
| Location | `locations[0].path`, `start_line` |
| Engines, "merged from n" | `engine`; merged engine list and count **NEW** (`engines[]`) |
| LLM verdict, Conf. | `llm.is_vulnerable`, `llm.confidence` (see verdict mapping in COMPONENTS.md §6) |
| Status | `status` (map `open` "Open", `confirmed` "Confirmed", `false_positive` "False positive", `accepted_risk` "Suppressed" (faint), `fixed` "Fixed"); the design's "In progress" and "Triage" are **NEW** statuses |
| Assignee | `assignee` (user id/name → initials via `GET /users`) |
| Tab counts | **NEW** counts per saved view (or compute from an unpaged list) |
| Saved views | **NEW** (`/views` per user); "Assigned to me" = `assignee = me` |
| Pagination | **NEW** `total`, `offset`, `limit` on the findings list |
| Language, Engine, Verdict, Privacy level filters | **NEW** filter params (`FindingFilters` has severity, status, cwe, q only) |

Empty: "No findings match these filters" + ghost "Clear filters"; no scans yet: "No findings yet" / "Run a scan to see results here."

## 09 Finding detail

Route `/findings/:id` (`?tab=`). Shell, "Findings" active. Example: "SQL injection in account statement query".

1. Header block (gap 10): breadcrumb nav "kavachbank-core / Findings / KB-2026-0012". `.ph` (top-aligned): left stack: row `.sev.c` "Critical", mono "KB-2026-0012", `.vd.conf` "Confirmed by LLM · 0.94"; h1 24 px "SQL injection in account statement query"; row: `.cvss.c` "9.3 CVSS 4.0", tags "CWE-89" (link to MITRE), "OWASP A05:2025 Injection", "ASVS V1.2", "CAPEC-66", "PCI DSS 4.0 6.2.4", "ISO 27001 A.8.28", "NIST SSDF PW.5.1". Right: "Assign", "Suppress", primary "Create GitHub issue".
2. `.g-side`, main column (gap 20):
   - Card "Taint path" / "Source to sink across 2 files. Select a step to jump to the line." + xs faint "4 steps · no sanitiser on path": four nodes (see COMPONENTS.md §14).
   - Card (padding-top 6) with tabs "What the LLM saw" / "Real code" / "LLM reasoning <cnt>3 runs</cnt>":
     - **What the LLM saw**: row "Payload <a mono acc>#0094</a> · L3 minimal slice · 13 of 62 lines · 2,914 bytes" + `.more` "Inspect side by side" → Privacy Inspect; payload `.code` with `.rn` pseudonyms, `<STR_n>` strings, `<col_n>`/`<tbl_n>`, `.fold` "region 2 · file_e01b.py", `hl`/`src`/`sink` lines; xs faint "Visible to the model: control flow, the f-string shape and public API names (request.args.get, cursor, execute). Not visible: real names, table and column names, string values."
     - **Real code**: `.code-h` mono path + faint "Local only · never sent"; original lines 52 to 62 with `hl` 58 to 60 and `sink` 61.
     - **LLM reasoning**: row of four labelled values (xs faint label above): "Verdict" `.vd.conf` "Confirmed", "Calibrated confidence" "0.94", "Consensus" "3 of 3 runs agree", "Model" "mock-reasoner-1 · temp 0.2"; h3 13 px "Rationale" + muted text where pseudonyms are `.rn` with the restored name in bold ("(restored locally: **month**)"); h3 "Exploit scenario"; table Run / Verdict / Confidence / Payload (#0094, #0095, #0096).
   - Card "Impact" (muted paragraph).
   - Card "Remediation" + xs faint "Suggested fix · review before applying": muted summary; `.code-h` path + "+5 −4"; diff `.code` with `diff-add` / `diff-del` lines.
   - Card "References": `.more` links with `arrow-up-right` (CWE-89 title, OWASP SQL Injection Prevention Cheat Sheet, OWASP Code Review Guide · data validation, CAPEC-66 · SQL Injection).
3. Right rail (gap 16):
   - Card "Details" `.dl`: Status (`.inp.sm` select Open / In progress / Fixed), Assignee (avatar xs + name), Scan ("SCN-0142 · New since SCN-0140"), Engines ("Opengrep, Taint · merged from 2"), Privacy level (`.lvl` "L3 Minimal slice"), Payload (mono acc link "#0094 · 7c1e9a…94af" → ledger), First seen, Due ("19 Nov 2026 · 7-day SLA").
   - Card "CVSS 4.0 · 9.3 Critical": mono xs vector (break-all); `.dl.sm` Attack vector, Attack complexity, Attack requirements, Privileges required ("Low · signed-in customer"), User interaction, Confidentiality, Integrity, Availability.
   - Card "Activity": `.timeline` newest first ("**Asha Verma** assigned to Rohan Iyer", "commented" + comment text, "**CodeKavach** rated Critical · CVSS 9.3", "opened from SCN-0142"); "Add a comment" textarea (submit on Ctrl+Enter or a `.btn.sm` "Comment").

Interactions: tabs switch in place and update `?tab=`. Taint node click → switch to "Real code" and scroll to the line. Status select → `PATCH /findings/{id} {status}`; Assign → `PATCH {assignee}`; comment → `PATCH {comment}` then refetch history. Suppress → dialog, `PATCH {status:"accepted_risk", comment}`. Create GitHub issue → `POST /scans/{scan_id}/sync/github` (single finding: **NEW** `finding_ids` filter in `GithubSyncRequest`).

Data:

| Element | Source |
|---|---|
| Severity, id, title | `Finding.severity, id, title` |
| Verdict line | `Finding.llm.is_vulnerable, confidence` |
| CVSS box and card | `cvss4_score`, `cvss4_vector` (parse the vector for the metric list) |
| Tags | `cwe` (+ `cwe_name`), `owasp`, `asvs`, `capec`, `compliance[] {framework, clause}` |
| Taint path | `evidence.taint_path[] {kind, label, path, line, code}` |
| What the LLM saw | ledger record for this finding: `GET /scans/{scan}/ledger` filtered by `finding_id` → `GET /scans/{scan}/ledger/{seq} → payload_text, markup[side=payload], entry.level`; byte size **NEW** `bytes` on `LedgerEntry`; "13 of 62 lines" from `payload_text`/`original_text` line counts |
| Real code | `evidence.code {path, start_line, lines[], highlight[]}`; source and sink lines from `taint_path` |
| LLM reasoning | `llm.reasoning, model, provider, confidence`; runs table, consensus and temperature **NEW** (`llm.runs[] {verdict, confidence, ledger_seq}`, `llm.temperature`); restored names in the rationale: **NEW** server-side de-pseudonymised rationale with markup |
| Exploit scenario | **NEW** `llm.exploit_scenario` |
| Impact | `llm.impact` or `Finding.impact` |
| Remediation summary and diff | `remediation` / `llm.remediation`; suggested patch **NEW** (`remediation_diff`) |
| References | `references[]` (`{title, url}` or string) |
| Details: status, assignee | `status`, `assignee` |
| Scan, baseline state | `scan_id`; baseline **NEW** |
| Engines | `engine` (+ merged list **NEW**) |
| Privacy level, payload link | ledger entry `level`, `seq`, `payload_hash` |
| First seen, due, SLA | `created_at`; due date and SLA **NEW** |
| Activity | `GET /findings/{id}/history → at, actor, action, comment, from_status, to_status` |

States: loading skeleton per card; payload tab when L0 or no payload exists: `.empty` "Nothing was sent for this finding" / "It was reviewed at L0 or by deterministic engines only."; blocked: banner "Blocked by policy · never-send. Nothing was sent."

## 10 Privacy Inspect

Route `/privacy/inspect/:scanId/:seq` (`?level=`). Shell, sub-item "Privacy Inspect" active. Top-bar level pill shows the level being previewed.

1. Header: crumb "Privacy / Inspect / <a>KB-2026-0018 · SQL injection in interest calculation</a>"; h1 "Privacy Inspect"; sub "The original code on the left. The exact payload prepared for the model on the right." Right: xs faint "Compare the same slice at each level" above `.seg` (`role="tablist"`): "L1 Redacted", "L2 Pseudonymised", "L3 Minimal slice", "L4 Facts only".
2. KPI strip `.sm` (card padding 0): "Lines sent" (e.g. "11 / 28"), "Identifiers renamed", "Secrets redacted", "Listed terms found" ("0 <small>of 2,486</small>"), "Payload size", "SHA-256" (hash chip with copy). Values per level in the design:

   | Level | Lines sent | Renamed | Secrets | Size | Hash | Payload label |
   |---|---|---|---|---|---|---|
   | L1 | 28 / 28 | 0 | 1 | 812 B | 1f9b04…c0d2 | payload #0118 at L1 (preview) |
   | L2 | 28 / 28 | 15 | 1 | 846 B | 5a0731…e913 | payload #0118 at L2 (preview) |
   | L3 | 11 / 28 | 9 | 0 | 402 B | b2d41e…6f08 | payload #0118 · as sent |
   | L4 | 0 / 28 | 2 | 0 | 618 B | c3d8f2…0a71 | payload #0118 at L4 (preview) |

3. Legend: red "redacted secret", blue "renamed identifier", grey italic "generalised string or comment", dashed "not sent".
4. `.g-2` (top-aligned):
   - Left: `.code-h` "**Original** <mono muted>web/routes/interest.js</mono>" / faint "Stays on this machine"; original code with the slice tinted (`hl`), `src` line 24, `sink` line 14; xs faint "Tinted lines are the vulnerability-relevant slice (source on line 24, sink on line 14)."
   - Right: `.code-h` "**Payload** <mono muted>{label}</mono>" / "Prepared for the model" in `--high-t`; then per level:
     - L1: code with only the secret as `.rd` `<SECRET:AWS_KEY_1>`, `.fold` "lines 18-28 sent unchanged"; `.banner.warn.sm` "At L1 real names, business terms and rates leave the machine. Only secrets and PII are removed."
     - L2: every identifier `.rn` (`c_91f0`, `m_6a1d`, `fn_a83c`, `v_19e2`…), comments `.gen` "// <comment removed>", literals `.gen` `<STR_n>`, `<NUM_n>`, `<col_1>`, `<tbl_1>`; `.fold` "lines 22-28 sent, pseudonymised".
     - L3 (default): `.fold` "lines 1-10 not sent", lines 11 to 17, vault tooltip after line 11 ("fn_a83c is **calculateInterest**" / "Restored locally from vault. Never sent."), `.fold` "lines 18-22 not sent", lines 23 to 26, `.fold` "lines 27-28 not sent"; xs faint "The secret on line 2 is outside the slice, so it is not sent at all. Redaction would still apply if it were inside."
     - L4: `.code.facts`: "// facts · no source code", F1 to F5, "// questions", Q1 to Q3 (bold ids, pseudonyms `.rn`); xs faint "Lower precision than L3 on complex flows; see Evaluation for the measured trade-off."
5. `.note.box` "**What this does not cover.**": "At L2 and L3 the model still sees control flow, literal shapes (a string, a number) and public API names such as <mono>db.query</mono> and <mono>res.json</mono>." / "The leak check is verbatim only. A listed term that is paraphrased, split or encoded would not be detected." / "Pseudonyms are deterministic per scan salt (I5), so repeated payloads in one scan can be linked to each other."

Interactions: level segment switches the payload pane and KPIs and updates `?level=`; the level actually sent is labelled "as sent", the others "(preview)". Hovering or focusing a pseudonym shows the vault tooltip with the original name (restored locally). Copy hash copies the full hash.

Data:

| Element | Source |
|---|---|
| Finding link in crumb | `LedgerEntry.finding_id` → `GET /findings/{id} → title` |
| Original pane | `GET /scans/{id}/ledger/{seq} → original_text` + `markup[side=original]`; file path and start line **NEW** (`path`, `start_line`); slice/source/sink lines **NEW** (`slice_lines`, `source_line`, `sink_line`) or from the finding's `taint_path` |
| Payload pane (sent level) | same call → `payload_text`, `markup[side=payload] {kind, start, end, label}`; folds come from gaps in the slice |
| Payload at other levels | **NEW** preview endpoint (`GET /scans/{id}/ledger/{seq}/preview?level=L2`) returning the same shape; never sent, never written to the ledger |
| Lines sent, renamed, secrets | derive from `markup` (counts by kind) and line counts, or **NEW** fields |
| Listed terms found | `GET /scans/{id}/privacy → zero_leak` (per payload **NEW**) |
| Size, hash | **NEW** `bytes`; `entry.payload_hash` |
| Vault tooltip | `markup.label` for identifiers (restored name, served only to authorised local users) |

## 11 Privacy Centre

Route `/privacy`. Shell, "Privacy Centre" active.

1. Header: crumb "kavachbank-core / Privacy Centre"; h1 "Privacy Centre"; sub "How much this project discloses, why, and how that is verified."; buttons "Inspect a payload" (→ Inspect), "Edit policy" (→ Policy).
2. `.g-3`:
   - Card "Privacy score" + xs faint scan id: `.big-num` "86" + faint "/ 100" + `sm down` "+3 vs SCN-0140"; five labelled `.bar.priv`: "Findings sent at L3 or stricter" 92, "Slice minimality · 11.4 lines avg" 88, "Redaction before slicing" 100, "Zero-leak check" 100, "Exposure budget headroom" 52.
   - Card "Exposure budget" + `.btn.sm` "Adjust": three ink bars with mono values: "This scan" "412.6 / 600 KB" ("187.4 KB remaining"), "Project, November" "1.8 / 5.0 MB" ("Resets 1 Dec · stop at 100%"), "Organisation, November" "6.4 / 25 MB".
   - Card "Invariant suite" + xs faint "CI · 12 Nov, 10:31 · 48 tests": guards I1 "One transport module opens LLM connections", I2 "LLM layer accepts sanitised payloads only", I3 "Vault never logged or exported", I4 "Privacy-step failure aborts the request", I5 "Pseudonyms deterministic per scan salt", I6 "No listed term of 4+ chars in payloads", each "Pass".
3. `.g-side`: left "Policy decisions" (14/600) + `.more` "Open policy"; table Path (mono) / Language / Rule (mono xs) / Decision (`.st` with bad dot "never-send", or `.lvl` L4/L3/L2) / Files. Right card "Privacy explain": "File" select (mono); rows "Scan default" L3, "Organisation floor" L2, "Rule fee-engine.l4 · engine/interest/**" L4, rule, "**Effective level**" `.lvl` "L4 Facts only"; xs faint "The strictest applicable rule wins. This file sends data-flow facts only, never code."
4. `.g-2`: card "Leakage evaluation" / "Identifier recovery by a simulated attacker with the payloads" + `.more` "Method" → Evaluation: bars L1 100% (fill `--high`, caption "real names are sent"), L2 7.8%, L3 4.1%, L4 0.9%; xs faint "KavachBank, 1,312 identifiers, 3 attacker models, 95% CI ±1.2 points.". Card "Privacy-utility frontier" / "Detection F1 against identifier recovery": SVG (below).
5. `.g-2`: card "Privacy attestation" / "Signed summary for auditors and customers" + `.btn.sm` "Download PDF", "JSON": `.dl`: Scan, "Levels used" (`.lvl` "L3 · 118", "L4 · 23", "never-send · 1"), Payloads ("142 sent · 412.6 KB · 0 whole files"), Checks ("Ledger chain, payload hashes and zero-leak check (2,486 terms) passed"), "Ledger head" (hash), Signed ("12 Nov 2026, 10:44 IST · key ck-attest-2026-11"). `.note.box` "**What this attestation does not cover.**" list: "It describes what left during this scan only, not earlier scans or other tools." / "The model still saw control flow, literal shapes and public API names in L3 slices." / "The zero-leak check is verbatim against the listed terms. Unlisted terms, paraphrases or encoded values are not checked." / "It does not attest to how the provider stores or uses received payloads. That is governed by your provider agreement." / "With the Mock provider, nothing was transmitted; the ledger records what would have been sent."

Frontier SVG (same on Evaluation):

```html
<svg viewBox="0 0 520 240" role="img" aria-label="F1 rises from 0.58 with SAST only to 0.80 at L3 and 0.82 at L2, while identifier recovery rises from 0 to 7.8 percent" style="width:100%;height:auto;font-family:'IBM Plex Sans',sans-serif">
  <line x1="48" y1="200" x2="500" y2="200" style="stroke:var(--border-strong)"/>
  <line x1="48" y1="20" x2="48" y2="200" style="stroke:var(--border-strong)"/>
  <line x1="48" y1="110" x2="500" y2="110" style="stroke:var(--border);stroke-dasharray:3 3"/>
  <line x1="48" y1="20" x2="500" y2="20" style="stroke:var(--border);stroke-dasharray:3 3"/>
  <text x="40" y="204" text-anchor="end" style="font-size:11px;fill:var(--faint)">0.5</text>
  <text x="40" y="114" text-anchor="end" style="font-size:11px;fill:var(--faint)">0.7</text>
  <text x="40" y="24" text-anchor="end" style="font-size:11px;fill:var(--faint)">0.9</text>
  <text x="48" y="222" text-anchor="middle" style="font-size:11px;fill:var(--faint)">0%</text>
  <text x="274" y="222" text-anchor="middle" style="font-size:11px;fill:var(--faint)">5%</text>
  <text x="500" y="222" text-anchor="end" style="font-size:11px;fill:var(--faint)">10%</text>
  <text x="274" y="238" text-anchor="middle" style="font-size:11px;fill:var(--muted)">identifier recovery rate</text>
  <polyline points="48,164 89,104 233,65 401,56" style="fill:none;stroke:var(--accent);stroke-width:1.5"/>
  <circle cx="48" cy="164" r="4" style="fill:var(--surface);stroke:var(--text);stroke-width:1.5"/>
  <circle cx="89" cy="104" r="4" style="fill:var(--accent)"/>
  <circle cx="233" cy="65" r="5" style="fill:var(--text)"/>
  <circle cx="401" cy="56" r="4" style="fill:var(--accent)"/>
  <text x="58" y="180" style="font-size:11px;fill:var(--muted)">SAST only · 0.58</text>
  <text x="97" y="98" style="font-size:11px;fill:var(--muted)">L4 · 0.71</text>
  <text x="241" y="58" style="font-size:12px;font-weight:600;fill:var(--text)">L3 default · 0.80</text>
  <text x="409" y="50" style="font-size:11px;fill:var(--muted)">L2 · 0.82</text>
  <text x="496" y="88" text-anchor="end" style="font-size:11px;fill:var(--faint)">L1 at 100% → off chart</text>
</svg>
```

Scales: x = 48 + recovery% × 45.2 (0 to 10%), y = 200 − (F1 − 0.5) × 450 (0.5 to 0.9).

Data:

| Element | Source |
|---|---|
| Privacy score | `GET /scans/{id}/privacy → privacy_score`; delta from the previous scan; the five component scores **NEW** (`score_parts[] {label, value}`) |
| Exposure budget | **NEW** budgets and usage (scan, project month, organisation month) |
| Invariant suite | **NEW** (see Overview) |
| Policy decisions table | `GET /policy → toml/parsed` rules; files matched per rule **NEW** (`matches`) |
| Privacy explain | **NEW** `GET /policy/explain?path=` → chain of rules and effective level; file list from the project inventory |
| Leakage evaluation, frontier | **NEW** evaluation results (see Evaluation) |
| Attestation | `GET /scans/{id}/privacy → attestation_text, level, payloads, blocked, chain_ok, zero_leak`; levels-used breakdown, bytes, ledger head, signing time and key **NEW** (structured attestation fields); Download PDF / JSON: **NEW** (`GET /scans/{id}/privacy/attestation.{pdf,json}`) or via `GET /scans/{id}/reports/{fmt}` |

## 12 Egress Ledger

Route `/privacy/ledger` (`?scan=&seq=`). Shell, "Egress Ledger" active.

1. Header: crumb "Privacy / Egress Ledger"; h1 "Egress Ledger"; sub "Every outbound payload, hash-chained in order. Scan SCN-0142."; buttons "Verify again", "Export ledger (JSONL)", "Export verification report".
2. Split banner (`.banner.info.split`): cell 1 "Chain verified · 142 records · 0 listed terms found" (sm 600) / xs faint "Verified offline at 10:44:12 IST against head e91a7c…3b20"; cell "Chain links" / ok dot "142 of 142 valid"; cell "Payload hashes" / ok "141 match · 1 blocked"; cell "Zero-leak check" / ok "0 of 2,486 terms, verbatim". On failure use red dots and a `.banner.bad` cell 1: "Chain broken at record {first_bad_seq}".
3. `.banner.warn.sm` (Mock or dry-run only): "Mock provider: the ledger shows what *would* have been sent. Nothing left this laptop."
4. `.g-side`:
   - Left: filter row (search "Hash, finding or sequence", "Status: all ▾", "Provider: all ▾"); table Seq (mono, 4 digits) / Time / "Provider · model" / Payload hash (hash chip, or faint "none") / Bytes / Chain hash / Status (ok "Sent", bad "Blocked · never-send", grey "Dry-run", grey "Genesis"); newest first; selected row `tr.sel`; footer "Showing 10 of 142" + "Load more ↓".
   - Right card "Record 0118" + close `iconbtn`: `.dl.sm` Finding (acc mono link), Level (`.lvl`), Payload, Previous, Chain (hash chips), "Leak check" "0 of 2,486 terms"; `.code-h` "Payload · read-only" / "402 B"; payload JSON `.code` (11.5/19 px) with pseudonyms `.rn`; `.more` "Open in Privacy Inspect".

Interactions: row click selects and opens the record panel (`?seq=`); close hides it (table full width). Verify again → `POST /scans/{id}/ledger/verify` then refresh the banner and show the toast "Ledger chain verified" / "{n} records · chain, payload hash and zero-leak checks passed". Exports download files.

Data:

| Element | Source |
|---|---|
| Banner | `POST /scans/{id}/ledger/verify → ok, entries, first_bad_seq, message, verified_at`; counts of hash matches, blocked, terms **NEW** (`hashes_ok`, `blocked`, `terms_checked`, `terms_found`, `head_hash`) or from `GET /scans/{id}/privacy → blocked, zero_leak, chain_ok` |
| Mock banner | `Scan.provider === "mock"` or `Scan.send === false` |
| Rows | `GET /scans/{id}/ledger → seq, timestamp, provider, model, payload_hash, entry_hash, outcome`; bytes **NEW** (`bytes`; contract has `tokens`); paging **NEW** |
| Status | `LedgerEntry.outcome` (`sent`, `blocked:never-send`, `dry-run`, `genesis`) |
| Record panel | `GET /scans/{id}/ledger/{seq} → entry (finding_id, level, payload_hash, prev_hash, entry_hash), payload_text, markup` |
| Export ledger JSONL | **NEW** (`GET /scans/{id}/ledger?format=jsonl`) |
| Export verification report | **NEW** |
| Search, filters | **NEW** query params on `/ledger` (`q`, `status`, `provider`) or filter client-side |

Empty: L0 scan: `.empty` "No payloads left this machine" / "This scan ran at L0. The ledger holds only the genesis record."

## 13 Privacy policy

Route `/privacy/policy`. Shell, "Policy" active.

1. Header: crumb "Privacy / Policy"; h1 "Privacy policy"; sub "Decide which level each part of the codebase is reviewed at. The strictest matching rule wins."; right `.sub` "Unsaved changes · 2" + "Discard" + primary "Save policy".
2. `.g-side`, left stack:
   - Card "Rules" + `.btn.sm` "+ Add rule": table Order (mono faint) / Path glob (`.inp.mono.sm`) / Language / Rule ID (mono xs) / Action (`.inp.sm` select, 140 px: never-send, L1 to L4 names) / Matches (num) / ghost "Remove" (none on the catch-all `**` default rule). Selected rule `tr.sel`.
   - `.g-2`: card "Floor level" ("Scans and users cannot choose a level that discloses more than this.", `.seg` L1 / **L2** / L3, xs faint "Current floor L2. L1 is unavailable to every project in this organisation."); card "Templates": list rows "Bank strict" ("Floor L2 · config, keys and fixtures never-send · business logic L4", `chip on` "Applied"), "Healthcare" ("Floor L3 · PII paths never-send", "Apply"), "Minimal" ("Default L3 · no extra rules", "Apply").
3. Right stack: `.code-h` mono "kavach-policy.toml" + `.st.xs` ok "Valid · schema v2"; TOML `.code` (12/20 px) with the selected rule's lines `hl`. Card "Validation": guards "Schema and glob syntax" Pass, "No rule below floor L2" Pass, "Rule 5 overlaps rule 6 on 6 files · stricter wins" `.note-w` "Note", "Dry run on kavachbank-core · 486 files resolved" Pass.

Interactions: editing the table updates the TOML preview live and the unsaved counter; selecting a rule highlights its TOML block. Save → validate then save; Discard → reload. Apply template → confirm, replace rules.

Data:

| Element | Source |
|---|---|
| Rules, floor, default, TOML | `GET /policy → toml, parsed` |
| Save | **NEW** `PUT /policy {toml}` (contract lists `/policy` only; confirm the method) |
| Matches per rule, dry run | **NEW** (`POST /policy/validate {toml}` → `{valid, schema, errors[], notes[], matches{rule_id: n}, files_resolved}`) |
| Templates | **NEW** (`GET /policy/templates`) |

## 14 Providers

Route `/providers`. Shell, "Providers" active.

1. Header: crumb "Organisation / Providers"; h1 "Providers"; sub "Bring your own keys. Keys are stored as references, never as plaintext."; "Run health checks" + primary "+ Add provider".
2. `.g-3` provider cards (each `.card.stack`): row with `.provlogo` + bold name + xs faint mono "wire: …", right `.st.sm` health ("Healthy" ok, "Unreachable · air-gapped" warn, "Not checked" grey); capability chips; `.dl.sm`:
   - M "Mock" (wire: internal): chips "Structured output", "Deterministic"; Key "Offline · no key", Cost "None", Use "Demos, CI, dry runs".
   - R "Replay" (wire: recorded JSONL): "Structured output", "Reproducible"; Key, Cost "None", Source mono "replays/SCN-0140.jsonl".
   - O "Ollama · self-hosted" (wire: openai-compatible): "Structured output", "Local network only"; Models (mono xs), Endpoint (mono xs), Cost "Your hardware".
   - A "Anthropic Claude" (wire: messages): "Structured output", "Tool use"; Key "<mono>env:ANTHROPIC_API_KEY</mono> · present", "Rate card" faint "[set by admin]", "Data use" "Per your provider agreement".
   - O "OpenAI · Azure OpenAI" (wire: chat completions): Key "keyring:openai · present", Azure "file:/etc/kavach/azure.key · missing", Rate card.
   - "+" "Gemini · Grok · Bedrock · vLLM" ("4 more configured", status "Not checked"): sub "Google Gemini, xAI Grok, AWS Bedrock and a vLLM cluster serving GLM and Kimi." + `.more` "Show all providers".
3. `.g-2`: card "Auto-selection rules" / "Evaluated top to bottom for every scan" + `.btn.sm` "Edit": table # / When / Use (rows: "Level is L0" → "Ollama · qwen2.5-coder"; "No outbound network" → "Mock"; "Scan tagged ci" → "Replay, then Mock"; "Project kavachbank-core" → "Claude, then Ollama"; "Otherwise" → "Ollama"). Card "Token usage, November" / "Input and output tokens by provider" + legend Input (ink) / Output (accent): `.tokbar` rows with mono "1.42M · 0.31M"; xs faint "Costs appear once an admin sets a rate card for each paid provider."
4. "Conformance tests" + xs faint "64 tests: schema, refusal handling, pseudonym round-trip, timeout, fail-closed": table "Provider · model" / Passed / Failed (`.badc` when > 0) / Skipped / Notes / "Last run".

Interactions: "Run health checks" → `POST /providers/{id}/test` for each provider, updating each card's status as results arrive (show `latency_ms` in a tooltip). "+ Add provider" → dialog (name, kind, endpoint, key reference) **NEW** endpoint.

Data:

| Element | Source |
|---|---|
| Cards: name, kind, models, local, configured | `GET /providers → id, name, kind, models, local, configured, default_model, capabilities` |
| Wire protocol | **NEW** `wire` (or derive from `kind`) |
| Health | `POST /providers/{id}/test → ok, latency_ms, message` |
| Key reference and presence | **NEW** `key_refs[] {ref, present}` (references only, never values) |
| Endpoint, cost/rate card, data use, replay source | **NEW** |
| Auto-selection rules | **NEW** (`GET /providers/rules`) |
| Token usage per month | **NEW** (`GET /stats/usage?month=` → per provider input/output tokens) |
| Conformance tests | **NEW** (`GET /providers/conformance`) |

## 15 Reports

Route `/reports`. Shell, "Reports" active.

1. Header: crumb "kavachbank-core / Reports"; h1 "Reports"; primary "New report" (scrolls to / focuses the builder).
2. Reports table: Report ("**KB-AR-014**" + xs faint title "Secure code review · November") / Scan (mono) / Audience (Technical, Executive, Compliance) / Formats (tags PDF, DOCX, SARIF, JSON, HTML, XLSX, CSV, Markdown) / "Integrity manifest" (hash chip) / Generated / `.more` "Open". Selected `tr.sel` is the one previewed.
3. `.g-side-l`:
   - Left form card "Report builder": "Audience" `.seg` Executive / **Technical** / Compliance; "Baseline for delta" select ("SCN-0140 · 10 Nov", "None"); "Sections" checkboxes "Document control", "Executive summary and risk matrix", "Scope and methodology", "Findings with evidence", "Remediation roadmap", "Compliance annex", "Privacy attestation"; "Compliance frameworks" toggle chips "OWASP ASVS", "PCI DSS 4.0", "ISO 27001" (on), "NIST SSDF", "CERT-In"; "Branding" drop zone ("kavachbank-logo.svg" + "Replace"); "Classification" select ("Confidential · restricted distribution"); "Formats" toggle chips PDF, DOCX (on), HTML, SARIF, JSON (on), CSV, XLSX, Markdown; primary "Generate report".
   - Right: row sub "Preview · KB-AR-014 · 31 pages" + "Previous page" / "Next page"; `.page-tray` `.g-2` of two `.page` (min-height 560): **cover** ("KAVACHBANK" letter-spaced + "CONFIDENTIAL", 2 px ink rule, "SECURE SOURCE CODE REVIEW", serif 26 px title "kavachbank-core / Audit report KB-AR-014", scope line, "Document control" table: Version, Classification, Prepared by, Reviewed by, Distribution, Integrity sha256); **page 3** ("KB-AR-014" / "Page 3 of 31", "1. Executive summary" paragraph with bold counts, severity table Severity / Open / New / "Fixed since SCN-0140", "Remediation roadmap" table "Now · 7 days" / "Next · 30 days" / "Later · 90 days", privacy attestation line).

Interactions: Generate → produce each selected format; then the new report appears at the top of the table. Open → download or preview.

Data:

| Element | Source |
|---|---|
| Available formats | `GET /scans/{id}/reports → format, label, available, reason, media_type` (disable chips that are not available, tooltip `reason`) |
| Download a format | `GET /scans/{id}/reports/{fmt}` |
| Reports history (id, title, audience, formats, manifest hash, generated) | **NEW** (`GET /reports` list of generated reports) |
| Builder options (audience, baseline, sections, frameworks, branding, classification) | **NEW** (`POST /scans/{id}/reports {audience, baseline, sections[], frameworks[], classification, formats[], logo}`); today only `{fmt}` is selectable |
| Preview pages | **NEW** (rendered page images or HTML) or render the HTML format in an iframe |

## 16 Integrations

Route `/integrations`. Shell, "Integrations" active.

1. Header: crumb "kavachbank-core / Integrations"; h1 "Integrations".
2. `.g-side`:
   - Card (gap 16): row `.provlogo` "GH" + "**GitHub**" / xs faint "GitHub App · kavachbank/core", right ok "Connected · last sync 10:44" + `.btn.sm` "Configure". `.swgrid` switches with descriptions: "SARIF upload" ("Code scanning alerts, SARIF 2.1.0"), "PR check runs" ("Fail on new Critical or High"), "Review comments" ("Inline on the changed line"), "Issue sync" ("Two-way status with findings"), "Projects board" ("Projects v2 · \"AppSec Kanban\""), "Include payload hash" ("Adds ledger link to each issue", off). Sub "Kanban column mapping"; table "Finding status" / arrow / "Board column" / Cards: "Open · Critical or High" → "Fix now", "Open · Medium or Low" → "Backlog", "In progress" → "In progress", "Fixed · awaiting rescan" → "Verify".
   - Right stack: card "VS Code extension" + chip "v0.9", sub "See findings inline, open Privacy Inspect for the current file and run L0 scans before you commit.", `.more` external "Install from marketplace"; card "Local MCP server" + ok "Running · stdio", sub "Lets a local coding assistant query findings and the ledger. Read-only, no vault access (I3).", `.code.cmd` "kavach mcp serve --read-only"; card "CI badge": two `.ci-badge` ("codekavach | 3 critical", "privacy | L3 · 0 leaks") + markdown snippet in `.code` (break-all).
3. `.g-2`: "GitHub Action" `.code-h` (mono ".github/workflows/codekavach.yml" + `.btn.sm` "Copy") + 16-line YAML; "Pre-commit hook" (".pre-commit-config.yaml" + "Copy") + 7-line YAML + xs faint "Runs at L0 by default: nothing leaves the developer's machine on commit."

Interactions: switches save immediately (optimistic, revert on error). Copy buttons copy the snippet and show a toast "Copied".

Data:

| Element | Source |
|---|---|
| GitHub connection status, repo, last sync | **NEW** (`GET /integrations/github`) |
| Feature switches | **NEW** (`PATCH /integrations/github`) |
| Kanban mapping and card counts | **NEW** |
| Manual sync | `POST /scans/{id}/sync/github {repo, token_ref, dry_run}` → `created, updated, closed, items` |
| VS Code version, MCP server status | **NEW** |
| Badge counts | `GET /stats → findings_by_severity.critical`; privacy part from `GET /scans/{last}/privacy` |
| Snippets | static, with the project's level and provider from `GET /settings` |

## 17 Evaluation

Route `/evaluation`. Shell, "Evaluation" active.

1. Header: crumb "Organisation / Evaluation"; h1 "Evaluation"; sub "How detection quality changes with privacy level, and what an attacker can recover from the payloads."; chip "Sample results · replace with your runs" + "Run benchmark".
2. "Benchmark results" (14/600) + xs faint "Precision, recall, F1 · 95% bootstrap confidence intervals"; table Dataset / Arm / Precision / Recall / F1 / "F1 with CI" (220 px `.ci-bar`, axis 0 to 1). Rows: KavachBank · 61 planted: "SAST only", "SAST + LLM · L4", **"SAST + LLM · L3"** (`tr.sel`, `.ci-bar.acc`, bold F1), "SAST + LLM · L2", "SAST + LLM · L1"; "Regression set · 412 cases" "SAST + LLM · L3".
3. `.g-2`: card "Arms comparison" / "F1 on KavachBank by arm": `.hbar` rows "SAST only" (base), "+ LLM · L4", **"+ LLM · L3"** (accent), "+ LLM · L2", "+ LLM · L1"; xs faint "L3 keeps 96% of the F1 available at L1 while sending no whole files." Card "Privacy-utility frontier" / "F1 against identifier recovery rate": the SVG from Privacy Centre.
4. "Attacker experiments" + xs faint "Simulated adversary holding every payload from one scan"; table Experiment (bold) / "What the attacker tries" (wrap, muted) / L2 / L3 / L4 / Reading: "Identifier recovery" (7.8% / 4.1% / 0.9%), "Business inference" (62% / 38% / 11%), "Stitching" (n/a / 18% / 2%), "Secret extraction" (0% / 0% / 0%). xs faint "These rates measure disclosure; they are not a guarantee. Re-run per codebase, as results depend on naming style and code structure."

Data: all **NEW** (`GET /evaluation` → `benchmarks[] {dataset, arm, precision, recall, f1, f1_ci:[lo,hi]}`, `frontier[] {arm, f1, recovery}`, `attacks[] {experiment, description, by_level{L2,L3,L4}, reading}`, `sample: boolean`; `POST /evaluation/run`). Keep the "Sample results" chip while `sample` is true.

## 18 Admin

Route `/admin` (tabs as sub-routes). Shell, "Admin" active. Top bar: organisation pill "Demo Organisation", level pill "Floor L2 · default L3", no provider pill, user role "Admin".

1. Header: crumb "Organisation / Admin"; h1 "Admin"; primary "Invite user".
2. Tabs: "Users and roles" (on), "Organisations 3", "API tokens", "Provider keys", "Audit log", "Retention", "System health". The design draws the first tab; the panels below appear on it as an overview, and each other tab shows its panel full width.
3. `.g-side`, left stack:
   - Users table: User (`.avatar.sm` + bold name + xs faint email or "expires 20 Nov 2026") / Role (`.inp.sm` select, 120 px: Admin, Auditor, Developer, Viewer) / Projects / Sign-in ("SSO · SAML", "Local · MFA", "Magic link") / "Last active" / ghost "Edit" (or "Revoke" for guests).
   - `.g-2`: card "API tokens" + `.btn.sm` "+ New token": guard rows (bold name, xs "scopes · expires …", right mono faint masked token "ck_live_…7f2a"). Card "Provider keys" + `.more` "Providers": guard rows (name, mono reference, `.st.xs` "present" ok / "missing" bad) + xs faint "Only references are stored. Values are read at request time and never written to logs or the ledger."
   - "Audit log" (14/600) + `.btn.sm` "Export": table Time (mono) / Actor / Action (`policy.update`, `attestation.sign`, `scan.start`, `vault.rotate_key`) / Target (mono xs) / Source (mono xs IP or "local").
4. Right stack: card "Data retention and vault": selects "Findings and ledger retention" ("365 days"), "Vault retention after scan" ("30 days, then purge"); `.dl.sm` "Vault key" (mono "vault-kb-core · AES-256-GCM"), "Last rotated", "Vault size" ("14,882 mappings · 3 scans"); buttons "Rotate key", danger "Purge vault"; xs faint "Purging the vault means old verdicts can no longer be mapped back to real names. Reports already generated are unaffected." Card "System health" + mono xs faint "kavach doctor · 10:40": guards "Database and migrations", "Engines installed · 7 of 7", "OSV mirror age · 2 days", "Transport module single entry (I1)", "Disk free · 11% on /var/lib/kavach" (`.note-w` "Low"), "Clock skew vs NTP · 0.2 s".

Interactions: role select → `PATCH` user (**NEW**: contract has `/users` list and create only); Invite → dialog (username, display name, email, role, password or invite) → `POST /users`; Purge vault → confirmation dialog that requires typing the vault name.

Data:

| Element | Source |
|---|---|
| Users | `GET /users → id, username, display_name, email, role, active, last_login`; projects, sign-in method, guest expiry **NEW** |
| Invite | `POST /users {username, password, role, display_name, email}` |
| Change role, revoke | **NEW** `PATCH /users/{id}`, `DELETE /users/{id}` |
| Organisations tab | **NEW** |
| API tokens | **NEW** (`GET/POST/DELETE /tokens`) |
| Provider keys | **NEW** key references with presence (see Providers) |
| Audit log | **NEW** (`GET /audit`) |
| Retention, vault info, rotate, purge | **NEW** (`GET/PATCH /settings` retention fields; `POST /vault/rotate`, `POST /vault/purge`) |
| System health | `GET /health` (extend with checks[] **NEW**) |

## 19 Settings

Route `/settings` (anchors). Shell, "Settings" active. Content max-width 1100.

1. Header: h1 "Settings" (no crumb); primary "Save changes".
2. `.g-side-l`: left `.subnav-list` ghost buttons "Profile" (on), "Appearance", "Notifications", "CLI and API tokens", "Language and region" (anchor links; highlight follows scroll). Right stack of cards:
   - `#profile` "Profile": `.avatar.lg` + `.btn.sm` "Change photo"; `.g-2` "Name", "Email" (disabled); `.g-2` "Role" (disabled, "Auditor · set by admin"), "Title".
   - `#appearance` "Appearance": "Density" `.seg` Comfortable / **Compact**; switches "Show severity shapes as well as colour" (on), "Reduce motion" (off). There is no theme switch: the design is light only.
   - `#notifications` "Notifications": borderless table Event / "In app" / Email with checkboxes: "New Critical or High finding", "Finding assigned to me", "Privacy step failed or payload blocked", "Exposure budget above 80%", "Scan completed".
   - `#tokens` "CLI and API tokens" + `.btn.sm` "+ New personal token": guard row "laptop-cli" ("scan:write, findings:read · created 2 Nov · expires 2 Feb 2027") + `.btn.sm` "Revoke"; `.code` "kavach login --token-ref keyring:codekavach" / "kavach scan . --level L3 --provider mock".
   - `#language` "Language and region": "Language" (English (United Kingdom), हिन्दी), "Time zone" (Asia/Kolkata · IST), "Date format" (12 Nov 2026, 2026-11-12).

Data:

| Element | Source |
|---|---|
| Name, email, role | `GET /auth/me → display_name, email, role`; title and photo **NEW** |
| Save profile | **NEW** `PATCH /auth/me` (or `/users/{id}`) |
| Appearance, language, time zone, date format | **NEW** per-user preferences (`GET/PATCH /me/preferences`); local storage until then |
| Notifications matrix | **NEW** (`GET/PATCH /me/notifications`) |
| Personal tokens | **NEW** (`GET/POST/DELETE /me/tokens`) |
| Organisation defaults (if shown to admins) | `GET /settings → default_provider, default_model, default_privacy_level, org_name` |

---

## API gaps

Data the design shows that the current contract does not provide. Grouped by suggested endpoint; each item names the screens that need it.

**Scans and stats**
- `Scan`: `mode` (branch|diff), `ref`, `payloads`, `engines[]`, `eta_seconds` (Overview recent scans, Scan live, Demo mode).
- SSE: per-stage `count`/`total` on `stage` events; an `egress` event with payloads, bytes, secrets checked, terms found; timestamps on `log` events (Scan live).
- `GET /stats`: `mttr_days` and delta, `info` in `TrendPoint`, risk matrix counts, OWASP × engine counts, top CWEs (Overview). Client-side aggregation over findings is a fallback.
- Engine list with install status (Onboarding step 2, Scan launch, Admin system health).
- Project inventory per language: files, lines, support level (Onboarding step 2).

**Findings**
- Pagination (`total`, `offset`, `limit`), more filters (engine, language, verdict, privacy level, OWASP), saved views and their counts (Findings).
- Baseline comparison: `baseline_state` (new, unchanged, fixed) with `?baseline=` (Findings, Finding detail, Reports).
- Verdict enum, merged `engines[]`, `due_at`/SLA, extra statuses ("In progress", "Triage") (Findings, Finding detail).
- `llm.runs[]`, `llm.temperature`, `llm.exploit_scenario`, de-pseudonymised rationale with markup, `remediation_diff` (Finding detail).
- `finding_ids` filter on `POST /scans/{id}/sync/github` (Create GitHub issue for one finding).
- SARIF import (Findings "Upload SARIF").

**Privacy and ledger**
- `bytes` on `LedgerEntry` and `bytes_sent` on the privacy summary (the contract counts tokens; the design shows bytes everywhere).
- Ledger detail: `path`, `start_line`, slice/source/sink lines; per-payload leak check; `lines_sent`/`lines_total` (Privacy Inspect, Finding detail, Demo mode).
- Level preview of a payload at other levels, never sent (Privacy Inspect).
- Verify result counts (`hashes_ok`, `blocked`, `terms_checked`, `terms_found`, `head_hash`); ledger paging, search and filters; JSONL and verification report exports (Egress Ledger).
- Privacy score parts, exposure budgets and usage, invariant suite results, structured attestation (levels used, bytes, head, signing time and key) and attestation PDF/JSON (Privacy Centre, Overview, Scan live).
- Policy save (`PUT /policy`), validation with per-rule matches and dry run, templates, explain-for-path (Policy, Privacy Centre).

**Providers, reports, integrations, evaluation**
- Provider `wire`, key references with presence, endpoint, rate card, auto-selection rules, token usage per month, conformance results, add provider (Providers, Onboarding step 4, Admin).
- Generated reports history and builder options (audience, baseline, sections, frameworks, branding, classification), page previews (Reports, Demo mode).
- GitHub integration status and switches, Kanban mapping, VS Code and MCP status (Integrations).
- Evaluation results and benchmark runs (Evaluation, Privacy Centre).

**Organisation and user**
- Network posture for the top-bar pill (shell).
- Notifications feed and per-user notification settings (shell, Settings).
- User update and revoke, organisations, API tokens (org and personal), audit log, retention and vault rotate/purge, system health checks (Admin, Settings).
- Profile update, preferences (density, motion, language, time zone, date format) (Settings).
- SSO, organisation (tenant) selection and an anonymous demo session (Login).
