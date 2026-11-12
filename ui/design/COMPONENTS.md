# Component inventory

Every component in the approved design ([`codekavach-dashboard.html`](codekavach-dashboard.html)), with the markup and class names to reproduce it 1:1 in React. Styles come from [`components.css`](components.css) and [`tokens.css`](tokens.css); a React component only has to emit this markup (`class` becomes `className`). Icons are listed in [SCREENS.md, Icons](SCREENS.md#icons); `<Icon name="arrow-right"/>` below stands for the inline SVG given there.

Design rules, from the design system board: flat surfaces, 1 px lines, no shadows or gradients, one accent (blue `--accent`) for links, selection and data, ink (`--text`) for primary actions, colour reserved for severity, everything else greyscale, arrows for navigation, words instead of tick marks ("Pass", "Sent", "chain ok", never a check glyph). British English in all copy.

The app root needs `class="ck"` (see the header of `components.css`).

## Contents

1. [App shell](#1-app-shell): `.app`, `.side`, `.brand`, `.nav`, `.side-foot`, `.main`, `.top`, `.content`
2. [Page header and breadcrumb](#2-page-header-and-breadcrumb): `.ph`, `.crumb`
3. [Layout helpers](#3-layout-helpers): `.row`, `.stack`, `.g-*`, text helpers
4. [Card](#4-card): `.card`, `.card-h`, `.sec-h`, `.more`
5. [KPI](#5-kpi): `.kpi`, `.kpi-strip`, `.spark`
6. [Severity, CVSS, verdict](#6-severity-cvss-verdict): `.sev`, `.cvss`, `.vd`
7. [Privacy level badge](#7-privacy-level-badge): `.lvl`, `.meter`
8. [Pills, chips, tags, status, hash](#8-pills-chips-tags-status-hash): `.pill`, `.chip`, `.tag`, `.st`, `.dot`, `.hash`, `.kbd`
9. [Buttons](#9-buttons): `.btn` and modifiers, `.iconbtn`
10. [Form controls](#10-form-controls): `.fld`, `.inp`, `.sw`, `.chk`, `.swrow`, `.seg`
11. [Tabs and stepper](#11-tabs-and-stepper): `.tabs`, `.steps`, `.step`
12. [Table](#12-table): `.tbl-wrap`, `.tbl`
13. [Code viewer and privacy markup](#13-code-viewer-and-privacy-markup): `.code`, `.ln`, `.rd`, `.rn`, `.gen`, `.fold`, diff
14. [Taint path](#14-taint-path): `.taint`, `.tnode`, `.tedge`
15. [Pipeline stepper](#15-pipeline-stepper): `.pipe`, `.stage`, `.stand`
16. [Guard row (checks list)](#16-guard-row-checks-list): `.guard`
17. [Notes, banners, toasts](#17-notes-banners-toasts): `.note`, `.banner`, `.toast`
18. [Data viz](#18-data-viz): `.bar`, `.vbars`, `.legend`, `.hm`, `.rm`, frontier SVG, `.ci-bar`, `.hbar`, `.tokbar`
19. [Definition list, timeline, avatar](#19-definition-list-timeline-avatar): `.dl`, `.timeline`, `.avatar`
20. [Selection cards](#20-selection-cards): `.lvlcard`, `.provlogo`
21. [Console (live log)](#21-console-live-log): `.console`
22. [States: skeleton, empty, error](#22-states-skeleton-empty-error)
23. [Command palette](#23-command-palette)
24. [Report page preview](#24-report-page-preview): `.page`
25. [Small extras](#25-small-extras): CI badge, drop zone, list row, vault tooltip

---

## 1. App shell

Two columns: a 228 to 236 px side nav and a main column. Below 760 px the side nav becomes a top strip, nav items wrap in a row, sub-items lose their indent and the side footer is hidden (built into the CSS).

```html
<div class="ck app">
  <aside class="side" aria-label="Main navigation">
    <a class="brand" href="/">
      <svg class="logo" viewBox="0 0 28 28" aria-hidden="true"><!-- logo, see SCREENS.md#logo --></svg>
      <span><span class="brand-name">CodeKavach</span><br><span class="brand-sub">कवच · secure code review</span></span>
    </a>
    <nav class="nav">
      <a class="on" href="/"><Icon name="grid"/>Overview</a>
      <a href="/projects"><Icon name="folder"/>Projects</a>
      <a href="/scans"><Icon name="gauge"/>Scans</a>
      <a href="/findings"><Icon name="flag"/>Findings</a>
      <div class="nav-h">Privacy</div>
      <a href="/privacy"><Icon name="shield"/>Privacy Centre</a>
      <a class="subnav" href="/privacy/inspect">Privacy Inspect</a>
      <a href="/privacy/ledger"><Icon name="lines"/>Egress Ledger</a>
      <a href="/privacy/policy"><Icon name="sliders"/>Policy</a>
      <div class="nav-h">Deliver</div>
      <a href="/reports"><Icon name="doc"/>Reports</a>
      <a href="/integrations"><Icon name="plug"/>Integrations</a>
      <a href="/providers"><Icon name="chip"/>Providers</a>
      <div class="nav-h">Organisation</div>
      <a href="/evaluation"><Icon name="bars"/>Evaluation</a>
      <a href="/admin"><Icon name="users"/>Admin</a>
      <a href="/settings"><Icon name="cog"/>Settings</a>
    </nav>
    <div class="side-foot">
      <a class="btn sm" href="/demo" style="justify-content:flex-start"><Icon name="play"/>Demo mode</a>
      <a class="btn sm ghost" href="/how-it-works" style="justify-content:flex-start">How it works</a>
      <div class="xs faint" style="padding:4px 10px">v0.9.0 · Demo Organisation</div>
    </div>
  </aside>
  <div class="main">
    <header class="top">…</header>
    <main class="content">…</main>
  </div>
</div>
```

- Active item: `class="on"` (surface-3 background, ink text, 600). A sub-item that is active is `class="subnav on"`. Finding detail keeps "Findings" active.
- Side footer, active states: on Demo mode the button gets `style="border-color:var(--accent);background:var(--accent-soft)"`; on How it works the ghost button gets `class="btn sm ghost on"` and `color:var(--text)`.
- Footer text = `v{GET /version .version} · {settings.org_name}`.

### Top bar

```html
<header class="top">
  <button class="pill" type="button"><Icon name="folder"/>kavachbank-core<Icon name="chevron-down"/></button>
  <span class="pill priv"><Icon name="shield"/>L3 · Minimal slice</span>
  <span class="pill off"><span class="dot"></span>Offline · air-gapped</span>
  <span class="pill"><Icon name="chip"/>Mock (offline)</span>
  <span class="grow"></span>
  <div class="search" role="search"><Icon name="search"/><span class="grow">Search findings, files, scans</span><span class="kbd">⌘K</span></div>
  <button class="iconbtn" type="button" aria-label="Notifications, 3 unread"><Icon name="bell"/><span class="badge-n">3</span></button>
  <div class="user"><span class="avatar">AV</span><span style="line-height:1.15"><span class="sm" style="font-weight:600">Asha Verma</span><br><span class="role">Auditor</span></span></div>
</header>
```

- Pill 1: project switcher (dropdown of `GET /projects`). On organisation-level pages (Admin) it reads the organisation name with no folder icon; on onboarding it reads "New project".
- Pill 2 (`.pill.priv`): the effective privacy level, `L{n} · {level name}`. On Admin it reads "Floor L2 · default L3". On onboarding and Privacy Inspect it follows the level chosen on the page.
- Pill 3 (`.pill.off`, green dot): network posture, "Offline · air-gapped". Hidden or replaced when online (NEW: needs a network posture field; `GET /health` is the natural home).
- Pill 4: active provider (`settings.default_provider` and its `ProviderInfo.name`). Omitted on Admin.
- `.badge-n` is a 7 px red dot; the count is only in `aria-label`.
- `.role` is the capitalised `User.role`. Avatar initials from `display_name`.

### Content area

`<main class="content">` is a flex column, gap 20 px, padding 24/28 px, max-width 1440 px. Onboarding uses `style="max-width:1180px"`, Settings `style="max-width:1100px"`.

## 2. Page header and breadcrumb

```html
<div class="ph">
  <div>
    <div class="crumb"><a href="/">kavachbank-core</a><span>/</span><span>Findings</span></div>
    <h1>Findings</h1>
    <p class="sub" style="margin-top:4px">Optional one-line description.</p>
  </div>
  <div class="row"><span class="sub">Context text</span><button class="btn">Secondary</button><button class="btn pri">Primary</button></div>
</div>
```

`.ph` aligns to the bottom (`align-items:flex-end`) and wraps. `h1` is 22 px / 600 / -0.01em. Breadcrumb is 12.5 px faint; links turn accent on hover; separator is a literal `/` span. A standalone breadcrumb can be `<nav class="crumb" aria-label="Breadcrumb">`, the current item may be `style="color:var(--text)"`.

## 3. Layout helpers

| Class | Effect |
|---|---|
| `.row` | flex, centred, gap 8, wraps |
| `.row.between` | plus `justify-content:space-between` |
| `.stack` | flex column, gap 12; `.s6` `.s16` `.s20` change the gap |
| `.g` | grid, gap 16 |
| `.g-kpi` | auto-fit, min 170 px |
| `.g-2` / `.g-3` / `.g-4` | auto-fit, min 440 / 300 / 230 px |
| `.g-side` | main + 360 px right rail; one column under 1100 px |
| `.g-side-l` | 280 px left rail + main; one column under 1100 px |
| `.hr` | 1 px rule |
| `.muted` `.faint` `.acc` `.okc` `.badc` | text colours: muted, faint, accent, ok text, critical text |
| `.sm` `.xs` | 12.5 px, 11.5 px |
| `.mono` | IBM Plex Mono |
| `.up` / `.down` | red / green delta text (more findings is "up" and bad) |

## 4. Card

```html
<div class="card">
  <div class="card-h">
    <div><h2>Findings trend</h2><p class="sub">Open findings by severity, last 12 weeks</p></div>
    <a class="more" href="/findings">Open findings <Icon name="arrow-right"/></a>
  </div>
  …
</div>
```

- `.card`: white, 1 px `--border`, radius 8, padding 18. `h2`/`h3` inside are 14 px / 600.
- `.card.flat`: `--surface-2` background.
- `.card-h`: title row, space-between, margin-bottom 14.
- `.card.stack` is common: card with a 12 px vertical gap instead of `.card-h`.
- `.sec-h`: 11 px uppercase overline, 0.08em tracking, faint.
- `.more`: accent link with a trailing arrow; external links use the `arrow-up-right` icon.
- A card that is a link (`<a class="card stack" style="text-decoration:none">`) is used on Demo mode.
- Highlighted cards: `style="border-color:var(--high)"` (what leaves) and `style="border-color:var(--ok)"` (what stays) on onboarding step 3.

## 5. KPI

```html
<div class="kpi">
  <div class="k-l">Bytes egressed, this scan</div>
  <div class="k-v">412.6 <small>KB</small></div>
  <div class="k-d"><Icon name="arrow-up" style="width:12px;height:12px"/>4.1% vs last scan · 142 payloads</div>
  <svg class="spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true"><polyline points="0,22 12,20 …"/></svg>
</div>
```

- `.k-l` 12.5 muted label; `.k-v` 28 px / 500 tabular; `small` 13 px faint unit; `.k-d` 12 px faint detail; add `.down` (green) or `.up` (red) on `.k-d` for deltas.
- **KPI strip** (Overview, Privacy Inspect, Scan egress meter): a `.card` with `style="padding:0"` wrapping a grid of KPIs separated by right borders. Use `<div class="kpi-strip">` (Overview, 190 px min, KPIs padded 18/20), `.kpi-strip.sm` (Privacy Inspect, 140 px min, padding 14/18, value 22 px) or `.kpi-strip.boxed` (inside a card, own border and radius, padding 14/16). KPIs in a strip may be `<a class="kpi" href>` links.
- Severity breakdown inside `.k-d`: `<span class="sev c" style="height:auto">3</span><span class="sev h" style="height:auto;margin-left:8px">9</span>…`

## 6. Severity, CVSS, verdict

Severity always pairs colour with a marker shape so it reads in greyscale.

```html
<span class="sev c">Critical</span>   <!-- red diamond -->
<span class="sev h">High</span>       <!-- orange square -->
<span class="sev m">Medium</span>     <!-- yellow circle -->
<span class="sev l">Low</span>        <!-- blue ring -->
<span class="sev i">Info</span>       <!-- grey dash -->
```

Map `Severity` to modifier: critical `c`, high `h`, medium `m`, low `l`, info `i`. Empty `<span class="sev c"></span>` gives the marker alone.

```html
<span class="cvss c"><b>9.3</b><span>CVSS 4.0</span></span>
```

Modifier from score band: `c` 9.0 to 10, `h` 7.0 to 8.9, `m` 4.0 to 6.9, `l` 0.1 to 3.9. The trailing span is optional (tables show only the box) and reads "v4.0" or "CVSS 4.0".

```html
<span class="vd conf">Confirmed</span>       <!-- red dot -->
<span class="vd like">Likely</span>          <!-- orange dot -->
<span class="vd rev">Needs review</span>     <!-- hollow blue ring -->
<span class="vd fp">False positive</span>    <!-- grey, struck through -->
```

Verdict comes from `Finding.llm` (`is_vulnerable`, `confidence`); NEW: the contract has no explicit verdict enum, so map: confirmed = vulnerable and confidence >= 0.8, likely = vulnerable and below 0.8, needs review = confidence below 0.65 or runs disagree, false positive = status `false_positive`. Prefer a server-side `verdict` field (NEW).

## 7. Privacy level badge

Neutral greyscale, never a severity colour. The meter shows protection: more filled bars means less leaves.

```html
<span class="lvl">L3 Minimal slice<span class="meter"><i class="f"></i><i class="f"></i><i class="f"></i><i></i><i></i></span></span>
```

| Level | Name | Filled bars | Caption |
|---|---|---|---|
| L0 | Local only | 5 | nothing leaves |
| L4 | Facts only | 4 | no code |
| L3 | Minimal slice | 3 | default |
| L2 | Pseudonymised | 2 | whole files, renamed |
| L1 | Redacted | 1 | secrets and PII removed |

In tables the badge is just `<span class="lvl">L3</span>` with no meter. "never-send" can also be shown as `<span class="lvl">never-send · 1</span>`.

## 8. Pills, chips, tags, status, hash

```html
<span class="pill">Mock (offline)</span>                        <!-- 32 px, top bar -->
<span class="chip">486 files</span>                              <!-- 24 px, neutral -->
<span class="chip on">OWASP ASVS</span>                          <!-- selected (accent soft) -->
<span class="chip new">New</span>                                <!-- accent outline -->
<span class="chip fixed">chain ok</span>                         <!-- success -->
<a class="tag" href="https://cwe.mitre.org/data/definitions/89.html">CWE-89</a>  <!-- 22 px mono -->
<span class="st"><span class="dot ok"></span>Completed</span>    <!-- status with dot -->
<span class="hash">7c1e9a…94af<button type="button" aria-label="Copy hash"><Icon name="copy"/></button></span>
<span class="kbd">⌘K</span>
```

- Dots: `.dot` grey (neutral, dry-run, genesis, not checked), `.dot.ok` green, `.dot.warn` orange, `.dot.bad` red, `.dot.acc` blue (running).
- Hashes are shown as the first 6 and last 4 hex characters joined by `…`, optionally prefixed `sha256:`. The copy button is optional.
- Chips used as toggles (report frameworks and formats) switch between `.chip` and `.chip.on`.

## 9. Buttons

```html
<button class="btn pri" type="button">Run scan</button>         <!-- ink, white text -->
<button class="btn" type="button">Export</button>               <!-- outline -->
<button class="btn ghost" type="button">Cancel</button>         <!-- text only -->
<button class="btn danger" type="button">Purge vault</button>   <!-- red text, red border -->
<button class="btn sm">…</button>                               <!-- 30 px -->
<a class="btn pri xl" href="/scans/new"><Icon name="play" class="ico lg"/>Run KavachBank demo</a>  <!-- 48 px -->
<button class="iconbtn" type="button" aria-label="Close"><Icon name="close"/></button>
```

- Filter buttons are `.btn.sm` with a trailing `chevron-down` icon: "Severity: Critical, High ▾".
- Disabled: native `disabled` attribute (Pagination "Previous").
- `.btn` with `style="width:100%"` on the login form.

## 10. Form controls

```html
<div class="fld"><label for="repo">Repository</label><input id="repo" class="inp mono" value="/srv/repos/kavachbank-core"></div>
<div class="fld"><label for="prov">Provider</label><select id="prov" class="inp"><option>Mock (offline)</option></select></div>
<div class="fld"><label for="c">Add a comment</label><textarea id="c" class="inp" rows="2"></textarea></div>
<label class="swrow"><input type="checkbox" class="sw" checked> No-send (dry run)</label>     <!-- switch -->
<label class="swrow"><input type="checkbox" class="chk" checked> Opengrep</label>            <!-- checkbox -->
<div class="fld"><span class="lbl">Mode</span><div class="seg"><button class="on" type="button">Branch</button><button type="button">Diff</button></div></div>
```

- `.inp` is 36 px; `.inp.mono` for paths, globs, branches; inside tables use `.inp sm` (30 px).
- `.lbl` is the label style for groups that are not a single input.
- `.seg` is a segmented control; the active segment has `class="on"`. Use `role="tablist"` when it switches views (Privacy Inspect).
- Multi-line consent: `<label class="swrow" style="align-items:flex-start"><input type="checkbox" class="chk" style="margin-top:3px"> long text…</label>`.
- Two-up switch with a description (Integrations): `<label class="swrow"><input type="checkbox" class="sw"> <span><b class="sm">SARIF upload</b><br><span class="xs faint">Code scanning alerts, SARIF 2.1.0</span></span></label>`, inside `.swgrid`.

## 11. Tabs and stepper

```html
<div class="tabs" role="tablist">
  <button class="on" type="button">All open <span class="cnt">43</span></button>
  <button type="button">Critical and high <span class="cnt">12</span></button>
</div>
```

Ink underline on the active tab, counts in `.cnt`. Inside a card, give the card `style="padding-top:6px"` and the panel `style="padding-top:14px"` (Finding detail).

```html
<nav class="steps" aria-label="Setup steps">
  <button type="button" class="step done"><span class="sc">1</span>Connect repository</button>
  <button type="button" class="step on"><span class="sc">2</span>Detect inventory</button>
  <button type="button" class="step"><span class="sc">3</span>Privacy level</button>
</nav>
```

Step classes: `done` before the current step, `on` for the current one, none after.

## 12. Table

```html
<div class="tbl-wrap"><table class="tbl">
  <thead><tr><th>Scan</th><th class="num">Findings</th><th>Status</th></tr></thead>
  <tbody>
    <tr class="sel">
      <td class="mono"><a class="t-title" href="/scans/SCN-0142">SCN-0142</a></td>
      <td class="num mono">43</td>
      <td><span class="st"><span class="dot ok"></span>Completed</span></td>
    </tr>
  </tbody>
</table></div>
```

- Header cells: 12 px faint on `--surface-2`. Cells 10/12 px padding, no wrapping; `td.wrap` allows wrapping (min 240 px) for titles.
- `.num` right-aligns with tabular numbers; numbers also get `.mono`.
- `tr.sel` = selected or highlighted row (accent soft).
- Finding title cell: `<td class="wrap"><a class="t-title" href>Title</a><div class="xs faint mono">KB-2026-0012 · <span style="color:var(--accent)">New</span></div></td>`; the suffix is `New` (accent), `Unchanged` (faint) or `Fixed in branch` (`.okc`).
- Row checkbox column: `<th style="width:32px"><input type="checkbox" class="chk" aria-label="Select all"></th>`.
- Pagination row below the table: `<div class="row between sm muted"><span>Showing 1-12 of 43</span><div class="row"><button class="btn sm" disabled>Previous</button><button class="btn sm">Next<Icon name="arrow-right"/></button></div></div>`. The ledger uses "Showing 10 of 142" and a "Load more" button with `arrow-down`.
- A table inside a card without its own frame: `<div class="tbl-wrap" style="border:0">`.

## 13. Code viewer and privacy markup

```html
<div class="code-h"><span class="mono">app/statements/repository.py</span><span class="faint">Local only · never sent</span></div>
<div class="code">
  <div class="ln"><span class="n">52</span><span class="tk">def</span> <span class="tf">fetch_statement</span>(account_id, month, sort_by):</div>
  <div class="ln hl"><span class="n">58</span>    sql = (<span class="ts">"SELECT …"</span></div>
  <div class="ln src"><span class="n">24</span>…</div>
  <div class="ln sink"><span class="n">61</span>    cursor.execute(sql)</div>
  <div class="ln out"><span class="n">70</span>…</div>
  <div class="fold">lines 18-30 not sent</div>
</div>
```

- Line kinds: plain, `hl` (slice / relevant, pale blue), `src` (taint source, low-bg blue), `sink` (taint sink, crit-bg red), `out` (dimmed, outside slice).
- `.fold` is a dashed separator for skipped regions: "lines 1-10 not sent", "lines 18-28 sent unchanged", "region 2 · file_e01b.py".
- Syntax spans: `.tk` keyword (bold), `.ts` string, `.tc` comment (italic), `.tf` function, `.tn` number.
- Privacy markup (payload side):
  - `<span class="rd">&lt;SECRET:AWS_KEY_1&gt;</span>` redacted secret or PII (red on pink). Map `Markup.kind` `secret` and `pii`.
  - `<span class="rn">fn_a83c</span>` renamed identifier (blue on pale blue). `Markup.kind` `identifier`.
  - `<span class="gen">"&lt;STR_2&gt;"</span>` generalised literal or comment (faint italic). `Markup.kind` `literal`.
- Diff lines: `.ln.diff-add` (green, `+` after the number) and `.ln.diff-del` (red, `-`).
- `.code-h + .code` joins the header and body into one frame. The header's right side states where the code lives ("Stays on this machine", "Prepared for the model" in `color:var(--high-t)`, "+5 −4", "402 B", a "Copy" `.btn.sm`, or a validity status).
- Plain snippet: `<div class="code cmd">kavach mcp serve --read-only</div>`; free text: `.code.facts` (L4 facts).
- Legend above side-by-side code: `<div class="legend"><span><span class="rd">red</span> redacted secret</span><span><span class="rn">blue</span> renamed identifier</span><span><span class="gen">grey italic</span> generalised string or comment</span><span><span class="fold" style="margin:0;display:inline-flex">dashed</span> not sent</span></div>`.
- Vault tooltip in a payload (restored name, never sent): mark the pseudonym `<span class="rn focus">fn_a83c</span>` and insert after the line `<div class="vault-tip"><div><span class="mono rn">fn_a83c</span> <span class="faint">is</span> <span class="mono"><b>calculateInterest</b></span></div><div class="xs faint" style="margin-top:2px">Restored locally from vault. Never sent.</div></div>`.

## 14. Taint path

```html
<div class="taint">
  <a class="tnode src" href="#L21"><span class="tk-l">1 · Source</span><code>request.args.get("month")</code><span class="tl">api/statements.py:21</span></a>
  <div class="tedge"><Icon name="arrow-right"/></div>
  <a class="tnode" href="#L23"><span class="tk-l">2 · Propagation</span><code>fetch_statement(…, month, sort)</code><span class="tl">api/statements.py:23</span></a>
  <div class="tedge"><Icon name="arrow-right"/></div>
  <a class="tnode san" href="#L59"><span class="tk-l">Sanitiser · none</span><code>f"… '{month}' …"</code><span class="tl">repository.py:59 · validate_month() exists, not called</span></a>
  <div class="tedge"><Icon name="arrow-right"/></div>
  <a class="tnode sink" href="#L61"><span class="tk-l">4 · Sink</span><code>cursor.execute(sql)</code><span class="tl">repository.py:61</span></a>
</div>
```

`TaintStep.kind` maps to node class: `source` → `src`, `propagation` → none, `sanitiser` → `san` (dashed border), `sink` → `sink` (red tint). Label is `{index} · {Kind}`; a missing sanitiser reads "Sanitiser · none". Node `code` = `TaintStep.code`, `.tl` = `{path}:{line}`. Selecting a node jumps to that line in the code tab.

## 15. Pipeline stepper

Nine stages, in this order and wording: `01 Ingest & parse` (Local), `02 Deterministic analysis` (Local), `03 Candidate findings` (Local), `04 Privacy layer` (Local, `.guardz` tint), `05 LLM reasoning` (`.loc.rem` "Remote or local", orange), `06 De-pseudonymise` (Local), `07 Risk rating` (Local), `08 Audit report` (Local), `09 Issue sync` (Optional).

```html
<div class="pipe-wrap"><div class="pipe">
  <div class="stage done"><span class="sn">01</span><span class="st-t">Ingest &amp; parse</span><span class="cnt">486 files</span></div>
  <div class="stage done guardz"><span class="sn">04</span><span class="st-t">Privacy layer</span><span class="cnt">142 slices</span></div>
  <div class="stage run"><span class="sn">05 running</span><span class="st-t">LLM reasoning</span><span class="cnt">94 / 142 sent</span></div>
  <div class="stage wait"><span class="sn">07</span><span class="st-t">Risk rating</span><span class="cnt">waiting</span></div>
</div></div>
```

- State class: `done` (ink underline), `run` (blue underline, blue bold number, `sn` text gets " running"), `wait` (faint). Several stages can run at once.
- Third line: `.loc` (where it runs) on the design board, `.cnt` (live count) on the scan page.
- The grid is 9 columns, min 1060 px, inside `.pipe-wrap` (horizontal scroll).
- `.stand` is a standalone stage box used in How it works: `<div class="stand"><span class="sn">01</span><span class="st-t">Ingest &amp; parse</span><span class="xs muted">ASTs, symbols, call graph</span></div>`.

## 16. Guard row (checks list)

```html
<div class="guard"><span class="gid">I1</span><span class="gt">Single transport module</span><span class="chk">Pass</span></div>
<div class="guard"><span class="gt">Disk free · 11% on /var/lib/kavach</span><span class="note-w">Low</span></div>
```

`.gid` is optional (24 px mono id). `.chk` renders a green dot plus the word ("Pass"). A non-passing result uses `.note-w` (orange word: "Note", "Low"). Also used for token and key lists: `.gt` holds `<b class="sm" style="color:var(--text)">name</b><br><span class="xs">scopes · expiry</span>` and the right side holds a mono masked token, a `.st` status or a `.btn.sm`.

## 17. Notes, banners, toasts

```html
<div class="note"><b>What this does not cover.</b><ul><li>…</li></ul></div>    <!-- top rule only -->
<div class="note box"><b>…</b><ul>…</ul></div>                                <!-- framed, surface-2 -->
<div class="banner">…</div>                       <!-- success (green) -->
<div class="banner info"><Icon name="info"/><span><b>Mock provider:</b> …</span></div>
<div class="banner warn sm">Mock provider: the ledger shows what <i>would</i> have been sent. Nothing left this laptop.</div>
<div class="banner bad sm">Privacy step failed. Request aborted under I4. Nothing was sent.</div>
<div class="toast"><div><b>Ledger chain verified</b><div class="sub">142 records · chain, payload hash and zero-leak checks passed</div></div></div>
```

- "What this does not cover" notes appear on every privacy surface; keep them.
- Split banner (ledger verification): `<div class="banner info split">` with one `div` per cell (see SCREENS.md, Egress Ledger).
- Toast: ink background, white text, max 380 px, bottom-right (position it fixed yourself; the design shows it in place).

## 18. Data viz

- **Bar**: `<div class="bar"><i style="width:47%"></i></div>` (6 px, accent fill). `.bar.priv` or `.bar.ink` use an ink fill (privacy score parts, budgets). Severity-coloured fill via inline `background`.
- **Labelled bar**: `<div class="meter-row"><div class="row"><span class="muted">Slice minimality · 11.4 lines avg</span><span class="mono">88</span></div><div class="bar priv"><i style="width:88%"></i></div></div>`.
- **Stacked columns** (findings trend):

  ```html
  <div class="vbars" role="img" aria-label="Open findings fell from 58 to 43 over 12 weeks">
    <div class="col"><i style="height:16px;background:var(--crit)"></i><i style="height:36px;background:var(--high)"></i><i style="height:52px;background:var(--med)"></i><i style="height:47px;background:var(--border-strong)"></i></div>
    …
  </div>
  <div class="xax"><span>24 Aug</span><span>31</span>…</div>
  ```

  Columns stack bottom-up (critical at the bottom). Plot height 170 px. Low and info are grouped in `--border-strong`. X labels show the month only on the first week of a month.
- **Legend**: `<div class="legend"><span><i style="background:var(--crit)"></i>Critical</span>…</div>` (8 px squares).
- **Heatmap** (OWASP × source): `<div class="hm" style="grid-template-columns:220px repeat(6,minmax(56px,1fr));min-width:620px">` with row label `<span class="sm" style="align-self:center">A05 Injection</span>` and cells `<span class="c h4">5</span>`. Bucket: 0 → `h0`, 1 → `h1`, 2 → `h2`, 3-4 → `h3`, 5+ → `h4`. Wrap in `overflow-x:auto`.
- **Risk matrix**: `<div class="rm">` 6 columns (24 px axis + 5). Rows from likelihood 5 down to 1, each `<span class="ax">5</span>` then five `<span class="c rN">count</span>` (empty when 0); last row `<span></span><span class="ax">1</span>…<span class="ax">5</span>`. Under it `<div class="row between xs faint" style="margin-top:8px"><span>Likelihood ↑</span><span>Impact →</span></div>`. Cell colour `rN` is fixed by position, not by count (r1 grey, r2 blue, r3 yellow, r4 orange, r5 red). The design's lookup, likelihood rows 5 to 1, impact columns 1 to 5:

  | L \ I | 1 | 2 | 3 | 4 | 5 |
  |---|---|---|---|---|---|
  | 5 | r2 | r3 | r4 | r5 | r5 |
  | 4 | r1 | r2 | r3 | r4 | r5 |
  | 3 | r1 | r2 | r3 | r3 | r4 |
  | 2 | r1 | r1 | r2 | r2 | r3 |
  | 1 | r1 | r1 | r1 | r1 | r2 |
- **Frontier chart**: inline SVG 520×240, axes `--border-strong`, gridlines `--border` dashed 3 3, labels 11 px `--faint`, line `--accent` 1.5 px, points r=4 (SAST-only point hollow ink, levels accent, the default L3 point r=5 ink with a 12 px 600 label). Exact markup in SCREENS.md, Privacy Centre.
- **CI bar**: `<div class="ci-bar acc" style="--lo:75%;--hi:85%;--pt:80%"><i class="ci"></i><i class="pt"></i></div>`; the `.acc` variant marks the highlighted (default) arm.
- **Horizontal bars**: `<div class="hbar"><span class="hb-l"><b>+ LLM · L3</b></span><div class="hb-t"><i class="acc" style="width:80%"></i></div><span class="hb-v"><b>0.80</b></span></div>` (`i.base` for the baseline arm, plain `i` muted).
- **Token bar**: `<div class="tokbar"><i style="width:66%"></i><i class="out" style="width:14%"></i></div>`.
- **Sparkline**: `.spark` polyline, accent 1.5 px, 28 px high.
- **Donut**: `.donut` (120 px) is defined but unused on the screens.

## 19. Definition list, timeline, avatar

```html
<dl class="dl"><dt>Status</dt><dd>…</dd><dt>Assignee</dt><dd class="row"><span class="avatar xs">RI</span>Rohan Iyer</dd></dl>

<div class="timeline">
  <div class="tl-i"><span class="avatar">AV</span><div><div><b>Asha Verma</b> <span class="muted">commented</span></div><p class="sm" style="margin-top:4px">Reproduced on staging…</p><div class="xs faint">10:49</div></div></div>
</div>
```

`.dl` is a two-column grid (label faint). Add `.sm` for the compact version. Avatar: 30 px circle with initials; `.avatar.sm` 26 px (tables), `.avatar.xs` 22 px, `.avatar.lg` 48 px; timeline avatars are 26 px automatically. The system actor shows initials `CK`.

## 20. Selection cards

```html
<button type="button" class="lvlcard on"><b>Local path</b><span class="sub">A folder on this machine</span></button>
<button type="button" class="lvlcard"><span class="lvl">L2<span class="meter">…</span></span><b>Pseudonymised</b><span class="sub">…</span></button>
<button type="button" class="lvlcard"><div class="row between"><span class="provlogo">M</span><span class="chip fixed">Default</span></div><b>Mock</b><span class="sub">Offline · no key. …</span></button>
```

Selected card: `.on` (ink border plus 1 px ink outline). `.provlogo` is a 36 px rounded square with one or two letters (M, R, L, A, O, G, GH, +).

## 21. Console (live log)

```html
<div class="console" role="log">
  <div><span class="t">10:43:02</span>  ingest     parsed 486 files (py 214, js 188, java 52, go 21, iac 11)</div>
  <div><span class="t">10:43:19</span>  <span class="acl">privacy    policy: config/** never-send · 1 payload blocked</span></div>
  <div><span class="t">10:43:25</span>  <span class="okl">verdict    KB-2026-0012 confirmed · confidence 0.94</span></div>
  <div><span class="t">10:43:27</span>  <span class="wl">verdict    KB-2026-0035 needs review · confidence 0.61</span></div>
</div>
```

240 px tall, scrolls. Format: time, two spaces, stage name padded to 10 characters, message. Colour classes: `.acl` accent (policy events), `.okl` green (confirmed), `.wl` orange (needs review, warnings). Feed from SSE `log` events (and `finding` events).

## 22. States: skeleton, empty, error

The sitemap says every screen ships with empty, loading (skeleton) and error states, as on the design system board:

```html
<!-- loading -->
<div class="stack s6"><div class="skel" style="width:60%"></div><div class="skel"></div><div class="skel" style="width:80%"></div></div>
<!-- empty -->
<div class="empty"><b style="color:var(--text)">No findings yet</b><span class="sm">Run a scan to see results here.</span><a class="more" href="/scans/new">Run a scan <Icon name="arrow-right"/></a></div>
<!-- error -->
<div class="banner bad sm">Privacy step failed. Request aborted under I4. Nothing was sent.</div>
```

`.empty .em-ico` (40 px framed icon box) is available for an icon above the title. Skeleton bars are 10 px high; use rows of three with widths 60%, 100%, 80%. In tables, render skeleton bars inside cells.

## 23. Command palette

Opened by ⌘K / Ctrl+K from the top-bar search.

```html
<div class="palette">
  <div class="pal-in"><Icon name="search" class="ico faint"/><span style="flex:1">inspect KB-2026-0012</span><span class="kbd">esc</span></div>
  <div class="pal-list">
    <div class="pal-i on"><span class="sev c"></span><span style="flex:1">Open Privacy Inspect for KB-2026-0012</span><span class="kbd">↵</span></div>
    <div class="pal-i"><span class="pal-k">ACTION</span><span style="flex:1">Run KavachBank demo (offline)</span></div>
    <div class="pal-i"><span class="pal-k">ACTION</span><span style="flex:1">Verify egress ledger chain</span></div>
  </div>
</div>
```

Show it centred over a modal overlay (the design shows only the panel). Findings rows lead with a severity marker; actions lead with a mono `ACTION` label.

## 24. Report page preview

```html
<div class="g g-2 page-tray">
  <div class="page" style="min-height:560px">…</div>
</div>
```

`.page` imitates a printed A4 page: white, 36/40 px padding, 12 px text, `h3` 18 px, `.pm` meta grey, bordered tables with `th` on light grey. The cover title uses IBM Plex Serif 26 px. Full content in SCREENS.md, Reports.

## 25. Small extras

- **CI badge**: `<span class="ci-badge"><span>codekavach</span><span class="bad">3 critical</span></span>` and `<span class="ci-badge"><span>privacy</span><span class="ok">L3 · 0 leaks</span></span>`.
- **Drop zone**: `<div class="dropzone"><span class="sm muted">kavachbank-logo.svg</span><button class="btn sm">Replace</button></div>`.
- **List row**: `<div class="listrow"><div><b class="sm">Bank strict</b><div class="xs faint">Floor L2 · …</div></div><span class="chip on">Applied</span></div>`.
- **Bulk bar**: `<div class="bulkbar"><span class="sm"><b>2 selected</b></span><div class="row">…buttons…</div></div>`.
- **Settings section nav**: `<nav class="subnav-list" aria-label="Settings sections"><a class="btn ghost on" href="#profile">Profile</a>…</nav>`.
- **Logo on ink**: `<div class="brand-ink"><svg …logo with white bars and #6E95F5 accent…/><span style="font-weight:600;font-size:15px">CodeKavach</span></div>`.
