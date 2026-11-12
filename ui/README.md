# CodeKavach dashboard (`ui/`)

The web dashboard of CodeKavach: a React, TypeScript, Vite and Tailwind single-page application that talks to the REST API of `codekavach serve` (`/api/v1`). Owning epic: E33.

## Quick start

```bash
cd ui
npm ci
npm run build            # writes ui/dist, which `codekavach serve` serves at /
cd .. && uv run codekavach serve --host 127.0.0.1 --port 8080
# open http://127.0.0.1:8080 and sign in as admin (password printed at start-up)
```

Development with hot reload (the Vite server proxies `/api` to `http://127.0.0.1:8080`, override with `CODEKAVACH_API`):

```bash
npm run dev              # http://localhost:5173, needs a running server
npm run dev:mock         # no server needed: built-in demo data
```

## Mock mode

Mock mode answers every API call from an in-browser backend with realistic data modelled on the KavachBank sample (`src/mock/`). It is for development and offline demonstrations only, and the dashboard shows a "Demo data mode" banner whenever it is active. Turn it on with `VITE_MOCK=1` at dev or build time (`npm run dev:mock`, `npm run build:mock`), or by opening any page with `?mock` (and off again with `?mock=0`). Sign in as `admin` / `kavach-admin` (also `auditor`, `developer`, `viewer` with `kavach-<role>`). Scans started in mock mode are simulated stage by stage over the same event types as the real server.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` / `dev:mock` | Vite dev server (real API / mock data) |
| `npm run build` / `build:mock` | Type-check and build to `dist/` |
| `npm run typecheck` | `tsc -b` with `strict` and `noUncheckedIndexedAccess` |
| `npm run lint` | ESLint, zero warnings; forbids `dangerouslySetInnerHTML` |
| `npm run test` | Vitest unit tests in `tests/` |

## Layout

```
src/
  api/          types.ts (contract shapes), client.ts (fetch wrapper, ApiError, 401/429),
                endpoints.ts (one function per endpoint), queries.ts (React Query hooks),
                events.ts (SSE over fetch with Last-Event-ID, backoff, polling fallback),
                useScanEvents.ts (live scan reducer)
  app/          router, session (auth, role guards), current project, selected scan
  components/   ui/ primitives that emit the design's markup, layout/ shell and command palette,
                feature components (privacy markup, frontier chart, filters, GitHub sync)
  data/         sample-eval/: copies of the committed evaluation results (docs/research/results)
  lib/          formatting and display conventions, privacy-level semantics, policy globs,
                CVSS parsing, markup segmentation, preferences
  mock/         fixture data and the in-browser mock backend
  pages/        one file per route
  styles/       fonts.ts (bundled @fontsource fonts) and index.css (Tailwind utilities, overlays)
```

## Design

The dashboard reproduces the approved design in [`design/`](design/README.md): `design/tokens.css` and `design/components.css` are imported as they are (in `main.tsx`), Tailwind uses `design/tailwind.preset.cjs` without its preflight, and components emit the class names listed in `design/COMPONENTS.md`. Screens follow `design/SCREENS.md`. When the code and the design disagree, the design wins; change the design first.

Light theme only, as designed. Fonts (IBM Plex Sans, Mono and Serif; Noto Sans Devanagari for the brand line) are bundled from `@fontsource`, so the dashboard makes no request outside its own server and works air-gapped. Icons are inline SVG.

Severity is always a colour plus a marker shape plus a word; privacy levels are neutral grey with a five-bar meter.

Values the API does not report are not invented: an element is derived from data the client has (for example the risk matrix from the findings) or shows an empty state. The Evaluation screen shows the committed sample results, labelled "Sample results", until the server has its own runs.

## Privacy levels in the interface

The interface follows `docs/ARCHITECTURE.md` section 6.1: L0 sends nothing, L4 sends no code (abstract facts), L3 a pseudonymised minimal slice (default), L2 pseudonymised files, L1 code with only secrets and personal data replaced. Strictness is L1 < L2 < L3 < L4 < L0, so levels are listed in that order (strictest first) and a provider's privacy floor is applied as "the stricter level wins".

## Rendering rules

Finding text, model reasoning and code come from untrusted sources and are always rendered as text: no `dangerouslySetInnerHTML` (lint rule plus a test), no Markdown-to-HTML, no remote images or fonts. The HTML report preview is shown in a sandboxed iframe with scripts disabled. The bearer token lives in memory and `sessionStorage`, so closing the tab ends the session, unless the user ticks "Remember this device" at sign-in.

## Pages

The nineteen screens of `design/SCREENS.md`: Login, Overview, Set up a project, Scan launch and live view, Findings, Finding detail, Privacy Centre, Privacy Inspect, Egress Ledger, Privacy policy, Providers, Reports, Integrations, Evaluation, Admin (users, organisations, API tokens, provider keys, audit log, retention, system health), Settings, Demo mode and How it works, plus Projects, Project detail and Scans lists in the same table pattern. ⌘K / Ctrl+K opens the command palette.
