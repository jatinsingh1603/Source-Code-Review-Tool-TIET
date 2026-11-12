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
  components/   ui/ design-system primitives, layout/ shell, charts/, feature components
  lib/          formatting, privacy-level semantics, CVSS parsing, markup segmentation, theme
  mock/         fixture data and the in-browser mock backend
  pages/        one file per route
  styles/       tokens.css (all design tokens) and index.css
```

## Design tokens

Every colour, font, radius, shadow and layout size is a CSS variable in `src/styles/tokens.css`, with a light set on `:root` and a dark set on `:root.dark`; `tailwind.config.ts` maps them into the Tailwind theme (`bg-surface`, `text-fg-muted`, `bg-sev-critical-soft`, `text-lvl-3`, ...). To apply a new design system, replace the values in `tokens.css`; components do not hard-code colours. Colours are RGB channel triplets so opacity modifiers work (`bg-primary/10`).

Severity is always shown as colour plus icon plus label. The chart severity colours (`--ck-chart-*`) were checked for colour-vision-deficiency separation in both themes; badge colours are separate tokens tuned for text contrast.

## Privacy levels in the interface

The interface follows `docs/ARCHITECTURE.md` section 6.1: L0 sends nothing, L4 sends no code (abstract facts), L3 a pseudonymised minimal slice (default), L2 pseudonymised files, L1 code with only secrets and personal data replaced. Strictness is L1 < L2 < L3 < L4 < L0, so levels are listed in that order (strictest first) and a provider's privacy floor is applied as "the stricter level wins".

## Rendering rules

Finding text, model reasoning and code come from untrusted sources and are always rendered as text: no `dangerouslySetInnerHTML` (lint rule plus a test), no Markdown-to-HTML, no remote images or fonts. The HTML report preview is shown in a sandboxed iframe with scripts disabled. The bearer token lives in memory and `sessionStorage`, so closing the tab ends the session.

## Pages

Login, Overview (stat tiles, severity donut, findings trend, recent scans, privacy posture), Projects (sample, local path, git URL, archive upload), Project detail (scan history), New scan (source, privacy level with an egress preview, provider and model with a connection test, send toggle, rules), Scan (live stage stepper, progress, log and findings from the event stream; cancel), Findings (filters in the URL, bulk status change, GitHub sync), Finding detail (code evidence, data-flow path, model verdict, CVSS v4 and v3.1, OWASP, CWE, ASVS, CAPEC, compliance, remediation, triage, history), Privacy Centre (attestation, placeholders by type, ledger with hash-chain status and verification, side-by-side original and payload viewer), Reports (download every format, inline HTML preview), Providers and settings (provider cards with test, defaults, policy editor), Users (roles, activation, create and delete).
