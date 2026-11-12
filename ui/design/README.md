# Dashboard design

`codekavach-dashboard.html` is the approved design for the CodeKavach web dashboard, made with Claude Design. It is the single source of truth for the dashboard's look and feel: design tokens (the `.ck` custom properties), typography (IBM Plex Sans, Mono and Serif; Noto Sans Devanagari for the brand subtitle), the app shell, components and every screen.

The React app in `ui/src` reproduces this design. When the two disagree, the design wins.

Open it in a browser to view all screens (use the "Screen" menu at the bottom right). Names, emails, hosts and values in it are fictional demo data; the AWS key shown is AWS's documented example key.

## Design kit: use these instead of re-reading the prototype

The prototype is one 3,000-line HTML file. The files below extract everything from it in a form the React app can use directly, so you do not need to read the prototype to build or change a screen.

| File | What it is | How to use it |
|---|---|---|
| [`tokens.css`](tokens.css) | Every design token as a CSS custom property on `:root` and `.ck`, with the prototype's names (`--bg`, `--surface`, `--accent`, `--crit`, `--rename`, …), plus named extras (heatmap and risk ramps, line-number grey) and typography, radius, height and layout variables. Light theme only: the prototype has no dark theme. | Import once, first. |
| [`components.css`](components.css) | The prototype's component CSS, rule for rule, with the same class names (`.app`, `.side`, `.nav`, `.top`, `.card`, `.kpi`, `.sev`, `.lvl`, `.btn`, `.tbl`, `.code`, `.rd`, `.rn`, `.pipe`, `.stage`, `.taint`, `.guard`, …), plus a few classes for patterns the prototype wrote inline (`.kpi-strip`, `.ci-bar`, `.hbar`, `.tokbar`, `.vault-tip`, …). Rendering every prototype screen with these two files in place of its own `<style>` gives pixel-identical screenshots. | Import after `tokens.css` (and after Tailwind's base layer). Put `class="ck"` on the app root. |
| [`tailwind.preset.cjs`](tailwind.preset.cjs) | Tailwind preset mapping the same tokens: colours (`bg-surface-2`, `text-faint`, `text-crit-t`, `bg-rename-bg`, …), fonts, font sizes (`text-sm` = 12.5 px, `text-page`, `text-kpi`), radii, control heights, layout widths and the auto-fit grids. | `presets: [require("./design/tailwind.preset.cjs")]` in `ui/tailwind.config.ts`. |
| [`COMPONENTS.md`](COMPONENTS.md) | Component inventory: for each component, the exact HTML structure and classes, its variants and states, and which API field drives it. | Build each React component to emit this markup. |
| [`SCREENS.md`](SCREENS.md) | One section per screen: route, layout top to bottom, exact copy, interactions, loading/empty/error states, and the data for every element mapped to the `/api/v1` contract. Data the contract lacks is marked **NEW** and collected under "API gaps". Also holds the route table, role access, the full icon set (inline SVG paths) and the logo SVG. | Build or check a page against its section. |

### Wiring it into the app

```ts
// ui/src/main.tsx (or the global stylesheet)
import "../design/tokens.css";
import "../design/components.css";
```

```ts
// ui/tailwind.config.ts
import preset from "./design/tailwind.preset.cjs";
export default { presets: [preset], content: ["./index.html", "./src/**/*.{ts,tsx}"] };
```

Load the fonts in `index.html` exactly as the prototype does (the URL is in the header of `tokens.css`).

Both styling routes give the same result: a component can use the design classes (`<span className="sev c">Critical</span>`) or Tailwind utilities built on the same tokens (`text-crit-t bg-crit-bg`). Prefer the design classes for anything listed in `COMPONENTS.md`, so the markup stays 1:1 with the prototype; use utilities for one-off layout.

### Rules worth knowing before you start

- Flat: 1 px lines, no shadows, no gradients. One accent (blue) for links, selection and data; ink (near-black) for primary buttons. Colour is reserved for severity; everything else is greyscale.
- Severity always has a shape as well as a colour (`.sev.c` diamond, `.h` square, `.m` circle, `.l` ring, `.i` dash). Privacy levels are neutral grey with a 5-bar meter, never a severity colour.
- Words, not tick marks: "Pass", "Sent", "chain ok".
- Privacy screens keep their "What this does not cover" notes.
- British English in all copy (organisation, pseudonymise, behaviour).
- Every screen has loading (skeleton), empty and error states; see `COMPONENTS.md` §22.

### Changing the design

If the approved design changes, update `codekavach-dashboard.html` first, then bring `tokens.css` and `components.css` back in line (the class names and token names must keep matching the prototype), then the two Markdown files.
