/**
 * Tailwind preset for the CodeKavach design.
 *
 * Every value points at a CSS custom property from ./tokens.css, with the
 * prototype's names, so Tailwind utilities and the component classes in
 * ./components.css always agree. Import tokens.css once in the app.
 *
 * Use in ui/tailwind.config.ts:
 *
 *   import preset from "./design/tailwind.preset.cjs";
 *   export default { presets: [preset], content: [...] } satisfies Config;
 *
 * Utility names, for example:
 *   bg-bg bg-surface bg-surface-2 bg-surface-3 border-border border-border-strong
 *   text-ink text-muted text-faint text-accent bg-accent-soft border-accent-line
 *   bg-crit text-crit-t bg-crit-bg (same for high, med, low, info)
 *   text-ok-t bg-ok-bg bg-warn-bg text-redact bg-redact-bg text-rename bg-rename-bg
 *   font-sans font-mono font-serif font-deva
 *   text-xs (11.5) text-sm (12.5) text-control (13) text-base (14) text-page (22) text-kpi (28)
 *   rounded-xs (3) rounded-sm (4) rounded-md / rounded (6) rounded-lg (8)
 *   h-btn h-btn-sm h-input h-pill h-chip h-tag h-nav h-tab w-side max-w-content
 *   grid-cols-kpi grid-cols-auto-2 grid-cols-auto-3 grid-cols-auto-4 grid-cols-side grid-cols-side-l
 *   Breakpoints (max-width, as in the prototype): max-[760px]: and max-[1100px]:
 *
 * Colours are plain var() references (the tokens are hex values), so opacity
 * modifiers such as bg-accent/50 are not supported. The design does not use
 * transparency anywhere, so none are needed.
 *
 * Light theme only: the prototype has no dark theme.
 */

/** @param {string} name */
const v = (name) => `var(--${name})`;

/** @type {import('tailwindcss').Config} */
module.exports = {
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        surface: { DEFAULT: v("surface"), 2: v("surface-2"), 3: v("surface-3") },
        border: { DEFAULT: v("border"), strong: v("border-strong") },
        ink: v("text"),
        text: v("text"),
        muted: v("muted"),
        faint: v("faint"),
        accent: {
          DEFAULT: v("accent"),
          ink: v("accent-ink"),
          soft: v("accent-soft"),
          line: v("accent-line"),
        },
        crit: { DEFAULT: v("crit"), t: v("crit-t"), bg: v("crit-bg") },
        high: { DEFAULT: v("high"), t: v("high-t"), bg: v("high-bg") },
        med: { DEFAULT: v("med"), t: v("med-t"), bg: v("med-bg") },
        low: { DEFAULT: v("low"), t: v("low-t"), bg: v("low-bg") },
        info: { DEFAULT: v("info"), t: v("info-t"), bg: v("info-bg") },
        priv: { DEFAULT: v("priv"), bg: v("priv-bg") },
        ok: { DEFAULT: v("ok"), t: v("ok-t"), bg: v("ok-bg"), line: v("ok-line") },
        warn: { DEFAULT: v("warn"), bg: v("warn-bg"), line: v("warn-line") },
        bad: { DEFAULT: v("bad"), bg: v("bad-bg"), line: v("bad-line") },
        redact: { DEFAULT: v("redact"), bg: v("redact-bg") },
        rename: { DEFAULT: v("rename"), bg: v("rename-bg") },
        code: { bg: v("code-bg"), hl: v("code-hl"), ln: v("ln-num") },
        syn: { k: v("syn-k"), s: v("syn-s"), c: v("syn-c"), f: v("syn-f"), n: v("syn-n") },
        hm: { 0: v("hm-0"), 1: v("hm-1"), 2: v("hm-2"), 3: v("hm-3"), 4: v("hm-4") },
        rm: { 1: v("rm-1"), 2: v("rm-2"), 3: v("rm-3"), 4: v("rm-4"), 5: v("rm-5") },
      },
      fontFamily: {
        sans: v("font-sans"),
        mono: v("font-mono"),
        serif: v("font-serif"),
        deva: v("font-deva"),
      },
      fontSize: {
        overline: [v("fs-overline"), { lineHeight: "1.5", letterSpacing: v("tracking-overline") }],
        xs: [v("fs-xs"), { lineHeight: "1.5" }],
        sm: [v("fs-sm"), { lineHeight: "1.5" }],
        control: [v("fs-control"), { lineHeight: "1.5" }],
        nav: [v("fs-nav"), { lineHeight: "1.5" }],
        base: [v("fs-base"), { lineHeight: v("lh-base") }],
        section: [v("fs-section"), { lineHeight: "1.5", fontWeight: "600" }],
        h2: [v("fs-h2"), { lineHeight: "1.5", fontWeight: "600" }],
        page: [v("fs-page"), { lineHeight: "1.25", letterSpacing: v("tracking-page"), fontWeight: "600" }],
        kpi: [v("fs-kpi"), { lineHeight: "1.15", letterSpacing: v("tracking-kpi"), fontWeight: "500" }],
        hero: [v("fs-hero"), { lineHeight: "1.15", letterSpacing: "-.025em", fontWeight: "650" }],
      },
      fontWeight: { 650: "650" },
      letterSpacing: {
        overline: v("tracking-overline"),
        page: v("tracking-page"),
        kpi: v("tracking-kpi"),
      },
      borderRadius: {
        xs: v("r-xs"),
        sm: v("r-sm"),
        DEFAULT: v("r-md"),
        md: v("r-md"),
        lg: v("r-lg"),
        xl: v("r-xl"),
        full: v("r-full"),
      },
      boxShadow: {
        // The design is flat: every shadow resolves to none.
        DEFAULT: v("shadow"),
        sm: v("shadow"),
        md: v("shadow"),
        lg: v("shadow"),
      },
      height: {
        btn: v("h-btn"),
        "btn-sm": v("h-btn-sm"),
        "btn-xl": v("h-btn-xl"),
        input: v("h-input"),
        pill: v("h-pill"),
        chip: v("h-chip"),
        tag: v("h-tag"),
        nav: v("h-nav"),
        tab: v("h-tab"),
      },
      minHeight: { nav: v("h-nav"), tab: v("h-tab") },
      width: { side: v("side-w"), rail: v("rail-w"), "rail-l": v("rail-l-w") },
      maxWidth: { side: v("side-w"), content: v("content-max") },
      spacing: {
        gutter: v("gap"),
        page: v("gap-page"),
        card: v("card-pad"),
        "content-x": v("content-pad-x"),
        "content-y": v("content-pad-y"),
      },
      gridTemplateColumns: {
        kpi: "repeat(auto-fit,minmax(170px,1fr))",
        "auto-2": "repeat(auto-fit,minmax(min(100%,440px),1fr))",
        "auto-3": "repeat(auto-fit,minmax(min(100%,300px),1fr))",
        "auto-4": "repeat(auto-fit,minmax(min(100%,230px),1fr))",
        side: "minmax(0,1fr) 360px",
        "side-l": "280px minmax(0,1fr)",
      },
    },
  },
};
