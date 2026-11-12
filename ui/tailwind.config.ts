import type { Config } from "tailwindcss";

// Every value resolves to a CSS variable from src/styles/tokens.css, so a new
// design system only has to replace that file.
const c = (name: string) => `rgb(var(--ck-${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: c("bg"),
        surface: { DEFAULT: c("surface"), 2: c("surface-2"), 3: c("surface-3") },
        border: { DEFAULT: c("border"), strong: c("border-strong") },
        fg: { DEFAULT: c("text"), muted: c("text-muted"), subtle: c("text-subtle") },
        overlay: c("overlay"),
        primary: {
          DEFAULT: c("primary"),
          hover: c("primary-hover"),
          fg: c("primary-fg"),
          soft: c("primary-soft"),
        },
        accent: { DEFAULT: c("accent"), soft: c("accent-soft") },
        sidebar: {
          DEFAULT: c("sidebar-bg"),
          fg: c("sidebar-fg"),
          muted: c("sidebar-muted"),
          active: c("sidebar-active"),
          "active-bg": c("sidebar-active-bg"),
        },
        success: { DEFAULT: c("success"), soft: c("success-soft") },
        warning: { DEFAULT: c("warning"), soft: c("warning-soft") },
        danger: { DEFAULT: c("danger"), soft: c("danger-soft") },
        info: { DEFAULT: c("info"), soft: c("info-soft") },
        sev: {
          critical: c("sev-critical"),
          "critical-soft": c("sev-critical-soft"),
          high: c("sev-high"),
          "high-soft": c("sev-high-soft"),
          medium: c("sev-medium"),
          "medium-soft": c("sev-medium-soft"),
          low: c("sev-low"),
          "low-soft": c("sev-low-soft"),
          info: c("sev-info"),
          "info-soft": c("sev-info-soft"),
        },
        lvl: { 0: c("lvl-0"), 1: c("lvl-1"), 2: c("lvl-2"), 3: c("lvl-3"), 4: c("lvl-4") },
        mark: {
          secret: c("mark-secret"),
          pii: c("mark-pii"),
          identifier: c("mark-identifier"),
          literal: c("mark-literal"),
        },
        code: {
          bg: c("code-bg"),
          gutter: c("code-gutter"),
          hl: c("code-highlight"),
          "hl-border": c("code-highlight-border"),
        },
        focus: c("focus"),
      },
      fontFamily: {
        sans: "var(--ck-font-sans)",
        mono: "var(--ck-font-mono)",
      },
      fontSize: {
        xs: ["var(--ck-text-xs)", { lineHeight: "1rem" }],
        sm: ["var(--ck-text-sm)", { lineHeight: "1.25rem" }],
        base: ["var(--ck-text-base)", { lineHeight: "1.375rem" }],
        lg: ["var(--ck-text-lg)", { lineHeight: "1.5rem" }],
        xl: ["var(--ck-text-xl)", { lineHeight: "1.75rem" }],
        "2xl": ["var(--ck-text-2xl)", { lineHeight: "2rem" }],
        "3xl": ["var(--ck-text-3xl)", { lineHeight: "2.25rem" }],
      },
      borderRadius: {
        sm: "var(--ck-radius-sm)",
        DEFAULT: "var(--ck-radius-md)",
        md: "var(--ck-radius-md)",
        lg: "var(--ck-radius-lg)",
        xl: "var(--ck-radius-xl)",
        full: "var(--ck-radius-full)",
      },
      boxShadow: {
        sm: "var(--ck-shadow-sm)",
        DEFAULT: "var(--ck-shadow-md)",
        md: "var(--ck-shadow-md)",
        lg: "var(--ck-shadow-lg)",
      },
      width: { sidebar: "var(--ck-sidebar-width)" },
      height: { topbar: "var(--ck-topbar-height)" },
      spacing: { sidebar: "var(--ck-sidebar-width)", topbar: "var(--ck-topbar-height)" },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "slide-in-right": {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        "pop-in": {
          from: { opacity: "0", transform: "scale(0.97) translateY(4px)" },
          to: { opacity: "1", transform: "scale(1) translateY(0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 150ms ease-out",
        "slide-in-right": "slide-in-right 200ms ease-out",
        "pop-in": "pop-in 160ms ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
