import type { Config } from "tailwindcss";
// The approved design's preset: every utility resolves to a token in
// design/tokens.css, so utilities and the design classes always agree.
// @ts-expect-error -- the preset is plain CommonJS without type declarations
import preset from "./design/tailwind.preset.cjs";

export default {
  presets: [preset as Config],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // The design's components.css carries its own resets (it was verified
  // pixel-identical to the prototype without Tailwind's preflight).
  corePlugins: { preflight: false },
  // "fixed" is a design tone (`.chip.fixed`, the green "Default" or "Full"
  // chip); Tailwind's utility of the same name would pin those chips to the
  // viewport and stack them on top of their neighbours.
  blocklist: ["fixed"],
} satisfies Config;
