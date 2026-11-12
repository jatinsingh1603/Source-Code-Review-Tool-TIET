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
} satisfies Config;
