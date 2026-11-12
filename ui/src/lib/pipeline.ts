/** The scan pipeline as the design draws it (COMPONENTS.md §15). */

/** The nine design stages and the server stages that make them up. */
export const STAGES: { n: string; title: string; members: (s: string) => boolean; guard?: boolean }[] = [
  { n: "01", title: "Ingest & parse", members: (s) => s === "intake" || s === "ingest" || s === "parse" },
  { n: "02", title: "Deterministic analysis", members: (s) => s.startsWith("analyse") },
  { n: "03", title: "Candidate findings", members: (s) => s === "aggregate" || s === "candidates" },
  { n: "04", title: "Privacy layer", members: (s) => s === "privacy-prepare" || s === "privacy", guard: true },
  { n: "05", title: "LLM reasoning", members: (s) => s === "llm-review" || s === "llm" },
  { n: "06", title: "De-pseudonymise", members: (s) => s === "restore" || s === "depseudonymise" },
  { n: "07", title: "Risk rating", members: (s) => s === "rate" || s === "risk" },
  { n: "08", title: "Audit report", members: (s) => s === "report" || s === "privacy-check" },
  { n: "09", title: "Issue sync", members: (s) => s === "sync" || s.startsWith("sync") },
];

/** Engine groups the server runs on every scan (per-scan selection is an API gap). */
export const ENGINE_GROUPS = ["Rules (SAST)", "External engines (Opengrep, Bandit, ESLint) when installed", "Secrets · SCA · IaC", "Taint engine"];

