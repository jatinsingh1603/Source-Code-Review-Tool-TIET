/**
 * The committed evaluation results (docs/research/results, copied to
 * src/data/sample-eval so the Docker build, which sees only ui/, can bundle
 * them; tests/sample-eval.test.ts keeps the copies identical), bundled so the
 * Evaluation and Privacy Centre screens can show measured numbers when the
 * server has no `GET /evaluation` yet. They are labelled "Sample results" in
 * the UI, as the design specifies. Nothing here is invented: every number is
 * read from the JSON files the evaluation harness wrote.
 */
import mockResults from "@/data/sample-eval/kavachbank-mock-detection.json";
import routerResults from "@/data/sample-eval/kavachbank-agentrouter-L3-detection.json";
import leakage from "@/data/sample-eval/kavachbank-mock-leakage.json";
import type { EvaluationData } from "@/components/Frontier";

interface Overall {
  precision?: number;
  recall?: number;
  f1?: number;
  f1_ci?: number[];
}
interface Arm {
  arm: string;
  provider?: string;
  level?: string | null;
  overall: Overall;
  skipped_reason?: string | null;
}
interface DetectionFile {
  dataset: { name: string; vulnerabilities?: number };
  arms: Arm[];
}
interface LevelLeak {
  detection_f1?: number;
  identifier?: { exact_rate?: number; defined?: number };
  inference?: { evidence_share?: number };
  stitching?: { coverage?: number; linkability?: number };
  canary?: { by_category?: Record<string, { checked: number; occurrences: number }> };
}

function armName(a: Arm): string {
  if (a.arm === "engines-only") return "SAST only";
  const [prov, lvl] = a.arm.split("@");
  if (!lvl) return a.arm;
  const p = prov === "mock" ? "Mock" : prov === "agentrouter" ? "AgentRouter" : prov;
  return `SAST + LLM · ${lvl} (${p})`;
}

function bench(file: DetectionFile, label: string) {
  return file.arms
    .filter((a) => a.overall && a.overall.f1 !== undefined)
    .map((a) => ({
      dataset: label,
      arm: armName(a),
      precision: a.overall.precision ?? 0,
      recall: a.overall.recall ?? 0,
      f1: a.overall.f1 ?? 0,
      f1_ci: (a.overall.f1_ci as [number, number] | undefined) ?? undefined,
    }));
}

export function sampleEvaluation(): EvaluationData {
  const m = mockResults as unknown as DetectionFile;
  const r = routerResults as unknown as DetectionFile;
  const levels = (leakage as unknown as { levels: Record<string, LevelLeak> }).levels;
  const n = m.dataset.vulnerabilities ?? 0;
  const benchmarks = [
    ...bench(r, `${r.dataset.name} · ${n} planted`),
    ...bench(m, `${m.dataset.name} · ${n} planted`).filter((b) => b.arm !== "SAST only"),
  ];
  const engines = m.arms.find((a) => a.arm === "engines-only");
  const frontier = [
    ...(engines?.overall.f1 !== undefined ? [{ arm: "SAST only", f1: engines.overall.f1, recovery: 0 }] : []),
    ...Object.entries(levels).map(([lvl, v]) => ({ arm: lvl, f1: v.detection_f1 ?? 0, recovery: v.identifier?.exact_rate ?? 0 })),
  ];
  const by = (f: (v: LevelLeak) => number | undefined) =>
    Object.fromEntries(Object.entries(levels).map(([l, v]) => [l, f(v) ?? null])) as Record<string, number | null>;
  return {
    sample: true,
    benchmarks,
    frontier,
    leakage: Object.entries(levels).map(([level, v]) => ({
      level,
      recovery: v.identifier?.exact_rate ?? 0,
      note: level === "L1" ? "real names are sent" : undefined,
    })),
    attacks: [
      {
        experiment: "Identifier recovery",
        description: "Read project-defined identifiers off the payloads, verbatim",
        by_level: by((v) => v.identifier?.exact_rate),
        reading: "Share of defined identifiers recovered",
      },
      {
        experiment: "Business inference",
        description: "Guess the business sector from words left in the payloads",
        by_level: by((v) => v.inference?.evidence_share),
        reading: "Share of sector evidence visible",
      },
      {
        experiment: "Stitching",
        description: "Link payloads that share a pseudonym and rebuild the code base",
        by_level: by((v) => v.stitching?.linkability),
        reading: "Share of payload pairs that can be linked",
      },
      {
        experiment: "Secret extraction",
        description: "Find planted secrets in the payloads",
        by_level: by((v) => {
          const s = v.canary?.by_category?.secret;
          return s ? (s.checked ? s.occurrences / s.checked : 0) : undefined;
        }),
        reading: "Planted secrets found verbatim",
      },
    ],
    note: `${m.dataset.name} (synthetic), ${n} planted vulnerabilities; ${Object.values(levels)[0]?.identifier?.defined ?? "—"} identifiers; mock provider for the leakage runs.`,
  };
}
