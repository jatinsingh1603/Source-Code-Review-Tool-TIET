import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sampleEvaluation } from "@/lib/sampleEval";

const ROOT = join(__dirname, "..", "..");
const PAIRS: [string, string][] = [
  ["ui/src/data/sample-eval/kavachbank-mock-detection.json", "docs/research/results/kavachbank-mock/results.json"],
  ["ui/src/data/sample-eval/kavachbank-agentrouter-L3-detection.json", "docs/research/results/kavachbank-agentrouter-L3/results.json"],
  ["ui/src/data/sample-eval/kavachbank-mock-leakage.json", "docs/research/results/kavachbank-mock/leakage/results.json"],
];

describe("sample evaluation results", () => {
  it.each(PAIRS)("%s is an exact copy of %s", (copy, source) => {
    expect(readFileSync(join(ROOT, copy), "utf8")).toBe(readFileSync(join(ROOT, source), "utf8"));
  });

  it("reads every number from the committed results", () => {
    const e = sampleEvaluation();
    expect(e.sample).toBe(true);
    expect(e.benchmarks?.some((b) => b.arm === "SAST only")).toBe(true);
    expect(e.frontier?.map((p) => p.arm)).toEqual(["SAST only", "L1", "L2", "L3", "L4"]);
    for (const b of e.benchmarks ?? []) {
      expect(b.f1).toBeGreaterThan(0);
      expect(b.f1).toBeLessThanOrEqual(1);
    }
  });
});
