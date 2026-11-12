/** Parse and explain CVSS v3.1 / v4.0 vectors for display (scores come from the server). */

const NAMES: Record<string, string> = {
  AV: "Attack vector",
  AC: "Attack complexity",
  AT: "Attack requirements",
  PR: "Privileges required",
  UI: "User interaction",
  S: "Scope",
  C: "Confidentiality",
  I: "Integrity",
  A: "Availability",
  VC: "Confidentiality (vulnerable system)",
  VI: "Integrity (vulnerable system)",
  VA: "Availability (vulnerable system)",
  SC: "Confidentiality (subsequent)",
  SI: "Integrity (subsequent)",
  SA: "Availability (subsequent)",
};

const VALUES: Record<string, Record<string, string>> = {
  AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC: { L: "Low", H: "High" },
  AT: { N: "None", P: "Present" },
  PR: { N: "None", L: "Low", H: "High" },
  UI: { N: "None", R: "Required", P: "Passive", A: "Active" },
  S: { U: "Unchanged", C: "Changed" },
};
const CIA = { H: "High", L: "Low", N: "None" };

export interface CvssMetric {
  key: string;
  name: string;
  value: string;
  label: string;
}

export function parseVector(vector: string | null | undefined): { version: string; metrics: CvssMetric[] } | null {
  if (!vector) return null;
  const parts = vector.split("/");
  const head = parts.shift() ?? "";
  const m = /^CVSS:(\d\.\d)$/.exec(head);
  if (!m) return null;
  const metrics = parts
    .map((p) => p.split(":"))
    .filter((kv): kv is [string, string] => kv.length === 2)
    .map(([k, v]) => ({
      key: k,
      name: NAMES[k] ?? k,
      value: v,
      label: VALUES[k]?.[v] ?? (CIA as Record<string, string>)[v] ?? v,
    }));
  return { version: m[1]!, metrics };
}

/** Qualitative rating shared by CVSS v3.1 and v4.0. */
export function cvssRating(score: number | null | undefined): "None" | "Low" | "Medium" | "High" | "Critical" | "—" {
  if (score === null || score === undefined) return "—";
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}
