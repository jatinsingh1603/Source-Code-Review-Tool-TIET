import type { Finding, FindingStatus, Project, ProviderInfo, Scan, Severity } from "@/api/types";
import { confidenceFraction, SEVERITY_RANK } from "./format";
import { engineLabel } from "./display";
import type { VerdictKind } from "@/components/ui/Badge";

export const CLOSED: FindingStatus[] = ["fixed", "false_positive", "accepted_risk"];
export const isOpen = (f: Pick<Finding, "status">) => !CLOSED.includes(f.status);

export function sevCounts(fs: Pick<Finding, "severity">[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of fs) if (f.severity in c) c[f.severity] += 1;
  return c;
}

/** Severity, then CVSS, descending (the Findings table order). */
export function bySeverity(a: Finding, b: Finding): number {
  const s = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
  if (s) return s;
  return (b.cvss4_score ?? 0) - (a.cvss4_score ?? 0);
}

/**
 * LLM verdict for the `.vd` badge (COMPONENTS.md §6): confirmed = vulnerable
 * and confidence >= 0.8; likely = vulnerable below 0.8; needs review =
 * confidence below 0.65; false positive = status false_positive or the model
 * said not vulnerable. `null` when no model reviewed the finding.
 */
export function verdictOf(
  f: Pick<Finding, "llm" | "status" | "llm_reviewed"> & { verdict?: string | null; confidence?: number | string },
): { kind: VerdictKind; conf: number | null } | null {
  if (f.status === "false_positive") return { kind: "fp", conf: null };
  const llm = f.llm;
  if (!llm) {
    // List rows carry the server's verdict word but not the model's confidence.
    if (f.verdict === "not_vulnerable") return { kind: "fp", conf: null };
    if (f.verdict === "uncertain") return { kind: "rev", conf: null };
    if (f.verdict === "vulnerable") return { kind: "like", conf: null };
    return null;
  }
  const c = confidenceFraction(llm.confidence);
  if (!llm.is_vulnerable) return { kind: "fp", conf: c };
  if (c !== null && c < 0.65) return { kind: "rev", conf: c };
  if (c !== null && c >= 0.8) return { kind: "conf", conf: c };
  return { kind: "like", conf: c };
}

export function providerName(id: string | null | undefined, providers?: ProviderInfo[]): string {
  if (!id) return "—";
  return providers?.find((p) => p.id === id)?.name ?? id;
}

/** "AgentRouter (OpenAI Responses)" → "AgentRouter", for narrow form columns. */
export function shortProviderName(name: string): string {
  return name.replace(/\s*\([^)]*\)\s*$/, "") || name;
}

/** The "Target" text of a scan row: mode and ref when the server reports them, else the project source. */
export function scanTarget(s: Scan, project?: Project | null): string {
  if (s.ref) return `${s.mode ?? "branch"} · ${s.ref}`;
  const src = project?.source;
  if (!src) return s.project_name ?? "—";
  if (src.ref) return `${src.type === "git" ? "branch" : src.type} · ${src.ref}`;
  const up = (src as { upload_name?: string }).upload_name;
  if (up) return `upload · ${up}`;
  if (src.type === "sample") return "sample · built in";
  if (src.path) return `path · ${src.path}`;
  if (src.url) return `git · ${src.url}`;
  return src.type;
}

/** Payload count of a scan, from the embedded privacy summary. */
export function scanPayloads(s: Scan): number | null {
  return s.payloads ?? s.privacy_summary?.payloads ?? null;
}

export function sortScans(scans: Scan[]): Scan[] {
  return [...scans].sort((a, b) =>
    (b.created_at ?? b.started_at ?? "").localeCompare(a.created_at ?? a.started_at ?? ""),
  );
}

/** Engine names of a finding (merged engines first-class), as design labels, unique. */
export function enginesOf(f: Finding): string[] {
  const raw: string[] = [];
  if (Array.isArray(f.engines) && f.engines.length) {
    for (const e of f.engines) raw.push(typeof e === "string" ? e : e.engine);
  } else if (f.provenance?.engines?.length) {
    for (const e of f.provenance.engines) raw.push(e.engine);
  } else if (f.engine) raw.push(f.engine);
  return [...new Set(raw.map(engineLabel))];
}

/** The finding's file and line. */
export function locationOf(f: Finding): { path: string; line: number } | null {
  const l = f.locations?.[0];
  if (l) return { path: l.path, line: l.start_line };
  if (f.path) return { path: f.path, line: f.line ?? 0 };
  return null;
}
