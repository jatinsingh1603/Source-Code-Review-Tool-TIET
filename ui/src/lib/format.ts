import clsx, { type ClassValue } from "clsx";
import type { FindingStatus, PrivacyLevel, Severity } from "@/api/types";

export const cn = (...v: ClassValue[]) => clsx(v);

const dtf = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const df = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short" });
const rtf = new Intl.RelativeTimeFormat("en-GB", { numeric: "auto" });
const nf = new Intl.NumberFormat("en-GB");

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dtf.format(d);
}

export function fmtDay(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : df.format(d);
}

export function fmtRelative(iso?: string | null, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.round((t - now) / 1000);
  const abs = Math.abs(s);
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour");
  if (abs < 86400 * 30) return rtf.format(Math.round(s / 86400), "day");
  return fmtDateTime(iso);
}

export function fmtDuration(start?: string | null, end?: string | null): string {
  if (!start) return "—";
  const a = new Date(start).getTime();
  const b = end ? new Date(end).getTime() : Date.now();
  if (Number.isNaN(a) || Number.isNaN(b)) return "—";
  const s = Math.max(0, Math.round((b - a) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export const fmtNum = (n?: number | null) => (n === undefined || n === null ? "—" : nf.format(n));

export function fmtConfidence(c: number | string | undefined | null): string {
  if (c === undefined || c === null) return "—";
  if (typeof c === "string") return c.charAt(0).toUpperCase() + c.slice(1);
  return `${Math.round(c <= 1 ? c * 100 : c)}%`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Open",
  confirmed: "Confirmed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
};

export const LEVEL_INFO: Record<
  PrivacyLevel,
  { name: string; short: string; leaves: string; detail: string[] }
> = {
  L0: {
    name: "Local only",
    short: "Nothing leaves this machine",
    leaves: "Nothing. All analysis is deterministic and local; no model is called.",
    detail: [
      "Static rules, taint analysis and external engines run on this machine.",
      "No payload is prepared for a model and nothing is sent to any provider.",
      "Findings carry deterministic evidence only, without a model verdict.",
    ],
  },
  L1: {
    name: "Metadata",
    short: "Only finding metadata, no code",
    leaves: "Rule id, CWE, sink and source categories and abstract flow shape. No source code.",
    detail: [
      "The model sees what kind of weakness is suspected and its abstract data flow.",
      "No source text, identifiers or literals are sent.",
      "Useful for triage hints at the lowest possible disclosure.",
    ],
  },
  L2: {
    name: "Abstracted",
    short: "Structure only, names pseudonymised",
    leaves: "A skeleton of the relevant function with every name and literal replaced.",
    detail: [
      "Secrets and personal data become typed placeholders such as <SECRET_1>.",
      "Internal identifiers become neutral pseudonyms; string literals keep only their shape.",
      "Public library and framework names are kept so the model can recognise sinks.",
    ],
  },
  L3: {
    name: "Minimal slice",
    short: "Minimal sanitised code slice",
    leaves: "A minimal slice of code around each candidate, sanitised and pseudonymised.",
    detail: [
      "Secrets and personal data are replaced by typed placeholders before sending.",
      "Internal names are replaced by pseudonyms; comments and docstrings are removed.",
      "String literals keep their shape but lose domain words.",
      "Visible to the provider: the structure of the slice, the stack via public names, and the suspected weakness class.",
    ],
  },
  L4: {
    name: "Extended context",
    short: "Sanitised slice plus surrounding context",
    leaves: "The sanitised slice plus callers and callees needed for context.",
    detail: [
      "The same sanitisation as L3 is applied to every line that is sent.",
      "More of the repository is disclosed: neighbouring functions are included.",
      "Highest recall from the model at the highest measured disclosure volume.",
    ],
  },
};

export function initials(name: string): string {
  const parts = name.trim().split(/\s+|[._-]/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

export function shortHash(h?: string | null, n = 10): string {
  if (!h) return "—";
  const clean = h.replace(/^sha256:/, "");
  return clean.slice(0, n);
}
