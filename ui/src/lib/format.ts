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

const CONFIDENCE_WORDS: Record<string, number> = {
  certain: 1,
  "very high": 0.95,
  high: 0.85,
  medium: 0.6,
  low: 0.35,
  "very low": 0.15,
};

/** Confidence as a 0..1 fraction, whether given as a number or a word. */
export function confidenceFraction(c: number | string | undefined | null): number | null {
  if (c === undefined || c === null) return null;
  if (typeof c === "number") return c <= 1 ? c : c / 100;
  return CONFIDENCE_WORDS[c.toLowerCase()] ?? null;
}

const FRAMEWORK_LABEL: Record<string, string> = {
  "pci-dss": "PCI DSS 4.0",
  iso27001: "ISO/IEC 27001:2022",
  "nist-ssdf": "NIST SSDF",
  "nist-800-53": "NIST SP 800-53",
  rbi: "RBI Cyber Security Framework",
  "rbi-itgrca": "RBI IT Governance",
  "cert-in": "CERT-In",
  dpdp: "DPDP Act 2023",
  "dpdp-act": "DPDP Act 2023",
  gdpr: "GDPR",
  "owasp-asvs": "OWASP ASVS",
  sebi: "SEBI CSCRF",
  hipaa: "HIPAA",
  soc2: "SOC 2",
};

export function frameworkLabel(f: string): string {
  return FRAMEWORK_LABEL[f.toLowerCase()] ?? f;
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

/**
 * Privacy levels as defined in docs/ARCHITECTURE.md section 6.1. Strictness is
 * not the digit order: L1 < L2 < L3 < L4 < L0 (L0 sends nothing; L4 sends no
 * code; L1 sends code with only secrets and personal data replaced).
 */
export const LEVELS_BY_STRICTNESS: PrivacyLevel[] = ["L0", "L4", "L3", "L2", "L1"];

const STRICTNESS: Record<PrivacyLevel, number> = { L1: 1, L2: 2, L3: 3, L4: 4, L0: 5 };

/** True when `level` is at least as strict as `floor`. */
export function atLeastAsStrict(level: PrivacyLevel, floor: PrivacyLevel): boolean {
  return STRICTNESS[level] >= STRICTNESS[floor];
}

export const LEVEL_INFO: Record<
  PrivacyLevel,
  { name: string; short: string; leaves: string; use: string; detail: string[] }
> = {
  L0: {
    name: "Local only",
    short: "Nothing leaves this machine",
    leaves: "Nothing. Only local engines (or a local model) are used.",
    use: "Air-gapped",
    detail: [
      "Static rules, taint analysis and external engines run on this machine.",
      "No payload is sent to any third-party provider.",
      "Findings rest on deterministic evidence.",
    ],
  },
  L4: {
    name: "Facts only",
    short: "No code: abstract data-flow facts",
    leaves: "No source code. Only abstract data-flow facts and questions about each candidate.",
    use: "Crown-jewel paths",
    detail: [
      "The model sees the weakness class, source and sink categories and the shape of the flow.",
      "No source text, identifiers or literals are sent.",
      "Lowest disclosure of the sending levels, at some cost in model precision.",
    ],
  },
  L3: {
    name: "Minimal slice",
    short: "Pseudonymised minimal slice (default)",
    leaves: "A minimal slice of code around each candidate, redacted and pseudonymised.",
    use: "Public LLM APIs",
    detail: [
      "Secrets and personal data are replaced by typed placeholders before sending.",
      "Internal names are replaced by neutral pseudonyms; comments and docstrings are removed.",
      "String literals keep their security-relevant shape but lose domain words.",
      "Visible to the provider: the structure of the slice, the stack via public library names, and the suspected weakness class.",
    ],
  },
  L2: {
    name: "Pseudonymised files",
    short: "Whole files, pseudonymised",
    leaves: "Whole relevant files with secrets redacted and identifiers, literals and comments pseudonymised.",
    use: "Private cloud tenancy",
    detail: [
      "The same redaction and pseudonymisation as L3, applied to whole files rather than a slice.",
      "More of the repository is disclosed, which gives the model more context.",
      "Public library and framework names are kept.",
    ],
  },
  L1: {
    name: "Redacted code",
    short: "Code with secrets and PII replaced",
    leaves: "Source code with only secrets and personal data replaced by typed placeholders.",
    use: "Trusted local or private model",
    detail: [
      "Identifiers, literals and comments are sent as written.",
      "Suitable only for a model you trust with your source code.",
      "Highest disclosure of all levels.",
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
