/**
 * Display helpers that follow the approved design's conventions
 * (ui/design/SCREENS.md, Conventions): long and table date forms, byte sizes,
 * 6…4 hashes, level names and meters, engine names.
 */
import type { PrivacyLevel } from "@/api/types";

const nf = new Intl.NumberFormat("en-GB");
export const fmtInt = (n?: number | null) => (n === undefined || n === null ? "—" : nf.format(n));

/** Level names as the design writes them (COMPONENTS.md §7). */
export const LEVEL_NAME: Record<PrivacyLevel, string> = {
  L0: "Local only",
  L1: "Redacted",
  L2: "Pseudonymised",
  L3: "Minimal slice",
  L4: "Facts only",
};

/** Filled bars of the five-bar protection meter: more bars, less leaves. */
export const LEVEL_BARS: Record<PrivacyLevel, number> = { L0: 5, L4: 4, L3: 3, L2: 2, L1: 1 };

export const LEVEL_CAPTION: Record<PrivacyLevel, string> = {
  L0: "nothing leaves",
  L4: "no code",
  L3: "default",
  L2: "whole files, renamed",
  L1: "secrets and PII removed",
};

let TZ = "Asia/Kolkata";
let ISO_DATES = false;

/** Settings → Language and region: the time zone and date form every helper below uses. */
export function setDisplayPrefs(timeZone: string, isoDates: boolean): void {
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone }); // an unknown zone throws: keep the last good one
    TZ = timeZone;
  } catch {
    /* keep the current zone */
  }
  ISO_DATES = isoDates;
}

/** The time zone label of the current preference ("IST", "AEDT"). */
export function zoneLabel(iso?: string | null): string {
  return tzLabel(iso ? new Date(iso) : new Date(), TZ);
}

function tzLabel(d: Date, tz: string): string {
  if (tz === "Asia/Kolkata") return "IST";
  try {
    // en-GB names Sydney "GMT+11"; en-AU gives the name an Australian reader expects ("AEDT").
    const locale = tz.startsWith("Australia/") ? "en-AU" : "en-GB";
    const part = new Intl.DateTimeFormat(locale, { timeZone: tz, timeZoneName: "short" })
      .formatToParts(d)
      .find((p) => p.type === "timeZoneName");
    return part?.value ?? "";
  } catch {
    return "";
  }
}

function parse(iso?: string | null): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

function isoDay(d: Date, tz: string): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
}

function parts(d: Date, tz: string) {
  const p = new Intl.DateTimeFormat("en-GB", {
    timeZone: tz,
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(d);
  const get = (t: string) => p.find((x) => x.type === t)?.value ?? "";
  return {
    day: get("day"),
    month: get("month"),
    year: get("year"),
    hour: get("hour"),
    minute: get("minute"),
    second: get("second"),
  };
}

/** "12 Nov 2026, 10:42 IST" */
export function fmtLong(iso?: string | null, tz: string = TZ): string {
  const d = parse(iso);
  if (!d) return "—";
  const p = parts(d, tz);
  if (ISO_DATES) return `${isoDay(d, tz)} ${p.hour}:${p.minute} ${tzLabel(d, tz)}`.trim();
  return `${p.day} ${p.month} ${p.year}, ${p.hour}:${p.minute} ${tzLabel(d, tz)}`.trim();
}

/** "12 Nov 2026" */
export function fmtDate(iso?: string | null, tz: string = TZ): string {
  const d = parse(iso);
  if (!d) return "—";
  if (ISO_DATES) return isoDay(d, tz);
  const p = parts(d, tz);
  return `${p.day} ${p.month} ${p.year}`;
}

/** "12 Nov, 10:42" (tables) */
export function fmtShort(iso?: string | null, tz: string = TZ): string {
  const d = parse(iso);
  if (!d) return "—";
  const p = parts(d, tz);
  if (ISO_DATES) return `${isoDay(d, tz)} ${p.hour}:${p.minute}`;
  return `${p.day} ${p.month}, ${p.hour}:${p.minute}`;
}

/** "12 Nov" */
export function fmtDayMonth(iso?: string | null, tz: string = TZ): string {
  const d = parse(iso);
  if (!d) return "—";
  const p = parts(d, tz);
  return `${p.day} ${p.month}`;
}

/** "10:42" */
export function fmtHM(iso?: string | null, tz: string = TZ): string {
  const d = parse(iso);
  if (!d) return "—";
  const p = parts(d, tz);
  return `${p.hour}:${p.minute}`;
}

/** "10:43:41" */
export function fmtTime(iso?: string | number | null, tz: string = TZ): string {
  const d = typeof iso === "number" ? new Date(iso) : parse(iso);
  if (!d || Number.isNaN(d.getTime())) return "—";
  const p = parts(d, tz);
  return `${p.hour}:${p.minute}:${p.second}`;
}

/** Seconds between two instants (or until now). */
export function secondsBetween(start?: string | null, end?: string | null, now: number = Date.now()): number | null {
  const a = parse(start);
  if (!a) return null;
  const b = end ? parse(end) : new Date(now);
  if (!b) return null;
  return Math.max(0, Math.round((b.getTime() - a.getTime()) / 1000));
}

/** "1 min 27 s" */
export function fmtElapsed(start?: string | null, end?: string | null, now: number = Date.now()): string {
  const s = secondsBetween(start, end, now);
  if (s === null) return "—";
  return fmtSeconds(s);
}

export function fmtSeconds(s: number): string {
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${s % 60} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

/** "00:58" */
export function fmtClock(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const m = Math.floor(s / 60);
  return `${String(m).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

/** Byte sizes split into value and unit: "2,914" "B", "412.6" "KB", "1.8" "MB". */
export function fmtBytes(n?: number | null): { v: string; unit: string } {
  if (n === undefined || n === null || Number.isNaN(n)) return { v: "—", unit: "" };
  if (n < 10_000) return { v: nf.format(Math.round(n)), unit: "B" };
  if (n < 1_000_000) return { v: (n / 1000).toFixed(1), unit: "KB" };
  return { v: (n / 1e6).toFixed(1), unit: "MB" };
}

export function fmtBytesText(n?: number | null): string {
  const b = fmtBytes(n);
  return b.unit ? `${b.v} ${b.unit}` : b.v;
}

/** UTF-8 byte length of a string. */
export function byteLength(s?: string | null): number {
  if (!s) return 0;
  return new TextEncoder().encode(s).length;
}

/** Hashes as the first 6 and last 4 hex characters: "7c1e9a…94af". */
export function fmtHash(h?: string | null): string {
  if (!h) return "—";
  const c = h.replace(/^sha256:/, "");
  return c.length <= 12 ? c : `${c.slice(0, 6)}…${c.slice(-4)}`;
}

/** Display form of a scan id: `scn_78ebad4e…` → "SCN-78EBAD". The full id is in a title. */
export function scanLabel(id?: string | null): string {
  if (!id) return "—";
  const m = /^scn_([0-9a-z]+)$/i.exec(id);
  if (m) return `SCN-${m[1]!.slice(0, 6).toUpperCase()}`;
  return id;
}

/** Display form of a finding id: `find_01M78…5TCC` → "KF-…5TCC" style short id. */
export function findingLabel(id?: string | null): string {
  if (!id) return "—";
  const m = /^find_([0-9A-Z]+)$/i.exec(id);
  if (m) return `F-${m[1]!.slice(-6).toUpperCase()}`;
  return id;
}

/** 4-digit ledger sequence: 94 → "0094". */
export function fmtSeq(n?: number | null): string {
  if (n === undefined || n === null) return "—";
  return String(n).padStart(4, "0");
}

/** CVSS band modifier (COMPONENTS.md §6). */
export function cvssBand(score: number): "c" | "h" | "m" | "l" {
  if (score >= 9) return "c";
  if (score >= 7) return "h";
  if (score >= 4) return "m";
  return "l";
}

export function capitalise(s?: string | null): string {
  if (!s) return "";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

const LANGUAGE_NAMES: Record<string, string> = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  json: "JSON",
  yaml: "YAML",
  toml: "TOML",
  xml: "XML",
  html: "HTML",
  css: "CSS",
  sql: "SQL",
  php: "PHP",
  csharp: "C#",
  cpp: "C++",
  hcl: "HCL",
  unknown: "Other",
};

/** A language id from the inventory as people write it ("javascript" → "JavaScript"). */
export function languageLabel(id?: string | null): string {
  if (!id) return "";
  return LANGUAGE_NAMES[id.toLowerCase()] ?? capitalise(id);
}

/** Engine id to the design's detection-source names. */
export function engineLabel(e?: string | null): string {
  if (!e) return "—";
  const k = e.toLowerCase();
  if (k.includes("taint")) return "Taint";
  if (k.includes("secret")) return "Secrets";
  if (k.includes("sca") || k.includes("osv")) return "SCA";
  if (k.includes("iac")) return "IaC";
  if (k.includes("semgrep") || k.includes("opengrep")) return "Opengrep";
  if (k.includes("bandit")) return "Bandit";
  if (k.includes("eslint")) return "ESLint security";
  if (k.includes("rules") || k.includes("sast")) return "SAST";
  if (k.includes("llm")) return "LLM";
  return e;
}

export type EngineColumn = "SAST" | "Secrets" | "SCA" | "IaC" | "Taint";
export const ENGINE_COLUMNS: EngineColumn[] = ["SAST", "Secrets", "SCA", "IaC", "Taint"];

/** Detection-source column of the OWASP heatmap. */
export function engineColumn(e?: string | null): EngineColumn {
  const l = engineLabel(e);
  if (l === "Secrets" || l === "SCA" || l === "IaC" || l === "Taint") return l;
  return "SAST";
}

/** Likelihood and impact words (or numbers) to the 1..5 matrix scale. */
export function riskLevel(word?: string | number | null): number | null {
  if (word === undefined || word === null) return null;
  if (typeof word === "number") return Math.max(1, Math.min(5, Math.round(word)));
  const w = word.toLowerCase().trim();
  const map: Record<string, number> = {
    "very low": 1,
    low: 2,
    medium: 3,
    moderate: 3,
    high: 4,
    "very high": 5,
    critical: 5,
  };
  return map[w] ?? null;
}

/** Header lines the payload builder adds ("# codekavach payload L3", "# file_1"); not code. */
export const PAYLOAD_HEADER = /^\s*(#|\/\/) (codekavach payload|file_\w+|region \d+)/;

/** Code lines of a payload, without the builder's header lines. */
export function payloadLineCount(s?: string | null): number {
  if (!s) return 0;
  return s.replace(/\n$/, "").split("\n").filter((l) => !PAYLOAD_HEADER.test(l)).length;
}

/** Line count of a text block, ignoring one trailing newline. */
export function lineCount(s?: string | null): number {
  if (!s) return 0;
  return s.replace(/\n$/, "").split("\n").length;
}
