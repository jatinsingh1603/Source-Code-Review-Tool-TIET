import { useState, type ReactNode } from "react";
import type { FindingStatus, PrivacyLevel, ScanStatus, Severity } from "@/api/types";
import { cn, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/format";
import { cvssBand, fmtHash, LEVEL_BARS, LEVEL_NAME } from "@/lib/display";
import { Icon } from "./Icon";

/** Severity with its marker shape (COMPONENTS.md §6). */
export const SEV_CLASS: Record<Severity, string> = { critical: "c", high: "h", medium: "m", low: "l", info: "i" };

export function SeverityBadge({ severity, label, className }: { severity: Severity; label?: ReactNode; className?: string }) {
  const known = SEV_CLASS[severity] ? severity : "info";
  return (
    <span className={cn("sev", SEV_CLASS[known], className)}>{label === undefined ? SEVERITY_LABEL[known] : label}</span>
  );
}

/** Severity marker plus a count, as in the KPI detail line. */
export function SevCount({ severity, n, first }: { severity: Severity; n: number; first?: boolean }) {
  return (
    <span
      className={cn("sev", SEV_CLASS[severity])}
      style={{ height: "auto", marginLeft: first ? undefined : 8 }}
      title={`${SEVERITY_LABEL[severity]}: ${n}`}
    >
      {n}
    </span>
  );
}

export function CvssBox({ score, suffix }: { score?: number | null; suffix?: string }) {
  if (score === null || score === undefined) return <span className="faint">—</span>;
  return (
    <span className={cn("cvss", cvssBand(score))}>
      <b>{score.toFixed(1)}</b>
      {suffix && <span>{suffix}</span>}
    </span>
  );
}

export type VerdictKind = "conf" | "like" | "rev" | "fp";
export const VERDICT_LABEL: Record<VerdictKind, string> = {
  conf: "Confirmed",
  like: "Likely",
  rev: "Needs review",
  fp: "False positive",
};

export function Verdict({ kind, children }: { kind: VerdictKind; children?: ReactNode }) {
  return <span className={cn("vd", kind)}>{children ?? VERDICT_LABEL[kind]}</span>;
}

/** Privacy level badge: neutral grey with a five-bar protection meter (COMPONENTS.md §7). */
export function LevelBadge({
  level,
  meter = false,
  name = false,
  label,
}: {
  level: PrivacyLevel | string;
  meter?: boolean;
  /** Append the level name ("L3 Minimal slice"). */
  name?: boolean;
  /** Replace the visible text entirely. */
  label?: ReactNode;
}) {
  const lv = level as PrivacyLevel;
  const bars = LEVEL_BARS[lv] ?? 0;
  return (
    <span className="lvl" title={LEVEL_NAME[lv] ? `${lv} · ${LEVEL_NAME[lv]}` : undefined}>
      {label ?? (name && LEVEL_NAME[lv] ? `${lv} ${LEVEL_NAME[lv]}` : level)}
      {meter && (
        <span className="meter" aria-hidden>
          {[0, 1, 2, 3, 4].map((i) => (
            <i key={i} className={i < bars ? "f" : undefined} />
          ))}
        </span>
      )}
    </span>
  );
}

export type DotTone = "ok" | "warn" | "bad" | "acc" | "neutral";

/** Status word with a coloured dot (`.st`). */
export function StatusDot({ tone, children, className }: { tone: DotTone; children: ReactNode; className?: string }) {
  return (
    <span className={cn("st", className)}>
      <span className={cn("dot", tone !== "neutral" && tone)} />
      {children}
    </span>
  );
}

export const SCAN_STATUS: Record<ScanStatus, { tone: DotTone; label: string }> = {
  queued: { tone: "neutral", label: "Queued" },
  running: { tone: "acc", label: "Running" },
  completed: { tone: "ok", label: "Completed" },
  failed: { tone: "bad", label: "Failed" },
  cancelled: { tone: "neutral", label: "Cancelled" },
};

export function ScanStatusBadge({ status, error }: { status: ScanStatus; error?: string | null }) {
  const s = SCAN_STATUS[status] ?? { tone: "neutral" as DotTone, label: status };
  let label = s.label;
  if (status === "failed" && error && /abort|I4|privacy/i.test(error)) label = "Aborted · I4";
  return (
    <StatusDot tone={s.tone}>
      <span title={error ?? undefined}>{label}</span>
    </StatusDot>
  );
}

/** Finding status as a word ("Suppressed" is faint, as in the design). */
export function StatusBadge({ status }: { status: FindingStatus }) {
  const label = STATUS_LABEL[status] ?? status;
  return <span className={status === "accepted_risk" || status === "false_positive" ? "faint" : undefined}>{label}</span>;
}

export function Chip({ children, tone, className, title }: { children: ReactNode; tone?: "on" | "new" | "fixed"; className?: string; title?: string }) {
  return (
    <span className={cn("chip", tone, className)} title={title}>
      {children}
    </span>
  );
}

/** Hash chip: first 6 and last 4 hex characters, with an optional copy button. */
export function Hash({ value, copy = true, prefix }: { value?: string | null; copy?: boolean; prefix?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="faint">none</span>;
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable (insecure context) */
    }
  };
  return (
    <span className="hash" title={value}>
      {prefix}
      {fmtHash(value)}
      {copy && (
        <button type="button" aria-label={copied ? "Copied" : "Copy hash"} title={copied ? "Copied" : "Copy full hash"} onClick={onCopy}>
          <Icon name="copy" />
        </button>
      )}
    </span>
  );
}

export function Avatar({ name, size }: { name: string; size?: "xs" | "sm" | "lg" }) {
  return (
    <span className={cn("avatar", size)} aria-hidden>
      {initialsOf(name)}
    </span>
  );
}

function initialsOf(name: string): string {
  if (name === "CodeKavach" || name === "system") return "CK";
  const parts = name.trim().split(/\s+|[._-]/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

/** One row of a checks list (`.guard`): id, text, and "Pass" or a note word. */
export function Guard({ id, children, result }: { id?: string; children: ReactNode; result: ReactNode | "pass" }) {
  return (
    <div className="guard">
      {id && <span className="gid">{id}</span>}
      <span className="gt">{children}</span>
      {result === "pass" ? <span className="chk">Pass</span> : result}
    </div>
  );
}
