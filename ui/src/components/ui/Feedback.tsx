import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "@/api/client";
import { cn } from "@/lib/format";
import { Icon } from "./Icon";

/** Loading: three skeleton bars (60%, 100%, 80%) per card (COMPONENTS.md §22). */
export function Skeleton({ rows = 1, className }: { rows?: number; className?: string }) {
  const widths = ["60%", "100%", "80%"];
  return (
    <div className={cn("stack s6", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows * 3 }, (_, i) => (
        <div key={i} className="skel" style={{ width: widths[i % 3] }} />
      ))}
    </div>
  );
}

/** Skeleton rows inside a table body. */
export function SkeletonRows({ cols, rows = 5 }: { cols: number; rows?: number }) {
  const widths = ["60%", "100%", "80%"];
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} aria-hidden>
          {Array.from({ length: cols }, (_, c) => (
            <td key={c}>
              <div className="skel" style={{ width: widths[(r + c) % 3], minWidth: 24 }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

/** Empty state: bold title, one sentence and an optional `.more` action. */
export function Empty({
  title,
  children,
  action,
  to,
  onAction,
  className,
}: {
  title: string;
  children?: ReactNode;
  /** Action label; give `to` for a link or `onAction` for a button. */
  action?: string;
  to?: string;
  onAction?: () => void;
  className?: string;
}) {
  return (
    <div className={cn("empty", className)}>
      <b style={{ color: "var(--text)" }}>{title}</b>
      {children && <span className="sm">{children}</span>}
      {action && to && (
        <Link className="more" to={to}>
          {action} <Icon name="arrow-right" />
        </Link>
      )}
      {action && onAction && !to && (
        <button type="button" className="more linkbtn" onClick={onAction}>
          {action} <Icon name="arrow-right" />
        </button>
      )}
    </div>
  );
}

/** Server permissions (server/rbac.py) in words, with the lowest role that holds each. */
const PERMISSION_WORDS: Record<string, string> = {
  "privacy:read_original": "the Auditor role, because it shows original code or payload text",
  "audit:read": "the Auditor role",
  "finding:review": "the Auditor role",
  "privacy:read_ledger": "the Developer role",
  "finding:triage": "the Developer role",
  "scan:run": "the Developer role",
  "project:write": "the Developer role",
  "provider:test": "the Developer role",
  "sync:github": "the Developer role",
  "settings:write": "the Admin role",
  "users:admin": "the Admin role",
};

export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      // "scan not found" -> "This scan does not exist..." reads better than a code.
      const what = /^(\w+) not found\.?$/i.exec(error.message)?.[1]?.toLowerCase();
      return what
        ? `This ${what} does not exist, or it was deleted. Check the address, or open it from the list.`
        : `${error.message} Check the address, or open it from the list.`;
    }
    if (error.status === 403) {
      // "the role developer lacks the permission privacy:read_original" reads as a server log.
      const m = /role (\w+) lacks the permission ([\w:]+)/i.exec(error.message);
      const need = m ? (PERMISSION_WORDS[m[2]!] ?? "a role with more access") : "a role with more access";
      return m
        ? `Your role (${m[1]}) cannot open this: it needs ${need}. Ask an administrator if you need access.`
        : `Your role cannot open this. Ask an administrator if you need access.`;
    }
    const quiet = !error.code || error.code.startsWith("http_") || error.code === "validation_error";
    return `${error.message}${quiet ? "" : ` (${error.code})`}`;
  }
  if (error instanceof Error) return error.message;
  return "Unknown error";
}

/** Error: a `.banner.bad.sm` saying what failed and what happened as a result. */
export function ErrorBanner({
  error,
  what,
  onRetry,
  back,
  className,
}: {
  error?: unknown;
  /** What failed, e.g. "Findings could not be loaded." */
  what: string;
  onRetry?: () => void;
  /** Where to go instead when the thing does not exist (404), e.g. the list it came from. */
  back?: { label: string; to: string };
  className?: string;
}) {
  // Retrying a missing or malformed address gives the same answer; offer a way out instead.
  const final = error instanceof ApiError && (error.status === 404 || error.status === 422);
  return (
    <div role="alert" className={cn("banner bad sm", className)}>
      <span>
        <b>{what}</b>
        {error !== undefined && error !== null && <> {errorText(error)}</>}
      </span>
      {onRetry && !final && (
        <button type="button" className="btn sm" style={{ marginLeft: "auto" }} onClick={onRetry}>
          Try again
        </button>
      )}
      {back && final && (
        <Link className="btn sm" style={{ marginLeft: "auto" }} to={back.to}>
          {back.label}
        </Link>
      )}
    </div>
  );
}

/** A labelled bar row (`.meter-row`). */
export function MeterRow({
  label,
  value,
  pct,
  tone = "accent",
}: {
  label: ReactNode;
  value: ReactNode;
  pct: number;
  tone?: "accent" | "ink";
}) {
  const w = Math.max(0, Math.min(100, pct));
  return (
    <div className="meter-row">
      <div className="row">
        <span className="muted">{label}</span>
        <span className="mono">{value}</span>
      </div>
      <div className={cn("bar", tone === "ink" && "ink")}>
        <i style={{ width: `${w}%` }} />
      </div>
    </div>
  );
}

export function Bar({ pct, tone, label }: { pct: number; tone?: "priv" | "ink"; label?: string }) {
  const w = Math.max(0, Math.min(100, pct));
  return (
    <div
      className={cn("bar", tone)}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(w)}
      aria-label={label ?? "Progress"}
    >
      <i style={{ width: `${w}%` }} />
    </div>
  );
}
