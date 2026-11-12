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

export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    return `${error.message}${error.code && !error.code.startsWith("http_") ? ` (${error.code})` : ""}`;
  }
  if (error instanceof Error) return error.message;
  return "Unknown error";
}

/** Error: a `.banner.bad.sm` saying what failed and what happened as a result. */
export function ErrorBanner({
  error,
  what,
  onRetry,
  className,
}: {
  error?: unknown;
  /** What failed, e.g. "Findings could not be loaded." */
  what: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div role="alert" className={cn("banner bad sm", className)}>
      <span>
        <b>{what}</b>
        {error !== undefined && error !== null && <> {errorText(error)}</>}
      </span>
      {onRetry && (
        <button type="button" className="btn sm" style={{ marginLeft: "auto" }} onClick={onRetry}>
          Try again
        </button>
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
