import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/format";

export interface StatTileProps {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  hint?: ReactNode;
  tone?: "primary" | "danger" | "warning" | "success" | "accent";
  to?: string;
  className?: string;
}

const toneClass = {
  primary: "bg-primary-soft text-primary",
  danger: "bg-danger-soft text-danger",
  warning: "bg-warning-soft text-warning",
  success: "bg-success-soft text-success",
  accent: "bg-accent-soft text-accent",
};

export function StatTile({ label, value, icon, hint, tone = "primary", to, className }: StatTileProps) {
  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-fg-muted">{label}</p>
        {icon && (
          <div className={cn("flex h-9 w-9 items-center justify-center rounded-lg", toneClass[tone])}>{icon}</div>
        )}
      </div>
      <p className="mt-2 text-3xl font-semibold tracking-tight text-fg tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-fg-subtle">{hint}</p>}
    </>
  );
  const cls = cn(
    "block rounded-lg border border-border bg-surface p-5 shadow-sm transition-shadow",
    to && "hover:border-border-strong hover:shadow-md",
    className,
  );
  return to ? (
    <Link to={to} className={cls}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}
