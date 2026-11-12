import type { ReactNode } from "react";
import { AlertTriangle, Inbox, Loader2, RotateCw } from "lucide-react";
import { cn } from "@/lib/format";
import { Button } from "./Button";
import { ApiError } from "@/api/client";

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-surface-3", className)} />;
}

export function SkeletonRows({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2.5", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  );
}

export function Spinner({ className, label = "Loading" }: { className?: string; label?: string }) {
  return (
    <span role="status" aria-label={label} className="inline-flex">
      <Loader2 className={cn("h-5 w-5 animate-spin text-fg-subtle", className)} aria-hidden />
    </span>
  );
}

export interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ title, description, icon, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-surface-2 text-fg-subtle ring-1 ring-border">
        {icon ?? <Inbox className="h-6 w-6" aria-hidden />}
      </div>
      <h3 className="text-lg font-semibold text-fg">{title}</h3>
      {description && <p className="mt-1 max-w-md text-sm text-fg-muted">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  title = "Something went wrong",
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  className?: string;
}) {
  const msg =
    error instanceof ApiError
      ? `${error.message}${error.code && !error.code.startsWith("http_") ? ` (${error.code})` : ""}`
      : error instanceof Error
        ? error.message
        : "Unknown error";
  return (
    <div role="alert" className={cn("flex flex-col items-center px-6 py-10 text-center", className)}>
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-danger-soft text-danger">
        <AlertTriangle className="h-5 w-5" aria-hidden />
      </div>
      <h3 className="font-semibold text-fg">{title}</h3>
      <p className="mt-1 max-w-md text-sm text-fg-muted">{msg}</p>
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry} icon={<RotateCw className="h-3.5 w-3.5" />}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function Callout({
  tone = "info",
  title,
  children,
  icon,
  className,
}: {
  tone?: "info" | "warning" | "danger" | "success";
  title?: ReactNode;
  children?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  const t = {
    info: "border-info/30 bg-info-soft/60 text-info",
    warning: "border-warning/30 bg-warning-soft/60 text-warning",
    danger: "border-danger/30 bg-danger-soft/60 text-danger",
    success: "border-success/30 bg-success-soft/60 text-success",
  }[tone];
  return (
    <div className={cn("flex gap-3 rounded-lg border px-4 py-3", t, className)}>
      {icon && <div className="mt-0.5 shrink-0">{icon}</div>}
      <div className="min-w-0 text-sm text-fg">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={cn("text-fg-muted", title ? "mt-0.5" : "")}>{children}</div>}
      </div>
    </div>
  );
}

export function ProgressBar({ value, className, label }: { value: number; className?: string; label?: string }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(v)}
      aria-label={label ?? "Progress"}
      className={cn("h-2 w-full overflow-hidden rounded-full bg-surface-3", className)}
    >
      <div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${v}%` }} />
    </div>
  );
}
