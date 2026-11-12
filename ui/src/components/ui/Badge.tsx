import type { HTMLAttributes, ReactNode } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Circle,
  Info,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  XCircle,
  Loader2,
  Ban,
  Clock,
} from "lucide-react";
import type { FindingStatus, PrivacyLevel, ScanStatus, Severity } from "@/api/types";
import { cn, LEVEL_INFO, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/format";

export type BadgeTone =
  | "neutral"
  | "primary"
  | "success"
  | "warning"
  | "danger"
  | "info"
  | "accent";

const tones: Record<BadgeTone, string> = {
  neutral: "bg-surface-3 text-fg-muted",
  primary: "bg-primary-soft text-primary",
  success: "bg-success-soft text-success",
  warning: "bg-warning-soft text-warning",
  danger: "bg-danger-soft text-danger",
  info: "bg-info-soft text-info",
  accent: "bg-accent-soft text-accent",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  icon?: ReactNode;
}

export function Badge({ tone = "neutral", icon, className, children, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium",
        tones[tone],
        className,
      )}
      {...rest}
    >
      {icon}
      {children}
    </span>
  );
}

const sevClass: Record<Severity, string> = {
  critical: "bg-sev-critical-soft text-sev-critical ring-sev-critical/30",
  high: "bg-sev-high-soft text-sev-high ring-sev-high/30",
  medium: "bg-sev-medium-soft text-sev-medium ring-sev-medium/30",
  low: "bg-sev-low-soft text-sev-low ring-sev-low/30",
  info: "bg-sev-info-soft text-sev-info ring-sev-info/30",
};

const sevIcon: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertTriangle,
  low: Info,
  info: Info,
};

export const sevDot: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const sevText: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

/** Severity is always shown as colour plus icon plus label, never colour alone. */
export function SeverityBadge({
  severity,
  className,
  size = "sm",
}: {
  severity: Severity;
  className?: string;
  size?: "sm" | "md";
}) {
  const Icon = sevIcon[severity] ?? Info;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-md font-semibold ring-1 ring-inset",
        size === "sm" ? "px-1.5 py-0.5 text-xs" : "px-2.5 py-1 text-sm",
        sevClass[severity] ?? sevClass.info,
        className,
      )}
    >
      <Icon className={size === "sm" ? "h-3 w-3" : "h-4 w-4"} aria-hidden />
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  );
}

const statusTone: Record<FindingStatus, BadgeTone> = {
  open: "warning",
  confirmed: "danger",
  false_positive: "neutral",
  accepted_risk: "info",
  fixed: "success",
};
const statusIcon: Record<FindingStatus, typeof Circle> = {
  open: Circle,
  confirmed: ShieldAlert,
  false_positive: XCircle,
  accepted_risk: ShieldQuestion,
  fixed: CheckCircle2,
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  const Icon = statusIcon[status] ?? Circle;
  return (
    <Badge tone={statusTone[status] ?? "neutral"} icon={<Icon className="h-3 w-3" aria-hidden />}>
      {STATUS_LABEL[status] ?? status}
    </Badge>
  );
}

const scanTone: Record<ScanStatus, BadgeTone> = {
  queued: "neutral",
  running: "primary",
  completed: "success",
  failed: "danger",
  cancelled: "warning",
};
const scanIcon: Record<ScanStatus, typeof Circle> = {
  queued: Clock,
  running: Loader2,
  completed: CheckCircle2,
  failed: XCircle,
  cancelled: Ban,
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const Icon = scanIcon[status] ?? Circle;
  return (
    <Badge
      tone={scanTone[status] ?? "neutral"}
      icon={
        <Icon className={cn("h-3 w-3", status === "running" && "animate-spin")} aria-hidden />
      }
    >
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </Badge>
  );
}

const lvlClass: Record<PrivacyLevel, string> = {
  L0: "text-lvl-0 ring-lvl-0/40 bg-lvl-0/10",
  L1: "text-lvl-1 ring-lvl-1/40 bg-lvl-1/10",
  L2: "text-lvl-2 ring-lvl-2/40 bg-lvl-2/10",
  L3: "text-lvl-3 ring-lvl-3/40 bg-lvl-3/10",
  L4: "text-lvl-4 ring-lvl-4/40 bg-lvl-4/10",
};

export function PrivacyLevelBadge({
  level,
  withName = false,
}: {
  level: PrivacyLevel;
  withName?: boolean;
}) {
  const info = LEVEL_INFO[level];
  return (
    <span
      title={info ? `${level}: ${info.short}` : level}
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs font-semibold ring-1 ring-inset",
        lvlClass[level] ?? lvlClass.L3,
      )}
    >
      {level === "L0" ? (
        <ShieldCheck className="h-3 w-3" aria-hidden />
      ) : (
        <ShieldAlert className="h-3 w-3" aria-hidden />
      )}
      {level}
      {withName && info ? ` · ${info.name}` : ""}
    </span>
  );
}

export function Chip({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs text-fg-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}
