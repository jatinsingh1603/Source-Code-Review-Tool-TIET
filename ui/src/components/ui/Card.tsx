import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/format";

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-lg border border-border bg-surface shadow-sm", className)}
      {...rest}
    />
  );
}

export interface CardHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  icon?: ReactNode;
  className?: string;
}

export function CardHeader({ title, description, actions, icon, className }: CardHeaderProps) {
  return (
    <div className={cn("flex items-start justify-between gap-4 px-5 pt-4 pb-3", className)}>
      <div className="flex min-w-0 items-start gap-3">
        {icon && (
          <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary-soft text-primary">
            {icon}
          </div>
        )}
        <div className="min-w-0">
          <h3 className="text-lg font-semibold leading-6 text-fg">{title}</h3>
          {description && <p className="mt-0.5 text-sm text-fg-muted">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 pb-5", className)} {...rest} />;
}
