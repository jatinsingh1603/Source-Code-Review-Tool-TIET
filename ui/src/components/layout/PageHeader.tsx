import type { ReactNode } from "react";
import { Link, useRouteError } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { ErrorState } from "@/components/ui";

export interface Crumb {
  label: string;
  to?: string;
}

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-2">
      <ol className="flex flex-wrap items-center gap-1 text-sm text-fg-subtle">
        {items.map((c, i) => (
          <li key={i} className="flex items-center gap-1">
            {i > 0 && <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
            {c.to ? (
              <Link to={c.to} className="hover:text-fg">
                {c.label}
              </Link>
            ) : (
              <span aria-current="page" className="text-fg-muted">
                {c.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

export function PageHeader({
  title,
  description,
  actions,
  crumbs,
  meta,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  crumbs?: Crumb[];
  meta?: ReactNode;
}) {
  return (
    <div className="mb-6">
      {crumbs && <Breadcrumbs items={crumbs} />}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-base text-fg-muted">{description}</p>}
          {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}

export function RouteError() {
  const error = useRouteError();
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <ErrorState error={error} title="This page could not be displayed" onRetry={() => window.location.reload()} />
    </div>
  );
}
