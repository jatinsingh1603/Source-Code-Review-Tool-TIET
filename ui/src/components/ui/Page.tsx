import { Fragment, type CSSProperties, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/format";

/** The page body (`main.content`): flex column, gap 20, padding 24/28, max 1440. */
export function Content({ children, maxWidth, style }: { children: ReactNode; maxWidth?: number; style?: CSSProperties }) {
  return (
    <main className="content" id="main" tabIndex={-1} style={{ outline: "none", ...(maxWidth ? { maxWidth } : {}), ...style }}>
      {children}
    </main>
  );
}

export interface Crumb {
  label: ReactNode;
  to?: string;
  current?: boolean;
}

export function Breadcrumb({ items, nav }: { items: Crumb[]; nav?: boolean }) {
  const inner = items.map((c, i) => (
    <Fragment key={i}>
      {i > 0 && <span>/</span>}
      {c.to ? (
        <Link to={c.to}>{c.label}</Link>
      ) : (
        <span aria-current={i === items.length - 1 ? "page" : undefined} style={c.current ? { color: "var(--text)" } : undefined}>
          {c.label}
        </span>
      )}
    </Fragment>
  ));
  if (nav) {
    return (
      <nav className="crumb" aria-label="Breadcrumb">
        {inner}
      </nav>
    );
  }
  return <div className="crumb">{inner}</div>;
}

/** Page header (`.ph`): breadcrumb, h1, optional sub line, actions on the right. */
export function PageHeader({
  crumbs,
  title,
  sub,
  actions,
  titleExtra,
  style,
}: {
  crumbs?: Crumb[];
  title: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
  titleExtra?: ReactNode;
  style?: CSSProperties;
}) {
  return (
    <div className="ph" style={style}>
      <div>
        {crumbs && <Breadcrumb items={crumbs} />}
        <h1>
          {title}
          {titleExtra}
        </h1>
        {sub && (
          <p className="sub" style={{ marginTop: 4 }}>
            {sub}
          </p>
        )}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

/** `.card` with an optional `.card-h` title row. */
export function Card({
  title,
  sub,
  right,
  children,
  className,
  style,
  as: Tag = "div",
}: {
  title?: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  as?: "div" | "section";
}) {
  return (
    <Tag className={cn("card", className)} style={style}>
      {(title || right) && (
        <div className="card-h">
          {sub ? (
            <div>
              <h2>{title}</h2>
              <p className="sub">{sub}</p>
            </div>
          ) : (
            <h2>{title}</h2>
          )}
          {right}
        </div>
      )}
      {children}
    </Tag>
  );
}

/** One KPI cell (`.kpi`), a link when `to` is given. */
export function Kpi({
  label,
  value,
  unit,
  detail,
  detailClass,
  to,
}: {
  label: ReactNode;
  value: ReactNode;
  unit?: ReactNode;
  detail?: ReactNode;
  detailClass?: string;
  to?: string;
}) {
  const body = (
    <>
      <div className="k-l">{label}</div>
      <div className="k-v">
        {value}
        {unit !== undefined && unit !== "" && (
          <>
            {" "}
            <small>{unit}</small>
          </>
        )}
      </div>
      {detail !== undefined && <div className={cn("k-d", detailClass)}>{detail}</div>}
    </>
  );
  if (to) {
    return (
      <Link className="kpi" to={to}>
        {body}
      </Link>
    );
  }
  return <div className="kpi">{body}</div>;
}

/** Section heading outside a card: 14/600 title with an optional right part. */
export function SectionHead({ title, right, extra }: { title: ReactNode; right?: ReactNode; extra?: ReactNode }) {
  return (
    <div className="row between">
      <div className="row">
        <h2 style={{ fontSize: 14, fontWeight: 600 }}>{title}</h2>
        {extra}
      </div>
      {right}
    </div>
  );
}
