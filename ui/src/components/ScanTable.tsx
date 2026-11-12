import { useNavigate } from "react-router-dom";
import type { Scan, Severity } from "@/api/types";
import { DataTable, PrivacyLevelBadge, ScanStatusBadge, type Column } from "@/components/ui";
import { fmtDuration, fmtRelative, SEVERITY_LABEL } from "@/lib/format";
import { sevDot } from "@/components/ui/Badge";
import { useCurrentProject } from "@/app/project-context";

/** Scan ids can be long; show a readable prefix and keep the full id in the title. */
export function ScanId({ id }: { id: string }) {
  const short = id.length > 16 ? `${id.slice(0, 14)}…` : id;
  return (
    <span className="font-mono text-sm font-medium text-fg" title={id}>
      {short}
    </span>
  );
}

export function SeverityCountsInline({ counts }: { counts: Scan["counts"] }) {
  const order: Severity[] = ["critical", "high", "medium", "low"];
  return (
    <span className="inline-flex items-center gap-2.5">
      {order.map((s) => (
        <span key={s} className="inline-flex items-center gap-1 text-sm tabular-nums" title={SEVERITY_LABEL[s]}>
          <span className={`h-2 w-2 rounded-full ${sevDot[s]}`} aria-hidden />
          <span className="sr-only">{SEVERITY_LABEL[s]}</span>
          <span className={counts?.[s] ? "font-semibold text-fg" : "text-fg-subtle"}>{counts?.[s] ?? 0}</span>
        </span>
      ))}
    </span>
  );
}

export function ScanTable({
  scans,
  showProject = false,
  dense,
  empty,
  compact = false,
}: {
  scans: Scan[];
  showProject?: boolean;
  dense?: boolean;
  /** Hide provider and duration columns (for narrow cards). */
  compact?: boolean;
  empty?: React.ReactNode;
}) {
  const navigate = useNavigate();
  const { projects } = useCurrentProject();
  const projectName = (s: Scan) => s.project_name ?? projects.find((p) => p.id === s.project_id)?.name ?? s.project_id;
  const cols: Column<Scan>[] = [
    {
      id: "id",
      header: "Scan",
      rowHeader: true,
      cell: (s) =>
        compact ? (
          <span className="flex flex-col items-start gap-1">
            <ScanId id={s.id} />
            <ScanStatusBadge status={s.status} />
          </span>
        ) : (
          <ScanId id={s.id} />
        ),
      sortValue: (s) => s.id,
    },
    ...(showProject
      ? [
          {
            id: "project",
            header: "Project",
            cell: (s: Scan) => <span className="whitespace-nowrap text-fg">{projectName(s)}</span>,
            sortValue: (s: Scan) => projectName(s),
          },
        ]
      : []),
    ...(compact ? [] : [{ id: "status", header: "Status", cell: (s: Scan) => <ScanStatusBadge status={s.status} />, sortValue: (s: Scan) => s.status }]),
    {
      id: "findings",
      header: "Findings",
      cell: (s) => <SeverityCountsInline counts={s.counts} />,
      sortValue: (s) => (s.counts?.critical ?? 0) * 1000 + (s.counts?.high ?? 0) * 100 + (s.counts?.medium ?? 0),
    },
    { id: "level", header: "Privacy", cell: (s) => <PrivacyLevelBadge level={s.privacy_level} />, sortValue: (s) => s.privacy_level },
    ...(compact ? [] : [{
      id: "provider",
      header: "Provider",
      cell: (s: Scan) => (
        <span className="whitespace-nowrap text-sm text-fg-muted">
          {s.provider === "none" || !s.provider ? "Local only" : `${s.provider}${s.model ? ` · ${s.model}` : ""}`}
        </span>
      ),
    }]),
    {
      id: "when",
      header: "Started",
      cell: (s) => <span className="whitespace-nowrap text-sm text-fg-muted">{fmtRelative(s.started_at ?? s.created_at)}</span>,
      sortValue: (s) => s.started_at ?? s.created_at ?? "",
    },
    ...(compact ? [] : [{
      id: "dur",
      header: "Duration",
      cell: (s: Scan) => <span className="text-sm tabular-nums text-fg-muted">{s.started_at ? fmtDuration(s.started_at, s.finished_at) : "—"}</span>,
    }]),
  ];
  return (
    <DataTable
      columns={cols}
      rows={scans}
      rowKey={(s) => s.id}
      onRowClick={(s) => navigate(`/scans/${s.id}`)}
      initialSort={{ id: "when", dir: "desc" }}
      empty={empty}
      dense={dense}
      caption="Scans"
    />
  );
}
