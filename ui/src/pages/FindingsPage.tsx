import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Bot, BotOff, Bug, Github, Search, X } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { qk, useFindings } from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import { FINDING_STATUSES, SEVERITIES, type Finding, type FindingStatus } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import {
  Button,
  Card,
  Checkbox,
  DataTable,
  EmptyState,
  ErrorState,
  Select,
  SeverityBadge,
  SkeletonRows,
  StatusBadge,
  useToast,
  type Column,
} from "@/components/ui";
import { ScanPicker } from "@/components/ScanPicker";
import { GithubSyncDialog } from "@/components/GithubSyncDialog";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { applyFiltersToParams, filtersFromParams, toggleListValue } from "@/lib/filters";
import { cn, fmtConfidence, SEVERITY_LABEL, SEVERITY_RANK, STATUS_LABEL } from "@/lib/format";
import { sevDot } from "@/components/ui/Badge";

export function isModelDismissed(f: Finding): boolean {
  return f.llm ? f.llm.is_vulnerable === false : false;
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const { scanId, setScanId, scans } = useSelectedScan();
  const filters = useMemo(() => filtersFromParams(params), [params]);
  const [q, setQ] = useState(filters.q ?? "");
  const serverFilters = useMemo(() => {
    // Multi-value filters are applied client-side so any server build works.
    const f = { ...filters };
    if (f.severity?.includes(",")) delete f.severity;
    if (f.status?.includes(",")) delete f.status;
    return f;
  }, [filters]);
  const findingsQ = useFindings(scanId, serverFilters);
  const navigate = useNavigate();
  const { can } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<FindingStatus>("confirmed");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [syncOpen, setSyncOpen] = useState(false);

  const setFilters = (f: typeof filters) => setParams(applyFiltersToParams(params, f), { replace: true });

  // Debounce free-text search into the URL.
  useEffect(() => {
    const t = setTimeout(() => {
      if ((filters.q ?? "") !== q) setFilters({ ...filters, q: q || undefined });
    }, 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  useEffect(() => setSelected(new Set()), [scanId]);

  // Filters are sent to the server; they are re-applied here so a server that
  // accepts only one value per filter still yields the exact view.
  const rows = useMemo(() => {
    const sev = new Set((filters.severity ?? "").split(",").filter(Boolean));
    const st = new Set((filters.status ?? "").split(",").filter(Boolean));
    return (findingsQ.data ?? []).filter((f) => (!sev.size || sev.has(f.severity)) && (!st.size || st.has(f.status)));
  }, [findingsQ.data, filters.severity, filters.status]);
  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));

  const applyBulk = async () => {
    setBulkBusy(true);
    const ids = [...selected];
    const results = await Promise.allSettled(ids.map((id) => endpoints.patchFinding(id, { status: bulkStatus })));
    const failed = results.filter((r) => r.status === "rejected").length;
    setBulkBusy(false);
    void qc.invalidateQueries({ queryKey: qk.findingsAll });
    void qc.invalidateQueries({ queryKey: qk.stats });
    if (failed) toast.error("Some updates failed", `${ids.length - failed} updated, ${failed} failed.`);
    else toast.success("Findings updated", `${ids.length} marked ${STATUS_LABEL[bulkStatus].toLowerCase()}.`);
    setSelected(new Set());
  };

  const cols: Column<Finding>[] = [
    ...(can("findings:triage")
      ? [
          {
            id: "sel",
            header: (
              <Checkbox
                label="Select all findings"
                checked={allSelected}
                indeterminate={selected.size > 0 && !allSelected}
                onChange={(v) => setSelected(v ? new Set(rows.map((r) => r.id)) : new Set())}
              />
            ),
            headerClassName: "w-10",
            cell: (f: Finding) => (
              <Checkbox
                label={`Select ${f.title}`}
                checked={selected.has(f.id)}
                onChange={(v) =>
                  setSelected((s) => {
                    const n = new Set(s);
                    if (v) n.add(f.id);
                    else n.delete(f.id);
                    return n;
                  })
                }
              />
            ),
          },
        ]
      : []),
    {
      id: "severity",
      header: "Severity",
      cell: (f) => <SeverityBadge severity={f.severity} />,
      sortValue: (f) => SEVERITY_RANK[f.severity] * 100 + (f.cvss4_score ?? 0),
    },
    {
      id: "title",
      header: "Finding",
      rowHeader: true,
      cell: (f) => (
        <div className={cn("min-w-[18rem]", isModelDismissed(f) && "opacity-70")}>
          <p className="font-medium text-fg">{f.title}</p>
          <p className="mt-0.5 font-mono text-xs text-fg-subtle">
            {f.locations[0]?.path}:{f.locations[0]?.start_line}
          </p>
          {isModelDismissed(f) && (
            <p className="mt-1 inline-flex items-center gap-1 rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-fg-muted">
              <BotOff className="h-3 w-3" aria-hidden /> Model judged not exploitable; kept with deterministic evidence
            </p>
          )}
        </div>
      ),
      sortValue: (f) => f.title,
    },
    { id: "cwe", header: "CWE", cell: (f) => <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{f.cwe ?? "—"}</span>, sortValue: (f) => f.cwe ?? "" },
    {
      id: "cvss",
      header: "CVSS v4",
      cell: (f) => <span className="tabular-nums text-sm text-fg">{f.cvss4_score != null ? f.cvss4_score.toFixed(1) : "—"}</span>,
      sortValue: (f) => f.cvss4_score ?? 0,
    },
    {
      id: "model",
      header: "Model",
      cell: (f) =>
        f.llm ? (
          <span className={cn("inline-flex items-center gap-1 whitespace-nowrap text-xs", f.llm.is_vulnerable ? "text-danger" : "text-fg-muted")}>
            <Bot className="h-3.5 w-3.5" aria-hidden />
            {f.llm.is_vulnerable ? "Confirmed" : "Dismissed"} · {fmtConfidence(f.llm.confidence)}
          </span>
        ) : (
          <span className="text-xs text-fg-subtle">Not reviewed</span>
        ),
      sortValue: (f) => (f.llm ? (f.llm.is_vulnerable ? 2 : 1) : 0),
    },
    { id: "engine", header: "Engine", cell: (f) => <span className="whitespace-nowrap text-xs text-fg-muted">{f.engine ?? "—"}</span>, sortValue: (f) => f.engine ?? "" },
    { id: "status", header: "Status", cell: (f) => <StatusBadge status={f.status} />, sortValue: (f) => f.status },
  ];

  const sevSet = new Set((filters.severity ?? "").split(",").filter(Boolean));
  const activeFilters = !!(filters.severity || filters.status || filters.cwe || filters.q);

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every finding keeps its deterministic evidence. A model verdict can annotate and down-rank a finding; it never removes one."
        actions={
          <>
            <ScanPicker scans={scans} value={scanId} onChange={setScanId} />
            {can("github:sync") && scanId && (
              <Button variant="outline" icon={<Github className="h-4 w-4" />} onClick={() => setSyncOpen(true)}>
                GitHub sync
              </Button>
            )}
          </>
        }
      />
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-border p-4">
          <div className="relative min-w-[16rem] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" aria-hidden />
            <input
              type="search"
              aria-label="Search findings"
              className="ck-input pl-9"
              placeholder="Search title, path, rule or CWE"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Severity filter">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                aria-pressed={sevSet.has(s)}
                onClick={() => setFilters({ ...filters, severity: toggleListValue(filters.severity, s) })}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
                  sevSet.has(s) ? "border-primary bg-primary-soft text-primary" : "border-border text-fg-muted hover:bg-surface-2",
                )}
              >
                <span className={`h-2 w-2 rounded-full ${sevDot[s]}`} aria-hidden />
                {SEVERITY_LABEL[s]}
              </button>
            ))}
          </div>
          <Select
            aria-label="Status filter"
            className="w-44"
            value={filters.status ?? ""}
            onChange={(e) => setFilters({ ...filters, status: e.target.value || undefined })}
          >
            <option value="">All statuses</option>
            {FINDING_STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </Select>
          <input
            aria-label="CWE filter"
            className="ck-input w-32"
            placeholder="CWE-89"
            value={filters.cwe ?? ""}
            onChange={(e) => setFilters({ ...filters, cwe: e.target.value || undefined })}
          />
          {activeFilters && (
            <Button
              variant="ghost"
              size="sm"
              icon={<X className="h-3.5 w-3.5" />}
              onClick={() => {
                setQ("");
                setFilters({});
              }}
            >
              Clear
            </Button>
          )}
        </div>

        {selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-3 border-b border-border bg-primary-soft/40 px-4 py-2.5">
            <span className="text-sm font-medium text-fg">{selected.size} selected</span>
            <Select aria-label="New status" className="w-48" value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value as FindingStatus)}>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  Mark as {STATUS_LABEL[s].toLowerCase()}
                </option>
              ))}
            </Select>
            <Button size="sm" loading={bulkBusy} onClick={applyBulk}>
              Apply
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              Clear selection
            </Button>
          </div>
        )}

        {findingsQ.isLoading || (!scanId && scans.length > 0) ? (
          <div className="p-4">
            <SkeletonRows rows={8} />
          </div>
        ) : findingsQ.error ? (
          <ErrorState error={findingsQ.error} onRetry={() => void findingsQ.refetch()} />
        ) : (
          <>
            <DataTable
              columns={cols}
              rows={rows}
              rowKey={(f) => f.id}
              selected={selected}
              onRowClick={(f) => navigate(`/findings/${f.id}`)}
              initialSort={{ id: "severity", dir: "desc" }}
              caption="Findings"
              empty={
                <EmptyState
                  icon={<Bug className="h-6 w-6" />}
                  title={activeFilters ? "No findings match these filters" : scanId ? "No findings in this scan" : "No scans yet"}
                  description={activeFilters ? "Clear or change the filters to see more." : undefined}
                />
              }
            />
            {rows.length > 0 && (
              <p className="border-t border-border px-4 py-2.5 text-xs text-fg-subtle">
                {rows.length} finding{rows.length === 1 ? "" : "s"}
              </p>
            )}
          </>
        )}
      </Card>
      {scanId && <GithubSyncDialog scanId={scanId} open={syncOpen} onClose={() => setSyncOpen(false)} />}
    </>
  );
}
