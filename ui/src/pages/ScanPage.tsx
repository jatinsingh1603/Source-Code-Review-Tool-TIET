import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Ban,
  Bug,
  Check,
  CircleDashed,
  FileText,
  Loader2,
  Lock,
  MinusCircle,
  Terminal,
  WifiOff,
  XCircle,
} from "lucide-react";
import { qk, useCancelScan, useFindings, useScan } from "@/api/queries";
import { useScanEvents, type StageState } from "@/api/useScanEvents";
import type { Severity } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorState,
  PrivacyLevelBadge,
  ProgressBar,
  ScanStatusBadge,
  SeverityBadge,
  Skeleton,
  StatTile,
  useToast,
} from "@/components/ui";
import { useSession } from "@/app/session";
import { cn, fmtDateTime, fmtDuration, SEVERITY_RANK } from "@/lib/format";

const STAGE_LABEL: Record<string, string> = {
  ingest: "Ingest",
  parse: "Parse",
  analyse: "Analyse",
  aggregate: "Aggregate",
  "privacy-prepare": "Privacy prepare",
  "llm-review": "Model review",
  restore: "Restore",
  rate: "Rate",
  report: "Report",
  sync: "Sync",
};

const STAGE_HINT: Record<string, string> = {
  ingest: "Read files, detect languages",
  parse: "Build syntax trees",
  analyse: "Rules, taint, engines",
  aggregate: "Deduplicate candidates",
  "privacy-prepare": "Redact, pseudonymise, slice",
  "llm-review": "Sanitised model review",
  restore: "Map pseudonyms back locally",
  rate: "CVSS, risk, compliance",
  report: "Render reports",
  sync: "Optional integrations",
};

function StageIcon({ state }: { state: StageState }) {
  if (state === "done") return <Check className="h-4 w-4" aria-hidden />;
  if (state === "running") return <Loader2 className="h-4 w-4 animate-spin" aria-hidden />;
  if (state === "failed") return <XCircle className="h-4 w-4" aria-hidden />;
  if (state === "skipped") return <MinusCircle className="h-4 w-4" aria-hidden />;
  return <CircleDashed className="h-4 w-4" aria-hidden />;
}

const stageTone: Record<StageState, string> = {
  done: "bg-success text-white",
  running: "bg-primary text-primary-fg ring-4 ring-primary/20",
  failed: "bg-danger text-white",
  skipped: "bg-surface-3 text-fg-subtle",
  pending: "bg-surface-2 text-fg-subtle ring-1 ring-border",
};

export default function ScanPage() {
  const { id } = useParams();
  const qc = useQueryClient();
  const toast = useToast();
  const { can } = useSession();
  const [fallback, setFallback] = useState(false);
  const scanQ = useScan(id, {
    refetchInterval: (q) => {
      const st = q.state.data?.status;
      if (st !== "running" && st !== "queued") return false;
      return fallback ? 5000 : 4000;
    },
  });
  const scan = scanQ.data;
  const running = scan?.status === "running" || scan?.status === "queued";
  const live = useScanEvents(id, !!scan && running);
  const findingsQ = useFindings(id && !running ? id : undefined);
  const cancel = useCancelScan();
  const [confirm, setConfirm] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (live.stream === "fallback") setFallback(true);
  }, [live.stream]);

  useEffect(() => {
    if (live.done) {
      void qc.invalidateQueries({ queryKey: qk.scan(id ?? "") });
      void qc.invalidateQueries({ queryKey: qk.findingsAll });
      void qc.invalidateQueries({ queryKey: qk.stats });
      void qc.invalidateQueries({ queryKey: qk.scansAll });
    }
  }, [live.done, id, qc]);

  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [live.logs.length]);

  const stages = useMemo(() => {
    if (running || live.done) return live.stages;
    // Finished before this page opened: derive the stepper from the scan summary.
    const doneAll = scan?.status === "completed";
    const llmOff = scan?.privacy_level === "L0" || scan?.send === false;
    return live.stages.map((s) => ({
      ...s,
      state: (doneAll
        ? (s.name === "llm-review" || s.name === "restore") && llmOff
          ? "skipped"
          : s.name === "sync"
            ? "skipped"
            : "done"
        : s.name === scan?.stage
          ? "failed"
          : "pending") as StageState,
    }));
  }, [running, live.stages, live.done, scan?.status, scan?.stage, scan?.privacy_level, scan?.send]);

  if (scanQ.error) return <ErrorState error={scanQ.error} onRetry={() => void scanQ.refetch()} />;
  if (!scan) return <Skeleton className="h-96" />;

  const percent = running ? (live.percent ?? scan.progress ?? 0) : scan.status === "completed" ? 100 : scan.progress;
  const liveFindings = running ? live.findings : [];
  const counts = scan.counts;
  const totalFindings = Object.values(counts ?? {}).reduce((a, b) => a + b, 0);
  const sortedFindings = [...(findingsQ.data ?? [])].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]).slice(0, 8);

  const doCancel = async () => {
    try {
      await cancel.mutateAsync(scan.id);
      toast.info("Scan cancelled");
    } catch (e) {
      toast.error("Could not cancel the scan", e instanceof Error ? e.message : undefined);
    }
    setConfirm(false);
  };

  return (
    <>
      <PageHeader
        crumbs={[
          { label: "Scans", to: "/scans" },
          { label: scan.project_name ?? scan.project_id, to: `/projects/${scan.project_id}` },
          { label: scan.id },
        ]}
        title={
          <span className="flex flex-wrap items-center gap-3">
            Scan <span className="font-mono">{scan.id}</span>
            <ScanStatusBadge status={scan.status} />
          </span>
        }
        meta={
          <>
            <PrivacyLevelBadge level={scan.privacy_level} withName />
            <Badge tone="neutral">
              {scan.provider && scan.provider !== "none" ? `${scan.provider}${scan.model ? ` · ${scan.model}` : ""}` : "No model"}
            </Badge>
            {scan.send === false && scan.privacy_level !== "L0" && <Badge tone="success">payloads not sent</Badge>}
            <span className="text-xs text-fg-subtle">
              Started {fmtDateTime(scan.started_at ?? scan.created_at)} · {fmtDuration(scan.started_at, scan.finished_at)}
            </span>
          </>
        }
        actions={
          running ? (
            can("scans:run") && (
              <Button variant="outline" icon={<Ban className="h-4 w-4" />} onClick={() => setConfirm(true)}>
                Cancel scan
              </Button>
            )
          ) : (
            <>
              <Link to={`/privacy?scan=${scan.id}`}>
                <Button variant="outline" icon={<Lock className="h-4 w-4" />}>
                  Privacy
                </Button>
              </Link>
              <Link to={`/reports?scan=${scan.id}`}>
                <Button variant="outline" icon={<FileText className="h-4 w-4" />}>
                  Reports
                </Button>
              </Link>
              <Link to={`/findings?scan=${scan.id}`}>
                <Button icon={<Bug className="h-4 w-4" />}>View findings</Button>
              </Link>
            </>
          )
        }
      />

      {scan.status === "failed" && (
        <Callout tone="danger" title="The scan failed" icon={<XCircle className="h-5 w-5" />} className="mb-6">
          {scan.error ?? "See the log for details."} Privacy steps fail closed, so nothing was sent for candidates whose preparation failed.
        </Callout>
      )}
      {scan.status === "cancelled" && (
        <Callout tone="warning" title="The scan was cancelled" icon={<Ban className="h-5 w-5" />} className="mb-6">
          Results up to the point of cancellation are kept.
        </Callout>
      )}
      {fallback && running && (
        <Callout tone="warning" title="Live updates interrupted" icon={<WifiOff className="h-5 w-5" />} className="mb-6">
          The event stream could not be re-established, so this page now refreshes the scan summary every five seconds.
        </Callout>
      )}

      <Card>
        <CardBody className="pt-5">
          <div className="mb-5 flex items-center gap-4">
            <ProgressBar value={percent} label="Scan progress" className="h-2.5" />
            <span className="w-12 text-right text-sm font-semibold tabular-nums text-fg">{Math.round(percent)}%</span>
          </div>
          <ol className="grid grid-cols-2 gap-x-2 gap-y-4 sm:grid-cols-5 xl:grid-cols-10" aria-label="Pipeline stages">
            {stages.map((s) => (
              <li key={s.name} className="flex flex-col items-center text-center">
                <span className={cn("flex h-8 w-8 items-center justify-center rounded-full transition-colors", stageTone[s.state])}>
                  <StageIcon state={s.state} />
                </span>
                <span className={cn("mt-2 text-xs font-semibold", s.state === "pending" ? "text-fg-subtle" : "text-fg")}>
                  {STAGE_LABEL[s.name] ?? s.name}
                </span>
                <span className="mt-0.5 text-[11px] leading-tight text-fg-subtle">
                  {s.state === "skipped"
                    ? "skipped"
                    : s.startedAt && s.endedAt
                      ? `${((s.endedAt - s.startedAt) / 1000).toFixed(1)}s`
                      : (STAGE_HINT[s.name] ?? "")}
                </span>
                <span className="sr-only">{s.state}</span>
              </li>
            ))}
          </ol>
          {running && live.message && (
            <p className="mt-4 text-sm text-fg-muted" aria-live="polite">
              {live.message}
            </p>
          )}
        </CardBody>
      </Card>

      {!running && scan.status === "completed" && (
        <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
            <StatTile
              key={s}
              label={s.charAt(0).toUpperCase() + s.slice(1)}
              value={counts?.[s] ?? 0}
              tone={s === "critical" || s === "high" ? "danger" : s === "medium" ? "warning" : "primary"}
              to={`/findings?scan=${scan.id}&severity=${s}`}
            />
          ))}
        </div>
      )}

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader
            icon={<Bug className="h-4 w-4" />}
            title={running ? "Findings as they appear" : "Top findings"}
            description={running ? `${liveFindings.length} so far` : `${totalFindings} in total`}
          />
          <div className="max-h-[26rem] overflow-y-auto px-2 pb-3">
            {(running ? liveFindings : sortedFindings).length === 0 ? (
              <EmptyState
                title={running ? "No findings yet" : "No findings"}
                description={running ? "Findings appear here as analysis produces them." : "This scan produced no findings."}
              />
            ) : (
              <ul aria-live="polite">
                {(running ? [...liveFindings].reverse() : sortedFindings).map((f) => (
                  <li key={f.id}>
                    <Link
                      to={`/findings/${f.id}`}
                      className="flex animate-fade-in items-center gap-3 rounded-md px-3 py-2.5 hover:bg-surface-2"
                    >
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 flex-1 truncate text-sm text-fg">{f.title}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader icon={<Terminal className="h-4 w-4" />} title="Scan log" description="Stage events, counts and codes; no source code" />
          <div ref={logRef} className="mx-5 mb-5 h-[24rem] overflow-y-auto rounded-md bg-code-bg p-3 font-mono text-xs leading-relaxed ring-1 ring-border" role="log" aria-live="off">
            {live.logs.length === 0 ? (
              <p className="text-fg-subtle">{running ? "Waiting for events…" : "The live log is available while a scan runs."}</p>
            ) : (
              live.logs.map((l, i) => (
                <div key={i} className="flex gap-3">
                  <span className="shrink-0 text-code-gutter">{new Date(l.at).toLocaleTimeString("en-GB")}</span>
                  <span
                    className={cn(
                      "w-14 shrink-0 uppercase",
                      l.level === "error" ? "text-danger" : l.level.startsWith("warn") ? "text-warning" : "text-accent",
                    )}
                  >
                    {l.level}
                  </span>
                  <span className="break-words text-fg">{l.message}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        size="sm"
        title="Cancel this scan?"
        description="Running stages stop at the next checkpoint. Findings produced so far are kept."
        footer={
          <>
            <Button variant="outline" onClick={() => setConfirm(false)}>
              Keep running
            </Button>
            <Button variant="danger" loading={cancel.isPending} onClick={doCancel} icon={<AlertTriangle className="h-4 w-4" />}>
              Cancel scan
            </Button>
          </>
        }
      />
    </>
  );
}
