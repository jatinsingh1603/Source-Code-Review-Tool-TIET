import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { subscribeScanEvents, type StreamState } from "@/api/events";
import { qk, useCancelScan, usePrivacy, useProject, useProviders, useScan } from "@/api/queries";
import type { PrivacySummary, Scan, ScanEvent } from "@/api/types";
import { useSession } from "@/app/session";
import { useShell } from "@/app/shell-context";
import { useCurrentProject } from "@/app/project-context";
import { fmtBytes, fmtClock, fmtElapsed, fmtInt, fmtTime, findingLabel, LEVEL_NAME, scanLabel, secondsBetween } from "@/lib/display";
import { providerName, scanProviderId, shortProviderName } from "@/lib/domain";
import {
  Button,
  Content,
  Dialog,
  Empty,
  ErrorBanner,
  Icon,
  MoreLink,
  PageHeader,
  SCAN_STATUS,
  Skeleton,

  useToast,
} from "@/components/ui";
import { ENGINE_GROUPS, STAGES } from "@/lib/pipeline";

type Ev = ScanEvent & { t: number };

const ENGINE_NAME: Record<string, string> = {
  rules: "Rules (SAST)",
  taint: "Taint engine",
  secrets: "Secrets",
  iac: "IaC checks",
  sca: "SCA · OSV",
  engines: "External engines (Opengrep, Bandit, ESLint)",
};

/** Collect a scan's events: the server replays history, then streams until `done`. */
function useScanTimeline(scanId: string | undefined, enabled: boolean) {
  const [events, setEvents] = useState<Ev[]>([]);
  const [stream, setStream] = useState<StreamState>("connecting");
  useEffect(() => {
    setEvents([]);
    if (!scanId || !enabled) return;
    const buf: Ev[] = [];
    let raf: number | null = null;
    const flush = () => {
      raf = null;
      setEvents([...buf]);
    };
    const stop = subscribeScanEvents(scanId, {
      onEvent: (e) => {
        const t = e.at ? Date.parse(e.at) : Date.now();
        buf.push({ ...e, t: Number.isNaN(t) ? Date.now() : t });
        if (raf === null) raf = window.setTimeout(flush, 80) as unknown as number;
      },
      onState: setStream,
    });
    return () => {
      stop();
      if (raf !== null) clearTimeout(raf);
    };
  }, [scanId, enabled]);
  return { events, stream };
}

const SHORT: [RegExp, string][] = [
  [/^(intake|ingest)$/, "ingest"],
  [/^parse$/, "parse"],
  [/^analyse/, "analyse"],
  [/^aggregate$/, "candidate"],
  [/^privacy/, "privacy"],
  [/^llm/, "llm"],
  [/^restore$/, "restore"],
  [/^rate$/, "risk"],
  [/^report$/, "report"],
  [/^sync/, "sync"],
];
const shortStage = (s: string) => SHORT.find(([r]) => r.test(s))?.[1] ?? s;

type StageState = "done" | "run" | "wait" | "skip" | "fail" | "stop";

function deriveStages(events: Ev[], scan: Scan | undefined) {
  const state = new Map<string, "running" | "done" | "skipped" | "failed">();
  for (const e of events) {
    if (e.type !== "stage") continue;
    const st = /start|running/.test(e.status) ? "running" : /skip/.test(e.status) ? "skipped" : /fail|error/.test(e.status) ? "failed" : "done";
    state.set(e.name, st);
  }
  const done = events.find((e) => e.type === "done") as (Ev & { type: "done" }) | undefined;
  const final = done?.status ?? (scan && scan.status !== "running" && scan.status !== "queued" ? scan.status : null);
  return STAGES.map((g) => {
    const members = [...state.entries()].filter(([k]) => g.members(k));
    let s: StageState = "wait";
    if (members.some(([, v]) => v === "running")) s = final ? (final === "completed" ? "done" : final === "cancelled" ? "stop" : "fail") : "run";
    else if (members.some(([, v]) => v === "failed")) s = "fail";
    else if (members.length && members.every(([, v]) => v === "skipped")) s = "skip";
    else if (members.length) s = "done";
    else if (final === "completed") s = "skip";
    return { ...g, state: s };
  });
}

type EgressEv = Extract<ScanEvent, { type: "egress" }>;

/** The largest count a server stage of this group reported. */
function groupCount(n: string, events: Ev[]): number | null {
  const g = STAGES.find((x) => x.n === n);
  let best: number | null = null;
  for (const e of events) {
    if (e.type === "stage" && g?.members(e.name) && typeof e.count === "number" && e.count > 0) best = Math.max(best ?? 0, e.count);
  }
  return best;
}

function stageCount(n: string, state: StageState, scan: Scan | undefined, events: Ev[], egress: EgressEv | undefined, privacy?: PrivacySummary): string {
  if (state === "wait") return "waiting";
  if (state === "skip") return n === "09" ? "off" : "skipped";
  if (state === "fail") return "failed";
  if (state === "stop") return "stopped";
  const c = groupCount(n, events);
  const findings = events.filter((e) => e.type === "finding" && !e.phase).length;
  const fallback = state === "run" ? "running" : "done";
  switch (n) {
    case "01":
      return c ? filesText(c) : scan?.files ? filesText(scan.files) : fallback;
    case "02":
      return c ? filesText(c) : fallback;
    case "03":
      return state === "done" && (findings || scan?.findings_total) ? `${fmtInt(findings || scan?.findings_total)} found` : fallback;
    case "04":
      if (egress?.total !== undefined) return `${fmtInt(egress.total)} slices`;
      return privacy ? `${fmtInt(privacy.payloads + (privacy.blocked ?? 0))} slices` : c ? `${fmtInt(c)} cand.` : fallback;
    case "05":
      if (egress?.payloads !== undefined && egress.total !== undefined) return `${fmtInt(egress.payloads)} / ${fmtInt(egress.total)} sent`;
      return privacy ? `${fmtInt(privacy.payloads)} sent` : fallback;
    case "06":
      return c ? `${fmtInt(c)} verdicts` : fallback;
    case "08":
      return c ? `${fmtInt(c)} records` : fallback;
    default:
      return c ? fmtInt(c) : fallback;
  }
}

export default function ScanPage() {
  const { id } = useParams();
  const scanQ = useScan(id, {
    refetchInterval: (q) => {
      const s = (q.state.data as Scan | undefined)?.status;
      return s === "running" || s === "queued" ? 3000 : false;
    },
  });
  const scan = scanQ.data;
  const project = useProject(scan?.project_id).data;
  const providers = useProviders().data;
  const { events } = useScanTimeline(id, !!scan);
  const running = scan?.status === "running" || scan?.status === "queued";
  const doneEv = events.find((e) => e.type === "done") as (Ev & { type: "done" }) | undefined;
  const status = doneEv?.status ?? scan?.status;
  const finished = status === "completed";
  const privacyQ = usePrivacy(finished ? id : undefined);
  const cancel = useCancelScan();
  const toast = useToast();
  const qc = useQueryClient();
  const { can } = useSession();
  const [confirm, setConfirm] = useState(false);
  const [now, setNow] = useState(Date.now());
  const wasRunning = useRef(false);
  const { setCurrentId } = useCurrentProject();
  // The top bar describes this scan: its project, level and provider.
  useShell({
    levelPill: scan ? `${scan.privacy_level} · ${LEVEL_NAME[scan.privacy_level] ?? ""}` : undefined,
    // An L0 scan used no provider; say so rather than fall back to the default provider's pill.
    providerPill: scan && scan.provider ? providerName(scanProviderId(scan), providers) : undefined,
  });
  useEffect(() => {
    if (scan?.project_id) setCurrentId(scan.project_id);
  }, [scan?.project_id, setCurrentId]);

  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);

  useEffect(() => {
    if (running) wasRunning.current = true;
    if (doneEv && wasRunning.current) {
      wasRunning.current = false;
      void qc.invalidateQueries({ queryKey: qk.scan(id!) });
      void qc.invalidateQueries({ queryKey: qk.scansAll });
      void qc.invalidateQueries({ queryKey: qk.stats });
      void qc.invalidateQueries({ queryKey: qk.health });
      if (doneEv.status === "completed") toast.success("Scan completed", "Findings and the egress ledger are ready.");
      // A cancel the viewer asked for is confirmed by the cancel button's own toast.
      else if (doneEv.status === "failed") toast.error("Scan failed", scan?.error ?? undefined);
    }
  }, [doneEv, running, id, qc, toast, scan?.error]);

  const stages = useMemo(() => deriveStages(events, scan), [events, scan]);
  const egress = useMemo(() => [...events].reverse().find((e) => e.type === "egress") as EgressEv | undefined, [events]);
  const egressFinal = useMemo(() => events.find((e) => e.type === "egress" && e.final) as EgressEv | undefined, [events]);
  const progress = useMemo(() => {
    const p = [...events].reverse().find((e) => e.type === "progress") as (Ev & { type: "progress" }) | undefined;
    if (finished) return 100;
    return p?.percent ?? scan?.progress ?? 0;
  }, [events, finished, scan]);
  const cur = stages.findIndex((s) => s.state === "run");
  const stageNo = cur >= 0 ? cur + 1 : finished ? 9 : stages.filter((s) => s.state === "done").length;

  const lines = useMemo(() => {
    let stage = "scan";
    const out: { t: number; stage: string; text: string; cls?: string }[] = [];
    for (const e of events) {
      if (e.type === "stage") stage = shortStage(e.name);
      if (e.type === "log") {
        const pol = /policy|never-send|egress_blocked|blocked/.test(e.message) && stage === "privacy";
        const warn = /warn|error/.test(e.level) || /failed/.test(e.message);
        out.push({ t: e.t, stage, text: e.message, cls: pol ? "acl" : warn ? "wl" : undefined });
      } else if (e.type === "finding") {
        if (e.phase === "verdict") out.push({ t: e.t, stage: "verdict", text: e.title, cls: "okl" });
        else out.push({ t: e.t, stage: "finding", text: `${findingLabel(e.id)} ${e.severity} · ${e.title}` });
      } else if (e.type === "done") {
        out.push({ t: e.t, stage: "done", text: `scan ${e.status}`, cls: e.status === "completed" ? "okl" : "wl" });
      }
    }
    return out;
  }, [events]);
  const consoleRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = consoleRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines.length]);

  if (scanQ.isError) {
    return (
      <Content>
        <PageHeader crumbs={[{ label: "Scans", to: "/scans" }, { label: scanLabel(id) }]} title="Scan" />
        <ErrorBanner what="This scan could not be loaded." error={scanQ.error} onRetry={() => void scanQ.refetch()} back={{ label: "All scans", to: "/scans" }} />
      </Content>
    );
  }
  if (!scan) {
    return (
      <Content>
        <div className="card">
          <Skeleton rows={3} />
        </div>
      </Content>
    );
  }

  const st = SCAN_STATUS[status ?? scan.status] ?? SCAN_STATUS.queued;
  const elapsed = secondsBetween(scan.started_at ?? scan.created_at, finished || !running ? scan.finished_at ?? null : null, now) ?? 0;
  const p = privacyQ.data;
  const download = () => {
    const text = lines.map((l) => `${fmtTime(l.t)}  ${l.stage.padEnd(10)} ${l.text}`).join("\n");
    const url = URL.createObjectURL(new Blob([text + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `codekavach-${scan.id}.log`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: project?.name ?? scan.project_name ?? "Project", to: "/" }, { label: "Scans", to: "/scans" }, { label: scanLabel(scan.id) }]}
        title={`Scan ${scanLabel(scan.id)}`}
        titleExtra={
          <span className="st sm" style={{ marginLeft: 8, verticalAlign: "middle" }}>
            <span className={`dot${st.tone === "neutral" ? "" : ` ${st.tone}`}`} />
            {st.label}
          </span>
        }
        actions={
          <>
            <span className="sub mono">
              {scan.status === "queued"
                ? `Waiting for a free scan slot · ${fmtClock(elapsed)}`
                : running
                ? `${fmtClock(elapsed)} elapsed${scan.eta_seconds ? ` · about ${Math.round(scan.eta_seconds)} s left` : ""}`
                : finished
                  ? `Completed in ${fmtElapsed(scan.started_at, scan.finished_at)}`
                  : scan.finished_at && scan.started_at
                    ? `Stopped after ${fmtElapsed(scan.started_at, scan.finished_at)}`
                    : null}
            </span>
            {running && can("scans:run") && (
              <Button variant="danger" onClick={() => setConfirm(true)}>
                Cancel scan
              </Button>
            )}
            {(status === "failed" || status === "cancelled") && can("scans:run") && (
              <Link className="btn primary" to={rerunLink(scan)}>
                Run again
              </Link>
            )}
            {finished && (
              <>
                <Link className="btn" to={`/findings?scan=${scan.id}`}>
                  Open findings
                </Link>
                <Link className="btn" to={`/privacy/ledger?scan=${scan.id}`}>
                  Open ledger
                </Link>
              </>
            )}
          </>
        }
      />
      {status === "failed" && (
        <div className="banner bad sm" role="alert">
          {scan.error ?? "The scan failed."}
          {/privacy|I4/i.test(scan.error ?? "") ? " Request aborted under I4. Nothing was sent." : ""}
        </div>
      )}

      <section className="g g-side-l">
        <LaunchSummary
          scan={scan}
          projectName={project?.name ?? scan.project_name}
          providers={providers}
          source={scan.ref ?? project?.source.ref ?? (project?.source as { upload_name?: string } | undefined)?.upload_name ?? project?.source.path ?? project?.source.url ?? project?.source.type}
        />

        <div className="stack s16">
          <div className="card stack s16">
            <div className="row between">
              <h2>Pipeline</h2>
              <span className="sub">
                {running || finished
                  ? `Stage ${Math.max(1, stageNo)} of 9 · ${Math.round(progress)}%`
                  : `Stopped at stage ${Math.min(9, stages.findIndex((x) => x.state === "stop") + 1 || stageNo + 1)} of 9`}
              </span>
            </div>
            <div className="bar" role="progressbar" aria-valuenow={Math.round(progress)} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
              <i style={{ width: `${progress}%` }} />
            </div>
            <div className="pipe-wrap" tabIndex={0} role="region" aria-label="Pipeline stages">
              <div className="pipe">
                {stages.map((s) => (
                  <div
                    key={s.n}
                    className={`stage ${s.state === "done" ? "done" : s.state === "run" ? "run" : s.state === "fail" ? "done" : "wait"}${s.guard ? " guardz" : ""}`}
                  >
                    <span className="sn">
                      {s.n}
                      {s.state === "run" ? " running" : ""}
                    </span>
                    <span className="st-t">{s.title}</span>
                    <span className={`cnt${s.state === "fail" ? " badc" : ""}`}>{stageCount(s.n, s.state, scan, events, egress, p)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-h">
              <div>
                <h2>Egress meter</h2>
                <p className="sub">What left during this scan, checked as it left</p>
              </div>
              <MoreLink to={`/privacy/ledger?scan=${scan.id}`}>Open ledger</MoreLink>
            </div>
            {scan.privacy_level === "L0" ? (
              <Empty title="Nothing leaves at L0">This scan uses local engines only; no payload is prepared.</Empty>
            ) : !p && egress ? (
              <div className="kpi-strip boxed">
                <div className="kpi">
                  <div className="k-l">Payloads</div>
                  <div className="k-v">
                    {fmtInt(egress.payloads)} <small>/ {fmtInt(egress.total)}</small>
                  </div>
                </div>
                <div className="kpi">
                  <div className="k-l">Bytes out</div>
                  <div className="k-v">{egressFinal?.bytes_sent !== undefined ? fmtBytes(egressFinal.bytes_sent).v : "—"} <small>{egressFinal?.bytes_sent !== undefined ? fmtBytes(egressFinal.bytes_sent).unit : ""}</small></div>
                  {egressFinal?.bytes_sent === undefined && <div className="k-d">totalled after the last payload</div>}
                </div>
                <div className="kpi">
                  <div className="k-l">Secrets checked</div>
                  <div className="k-v">{egressFinal?.secrets_checked !== undefined ? fmtInt(egressFinal.secrets_checked) : "—"}</div>
                  <div className="k-d">checked as each payload left</div>
                </div>
                <div className="kpi">
                  <div className="k-l">Domain terms in payloads</div>
                  <div className="k-v">{egressFinal?.terms_found !== undefined ? fmtInt(egressFinal.terms_found) : "—"}</div>
                  <div className="k-d">{egressFinal?.terms_checked !== undefined ? `${fmtInt(egressFinal.terms_checked)} listed terms` : "after the ledger check"}</div>
                </div>
              </div>
            ) : !p ? (
              running ? (
                <p className="sm muted">Counts appear here as soon as the privacy step has written the ledger.</p>
              ) : privacyQ.isLoading ? (
                <Skeleton />
              ) : (
                <p className="sm muted">
                  {status === "cancelled" || status === "failed"
                    ? "No egress summary: the scan stopped before the privacy step finished. The ledger lists anything that was recorded."
                    : "No egress summary for this scan."}
                </p>
              )
            ) : (
              <div className="kpi-strip boxed">
                <div className="kpi">
                  <div className="k-l">Payloads</div>
                  <div className="k-v">
                    {fmtInt(p.payloads)} <small>/ {fmtInt(p.payloads + (p.blocked ?? 0))}</small>
                  </div>
                  <div className="k-d">{fmtInt(p.blocked)} blocked</div>
                </div>
                <div className="kpi">
                  <div className="k-l">{p.bytes_sent !== undefined && p.bytes_sent !== null ? "Bytes out" : "Tokens out"}</div>
                  <div className="k-v">
                    {p.bytes_sent !== undefined && p.bytes_sent !== null ? fmtBytes(p.bytes_sent).v : (p.tokens_sent / 1000).toFixed(1)}{" "}
                    <small>{p.bytes_sent !== undefined && p.bytes_sent !== null ? fmtBytes(p.bytes_sent).unit : "k"}</small>
                  </div>
                  {p.lines_sent !== undefined && p.lines_sent !== null && <div className="k-d">{fmtInt(p.lines_sent)} lines</div>}
                </div>
                <div className="kpi">
                  <div className="k-l">Secrets redacted</div>
                  <div className="k-v">{fmtInt(Object.values(p.placeholders_by_type ?? {}).reduce((a, b) => a + b, 0))}</div>
                  <div className="k-d">replaced before sending</div>
                </div>
                <div className="kpi">
                  <div className="k-l">Domain terms in payloads</div>
                  <div className="k-v">{fmtInt(p.zero_leak.occurrences)}</div>
                  <div className="k-d">{fmtInt(p.zero_leak.checked)} listed terms</div>
                </div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-h">
              <h2>Log</h2>
              <div className="row">
                <span className="xs faint">{running ? "streaming" : `${lines.length} lines`}</span>
                <Button size="sm" onClick={download} disabled={!lines.length}>
                  Download log
                </Button>
              </div>
            </div>
            <div className="console" role="log" aria-live="polite" ref={consoleRef} tabIndex={0}>
              {lines.length === 0 && <div>{running ? "Waiting for the first event…" : "No log for this scan."}</div>}
              {lines.map((l, i) => (
                <div key={i}>
                  <span className="t">{fmtTime(l.t)}</span>
                  {"  "}
                  {l.cls ? <span className={l.cls}>{`${l.stage.padEnd(10)} ${l.text}`}</span> : `${l.stage.padEnd(10)} ${l.text}`}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Cancel this scan?"
        description="Stages that have not started will not run. Payloads already recorded stay in the ledger."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(false)}>
              Keep running
            </Button>
            <Button
              variant="danger"
              loading={cancel.isPending}
              onClick={() =>
                cancel.mutate(scan.id, {
                  onSuccess: () => {
                    setConfirm(false);
                    toast.info("Scan cancelled");
                  },
                  onError: (e) => toast.error("Could not cancel", e.message),
                })
              }
            >
              Cancel scan
            </Button>
          </>
        }
      />
    </Content>
  );
}

/** The launch form, locked while the scan runs (left column of the live view). */
function LaunchSummary({
  scan,
  projectName,
  providers,
  source,
}: {
  scan: Scan;
  projectName?: string;
  providers?: { id: string; name: string; models: string[] }[];
  source?: string;
}) {
  const rules = scan.rules ?? [];
  return (
    <form className="card stack s16 locked" aria-label="Scan configuration" onSubmit={(e) => e.preventDefault()}>
      <div className="row between">
        <h2>Launch settings</h2>
        <span className="xs faint">{scan.status === "running" || scan.status === "queued" ? "locked while running" : "as launched"}</span>
      </div>
      <div className="fld">
        <label htmlFor="sc-t">Target</label>
        <select id="sc-t" className="inp" disabled value="x">
          <option value="x">{projectName ?? scan.project_id}</option>
        </select>
      </div>
      <div className="fld">
        <span className="lbl">Mode</span>
        <div className="seg">
          <button className={scan.mode !== "diff" ? "on" : undefined} type="button" disabled>
            Branch
          </button>
          <button className={scan.mode === "diff" ? "on" : undefined} type="button" disabled>
            Diff
          </button>
        </div>
      </div>
      <div className="fld">
        <label htmlFor="sc-b">Source</label>
        <input id="sc-b" className="inp mono" disabled value={source ?? ""} />
      </div>
      <div className="fld">
        <label htmlFor="sc-l">Privacy level</label>
        <select id="sc-l" className="inp" disabled value="x">
          <option value="x">
            {scan.privacy_level} · {LEVEL_NAME[scan.privacy_level]}
            {scan.privacy_level === "L3" ? " (default)" : ""}
          </option>
        </select>
      </div>
      <div className="g" style={{ gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10 }}>
        <div className="fld">
          <label htmlFor="sc-p">Provider</label>
          <select id="sc-p" className="inp" disabled value="x" title={providerName(scanProviderId(scan), providers as never)}>
            <option value="x">{shortProviderName(providerName(scanProviderId(scan), providers as never))}</option>
          </select>
        </div>
        <div className="fld">
          <label htmlFor="sc-m">Model</label>
          <select id="sc-m" className="inp" disabled value="x">
            <option value="x">{scan.model ?? "default"}</option>
          </select>
        </div>
      </div>
      <div className="stack s6">
        <span className="lbl">Engines</span>
        {(Array.isArray(scan.engines) && scan.engines.length && typeof scan.engines[0] === "object"
          ? (scan.engines as { id: string; status: string }[]).map((e) => `${ENGINE_NAME[e.id] ?? e.id}${e.status === "succeeded" ? "" : ` · ${e.status}`}`)
          : ENGINE_GROUPS
        ).map((g) => (
          <label key={g} className="swrow">
            <input type="checkbox" className="chk" checked readOnly aria-readonly="true" tabIndex={-1} onClick={(e) => e.preventDefault()} /> {g}
          </label>
        ))}
        {rules.length > 0 && <span className="xs faint mono">rules: {rules.join(", ")}</span>}
      </div>
      <div className="hr" />
      <label className="swrow">
        <input type="checkbox" className="sw" checked={scan.send === false} readOnly disabled /> No-send (dry run)
      </label>
      <Link className="more" to={rerunLink(scan)}>
        Run again with changes <Icon name="arrow-right" />
      </Link>
    </form>
  );
}

function filesText(n: number): string {
  return `${fmtInt(n)} file${n === 1 ? "" : "s"}`;
}

/** The scan form for this scan's project, starting from the level, provider and model it ran with. */
function rerunLink(scan: Scan): string {
  const q = new URLSearchParams({ level: scan.privacy_level });
  if (scan.provider && scan.provider !== "none") q.set("provider", scan.provider);
  if (scan.model) q.set("model", scan.model);
  return `/projects/${scan.project_id}/scan?${q.toString()}`;
}
