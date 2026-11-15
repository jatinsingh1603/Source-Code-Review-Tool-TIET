import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useCan, useSession } from "@/app/session";
import { useCreateProject, useFindings, useLedger, useLedgerEntry, usePrivacy, useReports, useScans, useStartScan } from "@/api/queries";
import type { Severity } from "@/api/types";
import { isOpen, sevCounts, sortScans } from "@/lib/domain";
import { fmtElapsed, fmtInt, fmtLong, lineCount, payloadLineCount } from "@/lib/display";
import { CWE_SHORT } from "@/lib/taxonomy";
import { Button, ButtonLink, Content, ErrorBanner, Icon, SEV_CLASS, Skeleton, StatusDot, useToast } from "@/components/ui";

interface Step {
  title: string;
  body: string;
  /** What the server reports for this step, when it has something to report. */
  fact?: string;
  done: boolean;
  action?: { label: string; to: string };
}

/**
 * Getting started (SCREENS.md §03): the review workflow, step by step, for the project selected
 * in the top bar. Every status on it is read from the server; nothing here is canned.
 */
export default function GettingStartedPage() {
  const { projects, current, setCurrentId, loading } = useCurrentProject();
  const scansQ = useScans(current?.id);
  const scans = useMemo(() => (current ? sortScans(scansQ.data ?? []) : []), [current, scansQ.data]);
  const last = scans[0];
  const running = last && (last.status === "running" || last.status === "queued");
  const lastDone = scans.find((s) => s.status === "completed");
  const findings = useFindings(lastDone?.id).data;
  const { can } = useSession();
  const privacy = usePrivacy(lastDone?.id).data;
  const create = useCreateProject();
  const start = useStartScan();
  const navigate = useNavigate();
  const toast = useToast();
  const [error, setError] = useState<unknown>(null);
  const sample = projects.find((p) => p.source.type === "sample");
  const maySample = can("scans:run") && (!!sample || can("projects:write"));

  const scanSample = async () => {
    setError(null);
    try {
      const project = sample ?? (await create.mutateAsync({ name: "kavachbank-core", source: { type: "sample" } }));
      setCurrentId(project.id);
      const scan = await start.mutateAsync({ projectId: project.id, body: { privacy_level: "L3", provider: "mock", send: true } });
      toast.success("Scan started", "Opening the live view.");
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError(e);
    }
  };

  const triaged = (findings ?? []).filter((f) => f.status !== "open").length;
  const scanQuery = lastDone ? `?scan=${lastDone.id}` : "";
  const steps: Step[] = [
    {
      title: "Add a project",
      body: "Point CodeKavach at a Git repository, upload an archive, or use a folder on the server.",
      fact: current ? `${fmtInt(projects.length)} project${projects.length === 1 ? "" : "s"} · ${current.name} selected` : undefined,
      done: projects.length > 0,
      action: can("projects:write") ? { label: projects.length ? "Add another" : "Add project", to: "/projects/new" } : undefined,
    },
    {
      title: "Run a scan",
      body: "Choose the privacy level and the provider. The engines run on this server; only what the level allows is prepared for a model.",
      fact: running ? "A scan is running" : lastDone ? `Last completed ${fmtLong(lastDone.finished_at ?? lastDone.started_at)}` : undefined,
      done: !!lastDone,
      action: running && last ? { label: "Open the live view", to: `/scans/${last.id}` } : current && can("scans:run") ? { label: lastDone ? "Scan again" : "Run a scan", to: `/projects/${current.id}/scan` } : undefined,
    },
    {
      title: "Triage the findings",
      body: "Confirm, assign, fix or dismiss each finding. Every decision is kept in the finding's history.",
      fact: findings ? `${fmtInt(findings.filter(isOpen).length)} open · ${fmtInt(triaged)} triaged` : undefined,
      done: triaged > 0,
      action: lastDone ? { label: "Open findings", to: `/findings${scanQuery}` } : undefined,
    },
    {
      title: "See what the model saw",
      body: "Privacy Inspect shows each payload beside the original code, with every redaction and pseudonym marked.",
      fact: privacy ? `${fmtInt(privacy.payloads)} payload${privacy.payloads === 1 ? "" : "s"} recorded` : undefined,
      done: !!privacy && privacy.payloads > 0,
      action: lastDone && can("privacy:read_original") ? { label: "Open Privacy Inspect", to: "/privacy/inspect" } : undefined,
    },
    {
      title: "Verify the egress ledger",
      body: "Every payload is hashed into a chained ledger. Verify the chain and export it for your auditors.",
      fact: privacy ? (privacy.chain_ok ? "Chain verified" : "Chain broken") : undefined,
      done: !!privacy?.chain_ok,
      action: lastDone && can("privacy:read") ? { label: "Open Egress Ledger", to: `/privacy/ledger${scanQuery}` } : undefined,
    },
    {
      title: "Produce the audit report",
      body: "Download the report as PDF, Word, Excel, SARIF or JSON, with the privacy attestation attached.",
      done: false,
      action: lastDone && can("reports:read") ? { label: "Open Reports", to: `/reports${scanQuery}` } : undefined,
    },
  ];
  const next = steps.findIndex((s) => !s.done && s.action);

  return (
    <Content>
      <section className="card" style={{ padding: 32, display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 16 }}>
        <span className="sec-h">Getting started</span>
        <h1 style={{ fontSize: 28, fontWeight: 650, letterSpacing: "-0.02em" }}>Review your first project</h1>
        <p className="muted" style={{ maxWidth: 620 }}>
          Six steps take a code base from intake to a signed-off audit report. The status of each step is read from{" "}
          {current ? <b>{current.name}</b> : "the project you select"}; change the project in the top bar to follow another one.
        </p>
        {loading || scansQ.isLoading ? (
          <Skeleton rows={4} />
        ) : (
          <ol style={{ listStyle: "none", margin: 0, padding: 0, alignSelf: "stretch" }} aria-label="Review workflow">
            {steps.map((s, i) => (
              <li className="listrow" key={s.title} style={{ alignItems: "flex-start", flexWrap: "wrap" }}>
                <div className="row" style={{ gap: 12, alignItems: "flex-start", flex: "1 1 320px", minWidth: 0 }}>
                  <span className="mono xs faint" style={{ paddingTop: 2 }}>
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <b className="sm">{s.title}</b>
                    <div className="xs muted">{s.body}</div>
                    {s.fact && <div className="xs faint">{s.fact}</div>}
                  </div>
                </div>
                <div className="row">
                  {s.done && <span className="chip fixed">Done</span>}
                  {s.action && (
                    <ButtonLink size="sm" variant={i === next ? "primary" : "secondary"} to={s.action.to}>
                      {s.action.label}
                    </ButtonLink>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      {maySample && (
        <section className="card stack">
          <div className="row between" style={{ flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 320px", minWidth: 0 }}>
              <h2>No code at hand?</h2>
              <p className="sub">
                Scan the bundled KavachBank sample application: Python and JavaScript with planted vulnerabilities and synthetic secrets.
                It runs at L3 with the Mock provider, so nothing leaves this server and no API key is needed.
              </p>
            </div>
            <Button icon={<Icon name="play" />} onClick={() => void scanSample()} loading={create.isPending || start.isPending}>
              Scan the sample application
            </Button>
          </div>
          {error !== null && <ErrorBanner what="The sample scan could not start." error={error} />}
        </section>
      )}

      {lastDone && <LastRun scanId={lastDone.id} started={lastDone.started_at} finished={lastDone.finished_at} />}
    </Content>
  );
}

function LastRun({ scanId, started, finished }: { scanId: string; started?: string | null; finished?: string | null }) {
  const mayReport = useCan("reports:read");
  const findings = useFindings(scanId).data;
  const privacy = usePrivacy(scanId).data;
  const ledger = useLedger(scanId).data;
  const reports = useReports(mayReport ? scanId : undefined).data;
  const head = ledger?.find((e) => e.outcome === "sent" && e.finding_id);
  const entry = useLedgerEntry(scanId, head?.seq ?? null).data;
  const open = (findings ?? []).filter(isOpen);
  const c = sevCounts(open);
  // Same figures as Privacy Inspect: lines of the file that left, out of the whole file.
  const totalLines = entry ? entry.lines_total ?? lineCount(entry.original_text) : null;
  const sentLines = entry ? Math.min(entry.slice_lines?.length ?? payloadLineCount(entry.payload_text), totalLines ?? Infinity) : null;
  const top = [...new Set(open.filter((f) => f.severity === "critical" || f.severity === "high").map((f) => f.cwe && CWE_SHORT[f.cwe]).filter(Boolean))].slice(0, 3);
  const secrets = open.filter((f) => /secret/.test(f.engine ?? "")).length;
  const formats = (reports ?? []).filter((r) => r.available).map((r) => r.format.toUpperCase());
  return (
    <>
      <div className="row between">
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Latest scan · {fmtLong(started)}</h2>
        <StatusDot tone="ok" className="sm">
          Completed in {fmtElapsed(started, finished)}
        </StatusDot>
      </div>
      <section className="g g-4">
        <Link className="card stack" to={`/findings?scan=${scanId}`} style={{ textDecoration: "none" }}>
          <div className="row between">
            <span className="sec-h">Findings</span>
            <Icon name="arrow-right" className="faint" />
          </div>
          <div className="card-num">{findings ? fmtInt(open.length) : "—"}</div>
          <div className="row">
            {(Object.keys(c) as Severity[]).map((s) => (
              <span key={s} className={`sev ${SEV_CLASS[s]}`}>
                {c[s]}
              </span>
            ))}
          </div>
          <p className="sub">
            {top.length ? `${top.join(", ")} found` : "Open findings of the last run"}
            {secrets ? `; ${secrets} secret${secrets === 1 ? "" : "s"} flagged.` : "."}
          </p>
        </Link>
        <Link className="card stack" to={head ? `/privacy/inspect/${scanId}/${head.seq}` : "/privacy/inspect"} style={{ textDecoration: "none" }}>
          <div className="row between">
            <span className="sec-h">Inspect</span>
            <Icon name="arrow-right" className="faint" />
          </div>
          <div className="card-num">
            {sentLines ?? "—"}{" "}
            {totalLines !== null && (
              <small className="muted" style={{ fontSize: 14, fontWeight: 500 }}>
                of {totalLines} lines
              </small>
            )}
          </div>
          <div className="bar priv">
            <i style={{ width: `${sentLines && totalLines ? Math.min(100, (sentLines / totalLines) * 100) : 0}%` }} />
          </div>
          <p className="sub">See exactly what the model saw for the first reviewed finding, side by side with the real code.</p>
        </Link>
        <Link className="card stack" to={`/privacy/ledger?scan=${scanId}`} style={{ textDecoration: "none" }}>
          <div className="row between">
            <span className="sec-h">Ledger {privacy?.chain_ok ? "verified" : ""}</span>
            <Icon name="arrow-right" className="faint" />
          </div>
          <div style={{ fontSize: 30, fontWeight: 500 }}>
            {fmtInt(ledger?.length)}{" "}
            <small className="muted" style={{ fontSize: 14, fontWeight: 400 }}>
              records
            </small>
          </div>
          <div className="row">
            {privacy && <span className={privacy.chain_ok ? "chip fixed" : "chip"}>{privacy.chain_ok ? "chain ok" : "chain broken"}</span>}
            {privacy && (
              <span className={privacy.zero_leak.occurrences === 0 ? "chip fixed" : "chip"}>{fmtInt(privacy.zero_leak.occurrences)} terms</span>
            )}
          </div>
          <p className="sub">
            {privacy
              ? `${fmtInt(privacy.zero_leak.occurrences)} listed terms found verbatim across ${fmtInt(privacy.payloads)} payloads.`
              : "Hash-chained record of every payload."}
          </p>
        </Link>
        <Link className="card stack" to={`/reports?scan=${scanId}`} style={{ textDecoration: "none" }}>
          <div className="row between">
            <span className="sec-h">Report</span>
            <Icon name="arrow-right" className="faint" />
          </div>
          <div className="card-num">{formats.length ? `${formats.length} formats` : "—"}</div>
          <div className="row">
            {formats.slice(0, 4).map((f) => (
              <span key={f} className="tag">
                {f}
              </span>
            ))}
          </div>
          <p className="sub">Audit report with executive summary, risk matrix and privacy attestation.</p>
        </Link>
      </section>
    </>
  );
}
