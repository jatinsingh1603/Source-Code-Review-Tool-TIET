import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useSession } from "@/app/session";
import { useCreateProject, useFindings, useLedger, useLedgerEntry, usePrivacy, useReports, useScans, useStartScan } from "@/api/queries";
import type { Severity } from "@/api/types";
import { isOpen, sevCounts, sortScans } from "@/lib/domain";
import { fmtElapsed, fmtInt, fmtLong, lineCount, payloadLineCount } from "@/lib/display";
import { CWE_SHORT } from "@/lib/taxonomy";
import { Button, Content, ErrorBanner, Icon, SEV_CLASS, Skeleton, StatusDot, useToast } from "@/components/ui";

/** Demo mode (SCREENS.md §03): run the KavachBank sample offline with the Mock provider. */
export default function DemoPage() {
  const { projects, setCurrentId } = useCurrentProject();
  const sample = projects.find((p) => p.source.type === "sample");
  const scansQ = useScans(sample?.id);
  const scans = useMemo(() => sortScans(scansQ.data ?? []), [scansQ.data]);
  const last = scans[0];
  const running = last && (last.status === "running" || last.status === "queued");
  const lastDone = scans.find((s) => s.status === "completed");
  const create = useCreateProject();
  const start = useStartScan();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useSession();
  const [error, setError] = useState<unknown>(null);

  const run = async () => {
    setError(null);
    try {
      const project = sample ?? (await create.mutateAsync({ name: "kavachbank-core", source: { type: "sample" } }));
      setCurrentId(project.id);
      const scan = await start.mutateAsync({ projectId: project.id, body: { privacy_level: "L3", provider: "mock", send: true } });
      toast.success("Demo started", "The KavachBank scan is running.");
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Content>
      <section className="card" style={{ padding: 32, display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 16 }}>
        <span className="sec-h">Demo mode · offline</span>
        <h1 style={{ fontSize: 28, fontWeight: 650, letterSpacing: "-0.02em" }}>Run the KavachBank demo</h1>
        <p className="muted" style={{ maxWidth: 620 }}>
          Runs the full 9-stage pipeline on the synthetic KavachBank sample: Python and JavaScript, planted vulnerabilities, fake
          secrets and an interest and fee engine. Fully offline with the Mock provider. No API key needed.
        </p>
        <Button
          variant="primary"
          size="xl"
          icon={<Icon name="play" className="lg" />}
          onClick={() => void run()}
          loading={create.isPending || start.isPending}
          disabled={!can("scans:run")}
          title={can("scans:run") ? undefined : "Your role cannot start scans."}
        >
          Run KavachBank demo
        </Button>
        <div className="row">
          <span className="chip">Privacy level L3</span>
          <span className="chip">Mock provider</span>
          {sample?.files ? <span className="chip">{fmtInt(sample.files)} files</span> : null}
          {lastDone ? <span className="chip">about {fmtElapsed(lastDone.started_at, lastDone.finished_at)}</span> : null}
        </div>
        {error !== null && <ErrorBanner what="The demo could not start." error={error} />}
      </section>

      <div className="banner info">
        <Icon name="info" />
        <span>
          <b>Mock provider:</b> the ledger shows what <i>would</i> have been sent. Nothing left this laptop.
        </span>
      </div>

      {running && last && (
        <div className="banner info sm">
          <span>
            A demo scan is running. <Link className="acc" to={`/scans/${last.id}`}>Open the live view</Link>
          </span>
        </div>
      )}

      {lastDone && <LastRun scanId={lastDone.id} started={lastDone.started_at} finished={lastDone.finished_at} />}
      {scansQ.isLoading && <Skeleton rows={2} />}
    </Content>
  );
}

function LastRun({ scanId, started, finished }: { scanId: string; started?: string | null; finished?: string | null }) {
  const findings = useFindings(scanId).data;
  const privacy = usePrivacy(scanId).data;
  const ledger = useLedger(scanId).data;
  const reports = useReports(scanId).data;
  const head = ledger?.find((e) => e.outcome === "sent" && e.finding_id);
  const entry = useLedgerEntry(scanId, head?.seq ?? null).data;
  const open = (findings ?? []).filter(isOpen);
  const c = sevCounts(open);
  const sentLines = entry ? payloadLineCount(entry.payload_text) : null;
  const totalLines = entry ? lineCount(entry.original_text) : null;
  const top = [...new Set(open.filter((f) => f.severity === "critical" || f.severity === "high").map((f) => f.cwe && CWE_SHORT[f.cwe]).filter(Boolean))].slice(0, 3);
  const secrets = open.filter((f) => /secret/.test(f.engine ?? "")).length;
  const formats = (reports ?? []).filter((r) => r.available).map((r) => r.format.toUpperCase());
  return (
    <>
      <div className="row between">
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Last demo run · {fmtLong(started)}</h2>
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
            {secrets ? `; ${secrets} planted secret${secrets === 1 ? "" : "s"} flagged.` : "."}
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
