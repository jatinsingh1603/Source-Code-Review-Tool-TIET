import { useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useFollowScanProject } from "@/app/useSelectedScan";
import { useFindings, usePrivacy, useReports, useScans, useSettings } from "@/api/queries";
import { fetchReport, saveBlob } from "@/api/endpoints";
import type { Finding, Scan, Severity } from "@/api/types";
import { isOpen, sevCounts, sortScans } from "@/lib/domain";
import { fmtDate, fmtInt, fmtShort, scanLabel } from "@/lib/display";
import { frameworkLabel } from "@/lib/format";
import { CWE_SHORT } from "@/lib/taxonomy";
import { Button, Content, Dialog, Empty, ErrorBanner, Hash, Icon, PageHeader, Skeleton, useToast } from "@/components/ui";

const FORMAT_NAME: Record<string, string> = {
  pdf: "PDF",
  docx: "DOCX",
  html: "HTML",
  sarif: "SARIF",
  json: "JSON",
  csv: "CSV",
  xlsx: "XLSX",
  md: "Markdown",
  compliance: "Compliance annex",
  manifest: "Integrity manifest",
};

/** Formats that take a while to render the first time, with what to say meanwhile. */
const SLOW: Record<string, string> = {
  pdf: "Rendering the PDF; the first time for a scan takes up to a minute.",
  docx: "Writing the Word document.",
  manifest: "Rendering every format and hashing it into the manifest; this can take a minute.",
};

/** Reports (SCREENS.md §15): generated reports, the builder and a page preview. */
export default function ReportsPage() {
  const [params, setParams] = useSearchParams();
  const { current } = useCurrentProject();
  useFollowScanProject(params.get("scan"));
  const scansQ = useScans(current?.id);
  const scans = useMemo(() => sortScans(scansQ.data ?? []).filter((s) => s.status === "completed"), [scansQ.data]);
  const scanId = params.get("scan") ?? scans[0]?.id;
  const scan = scans.find((s) => s.id === scanId);
  const idx = scans.findIndex((s) => s.id === scanId);
  const [baselineId, setBaselineId] = useState<string | null>(null);
  const baseline = baselineId === "" ? undefined : scans.find((s) => s.id === baselineId) ?? scans[idx + 1];
  const reportsQ = useReports(scanId);
  const settings = useSettings().data;
  const findings = useFindings(scanId).data;
  const baseFindings = useFindings(baseline?.id).data;
  const privacy = usePrivacy(scanId).data;
  const toast = useToast();
  const [chosen, setChosen] = useState<Set<string>>(new Set(["pdf", "docx", "sarif", "json"]));
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const builderRef = useRef<HTMLFormElement>(null);
  const formats = (reportsQ.data ?? []).filter((f) => f.format !== "markdown");
  const frameworks = useMemo(() => {
    const s = new Set<string>();
    for (const f of findings ?? []) {
      for (const c of f.compliance ?? []) s.add(c.framework);
      for (const fw of f.frameworks ?? []) s.add(fw);
    }
    return [...s].filter((x) => !["capec", "cwe-top25"].includes(x));
  }, [findings]);

  const select = (id: string) => {
    const n = new URLSearchParams(params);
    n.set("scan", id);
    setParams(n, { replace: true });
  };

  const generate = async () => {
    if (!scanId) return;
    setBusy(true);
    let ok = 0;
    // The manifest hashes the other files, so it comes last.
    const order = formats.map((f) => f.format).filter((f) => chosen.has(f)).sort((a, b) => Number(a === "manifest") - Number(b === "manifest"));
    for (const [i, fmt] of order.entries()) {
      const f = formats.find((x) => x.format === fmt);
      if (!f?.available) continue;
      const name = FORMAT_NAME[fmt] ?? fmt.toUpperCase();
      setProgress(`${i + 1} of ${order.length} · ${f.rendered ? `Downloading ${name}.` : (SLOW[fmt] ?? `Rendering ${name}.`)}`);
      try {
        const { blob, filename } = await fetchReport(scanId, fmt);
        saveBlob(blob, filename);
        ok += 1;
      } catch (e) {
        toast.error(`${name} failed`, e instanceof Error ? e.message : undefined);
      }
    }
    setBusy(false);
    setProgress(null);
    void reportsQ.refetch();
    if (ok) toast.success("Report generated", `${ok} file${ok === 1 ? "" : "s"} downloaded.`);
  };

  const [preview, setPreview] = useState<string | null>(null);
  const openHtml = async () => {
    if (!scanId) return;
    try {
      const { blob } = await fetchReport(scanId, "html");
      // The sandbox blocks the report's scripts anyway; dropping them keeps the console clean.
      setPreview((await blob.text()).replace(/<script\b[\s\S]*?<\/script>/gi, ""));
    } catch (e) {
      toast.error("Preview failed", e instanceof Error ? e.message : undefined);
    }
  };

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: current?.name ?? "Project", to: "/" }, { label: "Reports" }]}
        title="Reports"
        actions={
          <Button
            variant="primary"
            onClick={() => {
              builderRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
              builderRef.current?.querySelector<HTMLElement>("button:not(:disabled), select:not(:disabled)")?.focus({ preventScroll: true });
            }}
          >
            New report
          </Button>
        }
      />

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Report</th>
              <th>Scan</th>
              <th>Audience</th>
              <th>Formats</th>
              <th>Integrity manifest</th>
              <th>Generated</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scansQ.isLoading ? (
              <tr>
                <td colSpan={7}>
                  <Skeleton />
                </td>
              </tr>
            ) : (
              scans.slice(0, 8).map((s) => (
                <ReportRow key={s.id} scan={s} selected={s.id === scanId} title={settings?.report_title as string | undefined} onOpen={() => select(s.id)} />
              ))
            )}
          </tbody>
        </table>
        {!scansQ.isLoading && scans.length === 0 && (
          <Empty title="No reports yet" action="Run a scan" to={current ? `/projects/${current.id}/scan` : "/projects/new"}>
            A report can be generated for any completed scan.
          </Empty>
        )}
      </div>

      {scan && (
        <section className="g g-side-l">
          <form ref={builderRef} className="card stack s16" aria-label="Report builder" onSubmit={(e) => e.preventDefault()}>
            <h2>Report builder</h2>
            <div className="fld">
              <span className="lbl">Audience</span>
              <div className="seg">
                <button type="button" disabled title="Audience templates need server support.">
                  Executive
                </button>
                <button className="on" type="button">
                  Technical
                </button>
                <button type="button" disabled title="Use the Compliance format below for the framework mapping.">
                  Compliance
                </button>
              </div>
            </div>
            <div className="fld">
              <label htmlFor="rb-base">Baseline for delta</label>
              <select id="rb-base" className="inp" value={baseline?.id ?? ""} onChange={(e) => setBaselineId(e.target.value)}>
                {scans.slice(idx + 1).map((s) => (
                  <option key={s.id} value={s.id}>
                    {scanLabel(s.id)} · {fmtDate(s.finished_at)}
                  </option>
                ))}
                <option value="">None</option>
              </select>
            </div>
            <div className="stack s6">
              <span className="lbl">Sections</span>
              {["Document control", "Executive summary and risk matrix", "Scope and methodology", "Findings with evidence", "Remediation roadmap", "Compliance annex", "Privacy attestation"].map((s) => (
                <label key={s} className="swrow" title="Every report includes these sections.">
                  <input type="checkbox" className="chk" checked readOnly aria-readonly="true" onClick={(e) => e.preventDefault()} /> {s}
                </label>
              ))}
            </div>
            <div className="stack s6">
              <span className="lbl">Compliance frameworks</span>
              <div className="row">
                {frameworks.length ? frameworks.map((f) => <span key={f} className="chip on">{frameworkLabel(f)}</span>) : <span className="xs faint">Mapped from the findings</span>}
              </div>
            </div>
            <div className="fld">
              <span className="lbl">Branding</span>
              <div className="dropzone">
                <span className="sm muted">{settings?.org_name ?? "Organisation name"}</span>
                <span className="xs faint">from Settings</span>
              </div>
            </div>
            <div className="fld">
              <label htmlFor="rb-cls">Classification</label>
              <select id="rb-cls" className="inp" disabled value="c">
                <option value="c">{(settings?.classification as string) ?? "Confidential"}</option>
              </select>
            </div>
            <div className="stack s6">
              <span className="lbl">Formats</span>
              {reportsQ.isLoading && <Skeleton />}
              <div className="row">
                {formats.map((f) => {
                  const on = chosen.has(f.format);
                  return (
                    <button
                      key={f.format}
                      type="button"
                      className={on ? "chip on" : "chip"}
                      style={{ cursor: f.available ? "pointer" : "not-allowed", font: "inherit", fontSize: 12 }}
                      aria-pressed={on}
                      disabled={!f.available}
                      title={f.available ? f.label : f.reason ?? "Not available"}
                      onClick={() =>
                        setChosen((c) => {
                          const n = new Set(c);
                          if (on) n.delete(f.format);
                          else n.add(f.format);
                          return n;
                        })
                      }
                    >
                      {FORMAT_NAME[f.format] ?? f.format.toUpperCase()}
                    </button>
                  );
                })}
              </div>
            </div>
            {reportsQ.isError && <ErrorBanner what="Report formats could not be loaded." error={reportsQ.error} />}
            <Button variant="primary" onClick={() => void generate()} loading={busy} disabled={!chosen.size}>
              Generate report
            </Button>
            {progress && (
              <p className="xs muted" role="status" aria-live="polite" style={{ marginTop: -8 }}>
                {progress}
              </p>
            )}
          </form>

          <div className="stack">
            <div className="row between">
              <span className="sub">Preview · {scanLabel(scan.id)} · cover and executive summary</span>
              <div className="row">
                <Button size="sm" onClick={() => void openHtml()}>
                  Open full HTML report
                  <Icon name="arrow-up-right" />
                </Button>
              </div>
            </div>
            <div className="g g-2 page-tray">
              <CoverPage
                org={settings?.org_name ?? ""}
                classification={(settings?.classification as string) ?? "Confidential"}
                title={(settings?.report_title as string) ?? "Secure Source Code Review Report"}
                project={current?.name ?? ""}
                scanId={scan.id}
                files={scan.files}
                date={scan.finished_at}
                digest={privacy?.attestation_digest}
              />
              <SummaryPage scanId={scan.id} baselineId={baseline?.id} findings={findings} base={baseFindings} privacy={privacy} />
            </div>
          </div>
        </section>
      )}
      <Dialog open={preview !== null} onClose={() => setPreview(null)} title="HTML report" size="lg" description="Shown in a sandbox: scripts in the report do not run.">
        {preview !== null && (
          <iframe title="HTML report preview" sandbox="" srcDoc={preview} style={{ width: "100%", height: "70vh", border: "1px solid var(--border)", borderRadius: 6 }} />
        )}
      </Dialog>
    </Content>
  );
}

function clip(s: string, n = 140): string {
  const t = s.replace(/[.\s]+$/, "");
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

function CoverPage(p: {
  org: string;
  classification: string;
  title: string;
  project: string;
  scanId: string;
  files?: number;
  date?: string | null;
  digest?: string | null;
}) {
  return (
    <div className="page" style={{ minHeight: 560, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
          <span style={{ fontWeight: 600, letterSpacing: "0.02em" }}>{p.org.toUpperCase()}</span>
          <span className="pm" style={{ fontSize: 10 }}>
            {p.classification.toUpperCase()}
          </span>
        </div>
        <div style={{ height: 2, background: "#101828", margin: "14px 0 64px" }} />
        <div className="pm" style={{ fontSize: 11, letterSpacing: "0.08em" }}>
          {p.title.toUpperCase()}
        </div>
        <h3 style={{ fontFamily: "'IBM Plex Serif', serif", fontSize: 26, lineHeight: 1.2, marginTop: 8 }}>
          {p.project}
          <br />
          Audit report {scanLabel(p.scanId)}
        </h3>
        <p className="pm" style={{ marginTop: 12 }}>
          Scope: {p.files ? `${fmtInt(p.files)} files` : "the project source"}. Review completed {fmtDate(p.date)}.
        </p>
      </div>
      <table>
        <tbody>
          <tr>
            <th colSpan={2}>Document control</th>
          </tr>
          <tr>
            <td>Version</td>
            <td>Generated from scan {scanLabel(p.scanId)}</td>
          </tr>
          <tr>
            <td>Classification</td>
            <td>{p.classification}</td>
          </tr>
          <tr>
            <td>Prepared by</td>
            <td>{p.org}</td>
          </tr>
          <tr>
            <td>Integrity</td>
            <td style={{ fontFamily: "'IBM Plex Mono', monospace", wordBreak: "break-all" }}>{p.digest ? `sha256 ${p.digest.slice(0, 6)}…${p.digest.slice(-4)}` : "—"}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

function SummaryPage({
  scanId,
  baselineId,
  findings,
  base,
  privacy,
}: {
  scanId: string;
  baselineId?: string;
  findings?: Finding[];
  base?: Finding[];
  privacy?: { payloads: number; level: string; zero_leak: { occurrences: number; checked: number } } | undefined;
}) {
  if (!findings) {
    return (
      <div className="page" style={{ minHeight: 560 }}>
        <Skeleton rows={3} />
      </div>
    );
  }
  const open = findings.filter(isOpen);
  const c = sevCounts(open);
  const baseFp = new Set((base ?? []).map((f) => f.fingerprint));
  const curFp = new Set(findings.map((f) => f.fingerprint));
  const rows: [string, Severity[]][] = [
    ["Critical", ["critical"]],
    ["High", ["high"]],
    ["Medium", ["medium"]],
    ["Low and info", ["low", "info"]],
  ];
  const by = (sev: Severity[], fs: Finding[]) => fs.filter((f) => sev.includes(f.severity));
  const topics = (sev: Severity[]) =>
    [...new Set(by(sev, open).map((f) => (f.cwe && CWE_SHORT[f.cwe]) || f.cwe).filter(Boolean))].slice(0, 3).join("; ") || "—";
  return (
    <div className="page" style={{ minHeight: 560 }}>
      <div className="pm" style={{ fontSize: 10, display: "flex", justifyContent: "space-between" }}>
        <span>{scanLabel(scanId)}</span>
        <span>Executive summary</span>
      </div>
      <h3 style={{ marginTop: 14 }}>1. Executive summary</h3>
      <p style={{ marginTop: 8 }}>
        The review identified <b>{open.length} open findings</b>, of which <b>{c.critical} are critical</b> and <b>{c.high} high</b>.
        {open[0] ? ` The most serious: ${clip(open.filter((f) => f.severity === "critical")[0]?.title ?? open[0].title)}.` : ""}
      </p>
      <table style={{ marginTop: 12 }}>
        <tbody>
          <tr>
            <th>Severity</th>
            <th>Open</th>
            <th>New</th>
            <th>Fixed since {baselineId ? scanLabel(baselineId) : "baseline"}</th>
          </tr>
          {rows.map(([label, sev]) => (
            <tr key={label}>
              <td>{label}</td>
              <td>{by(sev, open).length}</td>
              <td>{base ? by(sev, open).filter((f) => !baseFp.has(f.fingerprint)).length : "—"}</td>
              <td>{base ? by(sev, base).filter((f) => !curFp.has(f.fingerprint)).length : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3 style={{ marginTop: 18, fontSize: 14 }}>Remediation roadmap</h3>
      <table style={{ marginTop: 8 }}>
        <tbody>
          <tr>
            <th>Now · 7 days</th>
            <th>Next · 30 days</th>
            <th>Later · 90 days</th>
          </tr>
          <tr>
            <td>{topics(["critical"])}</td>
            <td>{topics(["high"])}</td>
            <td>{topics(["medium", "low"])}</td>
          </tr>
        </tbody>
      </table>
      {privacy && (
        <p className="pm" style={{ marginTop: 14, fontSize: 10.5 }}>
          Privacy attestation: {fmtInt(privacy.payloads)} payloads at {privacy.level}, {fmtInt(privacy.zero_leak.occurrences)} listed terms found verbatim of {fmtInt(privacy.zero_leak.checked)} checked. See the annex for what the attestation does not cover.
        </p>
      )}
    </div>
  );
}

/** One row of the reports table: the formats already rendered for that scan and its manifest. */
function ReportRow({ scan: s, selected, title, onOpen }: { scan: Scan; selected: boolean; title?: string; onOpen: () => void }) {
  const q = useReports(s.id);
  const rendered = (q.data ?? []).filter((f) => f.rendered && f.format !== "manifest" && f.format !== "markdown");
  const manifest = (q.data ?? []).find((f) => f.format === "manifest");
  return (
    <tr className={selected ? "sel" : undefined}>
      <td>
        <b className="sm">Report · {scanLabel(s.id)}</b>
        <div className="xs faint">{title ?? "Secure code review"}</div>
      </td>
      <td className="mono sm">{scanLabel(s.id)}</td>
      <td className="sm">Technical</td>
      <td>
        <div className="row" style={{ gap: 4 }}>
          {rendered.map((f) => (
            <span key={f.format} className="tag">
              {FORMAT_NAME[f.format] ?? f.format.toUpperCase()}
            </span>
          ))}
          {q.isSuccess && rendered.length === 0 && <span className="faint sm">None yet</span>}
        </div>
      </td>
      <td>
        {manifest?.sha256 ? (
          <Hash value={manifest.sha256} copy={false} />
        ) : (
          <span className="faint sm" title="Generate the report with Integrity manifest selected to hash every file.">
            Not generated
          </span>
        )}
      </td>
      <td className="sm muted">{fmtShort(s.finished_at)}</td>
      <td>
        <button type="button" className="more linkbtn" style={{ color: "var(--text)" }} onClick={onOpen}>
          Open <Icon name="arrow-right" />
        </button>
      </td>
    </tr>
  );
}
