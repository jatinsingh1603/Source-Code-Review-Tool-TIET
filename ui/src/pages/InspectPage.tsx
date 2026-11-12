import { useMemo } from "react";
import { Link, Navigate, useParams, useSearchParams } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useShell } from "@/app/shell-context";
import { useFinding, useLedger, useLedgerEntry, useOptional, usePrivacy, useScans } from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import type { LedgerDetail, PrivacyLevel } from "@/api/types";
import { sortScans } from "@/lib/domain";
import { byteLength, fmtBytesText, fmtInt, fmtSeq, findingLabel, LEVEL_NAME, lineCount, payloadLineCount } from "@/lib/display";
import { MarkedCode, markupCounts, MarkupLegend } from "@/components/Marked";
import { Content, Empty, ErrorBanner, Hash, Segmented, Skeleton } from "@/components/ui";

const LEVELS: PrivacyLevel[] = ["L1", "L2", "L3", "L4"];

/** Privacy Inspect (SCREENS.md §10): the original beside the exact payload. */
export default function InspectPage() {
  const { scanId, seq } = useParams();
  if (!scanId || !seq) return <LatestPayload />;
  return <Inspect scanId={scanId} seq={Number(seq)} />;
}

/** The nav item opens the latest payload of the current project's latest scan. */
function LatestPayload() {
  const { current } = useCurrentProject();
  const scans = sortScans(useScans(current?.id).data ?? []).filter((s) => s.status === "completed" && s.privacy_level !== "L0");
  const scan = scans[0];
  const ledger = useLedger(scan?.id);
  const entry = ledger.data?.find((e) => e.outcome === "sent" && e.finding_id) ?? ledger.data?.find((e) => e.outcome === "sent");
  if (entry && scan) return <Navigate to={`/privacy/inspect/${scan.id}/${entry.seq}`} replace />;
  const loading = !current || ledger.isLoading || (scan && !ledger.data);
  return (
    <Content>
      <div className="ph">
        <div>
          <div className="crumb">
            <Link to="/privacy">Privacy</Link>
            <span>/</span>
            <span>Inspect</span>
          </div>
          <h1>Privacy Inspect</h1>
        </div>
      </div>
      <div className="card">
        {loading ? (
          <Skeleton rows={2} />
        ) : (
          <Empty title="No payloads to inspect" action="Run the KavachBank demo" to="/demo">
            {scan ? "The latest scan sent no payload: it ran at L0 or every candidate stayed local." : "Run a scan at L1 to L4 to see what would leave this machine."}
          </Empty>
        )}
      </div>
    </Content>
  );
}

function Inspect({ scanId, seq }: { scanId: string; seq: number }) {
  const [params, setParams] = useSearchParams();
  const q = useLedgerEntry(scanId, seq);
  const d = q.data;
  const sentLevel = d?.entry.level;
  const level = ((params.get("level") ? `L${params.get("level")}` : sentLevel) ?? "L3") as PrivacyLevel;
  const isSent = level === sentLevel;
  const preview = useOptional<LedgerDetail>(`preview-${scanId}-${seq}-${level}`, () => endpoints.ledgerPreview(scanId, seq, level), !!d && !isSent);
  const finding = useFinding(d?.entry.finding_id ?? undefined).data;
  const privacy = usePrivacy(scanId).data;
  useShell({ levelPill: `${level} · ${LEVEL_NAME[level]}` });

  const shown: LedgerDetail | null | undefined = isSent ? d : preview.data;
  const counts = shown ? markupCounts(shown.markup) : null;
  const renamed = shown ? new Set(shown.markup.filter((m) => m.side === "payload" && m.kind === "identifier").map((m) => shown.payload_text.slice(m.start, m.end))).size : null;
  const total = d ? lineCount(d.original_text) : 0;
  const sent = shown ? payloadLineCount(shown.payload_text) : null;
  const bytes = shown ? shown.entry?.bytes ?? byteLength(shown.payload_text) : null;
  const start = d?.original_start_line ?? d?.start_line ?? 1;
  const path = d?.path ?? finding?.locations?.[0]?.path ?? finding?.path;
  const taint = finding?.evidence?.taint_path ?? [];
  const srcLine = d?.source_line ?? taint.find((t) => t.kind === "source" && t.path === path)?.line;
  const sinkLine = d?.sink_line ?? taint.find((t) => t.kind === "sink" && t.path === path)?.line ?? (finding?.locations?.[0]?.path === path ? finding?.locations?.[0]?.start_line : undefined);
  const hl = useMemo(() => {
    const s = new Set<number>(d?.slice_lines ?? []);
    for (const r of finding?.evidence?.code?.highlight ?? []) for (let i = r.start; i <= r.end; i++) s.add(i);
    return s;
  }, [d, finding]);

  const setLevel = (l: PrivacyLevel) => {
    const n = new URLSearchParams(params);
    if (l === sentLevel) n.delete("level");
    else n.set("level", l.slice(1));
    setParams(n, { replace: true });
  };

  return (
    <Content>
      <div className="ph">
        <div>
          <div className="crumb">
            <Link to="/privacy">Privacy</Link>
            <span>/</span>
            <span>Inspect</span>
            {finding && (
              <>
                <span>/</span>
                <Link to={`/findings/${finding.id}`}>
                  {findingLabel(finding.id)} · {finding.title}
                </Link>
              </>
            )}
          </div>
          <h1>Privacy Inspect</h1>
          <p className="sub" style={{ marginTop: 4 }}>
            The original code on the left. The exact payload prepared for the model on the right.
          </p>
        </div>
        <div className="stack s6" style={{ alignItems: "flex-end" }}>
          <span className="xs faint">Compare the same slice at each level</span>
          <Segmented
            tabs
            label="Privacy level"
            value={level}
            onChange={setLevel}
            options={LEVELS.map((l) => ({ value: l, label: `${l} ${LEVEL_NAME[l]}` }))}
          />
        </div>
      </div>

      {q.isError ? (
        <ErrorBanner what="This payload could not be loaded." error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <section className="card" style={{ padding: 0 }}>
            <div className="kpi-strip sm">
              <div className="kpi">
                <div className="k-l">Lines sent</div>
                <div className="k-v">{sent === null ? "—" : `${level === "L4" ? 0 : sent} / ${total}`}</div>
              </div>
              <div className="kpi">
                <div className="k-l">Identifiers renamed</div>
                <div className="k-v">{renamed ?? "—"}</div>
              </div>
              <div className="kpi">
                <div className="k-l">Secrets redacted</div>
                <div className="k-v">{counts ? counts.redacted : "—"}</div>
              </div>
              <div className="kpi">
                <div className="k-l">Listed terms found</div>
                <div className="k-v">
                  {privacy ? fmtInt(privacy.zero_leak.occurrences) : "—"} {privacy && <small>of {fmtInt(privacy.zero_leak.checked)}</small>}
                </div>
              </div>
              <div className="kpi">
                <div className="k-l">Payload size</div>
                <div className="k-v">{bytes === null ? "—" : fmtBytesText(bytes)}</div>
              </div>
              <div className="kpi">
                <div className="k-l">SHA-256</div>
                <div style={{ marginTop: 8 }}>{shown?.entry ? <Hash value={shown.entry.payload_hash} /> : <span className="faint">—</span>}</div>
              </div>
            </div>
          </section>

          <MarkupLegend />

          <section className="g g-2" style={{ alignItems: "start" }}>
            <div>
              {!d ? (
                <div className="card">
                  <Skeleton rows={3} />
                </div>
              ) : d.original_text ? (
                <>
                  <MarkedCode
                    text={d.original_text}
                    markup={d.markup}
                    side="original"
                    startLine={start}
                    title={
                      <>
                        <b>Original</b> <span className="mono muted">{path ?? ""}</span>
                      </>
                    }
                    titleRight={<span className="faint">Stays on this machine</span>}
                    kindOf={(n) => (n === sinkLine ? "sink" : n === srcLine ? "src" : hl.has(n) ? "hl" : undefined)}
                  />
                  {(srcLine || sinkLine) && (
                    <p className="xs faint" style={{ marginTop: 8 }}>
                      Tinted lines are the vulnerability-relevant slice
                      {srcLine ? ` (source on line ${srcLine}` : " ("}
                      {sinkLine ? `${srcLine ? ", " : ""}sink on line ${sinkLine})` : ")"}.
                    </p>
                  )}
                </>
              ) : (
                <div className="card">
                  <Empty title="Original hidden">Reading the original code needs the Auditor role or higher.</Empty>
                </div>
              )}
            </div>

            <div>
              <div className="code-h">
                <span>
                  <b>Payload</b>{" "}
                  <span className="mono muted">
                    payload #{fmtSeq(seq)}
                    {isSent ? " · as sent" : ` at ${level} (preview)`}
                  </span>
                </span>
                <span style={{ color: "var(--high-t)" }}>{d?.entry.outcome?.startsWith("blocked") ? "Blocked · not sent" : "Prepared for the model"}</span>
              </div>
              {!d || (!isSent && preview.isLoading) ? (
                <div className="code" style={{ padding: 16 }}>
                  <Skeleton rows={2} />
                </div>
              ) : shown ? (
                level === "L4" ? (
                  <div className="code facts">
                    {shown.payload_text.split("\n").map((l, i) => (
                      <div key={i} className={l.startsWith("//") || l.startsWith("#") ? "faint" : undefined}>
                        {l || " "}
                      </div>
                    ))}
                  </div>
                ) : (
                  <MarkedCode text={shown.payload_text} markup={shown.markup} side="payload" style={{ borderTopLeftRadius: 0, borderTopRightRadius: 0 }} />
                )
              ) : (
                <div className="code" style={{ padding: "8px 16px", whiteSpace: "normal" }}>
                  <Empty title={`No ${level} preview`}>
                    Only the payload as sent ({sentLevel}) is recorded. Previews at other levels need the server preview endpoint; they are never sent or written to the ledger.
                  </Empty>
                </div>
              )}
              {level === "L1" && shown && (
                <div className="banner warn sm" style={{ marginTop: 10 }}>
                  At L1 real names, business terms and rates leave the machine. Only secrets and PII are removed.
                </div>
              )}
              {level === "L4" && shown && (
                <p className="xs faint" style={{ marginTop: 8 }}>
                  Lower precision than L3 on complex flows; see Evaluation for the measured trade-off.
                </p>
              )}
            </div>
          </section>
        </>
      )}

      <div className="note box">
        <b>What this does not cover.</b>
        <ul>
          <li>
            At L2 and L3 the model still sees control flow, literal shapes (a string, a number) and public API names such as{" "}
            <span className="mono">db.query</span> and <span className="mono">res.json</span>.
          </li>
          <li>The leak check is verbatim only. A listed term that is paraphrased, split or encoded would not be detected.</li>
          <li>Pseudonyms are deterministic per scan salt (I5), so repeated payloads in one scan can be linked to each other.</li>
        </ul>
      </div>
    </Content>
  );
}
