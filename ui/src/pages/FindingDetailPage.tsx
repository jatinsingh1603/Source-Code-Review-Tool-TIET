import { useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  useFinding,
  useFindingHistory,
  useLedgerEntry,
  usePatchFinding,
  useProviders,
  useReviewFinding,
  useSettings,
  useUsers,
} from "@/api/queries";
import {
  FINDING_STATUSES,
  type Finding,
  type FindingStatus,
  type PrivacyLevel,
  type TaintStep,
} from "@/api/types";
import { useSession } from "@/app/session";
import { useFollowScanProject } from "@/app/useSelectedScan";
import { enginesOf, locationOf, verdictOf } from "@/lib/domain";
import {
  capitalise,
  byteLength,
  fmtDate,
  fmtHash,
  fmtInt,
  fmtSeq,
  fmtShort,
  findingLabel,
  LEVEL_NAME,
  lineCount,
  payloadLineCount,
  scanLabel,
} from "@/lib/display";
import { confidenceFraction, frameworkLabel, STATUS_LABEL } from "@/lib/format";
import { cvssRating, parseVector } from "@/lib/cvss";
import { MarkedCode } from "@/components/Marked";
import { GithubSyncDialog } from "@/components/GithubSyncDialog";
import { AssignDialog, SuppressDialog } from "./FindingsPage";
import {
  Avatar,
  Breadcrumb,
  Button,
  CodeBlock,
  Content,
  CvssBox,
  Empty,
  ErrorBanner,
  Icon,
  LevelBadge,
  MoreLink,
  SeverityBadge,
  Skeleton,
  Tabs,
  useToast,
  Verdict,
  VERDICT_LABEL,
} from "@/components/ui";

type Tab = "saw" | "real" | "reason";

/** Split the model's impact narrative into the impact text and the attack scenario. */
function splitImpact(text?: string | null): { impact: string; scenario: string | null } {
  if (!text) return { impact: "", scenario: null };
  const parts = text.split(/\n\s*\n/);
  let scenario: string | null = null;
  const rest: string[] = [];
  for (const p of parts) {
    const m = /^\s*(attack|exploit) scenario:\s*/i.exec(p);
    if (m) scenario = p.slice(m[0].length).trim();
    else rest.push(p.trim());
  }
  return { impact: rest.join("\n\n"), scenario };
}

/** Text with `inline code` spans set in the mono face (text only, never HTML). */
function Inline({ text }: { text: string }) {
  const parts = text.split(/`([^`\n]+)`/);
  return (
    <>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <code key={i} className="mono" style={{ fontSize: "0.92em" }}>
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}

/** Plain text with ``` fences rendered as code blocks (text only, never HTML). */
function RichText({ text }: { text: string }) {
  const blocks = text.split(/```[a-zA-Z0-9]*\n?/);
  return (
    <>
      {blocks.map((b, i) =>
        i % 2 === 1 ? (
          <CodeBlock key={i} code={b.replace(/\n$/, "")} />
        ) : (
          b
            .split(/\n\s*\n/)
            .filter((p) => p.trim())
            .map((p, j) => (
              <p key={`${i}-${j}`} className="sm muted" style={{ whiteSpace: "pre-line" }}>
                <Inline text={p.trim()} />
              </p>
            ))
        ),
      )}
    </>
  );
}

const TAINT_KIND: Record<string, { cls: string; label: string }> = {
  source: { cls: "src", label: "Source" },
  propagation: { cls: "", label: "Propagation" },
  propagator: { cls: "", label: "Propagation" },
  sanitiser: { cls: "san", label: "Sanitiser" },
  sanitizer: { cls: "san", label: "Sanitiser" },
  sink: { cls: "sink", label: "Sink" },
};

const CVSS_ROWS: [string, string][] = [
  ["AV", "Attack vector"],
  ["AC", "Attack complexity"],
  ["AT", "Attack requirements"],
  ["PR", "Privileges required"],
  ["UI", "User interaction"],
  ["VC", "Confidentiality"],
  ["VI", "Integrity"],
  ["VA", "Availability"],
];

export default function FindingDetailPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = ((params.get("tab") as Tab) || "saw") as Tab;
  const setTab = (t: Tab) => {
    const n = new URLSearchParams(params);
    n.set("tab", t);
    setParams(n, { replace: true });
  };
  const q = useFinding(id);
  const f = q.data;
  const history = useFindingHistory(id);
  useFollowScanProject(f?.scan_id);
  const reviews = f?.provenance?.llm_reviews ?? [];
  const seq =
    reviews.find((r) => r.ledger_seq !== null && r.ledger_seq !== undefined)?.ledger_seq ?? null;
  const ledger = useLedgerEntry(f?.scan_id, seq);
  const patch = usePatchFinding();
  const users = useUsers().data;
  const { can } = useSession();
  const toast = useToast();
  const [dialog, setDialog] = useState<null | "assign" | "suppress" | "sync">(null);
  const [comment, setComment] = useState("");
  const [jump, setJump] = useState<number | null>(null);
  /** A taint step picked in a file other than the one the excerpt shows. */
  const [elsewhere, setElsewhere] = useState<TaintStep | null>(null);
  const review = useReviewFinding();
  const providers = useProviders().data;
  const reviewProviderId =
    f?.scan?.provider && f.scan.provider !== "none" ? f.scan.provider : undefined;
  const defaultProviderId = useSettings().data?.default_provider;
  const reviewProvider = providers?.find((p) => p.id === (reviewProviderId ?? defaultProviderId));
  const runReview = () => {
    if (!id) return;
    const started = Date.now();
    review.mutate(
      { id },
      {
        onSuccess: (r) => {
          const secs = Math.round((Date.now() - started) / 1000);
          // Same words as the badge on this page: a low-confidence "vulnerable" reads "needs review".
          const shown = r.llm ? verdictOf(r) : null;
          const conf = shown?.conf != null ? ` at ${shown.conf.toFixed(2)}` : "";
          const verdict =
            r.llm?.is_vulnerable === true
              ? `vulnerable${conf}${shown?.kind === "rev" ? ", needs review" : ""}`
              : r.llm?.is_vulnerable === false
                ? `not vulnerable${conf}`
                : "undecided";
          toast.success(
            "Model review done",
            `${r.llm?.model ?? "The model"} says ${verdict}${secs ? ` · ${secs} s` : ""}.`,
          );
          setTab("reason");
        },
        onError: (e) =>
          toast.error("Model review failed", e instanceof Error ? e.message : undefined),
      },
    );
  };

  const doPatch = (p: Parameters<typeof patch.mutate>[0]["patch"], ok: string) =>
    patch.mutate(
      { id: id!, patch: p },
      {
        onSuccess: () => toast.success(ok),
        onError: (e) => toast.error("Update failed", e instanceof Error ? e.message : undefined),
      },
    );

  if (q.isError) {
    return (
      <Content>
        <Breadcrumb nav items={[{ label: "Findings", to: "/findings" }, { label: id ?? "" }]} />
        <ErrorBanner
          what="This finding could not be loaded."
          error={q.error}
          onRetry={() => void q.refetch()}
          back={{ label: "All findings", to: "/findings" }}
        />
      </Content>
    );
  }
  if (!f) {
    return (
      <Content>
        <div className="card">
          <Skeleton rows={2} />
        </div>
        <section className="g g-side">
          <div className="card">
            <Skeleton rows={3} />
          </div>
          <div className="card">
            <Skeleton rows={2} />
          </div>
        </section>
      </Content>
    );
  }

  const v = verdictOf(f);
  const conf = confidenceFraction(f.llm?.confidence ?? null);
  const loc = locationOf(f);
  const taint = f.evidence?.taint_path ?? [];
  const hasSan = taint.some((t) => /saniti[sz]/.test(t.kind));
  const files = new Set(taint.map((t) => t.path)).size;
  const { impact } = splitImpact(f.llm?.impact ?? f.impact_detail?.narrative ?? null);
  const level = (ledger.data?.entry.level ?? f.scan?.privacy_level ?? reviews[0]?.level) as
    PrivacyLevel | undefined;
  const engines = enginesOf(f);
  const sinkLine =
    taint.find((t) => t.kind === "sink" && t.path === f.evidence?.code?.path)?.line ?? loc?.line;
  const srcLine = taint.find((t) => t.kind === "source" && t.path === f.evidence?.code?.path)?.line;
  const assigneeName = f.assignee
    ? users?.find((u) => u.username === f.assignee || u.id === f.assignee)?.display_name ||
      f.assignee
    : null;

  const tags: ReactNode[] = [];
  if (f.cwe) {
    const n = f.cwe.replace(/\D/g, "");
    tags.push(
      <a
        key="cwe"
        className="tag"
        href={`https://cwe.mitre.org/data/definitions/${n}.html`}
        target="_blank"
        rel="noreferrer noopener"
      >
        {f.cwe}
      </a>,
    );
  }
  if (f.owasp)
    tags.push(
      <span key="owasp" className="tag">
        OWASP {f.owasp}
      </span>,
    );
  const asvs = f.asvs_refs?.[0] ?? f.asvs?.split(",")[0]?.trim();
  if (asvs)
    tags.push(
      <span key="asvs" className="tag">
        ASVS {asvs}
      </span>,
    );
  const capec = f.capec_refs?.[0] ?? f.capec?.split(",")[0]?.trim();
  if (capec)
    tags.push(
      <span key="capec" className="tag">
        {capec}
      </span>,
    );
  // Every clause of a framework, not only the first: the first is often the baseline control
  // (PCI DSS 6.2.3, code review) and the weakness-specific one follows (6.2.4, injection).
  const byFramework = new Map<string, { clause: string; title?: string | null }[]>();
  for (const c of f.compliance ?? []) {
    if (["owasp-asvs", "capec", "cwe-top25"].includes(c.framework)) continue;
    const list = byFramework.get(c.framework) ?? [];
    if (!list.some((x) => x.clause === c.clause)) list.push(c);
    byFramework.set(c.framework, list);
  }
  for (const [framework, clauses] of [...byFramework].slice(0, 4)) {
    tags.push(
      <span
        key={`c-${framework}`}
        className="tag"
        title={clauses.map((c) => `${c.clause}${c.title ? `: ${c.title}` : ""}`).join("\n")}
      >
        {frameworkLabel(framework)} {clauses.map((c) => c.clause).join(", ")}
      </span>,
    );
  }

  const hist = [...(history.data ?? f.history ?? [])].sort((a, b) => b.at.localeCompare(a.at));
  const vec = parseVector(f.cvss4_vector);

  return (
    <Content>
      <div className="stack" style={{ gap: 10 }}>
        <Breadcrumb
          nav
          items={[
            { label: f.scan?.project_name ?? "Project", to: "/" },
            { label: "Findings", to: `/findings?scan=${f.scan_id}` },
            { label: findingLabel(f.id) },
          ]}
        />
        <div className="ph" style={{ alignItems: "flex-start" }}>
          <div className="stack s6" style={{ minWidth: 0, flex: "1 1 100%" }}>
            <div className="row" style={{ gap: 12 }}>
              <SeverityBadge severity={f.severity} />
              <span className="mono sm muted" title={f.id}>
                {findingLabel(f.id)}
              </span>
              {v && (
                <Verdict kind={v.kind}>
                  {v.kind === "fp" ? VERDICT_LABEL.fp : `${VERDICT_LABEL[v.kind]} by LLM`}
                  {v.conf !== null ? ` · ${v.conf.toFixed(2)}` : ""}
                </Verdict>
              )}
            </div>
            <h1 style={{ fontSize: 24 }}>{f.title}</h1>
            <div className="row" style={{ gap: 6 }}>
              <CvssBox score={f.cvss4_score} suffix="CVSS 4.0" />
              {tags}
            </div>
          </div>
          <div className="row">
            {can("findings:review") && (
              <Button
                loading={review.isPending}
                onClick={runReview}
                title={`Send this finding's sanitised slice to ${reviewProvider?.name ?? "the scan's provider"} now; the request is recorded in the egress ledger.`}
              >
                {review.isPending
                  ? "Reviewing"
                  : reviews.length
                    ? "Review again"
                    : "Review with model"}
              </Button>
            )}
            {can("findings:triage") && (
              <>
                <Button onClick={() => setDialog("assign")}>Assign</Button>
                <Button onClick={() => setDialog("suppress")}>Suppress</Button>
              </>
            )}
            {can("github:sync") && (
              <Button variant="primary" onClick={() => setDialog("sync")}>
                Create GitHub issue
              </Button>
            )}
          </div>
        </div>
      </div>

      {review.isPending && (
        <div className="banner info sm" role="status">
          Asking {reviewProvider?.name ?? "the model"} about this finding. Only its sanitised slice
          leaves, through the egress guard
          {reviewProvider && !reviewProvider.local
            ? "; a remote model can take a minute or more"
            : ""}
          .
        </div>
      )}

      <section className="g g-side">
        <div className="stack s20">
          <div className="card">
            <div className="card-h">
              <div>
                <h2>Taint path</h2>
                <p className="sub">
                  {taint.length
                    ? `Source to sink across ${files} file${files === 1 ? "" : "s"}. Select a step to jump to the line.`
                    : "No data-flow path: this finding comes from a pattern, secret, dependency or configuration check."}
                </p>
              </div>
              {taint.length > 0 && (
                <span className="xs faint">
                  {taint.length} steps{hasSan ? "" : " · no sanitiser on path"}
                </span>
              )}
            </div>
            {taint.length > 0 ? (
              <div className="taint">
                {taint.map((t, i) => (
                  <TaintNode
                    key={i}
                    step={t}
                    n={t.index ?? i + 1}
                    last={i === taint.length - 1}
                    onPick={() => {
                      setTab("real");
                      const here = !f.evidence?.code || t.path === f.evidence.code.path;
                      setElsewhere(here ? null : t);
                      setJump(here ? t.line : null);
                      const target = here ? `L${t.line}` : "taint-elsewhere";
                      setTimeout(
                        () => document.getElementById(target)?.scrollIntoView({ block: "center" }),
                        50,
                      );
                    }}
                  />
                ))}
              </div>
            ) : loc ? (
              <p className="mono sm">
                {loc.path}:{loc.line}
              </p>
            ) : null}
          </div>

          <div className="card" style={{ paddingTop: 6 }}>
            <Tabs
              label="Evidence"
              value={tab}
              onChange={(t) => setTab(t as Tab)}
              tabs={[
                { id: "saw", label: "What the LLM saw" },
                { id: "real", label: "Real code" },
                {
                  id: "reason",
                  label: "LLM reasoning",
                  count: reviews.length
                    ? `${reviews.length} run${reviews.length === 1 ? "" : "s"}`
                    : undefined,
                },
              ]}
            />
            <div style={{ paddingTop: 14 }}>
              {tab === "saw" && <SawTab f={f} seq={seq} ledger={ledger} />}
              {tab === "real" && (
                <div className="stack">
                  {elsewhere && (
                    <div id="taint-elsewhere">
                      <CodeBlock
                        title={<span className="mono">{elsewhere.path}</span>}
                        titleRight={
                          <span className="faint">
                            Taint step ·{" "}
                            {TAINT_KIND[elsewhere.kind]?.label ?? capitalise(elsewhere.kind)}
                          </span>
                        }
                        code={elsewhere.code ?? elsewhere.label}
                        startLine={elsewhere.line}
                        kindOf={() =>
                          elsewhere.kind === "source"
                            ? "src"
                            : elsewhere.kind === "sink"
                              ? "sink"
                              : "hl"
                        }
                      />
                      <p className="xs faint" style={{ marginTop: 6 }}>
                        Only this line of <span className="mono">{elsewhere.path}</span> is kept
                        with the finding; the excerpt below is the file the finding is reported in.
                      </p>
                    </div>
                  )}
                  {f.evidence?.code ? (
                    <CodeBlock
                      title={<span className="mono">{f.evidence.code.path}</span>}
                      titleRight={<span className="faint">Local only · never sent</span>}
                      lines={f.evidence.code.lines}
                      highlight={f.evidence.code.highlight}
                      anchor="L"
                      kindOf={(n) =>
                        n === sinkLine
                          ? "sink"
                          : n === srcLine
                            ? "src"
                            : n === jump ||
                                f.evidence!.code!.highlight.some((r) => n >= r.start && n <= r.end)
                              ? "hl"
                              : undefined
                      }
                    />
                  ) : f.evidence?.snippet ? (
                    <CodeBlock
                      title={<span className="mono">{loc?.path}</span>}
                      code={f.evidence.snippet}
                      startLine={loc?.line ?? 1}
                    />
                  ) : (
                    <Empty title="No code excerpt">
                      The original code is only shown to roles allowed to read it.
                    </Empty>
                  )}
                </div>
              )}
              {tab === "reason" && (
                <ReasonTab
                  f={f}
                  conf={conf}
                  onReview={can("findings:review") ? runReview : undefined}
                  reviewing={review.isPending}
                />
              )}
            </div>
          </div>

          <div className="card stack">
            <h2>Impact</h2>
            {impact ? (
              <RichText text={impact} />
            ) : (
              <p className="sm muted">{f.description ?? "No impact statement for this finding."}</p>
            )}
          </div>

          <div className="card stack">
            <div className="row between">
              <h2>Remediation</h2>
              <span className="xs faint">Suggested fix · review before applying</span>
            </div>
            {f.remediation || f.llm?.remediation ? (
              <RichText text={(f.remediation ?? f.llm?.remediation)!} />
            ) : (
              <p className="sm muted">No remediation guidance for this rule yet.</p>
            )}
            {f.remediation_example && !(f.remediation ?? "").includes("```") && (
              <CodeBlock
                title={
                  <span className="mono">
                    Secure example · {f.remediation_example.language ?? f.language ?? ""}
                  </span>
                }
                code={f.remediation_example.code}
              />
            )}
            {f.remediation_diff && (
              <CodeBlock
                title={<span className="mono">{loc?.path}</span>}
                code={f.remediation_diff}
              />
            )}
          </div>

          {(f.references ?? []).length > 0 && (
            <div className="card stack">
              <h2>References</h2>
              <div className="stack s6 sm">
                {(f.references ?? []).map((r, i) => {
                  const ref =
                    typeof r === "string"
                      ? { title: r, url: /^https?:/.test(r) ? r : undefined }
                      : r;
                  return ref.url ? (
                    <a
                      key={i}
                      className="more"
                      href={ref.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      style={{ whiteSpace: "normal" }}
                    >
                      {ref.title} <Icon name="arrow-up-right" />
                    </a>
                  ) : (
                    <span key={i} className="muted">
                      {ref.title}
                    </span>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        <div className="stack s16">
          <div className="card">
            <h2 style={{ marginBottom: 12 }}>Details</h2>
            <dl className="dl">
              <dt>Status</dt>
              <dd>
                <select
                  className="inp sm"
                  aria-label="Status"
                  value={f.status}
                  disabled={!can("findings:triage") || patch.isPending}
                  onChange={(e) =>
                    e.target.value !== f.status &&
                    doPatch({ status: e.target.value as FindingStatus }, "Status updated")
                  }
                >
                  {FINDING_STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {STATUS_LABEL[s]}
                    </option>
                  ))}
                </select>
              </dd>
              <dt>Assignee</dt>
              <dd className="row">
                {assigneeName ? (
                  <>
                    <Avatar name={assigneeName} size="xs" />
                    {assigneeName}
                  </>
                ) : (
                  <span className="faint">Unassigned</span>
                )}
              </dd>
              <dt>Scan</dt>
              <dd className="mono sm">
                <Link
                  to={`/scans/${f.scan_id}`}
                  title={f.scan_id}
                  style={{ textDecoration: "none" }}
                >
                  {scanLabel(f.scan_id)}
                </Link>
                {f.baseline_state && f.baseline_scan_id && (
                  <span>
                    {" "}
                    ·{" "}
                    {f.baseline_state === "new"
                      ? "New since"
                      : f.baseline_state === "fixed"
                        ? "Fixed since"
                        : "Unchanged since"}{" "}
                    {scanLabel(f.baseline_scan_id)}
                  </span>
                )}
              </dd>
              <dt>Engines</dt>
              <dd>
                {engines.join(", ")}
                {engines.length > 1 ? ` · merged from ${engines.length}` : ""}
              </dd>
              <dt>Privacy level</dt>
              <dd>{level ? <LevelBadge level={level} name /> : "—"}</dd>
              <dt>Payload</dt>
              <dd>
                {seq !== null ? (
                  <Link
                    className="mono acc sm"
                    to={`/privacy/ledger?scan=${f.scan_id}&seq=${seq}`}
                    title="Open this payload in the egress ledger"
                  >
                    #{fmtSeq(seq)}
                    {ledger.data ? ` · ${fmtHash(ledger.data.entry.payload_hash)}` : ""}
                  </Link>
                ) : (
                  <span className="sm faint">Nothing sent</span>
                )}
              </dd>
              <dt>First seen</dt>
              <dd className="sm">{fmtDate(f.created_at)}</dd>
              {f.due_at && (
                <>
                  <dt>Due</dt>
                  <dd className="sm">
                    {fmtDate(f.due_at)}
                    {f.sla_days ? ` · ${f.sla_days}-day SLA` : ""}
                    {f.sla_state === "overdue" ? (
                      <span className="badc"> · overdue</span>
                    ) : f.sla_state === "due_soon" ? (
                      <span className="up"> · due soon</span>
                    ) : null}
                  </dd>
                </>
              )}
            </dl>
          </div>

          {f.cvss4_score !== null && f.cvss4_score !== undefined && (
            <div className="card">
              <h2 style={{ marginBottom: 4 }}>
                CVSS 4.0 · {f.cvss4_score.toFixed(1)} {cvssRating(f.cvss4_score)}
              </h2>
              {f.cvss4_vector && (
                <p className="mono xs muted" style={{ wordBreak: "break-all", marginBottom: 12 }}>
                  {f.cvss4_vector}
                </p>
              )}
              {f.risk?.metric_rationale?.length ? (
                <p className="xs muted" style={{ marginBottom: 12 }}>
                  {f.risk.cvss4_nomenclature === "CVSS-B" ? "Base score only (CVSS-B). " : ""}
                  Basis: {f.risk.metric_rationale.map(([, why]) => why).join("; ")}
                  {f.risk.adjustments?.length ? "" : ", not adjusted for this code's reachability or deployment"}.
                </p>
              ) : null}
              {vec && (
                <dl className="dl sm">
                  {CVSS_ROWS.map(([k, name]) => {
                    const m = vec.metrics.find((x) => x.key === k);
                    return m ? (
                      <Pair key={k} k={name}>
                        {m.label}
                      </Pair>
                    ) : null;
                  })}
                </dl>
              )}
              <OtherRatings f={f} />
            </div>
          )}

          <div className="card">
            <h2 style={{ marginBottom: 14 }}>Activity</h2>
            <div className="timeline">
              {hist.map((h, i) => (
                <div className="tl-i" key={h.id ?? i}>
                  <Avatar name={h.actor} />
                  <div>
                    <div>
                      <b>{h.actor}</b> <span className="muted">{describe(h)}</span>
                    </div>
                    {h.comment && (
                      <p className="sm" style={{ marginTop: 4 }}>
                        {h.comment}
                      </p>
                    )}
                    <div className="xs faint">{fmtShort(h.at)}</div>
                  </div>
                </div>
              ))}
              <div className="tl-i">
                <Avatar name="CodeKavach" />
                <div>
                  <div>
                    <b>CodeKavach</b>{" "}
                    <span className="muted">
                      opened from {scanLabel(f.scan_id)}
                      {f.cvss4_score
                        ? ` · rated ${capitalise(f.severity)} · CVSS ${f.cvss4_score.toFixed(1)}`
                        : ""}
                    </span>
                  </div>
                  <div className="xs faint">{fmtShort(f.created_at)}</div>
                </div>
              </div>
            </div>
            {can("findings:triage") && (
              <form
                className="fld"
                style={{ marginTop: 14 }}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!comment.trim()) return;
                  patch.mutate(
                    { id: f.id, patch: { comment: comment.trim() } },
                    {
                      onSuccess: () => setComment(""),
                      onError: (err) => toast.error("Comment not saved", err.message),
                    },
                  );
                }}
              >
                <label htmlFor="fd-c">Add a comment</label>
                <textarea
                  id="fd-c"
                  className="inp"
                  rows={2}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey))
                      (e.currentTarget.form as HTMLFormElement).requestSubmit();
                  }}
                />
                {comment.trim() && (
                  <div className="row" style={{ justifyContent: "flex-end" }}>
                    <button className="btn sm" type="submit" disabled={patch.isPending}>
                      Comment
                    </button>
                  </div>
                )}
              </form>
            )}
          </div>
        </div>
      </section>

      <AssignDialog
        open={dialog === "assign"}
        onClose={() => setDialog(null)}
        users={users?.map((u) => ({ id: u.username, name: u.display_name || u.username })) ?? []}
        busy={patch.isPending}
        onAssign={(a) => {
          doPatch({ assignee: a }, `Assigned to ${a}`);
          setDialog(null);
        }}
      />
      <SuppressDialog
        open={dialog === "suppress"}
        onClose={() => setDialog(null)}
        busy={patch.isPending}
        onSuppress={(reason) => {
          doPatch({ status: "accepted_risk", comment: reason }, "Finding suppressed");
          setDialog(null);
        }}
      />
      {dialog === "sync" && (
        <GithubSyncDialog
          scanId={f.scan_id}
          open
          onClose={() => setDialog(null)}
          findingIds={[f.id]}
        />
      )}
    </Content>
  );
}

function Pair({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{children}</dd>
    </>
  );
}

function describe(h: {
  action: string;
  from_status?: string | null;
  to_status?: string | null;
  comment?: string | null;
  assignee?: string | null;
}): string {
  if (h.to_status && h.to_status !== h.from_status) {
    return `changed status ${h.from_status ? `from ${STATUS_LABEL[h.from_status as FindingStatus] ?? h.from_status} ` : ""}to ${STATUS_LABEL[h.to_status as FindingStatus] ?? h.to_status}`;
  }
  if (h.action === "assign" || h.assignee) return `assigned to ${h.assignee ?? "someone"}`;
  if (h.action === "llm_review") return "asked the model";
  if (h.comment) return "commented";
  return h.action;
}

function TaintNode({
  step,
  n,
  last,
  onPick,
}: {
  step: TaintStep;
  n: number;
  last: boolean;
  onPick: () => void;
}) {
  const k = TAINT_KIND[step.kind] ?? { cls: "", label: capitalise(step.kind) };
  return (
    <>
      <a
        className={`tnode ${k.cls}`}
        href={`#L${step.line}`}
        onClick={(e) => {
          e.preventDefault();
          onPick();
        }}
        title={step.label}
      >
        <span className="tk-l">
          {n} · {k.label}
        </span>
        <code>{step.code ?? step.label}</code>
        <span className="tl" style={{ overflowWrap: "anywhere" }}>
          {step.path}:{step.line}
        </span>
      </a>
      {!last && (
        <div className="tedge">
          <Icon name="arrow-right" />
        </div>
      )}
    </>
  );
}

function SawTab({
  f,
  seq,
  ledger,
}: {
  f: Finding;
  seq: number | null;
  ledger: ReturnType<typeof useLedgerEntry>;
}) {
  if (seq === null) {
    return (
      <Empty title="Nothing was sent for this finding">
        The engines' evidence stands on its own: secrets, dependencies and configuration findings
        have no code slice to send, a quick review sends only the most severe candidates, and at L0
        nothing leaves.
      </Empty>
    );
  }
  if (ledger.isLoading) return <Skeleton rows={2} />;
  if (ledger.isError || !ledger.data) {
    return <ErrorBanner what="The payload could not be loaded." error={ledger.error} />;
  }
  const d = ledger.data;
  const lv = d.entry.level;
  if (d.entry.outcome?.startsWith("blocked")) {
    return (
      <div className="banner bad sm">
        Blocked by policy · {d.entry.block_code ?? "never-send"}. Nothing was sent.
      </div>
    );
  }
  const sent = payloadLineCount(d.payload_text);
  const total = d.lines_total ?? lineCount(d.original_text);
  const bytes = d.entry.bytes ?? byteLength(d.payload_text);
  return (
    <div className="stack">
      <div className="row between sm">
        <span className="muted">
          Payload{" "}
          <Link
            className="mono acc"
            to={`/privacy/ledger?scan=${f.scan_id}&seq=${seq}`}
            title="Open this payload in the egress ledger"
          >
            #{fmtSeq(seq)}
          </Link>{" "}
          · {lv} {LEVEL_NAME[lv]?.toLowerCase()} · {sent} of {total || "—"} lines · {fmtInt(bytes)}{" "}
          bytes
        </span>
        <MoreLink to={`/privacy/inspect/${f.scan_id}/${seq}`}>Inspect side by side</MoreLink>
      </div>
      <MarkedCode text={d.payload_text} markup={d.markup} side="payload" />
      <p className="xs faint">
        Visible to the model: control flow, literal shapes and public API names. Not visible: real
        names, secrets and string values that were replaced.
      </p>
    </div>
  );
}

function ReasonTab({
  f,
  conf,
  onReview,
  reviewing,
}: {
  f: Finding;
  conf: number | null;
  onReview?: () => void;
  reviewing?: boolean;
}) {
  const reviews = f.provenance?.llm_reviews ?? [];
  const runs = f.llm?.runs?.length
    ? f.llm.runs.filter((r) => r.source !== "ledger" || r.verdict)
    : reviews;
  if (!f.llm && !reviews.length) {
    return (
      <Empty
        title="No model review"
        action={onReview ? (reviewing ? "Reviewing…" : "Review with model") : undefined}
        onAction={onReview && !reviewing ? onReview : undefined}
      >
        This finding was not sent to a model: the scan reviewed only its most severe candidates, or
        ran at L0.
      </Empty>
    );
  }
  const v = verdictOf(f);
  const cons = f.llm?.consensus;
  const agree = cons
    ? f.llm?.is_vulnerable === false
      ? cons.votes_safe
      : cons.votes_vulnerable
    : reviews.filter((r) => r.is_vulnerable === f.llm?.is_vulnerable).length;
  const samples = cons?.samples ?? reviews.length;
  const { scenario } = splitImpact(f.llm?.impact ?? null);
  return (
    <div className="stack s16">
      <div className="row" style={{ gap: 24 }}>
        <div>
          <div className="xs faint">Verdict</div>
          {v ? <Verdict kind={v.kind} /> : "—"}
        </div>
        <div>
          <div className="xs faint">Confidence</div>
          <span className="mono">
            {conf === null ? (f.llm?.confidence ?? "—") : conf.toFixed(2)}
          </span>
        </div>
        <div>
          <div className="xs faint">Consensus</div>
          <span className="mono">
            {samples ? `${agree} of ${samples} run${samples === 1 ? "" : "s"} agree` : "—"}
          </span>
        </div>
        <div>
          <div className="xs faint">Model</div>
          <span className="mono sm">
            {f.llm?.model ?? reviews[0]?.model ?? "—"}
            {f.llm?.temperature !== undefined && f.llm?.temperature !== null
              ? ` · temp ${f.llm.temperature}`
              : ""}
          </span>
        </div>
      </div>
      <div>
        <h3 style={{ fontSize: 13, marginBottom: 4 }}>Rationale</h3>
        <p className="sm muted" style={{ whiteSpace: "pre-line" }}>
          <Inline text={f.llm?.reasoning ?? reviews[0]?.reasoning ?? "—"} />
        </p>
      </div>
      {(f.exploit_scenario || f.llm?.exploit_scenario || scenario) && (
        <div>
          <h3 style={{ fontSize: 13, marginBottom: 4 }}>Exploit scenario</h3>
          <p className="sm muted">
            <Inline text={f.exploit_scenario ?? f.llm?.exploit_scenario ?? scenario ?? ""} />
          </p>
        </div>
      )}
      {runs.length > 0 && (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Run</th>
                <th>Verdict</th>
                <th className="num">Confidence</th>
                <th>Payload</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r, i) => {
                const c = confidenceFraction(r.confidence ?? null);
                const vk =
                  r.is_vulnerable === null || r.is_vulnerable === undefined
                    ? null
                    : verdictOf({
                        status: f.status,
                        llm: {
                          is_vulnerable: !!r.is_vulnerable,
                          confidence: r.confidence ?? 0,
                          reasoning: "",
                        },
                      });
                return (
                  <tr key={i}>
                    <td className="mono">{i + 1}</td>
                    <td>{vk ? <Verdict kind={vk.kind} /> : "—"}</td>
                    <td className="num mono">
                      {c === null ? (r.confidence ?? "—") : c.toFixed(2)}
                    </td>
                    <td className="mono sm">
                      {r.ledger_seq !== undefined && r.ledger_seq !== null
                        ? `#${fmtSeq(r.ledger_seq)}`
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

interface RiskDetail {
  owasp_likelihood?: number;
  owasp_impact?: number;
  owasp_likelihood_band?: string;
  owasp_impact_band?: string;
  owasp_overall?: string;
}

/** CVSS 3.1 and the OWASP risk rating, under the CVSS 4.0 card (the report carries all three). */
function OtherRatings({ f }: { f: Finding }) {
  const risk = (f as Finding & { risk?: RiskDetail | null }).risk ?? null;
  const v31 = f.cvss31_score;
  const hasOwasp =
    risk?.owasp_overall && risk.owasp_likelihood !== undefined && risk.owasp_impact !== undefined;
  if ((v31 === null || v31 === undefined) && !hasOwasp) return null;
  return (
    <dl
      className="dl sm"
      style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}
    >
      {v31 !== null && v31 !== undefined && (
        <Pair k="CVSS 3.1">
          <span title={f.cvss31_vector ?? undefined}>
            <b>{v31.toFixed(1)}</b> {cvssRating(v31)}
          </span>
          {f.cvss31_vector && (
            <div className="mono xs muted" style={{ wordBreak: "break-all" }}>
              {f.cvss31_vector}
            </div>
          )}
        </Pair>
      )}
      {hasOwasp && (
        <Pair k="OWASP risk">
          <b>{capitalise(risk!.owasp_overall!)}</b>
          <div className="xs muted">
            Likelihood {risk!.owasp_likelihood!.toFixed(1)} {risk!.owasp_likelihood_band ?? ""} ·
            impact {risk!.owasp_impact!.toFixed(1)} {risk!.owasp_impact_band ?? ""}
          </div>
        </Pair>
      )}
    </dl>
  );
}
