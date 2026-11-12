import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowDown,
  Bot,
  BotOff,
  BookOpen,
  CircleDot,
  Code2,
  ExternalLink,
  Filter,
  GitCommitVertical,
  History,
  Scale,
  ShieldCheck,
  Target,
  Wrench,
} from "lucide-react";
import { useFinding, useFindingHistory, usePatchFinding } from "@/api/queries";
import { FINDING_STATUSES, type Finding, type FindingStatus, type TaintStep } from "@/api/types";
import { ApiError } from "@/api/client";
import { PageHeader } from "@/components/layout/PageHeader";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  Chip,
  CodeBlock,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  useToast,
} from "@/components/ui";
import { useSession } from "@/app/session";
import { cvssRating, parseVector } from "@/lib/cvss";
import { cn, fmtConfidence, fmtDateTime, fmtRelative, STATUS_LABEL } from "@/lib/format";

const stepStyle: Record<string, { icon: typeof Target; tone: string; label: string }> = {
  source: { icon: CircleDot, tone: "bg-info-soft text-info ring-info/40", label: "Source" },
  propagation: { icon: GitCommitVertical, tone: "bg-surface-3 text-fg-muted ring-border-strong", label: "Flow" },
  sanitiser: { icon: Filter, tone: "bg-success-soft text-success ring-success/40", label: "Sanitiser" },
  sink: { icon: Target, tone: "bg-danger-soft text-danger ring-danger/40", label: "Sink" },
};

function TaintPath({ steps }: { steps: TaintStep[] }) {
  if (!steps.length) {
    return (
      <p className="text-sm text-fg-muted">
        This finding comes from a pattern or configuration rule rather than a data flow, so there is no source-to-sink path.
      </p>
    );
  }
  return (
    <ol className="space-y-0" aria-label="Taint path from source to sink">
      {steps.map((s, i) => {
        const st = stepStyle[s.kind] ?? stepStyle.propagation!;
        const Icon = st.icon;
        return (
          <li key={i}>
            <div className="flex items-start gap-3">
              <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-full ring-1", st.tone)}>
                <Icon className="h-4 w-4" aria-hidden />
              </div>
              <div className="min-w-0 flex-1 rounded-lg border border-border bg-surface-2/50 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">{st.label}</span>
                  <span className="text-sm font-medium text-fg">{s.label}</span>
                </div>
                <p className="mt-0.5 font-mono text-xs text-fg-muted">
                  {s.path}:{s.line}
                </p>
                {s.code && <pre className="mt-1.5 overflow-x-auto rounded bg-code-bg px-2 py-1 font-mono text-xs text-fg">{s.code}</pre>}
              </div>
            </div>
            {i < steps.length - 1 && (
              <div className="ml-[17px] flex h-6 items-center">
                <ArrowDown className="h-4 w-4 text-fg-subtle" aria-hidden />
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function CvssCard({ label, vector, score }: { label: string; vector?: string | null; score?: number | null }) {
  const parsed = parseVector(vector);
  const rating = cvssRating(score);
  const tone =
    rating === "Critical" ? "text-sev-critical" : rating === "High" ? "text-sev-high" : rating === "Medium" ? "text-sev-medium" : "text-sev-low";
  return (
    <div className="rounded-lg border border-border p-4">
      <div className="flex items-baseline justify-between gap-3">
        <p className="text-sm font-semibold text-fg">{label}</p>
        {score != null && (
          <p>
            <span className={cn("text-2xl font-bold tabular-nums", tone)}>{score.toFixed(1)}</span>
            <span className="ml-1.5 text-sm text-fg-muted">{rating}</span>
          </p>
        )}
      </div>
      {vector ? (
        <>
          <p className="mt-1 break-all font-mono text-xs text-fg-muted">{vector}</p>
          {parsed && (
            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {parsed.metrics.map((m) => (
                <div key={m.key} className="flex justify-between gap-2 border-b border-border/60 py-0.5">
                  <dt className="text-fg-subtle">{m.name}</dt>
                  <dd className="font-medium text-fg">{m.label}</dd>
                </div>
              ))}
            </dl>
          )}
        </>
      ) : (
        <p className="mt-1 text-sm text-fg-subtle">Not rated</p>
      )}
    </div>
  );
}

function refLink(r: Finding["references"] extends (infer T)[] | undefined ? T : never) {
  if (typeof r === "string") return { title: r, url: /^https?:\/\//.test(r) ? r : undefined };
  return r;
}

function TriageCard({ f }: { f: Finding }) {
  const patch = usePatchFinding();
  const toast = useToast();
  const { can } = useSession();
  const [status, setStatus] = useState<FindingStatus>(f.status);
  const [assignee, setAssignee] = useState(f.assignee ?? "");
  const [comment, setComment] = useState("");
  useEffect(() => {
    setStatus(f.status);
    setAssignee(f.assignee ?? "");
  }, [f.status, f.assignee]);
  const needsReason = (status === "false_positive" || status === "accepted_risk") && status !== f.status;
  const dirty = status !== f.status || assignee !== (f.assignee ?? "") || comment.trim() !== "";
  const save = async () => {
    if (needsReason && !comment.trim()) {
      toast.error("A reason is required", `Explain why this finding is ${STATUS_LABEL[status].toLowerCase()}.`);
      return;
    }
    try {
      await patch.mutateAsync({
        id: f.id,
        patch: {
          status: status !== f.status ? status : undefined,
          assignee: assignee !== (f.assignee ?? "") ? assignee : undefined,
          comment: comment.trim() || undefined,
        },
      });
      setComment("");
      toast.success("Triage saved");
    } catch (e) {
      toast.error("Triage was not saved", e instanceof ApiError ? `${e.message} (${e.code})` : undefined);
    }
  };
  const disabled = !can("findings:triage");
  return (
    <Card>
      <CardHeader title="Triage" description="Recorded in the finding history" />
      <CardBody className="space-y-4">
        <Field label="Status">
          {(id) => (
            <Select id={id} value={status} disabled={disabled} onChange={(e) => setStatus(e.target.value as FindingStatus)}>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABEL[s]}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Assignee">
          {(id) => <Input id={id} value={assignee} disabled={disabled} placeholder="username" onChange={(e) => setAssignee(e.target.value)} />}
        </Field>
        <Field label={needsReason ? "Reason" : "Comment"} required={needsReason}>
          {(id) => (
            <textarea
              id={id}
              rows={3}
              disabled={disabled}
              className="ck-textarea"
              value={comment}
              placeholder={needsReason ? "Why is this not a risk to act on?" : "e.g. reproduced on staging"}
              onChange={(e) => setComment(e.target.value)}
            />
          )}
        </Field>
        <Button className="w-full" onClick={save} loading={patch.isPending} disabled={disabled || !dirty}>
          Save triage
        </Button>
        {f.comment && (
          <p className="rounded-md bg-surface-2 px-3 py-2 text-xs text-fg-muted">
            <span className="font-semibold text-fg">Latest comment: </span>
            {f.comment}
          </p>
        )}
      </CardBody>
    </Card>
  );
}

export default function FindingDetailPage() {
  const { id } = useParams();
  const q = useFinding(id);
  const history = useFindingHistory(id);
  const [tab, setTab] = useState("evidence");

  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const f = q.data;
  if (!f) return <Skeleton className="h-[32rem]" />;

  const loc = f.locations[0];
  const code = f.evidence?.code;
  const dismissed = f.llm?.is_vulnerable === false;
  const refs = (f.references ?? []).map(refLink);

  return (
    <>
      <PageHeader
        crumbs={[
          { label: "Findings", to: `/findings?scan=${f.scan_id}` },
          { label: f.id },
        ]}
        title={f.title}
        meta={
          <>
            <SeverityBadge severity={f.severity} size="md" />
            <StatusBadge status={f.status} />
            {f.cwe && <Chip title={f.cwe_name ?? undefined}>{f.cwe}</Chip>}
            {loc && (
              <span className="font-mono text-xs text-fg-muted">
                {loc.path}:{loc.start_line}
              </span>
            )}
            <span className="text-xs text-fg-subtle">
              {f.engine} · {f.rule_id}
            </span>
          </>
        }
      />
      {dismissed && (
        <Callout tone="info" icon={<BotOff className="h-5 w-5" />} title="The model judged this finding not exploitable" className="mb-6">
          It stays in the results with its deterministic evidence and is shown down-ranked. Only deterministic evidence or a person can close a finding.
        </Callout>
      )}
      <div className="grid gap-6 xl:grid-cols-[1fr_20rem]">
        <div className="min-w-0">
          <Tabs
            label="Finding detail"
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "evidence", label: "Evidence", icon: <Code2 className="h-4 w-4" /> },
              { id: "analysis", label: "Model analysis", icon: <Bot className="h-4 w-4" /> },
              { id: "standards", label: "Risk & standards", icon: <Scale className="h-4 w-4" /> },
              { id: "remediation", label: "Remediation", icon: <Wrench className="h-4 w-4" /> },
              { id: "history", label: "History", icon: <History className="h-4 w-4" />, count: history.data?.length },
            ]}
          />
          <div className="mt-5 space-y-6" role="tabpanel">
            {tab === "evidence" && (
              <>
                {f.description && <p className="text-base text-fg-muted">{f.description}</p>}
                <Card>
                  <CardHeader title="Code evidence" description="Secrets in evidence are masked on the server before they reach the browser" />
                  <CardBody>
                    {code ? (
                      <CodeBlock
                        title={code.path}
                        lines={code.lines}
                        highlight={code.highlight}
                        language={code.language}
                        maxHeight={420}
                      />
                    ) : f.evidence?.snippet ? (
                      <CodeBlock title={loc?.path} code={f.evidence.snippet} startLine={loc?.start_line ?? 1} highlight={loc ? [{ start: loc.start_line, end: loc.end_line ?? loc.start_line }] : []} />
                    ) : (
                      <p className="text-sm text-fg-muted">No code evidence was recorded for this finding.</p>
                    )}
                  </CardBody>
                </Card>
                <Card>
                  <CardHeader title="Data flow" description="How untrusted input reaches the dangerous operation" />
                  <CardBody>
                    <TaintPath steps={f.evidence?.taint_path ?? []} />
                  </CardBody>
                </Card>
              </>
            )}
            {tab === "analysis" && (
              <Card>
                <CardHeader
                  icon={<Bot className="h-4 w-4" />}
                  title="Model verdict"
                  description={f.llm ? `${f.llm.provider} · ${f.llm.model}` : undefined}
                />
                <CardBody>
                  {f.llm ? (
                    <div className="space-y-5">
                      <div className="flex flex-wrap items-center gap-4">
                        <Badge tone={f.llm.is_vulnerable ? "danger" : "neutral"} className="px-3 py-1 text-sm">
                          {f.llm.is_vulnerable ? "Vulnerable" : "Not exploitable"}
                        </Badge>
                        <div className="flex items-center gap-2">
                          <span className="text-sm text-fg-muted">Confidence</span>
                          <div className="h-2 w-32 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                            <div className="h-full rounded-full bg-primary" style={{ width: fmtConfidence(f.llm.confidence) }} />
                          </div>
                          <span className="text-sm font-semibold tabular-nums text-fg">{fmtConfidence(f.llm.confidence)}</span>
                        </div>
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-fg">Reasoning</h4>
                        <p className="mt-1 whitespace-pre-wrap text-base leading-relaxed text-fg-muted">{f.llm.reasoning}</p>
                      </div>
                      {f.llm.impact && (
                        <div>
                          <h4 className="text-sm font-semibold text-fg">Impact</h4>
                          <p className="mt-1 whitespace-pre-wrap text-base text-fg-muted">{f.llm.impact}</p>
                        </div>
                      )}
                      {f.llm.remediation && (
                        <div>
                          <h4 className="text-sm font-semibold text-fg">Suggested fix</h4>
                          <p className="mt-1 whitespace-pre-wrap text-base text-fg-muted">{f.llm.remediation}</p>
                        </div>
                      )}
                      <p className="flex items-start gap-1.5 text-xs text-fg-subtle">
                        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                        The model saw only the sanitised payload recorded in the ledger; pseudonyms were mapped back locally.
                      </p>
                    </div>
                  ) : (
                    <EmptyState
                      icon={<Bot className="h-6 w-6" />}
                      title="No model review"
                      description="This scan ran at level L0 or without sending payloads, so the finding rests on deterministic evidence only."
                    />
                  )}
                </CardBody>
              </Card>
            )}
            {tab === "standards" && (
              <>
                <div className="grid gap-4 lg:grid-cols-2">
                  <CvssCard label="CVSS v4.0" vector={f.cvss4_vector} score={f.cvss4_score} />
                  <CvssCard label="CVSS v3.1" vector={f.cvss31_vector} score={f.cvss31_score} />
                </div>
                <Card>
                  <CardHeader title="Classification" />
                  <CardBody>
                    <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
                      {[
                        ["CWE", f.cwe ? `${f.cwe}${f.cwe_name ? ` · ${f.cwe_name}` : ""}` : null],
                        ["OWASP Top 10", f.owasp],
                        ["OWASP ASVS", f.asvs],
                        ["CAPEC", f.capec],
                        ["Likelihood", f.likelihood],
                        ["Impact", f.impact],
                        ["Confidence", fmtConfidence(f.confidence)],
                        ["Fingerprint", f.fingerprint],
                      ].map(([k, v]) => (
                        <div key={k as string}>
                          <dt className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">{k}</dt>
                          <dd className={cn("mt-0.5 text-sm text-fg", k === "Fingerprint" && "break-all font-mono text-xs")}>{v || "—"}</dd>
                        </div>
                      ))}
                    </dl>
                  </CardBody>
                </Card>
                <Card>
                  <CardHeader title="Compliance mapping" description="Controls this weakness is relevant to" />
                  <CardBody>
                    {(f.compliance ?? []).length ? (
                      <div className="flex flex-wrap gap-2">
                        {f.compliance!.map((c) => (
                          <span key={`${c.framework}-${c.clause}`} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 py-1 text-xs" title={c.title}>
                            <span className="font-semibold text-fg">{c.framework}</span>
                            <span className="text-fg-muted">{c.clause}</span>
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-fg-muted">No compliance mapping for this rule.</p>
                    )}
                  </CardBody>
                </Card>
              </>
            )}
            {tab === "remediation" && (
              <Card>
                <CardHeader icon={<Wrench className="h-4 w-4" />} title="Remediation" />
                <CardBody className="space-y-5">
                  <p className="whitespace-pre-wrap text-base leading-relaxed text-fg">{f.remediation ?? f.llm?.remediation ?? "No remediation guidance recorded."}</p>
                  {refs.length > 0 && (
                    <div>
                      <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-fg">
                        <BookOpen className="h-4 w-4" aria-hidden /> References
                      </h4>
                      <ul className="space-y-1.5">
                        {refs.map((r) => (
                          <li key={r.title} className="text-sm">
                            {r.url ? (
                              <a href={r.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-primary hover:underline">
                                {r.title} <ExternalLink className="h-3 w-3" aria-hidden />
                              </a>
                            ) : (
                              <span className="text-fg">{r.title}</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardBody>
              </Card>
            )}
            {tab === "history" && (
              <Card>
                <CardHeader title="History" description="Status changes, assignments and comments" />
                <CardBody>
                  {history.isLoading ? (
                    <Skeleton className="h-24" />
                  ) : (history.data ?? []).length === 0 ? (
                    <p className="text-sm text-fg-muted">No history yet.</p>
                  ) : (
                    <ol className="relative space-y-4 border-l border-border pl-5">
                      {[...history.data!].reverse().map((h, i) => (
                        <li key={i} className="relative">
                          <span className="absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full bg-primary ring-4 ring-surface" aria-hidden />
                          <p className="text-sm text-fg">
                            <span className="font-semibold">{h.actor}</span>{" "}
                            {h.action === "status_changed" && h.to_status ? (
                              <>
                                changed status {h.from_status ? `from ${STATUS_LABEL[h.from_status]} ` : ""}to <span className="font-semibold">{STATUS_LABEL[h.to_status]}</span>
                              </>
                            ) : (
                              h.action.replace(/_/g, " ")
                            )}
                          </p>
                          {h.comment && <p className="mt-0.5 text-sm text-fg-muted">{h.comment}</p>}
                          <p className="mt-0.5 text-xs text-fg-subtle" title={fmtDateTime(h.at)}>
                            {fmtRelative(h.at)}
                          </p>
                        </li>
                      ))}
                    </ol>
                  )}
                </CardBody>
              </Card>
            )}
          </div>
        </div>
        <div className="space-y-6">
          <TriageCard f={f} />
          <Card>
            <CardHeader title="Details" />
            <CardBody>
              <dl className="space-y-2.5 text-sm">
                {[
                  ["Scan", <Link key="s" className="font-mono text-primary hover:underline" to={`/scans/${f.scan_id}`}>{f.scan_id}</Link>],
                  ["Engine", f.engine],
                  ["Rule", <span key="r" className="font-mono text-xs">{f.rule_id}</span>],
                  ["CVSS v4", f.cvss4_score != null ? `${f.cvss4_score.toFixed(1)} (${cvssRating(f.cvss4_score)})` : "—"],
                  ["Assignee", f.assignee || "Unassigned"],
                  ["First seen", fmtDateTime(f.created_at)],
                ].map(([k, v]) => (
                  <div key={k as string} className="flex justify-between gap-3">
                    <dt className="text-fg-muted">{k}</dt>
                    <dd className="text-right text-fg">{v || "—"}</dd>
                  </div>
                ))}
              </dl>
            </CardBody>
          </Card>
        </div>
      </div>
    </>
  );
}
