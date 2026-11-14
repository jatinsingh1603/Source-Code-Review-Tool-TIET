import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useFindings, useOptional, usePolicy, usePrivacy, useProviders } from "@/api/queries";
import { downloadApiFile, endpoints, fetchReport, saveBlob } from "@/api/endpoints";
import type { Budgets, PrivacyLevel, PrivacySummary } from "@/api/types";
import { locationOf, sortScans } from "@/lib/domain";
import { fmtBytesText, fmtInt, fmtLong, LEVEL_NAME, scanLabel } from "@/lib/display";
import { matches, policyDoc, strictest } from "@/lib/policy";
import { asEvaluation, Frontier } from "@/components/Frontier";
import { sampleEvaluation } from "@/lib/sampleEval";
import {
  Button,
  ButtonLink,
  Content,
  Empty,
  ErrorBanner,
  Guard,
  Hash,
  LevelBadge,
  MoreLink,
  PageHeader,
  Skeleton,
  StatusDot,
  useToast,
} from "@/components/ui";

const PART_LABEL: Record<string, string> = {
  level_strength: "Level strength",
  disclosure_volume: "Disclosure volume",
  residual_terms: "Zero-leak check",
  linkability: "Unlinkability",
  budget_usage: "Exposure budget headroom",
  ledger_integrity: "Ledger integrity",
  naming_channel: "Naming channel",
};

/** "ledger_integrity" -> "Ledger integrity", for a component the table above does not name. */
function humanise(name: string): string {
  const words = name.replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

const AXIS_LABEL: Record<string, string> = {
  provider_tier: "Provider minimum",
  path: "Path rule",
  language: "Language rule",
  rule: "Detection rule",
  classification: "Classification",
  never_send: "Never-send list",
};

export const INVARIANTS_LONG: [string, string][] = [
  ["I1", "One transport module opens LLM connections"],
  ["I2", "LLM layer accepts sanitised payloads only"],
  ["I3", "Vault never logged or exported"],
  ["I4", "Privacy-step failure aborts the request"],
  ["I5", "Pseudonyms deterministic per scan salt"],
  ["I6", "No listed term of 4+ chars in payloads"],
];

/** Privacy Centre (SCREENS.md §11). */
export default function PrivacyPage() {
  const { scanId, scans, project } = useSelectedScan();
  const sorted = useMemo(() => sortScans(scans), [scans]);
  const scan = sorted.find((s) => s.id === scanId);
  const prev = useMemo(() => {
    const i = sorted.findIndex((s) => s.id === scanId);
    return i < 0 ? undefined : sorted.slice(i + 1).find((s) => s.status === "completed");
  }, [sorted, scanId]);
  const privacyQ = usePrivacy(scanId);
  const prevPrivacy = usePrivacy(prev?.id).data;
  const policy = usePolicy().data;
  const invariants = useOptional("invariants", endpoints.invariants).data;
  const budgets = useOptional(`budgets-${scanId}`, () => endpoints.budgets(scanId!), !!scanId).data;
  const findings = useFindings(scanId).data;
  const providers = useProviders().data;
  const evalQ = useOptional("evaluation", endpoints.evaluation);
  const evaluation = useMemo(() => asEvaluation(evalQ.data) ?? sampleEvaluation(), [evalQ.data]);
  const toast = useToast();
  const p = privacyQ.data;

  const files = useMemo(() => [...new Set((findings ?? []).map((f) => locationOf(f)?.path).filter((x): x is string => !!x))].sort(), [findings]);
  const [file, setFile] = useState<string>("");
  const [pdfPending, setPdfPending] = useState(false);
  const doc = policyDoc(policy);
  const chosen = file || files[0] || "";
  const provider = providers?.find((x) => x.id === scan?.provider);
  // The server's policy engine explains every axis (path, language, rule, classification,
  // provider tier); the scan's own level replaces the server default as the base. Without the
  // endpoint, path rules are matched here.
  const explainQ = useQuery({
    queryKey: ["policy-explain", chosen, project?.id, scan?.provider],
    queryFn: () => endpoints.policyExplain(chosen, project?.id, scan?.provider),
    enabled: !!chosen && !!scan,
    retry: false,
    staleTime: 60_000,
  });
  const explained = explainQ.data;
  const contributions: { label: string; level: PrivacyLevel | "never-send" }[] = explained
    ? explained.contributions
        .filter((c) => c.axis !== "base")
        .map((c) => ({
          label: `${AXIS_LABEL[c.axis] ?? c.axis}${c.key ? ` · ${c.key}${c.axis === "provider_tier" ? " tier" : ""}` : ""}`,
          level: (c.level === "never_send" || c.level === null ? "never-send" : c.level) as PrivacyLevel | "never-send",
        }))
    : [
        ...(provider?.min_level ? [{ label: `Provider minimum · ${provider.name}`, level: provider.min_level as PrivacyLevel }] : []),
        ...doc.path
          .filter((r) => matches(r.pattern, chosen))
          .map((r) => ({ label: `Rule · ${r.pattern}`, level: (r.never_send ? "never-send" : r.level ?? scan?.privacy_level ?? "L3") as PrivacyLevel | "never-send" })),
      ];
  const effective = scan ? strictest([scan.privacy_level, ...contributions.map((c) => c.level)]) : null;

  const delta = p?.privacy_score !== null && p?.privacy_score !== undefined && prevPrivacy?.privacy_score !== null && prevPrivacy?.privacy_score !== undefined ? p.privacy_score - prevPrivacy.privacy_score : null;

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: project?.name ?? "Project", to: "/" }, { label: "Privacy Centre" }]}
        title="Privacy Centre"
        sub="How much this project discloses, why, and how that is verified."
        actions={
          <>
            <ButtonLink to="/privacy/inspect">Inspect a payload</ButtonLink>
            <ButtonLink to="/privacy/policy">Edit policy</ButtonLink>
          </>
        }
      />

      {privacyQ.isError && <ErrorBanner what="The privacy summary could not be loaded." error={privacyQ.error} />}
      {!scanId && !scans.length ? (
        <div className="card">
          <Empty title="No scans yet" action="Run the KavachBank demo" to="/demo">
            Privacy measurements appear after the first scan.
          </Empty>
        </div>
      ) : (
        <>
          <section className="g g-3">
            <div className="card">
              <div className="card-h">
                <h2>Privacy score</h2>
                <span className="xs faint">{scanLabel(scanId)}</span>
              </div>
              {!p ? (
                <Skeleton rows={2} />
              ) : (
                <>
                  <div className="row" style={{ alignItems: "baseline", gap: 6 }}>
                    <span className="big-num">{p.privacy_score ?? "—"}</span>
                    <span className="faint">/ 100</span>
                    {delta !== null && delta !== 0 && (
                      <span className={`sm ${delta > 0 ? "down" : "up"}`} style={{ marginLeft: 8 }}>
                        {delta > 0 ? "+" : ""}
                        {delta} vs {scanLabel(prev?.id)}
                      </span>
                    )}
                  </div>
                  <div className="stack" style={{ gap: 9, marginTop: 16 }}>
                    {(p.score_components ?? []).map((c) => (
                      <div key={c.name} title={c.basis}>
                        <div className="row between sm">
                          <span className="muted">
                            {PART_LABEL[c.name] ?? humanise(c.name)}
                            {c.raw ? ` · ${c.raw}` : ""}
                          </span>
                          <span className="mono">{c.value === null ? <span className="faint">n/a</span> : Math.round(c.value)}</span>
                        </div>
                        <div className="bar priv" style={{ marginTop: 4 }}>
                          <i style={{ width: `${c.value ?? 0}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>

            <div className="card">
              <div className="card-h">
                <h2>Exposure budget</h2>
                <Link className="btn sm" to="/privacy/policy">
                  Adjust
                </Link>
              </div>
              {!p ? (
                <Skeleton rows={2} />
              ) : (
                <ExposureBudget p={p} budgets={budgets} />
              )}
            </div>

            <div className="card">
              <div className="card-h">
                <h2>Invariant suite</h2>
                <span className="xs faint">
                  {invariants?.recorded
                    ? `${invariants.run_at ? `Run ${fmtLong(invariants.run_at)} · ` : ""}${invariants.invariants.reduce((a, r) => a + (r.tests?.passed ?? 0) + (r.tests?.failed ?? 0), 0)} tests`
                    : "not recorded on this server"}
                </span>
              </div>
              {INVARIANTS_LONG.map(([id, t]) => {
                const r = invariants?.invariants.find((x) => x.id === id);
                let res: React.ReactNode = <span className="xs faint">not recorded</span>;
                if (r && invariants?.recorded) res = r.passed ? "pass" : <span className="note-w">Fail</span>;
                else if (id === "I6" && p) res = p.zero_leak.passed ? "pass" : p.payloads === 0 ? <span className="xs faint">no payloads</span> : <span className="note-w">{p.zero_leak.checked ? "Fail" : "Not run"}</span>;
                else if (id === "I4" && p) res = <span className="xs faint">{fmtInt(p.blocked)} blocked</span>;
                return (
                  <Guard key={id} id={id} result={res}>
                    {t}
                  </Guard>
                );
              })}
              {p && p.zero_leak.checked > 0 && p.zero_leak.occurrences > 0 && (
                <p className="xs" style={{ marginTop: 8, color: "var(--warn)" }}>
                  The suite is the recorded test run. This scan&apos;s own zero-leak check found {fmtInt(p.zero_leak.occurrences)} listed term
                  {p.zero_leak.occurrences === 1 ? "" : "s"} in its payloads
                  {scan?.privacy_level === "L1" ? ": L1 sends real names and business terms by design. Use L2 or stricter for anything sensitive." : "."}
                </p>
              )}
              {invariants && !invariants.recorded && invariants.how_to_record && (
                <p className="xs faint" style={{ marginTop: 8 }}>
                  I4 and I6 show this scan&apos;s evidence. To show the CI results, run <span className="mono">{invariants.how_to_record}</span> on the server.
                </p>
              )}
            </div>
          </section>

          <section className="g g-side">
            <div className="stack">
              <div className="row between">
                <h2 style={{ fontSize: 14, fontWeight: 600 }}>Policy decisions</h2>
                <MoreLink to="/privacy/policy">Open policy</MoreLink>
              </div>
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Path</th>
                      <th>Language</th>
                      <th>Rule</th>
                      <th>Decision</th>
                      <th className="num">Files</th>
                    </tr>
                  </thead>
                  <tbody>
                    {doc.path.map((r, i) => (
                      <tr key={i}>
                        <td className="mono sm">{r.pattern}</td>
                        <td className="sm">{r.language ?? "any"}</td>
                        <td className="mono xs">{r.id ?? `path.${i + 1}`}</td>
                        <td>{r.never_send ? <StatusDot tone="bad">never-send</StatusDot> : r.level ? <LevelBadge level={r.level} /> : "—"}</td>
                        <td className="num mono">{files.filter((f) => matches(r.pattern, f)).length}</td>
                      </tr>
                    ))}
                    {scan && (
                      <tr>
                        <td className="mono sm">**</td>
                        <td className="sm">any</td>
                        <td className="mono xs">default</td>
                        <td>
                          <LevelBadge level={scan.privacy_level} />
                        </td>
                        <td className="num mono">{files.filter((f) => !doc.path.some((r) => matches(r.pattern, f))).length}</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <p className="xs faint">Files counts the files with findings in this scan that each rule matches.</p>
            </div>
            <div className="card stack">
              <h2>Privacy explain</h2>
              {files.length === 0 ? (
                <Empty title="No files to explain">Files with findings in this scan appear here.</Empty>
              ) : (
                <>
                  <div className="fld">
                    <label htmlFor="pe-f">File</label>
                    <select id="pe-f" className="inp mono" value={chosen} onChange={(e) => setFile(e.target.value)}>
                      {files.map((f) => (
                        <option key={f}>{f}</option>
                      ))}
                    </select>
                  </div>
                  <div className="stack s6 sm">
                    <div className="row between">
                      <span className="muted">Scan default</span>
                      {scan && <LevelBadge level={scan.privacy_level} />}
                    </div>
                    {contributions.map((c, i) => (
                      <div key={i} className="row between">
                        <span className="muted">{c.label}</span>
                        {c.level === "never-send" ? <StatusDot tone="bad">never-send</StatusDot> : <LevelBadge level={c.level} />}
                      </div>
                    ))}
                    <div className="hr" style={{ margin: "4px 0" }} />
                    <div className="row between">
                      <b>Effective level</b>
                      {effective === "never-send" ? (
                        <StatusDot tone="bad">never-send</StatusDot>
                      ) : effective ? (
                        <LevelBadge level={effective} name />
                      ) : null}
                    </div>
                  </div>
                  <p className="xs faint">
                    The strictest applicable rule wins.{" "}
                    {effective === "never-send"
                      ? "Nothing from this file is sent."
                      : effective === "L4"
                        ? "At L4 only data-flow facts may leave, never code; where facts cannot be prepared the candidate is withheld (fails closed)."
                        : effective === "L0"
                          ? "Nothing from this file leaves the machine."
                          : effective
                            ? `This file is reviewed at ${effective} (${LEVEL_NAME[effective].toLowerCase()}).`
                            : ""}
                  </p>
                </>
              )}
            </div>
          </section>

          <section className="g g-2">
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Leakage evaluation</h2>
                  <p className="sub">Identifier recovery by a simulated attacker with the payloads</p>
                </div>
                <div className="row">
                  {evaluation.sample !== false && <span className="chip">Sample results</span>}
                  <MoreLink to="/evaluation">Method</MoreLink>
                </div>
              </div>
              {evaluation?.leakage?.length ? (
                <div className="stack" style={{ gap: 10 }}>
                  {evaluation.leakage.map((l) => (
                    <div key={l.level}>
                      <div className="row between sm">
                        <span>
                          {l.level} {LEVEL_NAME[l.level as PrivacyLevel] ?? ""}
                        </span>
                        <span className="mono">{(l.recovery * 100).toFixed(1)}%</span>
                      </div>
                      <div className="bar" style={{ marginTop: 4 }}>
                        <i style={{ width: `${l.recovery * 100}%`, ...(l.recovery >= 0.5 ? { background: "var(--high)" } : {}) }} />
                      </div>
                      {l.note && <div className="xs faint">{l.note}</div>}
                    </div>
                  ))}
                  {evaluation.note && <p className="xs faint" style={{ marginTop: 2 }}>{evaluation.note}</p>}
                </div>
              ) : (
                <Empty title="No leakage evaluation yet" action="Open Evaluation" to="/evaluation">
                  Run the attacker benchmark to measure identifier recovery per level.
                </Empty>
              )}
            </div>
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Privacy-utility frontier</h2>
                  <p className="sub">Detection F1 against identifier recovery</p>
                </div>
              </div>
              {evaluation?.frontier?.length ? (
                <>
                  <Frontier points={evaluation.frontier} />
                  {new Set(evaluation.frontier.map((f) => f.f1.toFixed(2))).size === 1 && evaluation.frontier.length > 1 && (
                    <p className="xs faint" style={{ marginTop: 8 }}>
                      Same F1 at every level: the leakage runs use the Mock provider, which does not change verdicts.
                    </p>
                  )}
                </>
              ) : (
                <Empty title="No frontier yet" action="Open Evaluation" to="/evaluation">
                  It is drawn from benchmark runs at each level.
                </Empty>
              )}
            </div>
          </section>

          <section className="g g-2">
            <div className="card stack">
              <div className="row between">
                <div>
                  <h2>Privacy attestation</h2>
                  <p className="sub">Summary for auditors and customers, with a SHA-256 digest (not signed)</p>
                </div>
                <div className="row">
                  <Button
                    size="sm"
                    disabled={!scanId}
                    loading={pdfPending}
                    title="The PDF audit report includes the privacy attestation."
                    onClick={async () => {
                      setPdfPending(true);
                      const slow = setTimeout(() => toast.info("Rendering the PDF report", "The first PDF of a scan takes up to a minute; later downloads are instant."), 3000);
                      try {
                        const { blob, filename } = await fetchReport(scanId!, "pdf");
                        saveBlob(blob, filename);
                      } catch (e) {
                        toast.error("Download failed", e instanceof Error ? e.message : undefined);
                      } finally {
                        clearTimeout(slow);
                        setPdfPending(false);
                      }
                    }}
                  >
                    Download PDF
                  </Button>
                  <Button
                    size="sm"
                    disabled={!p}
                    onClick={() =>
                      p &&
                      void downloadApiFile(`/scans/${scanId}/privacy/attestation.json`, {}, `codekavach-attestation-${scanId}.json`).catch(() =>
                        downloadAttestation(scanId!, p),
                      )
                    }
                  >
                    JSON
                  </Button>
                </div>
              </div>
              {!p ? (
                <Skeleton rows={2} />
              ) : (
                <dl className="dl">
                  <dt>Scan</dt>
                  <dd className="mono sm">
                    {scanLabel(scanId)} · {project?.name}
                  </dd>
                  <dt>Levels used</dt>
                  <dd className="row">
                    {Object.entries(p.levels_by_candidate ?? { [p.level]: p.payloads }).map(([l, n]) => (
                      <LevelBadge key={l} level={l} label={`${l} · ${fmtInt(n)}`} title={`${fmtInt(n)} candidate${n === 1 ? "" : "s"} reviewed at ${l}`} />
                    ))}
                    {p.withheld ? (
                      p.level === "L0" ? (
                        <LevelBadge level="L0" label={`L0 · ${fmtInt(p.withheld)}`} title="Reviewed on this machine only; nothing was prepared for a model" />
                      ) : (
                        <LevelBadge level="never-send" label={`withheld · ${fmtInt(p.withheld)}`} title="Candidates kept local by policy or because their level failed closed" />
                      )
                    ) : null}
                    {p.blocked ? <LevelBadge level="never-send" label={`blocked · ${p.blocked}`} /> : null}
                  </dd>
                  <dt>Payloads</dt>
                  <dd className="sm">
                    {fmtInt(p.payloads)} {p.send === false || p.provider_tier === "local" ? "recorded" : "sent"} · {fmtInt(p.tokens_sent)} tokens
                    {p.disclosure?.repository_fraction_pct !== undefined ? ` · ${p.disclosure.repository_fraction_pct}% of repository lines` : ""}
                  </dd>
                  <dt>Checks</dt>
                  <dd className="sm">
                    Ledger chain {p.chain_ok ? "verified" : "broken"}; zero-leak check ({fmtInt(p.zero_leak.checked)} terms){" "}
                    {p.zero_leak.passed
                      ? "passed"
                      : p.payloads === 0
                        ? "had nothing to search: no payloads were recorded"
                        : p.zero_leak.checked
                          ? `failed (${fmtInt(p.zero_leak.occurrences)} found)`
                          : "not run"}
                  </dd>
                  <dt>Ledger head</dt>
                  <dd>
                    <Hash value={p.ledger_head ?? p.ledger_head_hash} />
                  </dd>
                  <dt>Digest</dt>
                  <dd className="sm row">
                    <Hash value={p.attestation_digest} />
                    <span className="faint">{fmtLong(scan?.finished_at)}</span>
                  </dd>
                </dl>
              )}
            </div>
            <div className="note box">
              <b>What this attestation does not cover.</b>
              <ul>
                <li>It describes what left during this scan only, not earlier scans or other tools.</li>
                <li>The model still saw control flow, literal shapes and public API names in L3 slices.</li>
                <li>The zero-leak check is verbatim against the listed terms. Unlisted terms, paraphrases or encoded values are not checked.</li>
                <li>It does not attest to how the provider stores or uses received payloads. That is governed by your provider agreement.</li>
                <li>With the Mock provider, nothing was transmitted; the ledger records what would have been sent.</li>
              </ul>
            </div>
          </section>
        </>
      )}
    </Content>
  );
}

function ExposureBudget({ p, budgets }: { p: PrivacySummary; budgets?: Budgets | null }) {
  const pct = Number(p.disclosure?.repository_fraction_pct ?? NaN);
  const rows = (budgets?.budgets ?? []).filter((b) => b.limit !== null);
  const fmtVal = (v: number | null, unit: string) =>
    v === null ? "—" : unit === "percent" ? `${v}%` : unit === "bytes" ? fmtBytesText(v) : fmtInt(v);
  return (
    <div className="stack s16">
      {rows.length ? (
        rows.slice(0, 3).map((b) => (
          <div key={b.id} title={b.source}>
            <div className="row between sm">
              <span>{b.label}</span>
              <span className="mono">
                {fmtVal(b.used, b.unit)} / {fmtVal(b.limit, b.unit)}
              </span>
            </div>
            <div className="bar ink" style={{ marginTop: 6 }}>
              <i style={{ width: `${Math.min(100, b.usage_pct ?? 0)}%` }} />
            </div>
            <div className="xs faint" style={{ marginTop: 4 }}>
              {b.usage_pct === null ? b.note ?? "not measured" : `${b.usage_pct}% used${b.note ? `. ${b.note}` : ""}`}
            </div>
          </div>
        ))
      ) : !Number.isNaN(pct) ? (
        <div>
          <div className="row between sm">
            <span>This scan</span>
            <span className="mono">{pct}% of repository lines</span>
          </div>
          <div className="bar ink" style={{ marginTop: 6 }}>
            <i style={{ width: `${Math.min(100, pct)}%` }} />
          </div>
        </div>
      ) : null}
      <p className="xs faint">
        {p.bytes_sent !== undefined && p.bytes_sent !== null
          ? `${fmtBytesText(p.bytes_sent)} ${p.send === false || p.provider_tier === "local" ? "recorded (not transmitted)" : "sent"} in this scan. `
          : ""}
        Limits come from the privacy configuration on the server.
      </p>
    </div>
  );
}

function downloadAttestation(scanId: string, p: PrivacySummary) {
  const body = {
    scan_id: scanId,
    level: p.level,
    provider: p.provider,
    provider_tier: p.provider_tier,
    payloads: p.payloads,
    blocked: p.blocked,
    withheld: p.withheld,
    levels_by_candidate: p.levels_by_candidate,
    tokens_sent: p.tokens_sent,
    disclosure: p.disclosure,
    zero_leak: p.zero_leak,
    chain_ok: p.chain_ok,
    ledger_head: p.ledger_head ?? p.ledger_head_hash,
    attestation_digest: p.attestation_digest,
    privacy_score: p.privacy_score,
    score_components: p.score_components,
    attestation_text: p.attestation_text,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(body, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `codekavach-attestation-${scanId}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
