import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useCan } from "@/app/session";
import {
  useFindings,
  useOptional,
  usePrivacy,
  useProviders,
  useScans,
  useStats,
} from "@/api/queries";
import { endpoints } from "@/api/endpoints";
import type {
  Finding,
  InvariantReport,
  PrivacySummary,
  Project,
  ProviderInfo,
  Scan,
  TrendPoint,
} from "@/api/types";
import { isOpen, providerName, scanPayloads, scanTarget, sevCounts, sortScans } from "@/lib/domain";
import {
  ENGINE_COLUMNS,
  engineColumn,
  fmtBytes,
  fmtDayMonth,
  fmtElapsed,
  fmtHM,
  fmtInt,
  fmtLong,
  fmtShort,
  fmtTime,
  riskLevel,
  scanLabel,
} from "@/lib/display";
import { CWE_SHORT, OWASP_TOP10, parseOwasp } from "@/lib/taxonomy";
import {
  ButtonLink,
  Content,
  Empty,
  ErrorBanner,
  Guard,
  Icon,
  Kpi,
  LevelBadge,
  MoreLink,
  PageHeader,
  ScanStatusBadge,
  SectionHead,
  SevCount,
  Skeleton,
} from "@/components/ui";

export default function OverviewPage() {
  const { current, loading: projLoading } = useCurrentProject();
  const canRun = useCan("scans:run");
  const canPrivacy = useCan("privacy:read");
  const scansQ = useScans(current?.id);
  const scans = useMemo(() => sortScans(scansQ.data ?? []), [scansQ.data]);
  const completed = scans.filter((s) => s.status === "completed");
  const last = completed[0] ?? scans[0];
  const prev = completed[1];
  const findingsQ = useFindings(last?.id);
  const privacyQ = usePrivacy(last?.status === "completed" ? last.id : undefined);
  const prevPrivacy = usePrivacy(prev?.id).data;
  const stats = useStats(current?.id).data;
  const providers = useProviders().data;
  const invariants = useOptional("invariants", endpoints.invariants).data;

  const crumbs = [{ label: current?.name ?? "Project" }, { label: "Overview" }];
  const loading = projLoading || scansQ.isLoading;

  if (!loading && scans.length === 0) {
    return (
      <Content>
        <PageHeader crumbs={crumbs} title="Overview" />
        <div className="card">
          <Empty
            title="No scans yet"
            action="Run a scan"
            to={current ? `/projects/${current.id}/scan` : "/projects/new"}
          >
            Run a scan to see results here.
          </Empty>
          <div className="row" style={{ justifyContent: "center" }}>
            <Link className="more" to="/demo">
              Or run the KavachBank demo <Icon name="arrow-right" />
            </Link>
          </div>
        </div>
      </Content>
    );
  }

  const findings = findingsQ.data ?? [];
  const open = findings.filter(isOpen);
  const counts = sevCounts(open);
  const trend = (stats?.trend ?? [])
    .filter((t) => !t.project_id || t.project_id === current?.id)
    .slice(-12);

  return (
    <Content>
      <PageHeader
        crumbs={crumbs}
        title="Overview"
        actions={
          <>
            {last && (
              <span className="sub">
                Last scan <span className="mono">{scanLabel(last.id)}</span> ·{" "}
                {fmtLong(last.started_at ?? last.created_at)}
              </span>
            )}
            {current && canRun && (
              <ButtonLink variant="primary" to={`/projects/${current.id}/scan`}>
                New scan
              </ButtonLink>
            )}
          </>
        }
      />

      <section className="card" style={{ padding: 0 }}>
        {loading || findingsQ.isLoading ? (
          <div style={{ padding: 18 }}>
            <Skeleton />
          </div>
        ) : (
          <div className="kpi-strip">
            <Kpi
              to="/findings"
              label="Open findings"
              value={fmtInt(open.length)}
              detail={
                <>
                  <SevCount severity="critical" n={counts.critical} first />
                  <SevCount severity="high" n={counts.high} />
                  <SevCount severity="medium" n={counts.medium} />
                  <SevCount severity="low" n={counts.low + counts.info} />
                </>
              }
            />
            <PrivacyScoreKpi p={privacyQ.data} prev={prevPrivacy} locked={!canPrivacy} />
            <EgressKpi p={privacyQ.data} scan={last} locked={!canPrivacy} />
            <Kpi
              to={canPrivacy ? "/privacy/ledger" : undefined}
              label="Zero-leak check"
              value={
                privacyQ.data?.zero_leak.checked ? fmtInt(privacyQ.data.zero_leak.occurrences) : "—"
              }
              unit={privacyQ.data?.zero_leak.checked ? "terms found" : undefined}
              detail={
                privacyQ.data?.zero_leak.checked
                  ? `${fmtInt(privacyQ.data.zero_leak.checked)} listed terms, verbatim`
                  : privacyQ.data
                    ? "not run: no listed terms for this project"
                    : canPrivacy
                      ? "not checked"
                      : LOCKED
              }
            />
            <Kpi
              label="Last scan"
              value={fmtHM(last?.started_at ?? last?.created_at)}
              detail={
                last
                  ? `${fmtDayMonth(last.started_at ?? last.created_at)} · ${fmtElapsed(last.started_at, last.finished_at)}${
                      current?.source?.ref ? ` · ${current.source.ref}` : ""
                    }`
                  : undefined
              }
            />
            <MttrKpi
              findings={findings}
              days={stats?.mttr_days}
              delta={stats?.mttr_delta_days}
              samples={stats?.mttr_samples}
            />
          </div>
        )}
      </section>

      <section className="g g-side">
        <TrendCard trend={trend} loading={!stats} />
        <RiskMatrix findings={open} loading={findingsQ.isLoading} />
      </section>

      <section className="g g-side">
        <OwaspCard findings={open} loading={findingsQ.isLoading} />
        <div className="stack s16">
          <TopCwes findings={open} loading={findingsQ.isLoading} />
          <GuardCard report={invariants} privacy={privacyQ.data} />
        </div>
      </section>

      <section className="stack">
        <SectionHead title="Recent scans" right={<MoreLink to="/scans">All scans</MoreLink>} />
        {scansQ.isError ? (
          <ErrorBanner
            what="Scans could not be loaded."
            error={scansQ.error}
            onRetry={() => void scansQ.refetch()}
          />
        ) : (
          <ScansTable scans={scans.slice(0, 5)} providers={providers} loading={loading} />
        )}
      </section>
    </Content>
  );
}

/** Shown where the privacy figures exist but this role may not read them. */
const LOCKED = "shown to developers and auditors";

function PrivacyScoreKpi({ p, prev, locked }: { p?: PrivacySummary; prev?: PrivacySummary; locked?: boolean }) {
  const score = p?.privacy_score;
  const d =
    score !== null &&
    score !== undefined &&
    prev?.privacy_score !== null &&
    prev?.privacy_score !== undefined
      ? score - prev.privacy_score
      : null;
  return (
    <Kpi
      to={locked ? undefined : "/privacy"}
      label="Privacy score"
      value={score ?? "—"}
      unit="/ 100"
      detailClass={d === null || d === 0 ? undefined : d > 0 ? "down" : "up"}
      detail={
        d === null ? (
          p ? (
            `${p.level} · ${p.payloads} payloads`
          ) : locked ? (
            LOCKED
          ) : (
            "not computed"
          )
        ) : d === 0 ? (
          "no change vs last scan"
        ) : (
          <>
            <Icon name={d > 0 ? "arrow-up" : "arrow-down"} size={12} />
            {Math.abs(d)} pts vs last scan
          </>
        )
      }
    />
  );
}

function EgressKpi({ p, scan, locked }: { p?: PrivacySummary; scan?: Scan; locked?: boolean }) {
  const payloads = p?.payloads ?? (scan ? scanPayloads(scan) : null);
  // The core's measure: distinct repository lines disclosed over inventory lines. Payload bytes
  // over repository bytes would count the prompt text and repeated context, and can pass 100%.
  const raw = p?.disclosure?.repository_fraction_pct;
  const frac =
    raw !== undefined && raw !== "" && Number.isFinite(Number(raw))
      ? Number(raw).toFixed(1)
      : undefined;
  const detail = `${fmtInt(payloads)} payloads${frac !== undefined ? ` · ${frac}% of repo lines` : ""}`;
  if (p?.bytes_sent !== undefined && p?.bytes_sent !== null) {
    const b = fmtBytes(p.bytes_sent);
    return (
      <Kpi
        to="/privacy/ledger"
        label={p.send === false || p.provider_tier === "local" ? "Payload bytes recorded, this scan" : "Payload bytes egressed, this scan"}
        value={b.v}
        unit={b.unit}
        detail={detail}
      />
    );
  }
  const tokens = p?.tokens_sent ?? scan?.privacy_summary?.tokens_sent;
  return (
    <Kpi
      to={locked ? undefined : "/privacy/ledger"}
      label="Tokens out, this scan"
      value={
        tokens === undefined ? "—" : tokens >= 10_000 ? (tokens / 1000).toFixed(1) : fmtInt(tokens)
      }
      unit={tokens === undefined ? "" : tokens >= 10_000 ? "k tokens" : "tokens"}
      detail={detail}
    />
  );
}

function MttrKpi({
  findings,
  days,
  delta,
  samples,
}: {
  findings: Finding[];
  days?: number | null;
  delta?: number | null;
  samples?: number | null;
}) {
  let value: number | null = days ?? null;
  if (value === null) {
    const fixed = findings.filter((f) => f.status === "fixed" && f.created_at && f.updated_at);
    if (fixed.length) {
      const total = fixed.reduce(
        (a, f) => a + (Date.parse(f.updated_at!) - Date.parse(f.created_at!)),
        0,
      );
      value = total / fixed.length / 86_400_000;
    }
  }
  return (
    <Kpi
      label="Mean time to remediate"
      value={value === null ? "—" : value.toFixed(1)}
      unit={value === null ? "" : "days"}
      detailClass={delta ? (delta < 0 ? "down" : "up") : undefined}
      detail={
        delta ? (
          <>
            <Icon name={delta < 0 ? "arrow-down" : "arrow-up"} size={12} />
            {Math.abs(delta).toFixed(1)} days in 30 days
          </>
        ) : value === null ? (
          "no findings fixed yet"
        ) : samples ? (
          `${samples} fixed finding${samples === 1 ? "" : "s"}`
        ) : (
          "fixed findings, this scan"
        )
      }
    />
  );
}

function TrendCard({ trend, loading }: { trend: TrendPoint[]; loading: boolean }) {
  // Keep the design's twelve column slots so a short history keeps its bar width.
  const pad = Math.max(0, 12 - trend.length);
  const max = Math.max(
    1,
    ...trend.map((t) => t.critical + t.high + t.medium + t.low + (t.info ?? 0)),
  );
  const scale = 160 / max;
  const first = trend[0];
  const lastT = trend[trend.length - 1];
  const tot = (t?: TrendPoint) => (t ? t.critical + t.high + t.medium + t.low + (t.info ?? 0) : 0);
  const label =
    trend.length > 1
      ? `Findings went from ${tot(first)} to ${tot(lastT)} over ${trend.length} scans`
      : "Findings by severity";
  // Label each bar by the time the scan started, as Recent scans does; the date marks a new day,
  // and two scans in the same minute get seconds so their labels differ.
  const when = (t: TrendPoint) => t.started ?? t.date;
  const minute = trend.map((t) => fmtHM(when(t)));
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <h2>Findings trend</h2>
          <p className="sub">
            Findings found by each scan, by severity;{" "}
            {trend.length === 1 ? "last scan" : `last ${trend.length || 12} scans`}
          </p>
        </div>
        <div className="legend">
          <span>
            <i style={{ background: "var(--crit)" }} />
            Critical
          </span>
          <span>
            <i style={{ background: "var(--high)" }} />
            High
          </span>
          <span>
            <i style={{ background: "var(--med)" }} />
            Medium
          </span>
          <span>
            <i style={{ background: "var(--border-strong)" }} />
            Low and info
          </span>
        </div>
      </div>
      {loading ? (
        <Skeleton rows={2} />
      ) : trend.length === 0 ? (
        <Empty title="No trend yet">Completed scans of this project appear here.</Empty>
      ) : (
        <>
          <div className="vbars" role="img" aria-label={label}>
            {Array.from({ length: pad }, (_, i) => (
              <div className="col" key={`pad-${i}`} />
            ))}
            {trend.map((t) => (
              <div className="col" key={t.scan_id} title={`${fmtShort(when(t))}: ${tot(t)} ${tot(t) === 1 ? "finding" : "findings"}`}>
                <i style={{ height: t.critical * scale, background: "var(--crit)" }} />
                <i style={{ height: t.high * scale, background: "var(--high)" }} />
                <i style={{ height: t.medium * scale, background: "var(--med)" }} />
                <i
                  style={{
                    height: (t.low + (t.info ?? 0)) * scale,
                    background: "var(--border-strong)",
                  }}
                />
              </div>
            ))}
          </div>
          <div className="xax">
            {Array.from({ length: pad }, (_, i) => (
              <span key={`pad-${i}`} />
            ))}
            {trend.map((t, i) => {
              const prevDay = i > 0 ? fmtDayMonth(when(trend[i - 1]!)) : "";
              const day = fmtDayMonth(when(t));
              const clash = minute[i - 1] === minute[i] || minute[i + 1] === minute[i];
              const time = clash ? fmtTime(when(t)) : minute[i];
              return <span key={t.scan_id}>{day === prevDay ? time : day}</span>;
            })}
          </div>
        </>
      )}
    </div>
  );
}

const RM: string[][] = [
  ["r2", "r3", "r4", "r5", "r5"],
  ["r1", "r2", "r3", "r4", "r5"],
  ["r1", "r2", "r3", "r3", "r4"],
  ["r1", "r1", "r2", "r2", "r3"],
  ["r1", "r1", "r1", "r1", "r2"],
];

function RiskMatrix({ findings, loading }: { findings: Finding[]; loading: boolean }) {
  const grid = Array.from({ length: 5 }, () => [0, 0, 0, 0, 0]);
  for (const f of findings) {
    const l = riskLevel(f.likelihood_detail?.level ?? f.likelihood);
    const i = riskLevel(f.impact_detail?.level ?? f.impact);
    if (l && i) grid[5 - l]![i - 1]! += 1;
  }
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <h2>Risk matrix</h2>
          <p className="sub">Likelihood × impact, open findings</p>
        </div>
      </div>
      {loading ? (
        <Skeleton rows={2} />
      ) : (
        <>
          <div className="rm" role="group" aria-label="Open findings by likelihood and impact">
            {grid.map((row, r) => (
              <RmRow key={r} lik={5 - r} row={row} cls={RM[r]!} />
            ))}
            <span aria-hidden="true" />
            {[1, 2, 3, 4, 5].map((n) => (
              <span key={n} className="ax" aria-hidden="true">
                {n}
              </span>
            ))}
          </div>
          <div className="row between xs faint" style={{ marginTop: 8 }}>
            <span>Likelihood ↑</span>
            <span>Impact →</span>
          </div>
        </>
      )}
    </div>
  );
}

function RmRow({ lik, row, cls }: { lik: number; row: number[]; cls: string[] }) {
  return (
    <>
      <span className="ax" aria-hidden="true">
        {lik}
      </span>
      {row.map((n, i) =>
        n ? (
          <Link
            key={i}
            className={`c ${cls[i]}`}
            to={`/findings?likelihood=${lik}&impact=${i + 1}`}
            style={{ textDecoration: "none" }}
            title={`Likelihood ${lik}, impact ${i + 1}: ${n}`}
            aria-label={`Likelihood ${lik}, impact ${i + 1}: ${n} open ${n === 1 ? "finding" : "findings"}`}
          >
            {n}
          </Link>
        ) : (
          <span key={i} className={`c ${cls[i]}`} aria-hidden="true" />
        ),
      )}
    </>
  );
}

function bucket(n: number): string {
  if (n <= 0) return "h0";
  if (n === 1) return "h1";
  if (n === 2) return "h2";
  if (n <= 4) return "h3";
  return "h4";
}

function OwaspCard({ findings, loading }: { findings: Finding[]; loading: boolean }) {
  const years = findings.map((f) => parseOwasp(f.owasp)?.year).filter(Boolean);
  const year: "2021" | "2025" = years.includes("2025") || years.length === 0 ? "2025" : "2021";
  const cols = [...ENGINE_COLUMNS, "LLM"] as const;
  const counts = new Map<string, number>();
  for (const f of findings) {
    const o = parseOwasp(f.owasp);
    if (!o) continue;
    const k1 = `${o.code}|${engineColumn(f.engine)}`;
    counts.set(k1, (counts.get(k1) ?? 0) + 1);
    if (f.llm_reviewed || f.llm)
      counts.set(`${o.code}|LLM`, (counts.get(`${o.code}|LLM`) ?? 0) + 1);
  }
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <h2>OWASP Top 10:{year} coverage</h2>
          <p className="sub">Findings per category and detection source</p>
        </div>
        <MoreLink to="/findings">Open findings</MoreLink>
      </div>
      {loading ? (
        <Skeleton rows={3} />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div
            className="hm"
            style={{ gridTemplateColumns: "220px repeat(6, minmax(56px, 1fr))", minWidth: 620 }}
          >
            <span />
            {cols.map((c) => (
              <span key={c} className="xs faint" style={{ textAlign: "center" }}>
                {c}
              </span>
            ))}
            {OWASP_TOP10[year].map(([code, name]) => (
              <HmRow key={code} code={code} name={name} cols={cols} counts={counts} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function HmRow({
  code,
  name,
  cols,
  counts,
}: {
  code: string;
  name: string;
  cols: readonly string[];
  counts: Map<string, number>;
}) {
  return (
    <>
      <span className="sm" style={{ alignSelf: "center" }}>
        {code} {name}
      </span>
      {cols.map((c) => {
        const n = counts.get(`${code}|${c}`) ?? 0;
        return n ? (
          <Link
            key={c}
            className={`c ${bucket(n)}`}
            style={{ textDecoration: "none" }}
            to={
              c === "LLM"
                ? `/findings?owasp=${code}`
                : `/findings?owasp=${code}&engine=${c.toLowerCase()}`
            }
            title={`${code} · ${c}: ${n}`}
          >
            {n}
          </Link>
        ) : (
          <span key={c} className="c h0">
            0
          </span>
        );
      })}
    </>
  );
}

function TopCwes({ findings, loading }: { findings: Finding[]; loading: boolean }) {
  const m = new Map<string, { n: number; name?: string }>();
  for (const f of findings) {
    if (!f.cwe) continue;
    const e = m.get(f.cwe) ?? { n: 0, name: f.cwe_name ?? undefined };
    e.n += 1;
    m.set(f.cwe, e);
  }
  const top = [...m.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 6);
  const max = top[0]?.[1].n ?? 1;
  return (
    <div className="card">
      <div className="card-h">
        <h2>Top CWEs</h2>
      </div>
      {loading ? (
        <Skeleton />
      ) : top.length === 0 ? (
        <Empty title="No open findings">Nothing to rank in this scan.</Empty>
      ) : (
        <div className="stack" style={{ gap: 10 }}>
          {top.map(([cwe, e]) => (
            <div key={cwe}>
              <div className="row between sm">
                <span>
                  <span className="mono">{cwe}</span>{" "}
                  <span className="muted">{CWE_SHORT[cwe] ?? e.name ?? ""}</span>
                </span>
                <span className="mono">{e.n}</span>
              </div>
              <div className="bar" style={{ marginTop: 4 }}>
                <i style={{ width: `${Math.round((e.n / max) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const INVARIANTS: [string, string][] = [
  ["I1", "Single transport module"],
  ["I2", "Sanitised payloads only"],
  ["I3", "Vault never logged or exported"],
  ["I4", "Fail closed on privacy error"],
  ["I5", "Deterministic pseudonyms per salt"],
  ["I6", "No listed term in ledger payloads"],
];

function GuardCard({
  report,
  privacy,
}: {
  report?: InvariantReport | null;
  privacy?: PrivacySummary;
}) {
  const recorded = report?.recorded;
  return (
    <div className="card">
      <div className="card-h">
        <h2>Privacy guard status</h2>
        <MoreLink to="/privacy">Details</MoreLink>
      </div>
      {INVARIANTS.map(([id, title]) => {
        const r = report?.invariants.find((x) => x.id === id);
        let result: React.ReactNode = <span className="xs faint">not recorded</span>;
        if (r && recorded) result = r.passed ? "pass" : <span className="note-w">Fail</span>;
        else if (id === "I6" && privacy)
          result = privacy.zero_leak.passed ? (
            "pass"
          ) : (
            <span className="note-w">{privacy.zero_leak.checked ? "Fail" : "Not run"}</span>
          );
        else if (id === "I4" && privacy)
          result = <span className="xs faint">{fmtInt(privacy.blocked)} blocked</span>;
        return (
          <Guard key={id} id={id} result={result}>
            {title}
          </Guard>
        );
      })}
      {report && !recorded && (
        <p className="xs faint" style={{ marginTop: 8 }}>
          I6 and I4 show this scan&apos;s evidence. Record the invariant suite on the server to show
          all six.
        </p>
      )}
    </div>
  );
}

export function ScansTable({
  scans,
  providers,
  loading,
  projects,
  showProject,
}: {
  scans: Scan[];
  providers?: ProviderInfo[];
  loading?: boolean;
  projects?: Project[];
  /** Add a Project column (the cross-project Scans list). */
  showProject?: boolean;
}) {
  const { projects: ctxProjects } = useCurrentProject();
  const list = projects ?? ctxProjects;
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>Scan</th>
            {showProject && <th>Project</th>}
            <th>Target</th>
            <th>Level</th>
            <th>Provider</th>
            <th className="num">Findings</th>
            <th className="num">Payloads</th>
            <th>Status</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={showProject ? 9 : 8}>
                <Skeleton />
              </td>
            </tr>
          ) : (
            scans.map((s) => {
              const total =
                s.findings_total ?? Object.values(s.counts ?? {}).reduce((a, b) => a + b, 0);
              const proj = list.find((p) => p.id === s.project_id);
              return (
                <tr key={s.id}>
                  <td className="mono">
                    <Link className="t-title" to={`/scans/${s.id}`} title={s.id}>
                      {scanLabel(s.id)}
                    </Link>
                  </td>
                  {showProject && <td className="wrap">{proj?.name ?? s.project_name ?? "—"}</td>}
                  <td className="mono sm">{scanTarget(s, proj)}</td>
                  <td>
                    <LevelBadge level={s.privacy_level} />
                  </td>
                  <td>{providerName(s.provider, providers)}</td>
                  <td className="num mono">{s.status === "completed" ? fmtInt(total) : "—"}</td>
                  <td className="num mono">{fmtInt(scanPayloads(s))}</td>
                  <td>
                    <ScanStatusBadge status={s.status} error={s.error} />
                  </td>
                  <td className="sm muted">{fmtShort(s.started_at ?? s.created_at)}</td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {!loading && scans.length === 0 && (
        <Empty title="No scans yet">Run a scan to see results here.</Empty>
      )}
    </div>
  );
}
