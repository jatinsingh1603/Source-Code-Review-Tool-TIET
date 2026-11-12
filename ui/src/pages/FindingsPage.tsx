import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { qk, useFindings, useUsers } from "@/api/queries";
import { endpoints, fetchReport, saveBlob } from "@/api/endpoints";
import type { Finding, FindingPatch, Severity } from "@/api/types";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { bySeverity, isOpen, locationOf, sortScans, verdictOf } from "@/lib/domain";
import { confidenceFraction, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/format";
import { engineLabel, findingLabel, LEVEL_NAME, riskLevel, scanLabel } from "@/lib/display";
import { parseOwasp } from "@/lib/taxonomy";
import { FilterMenu } from "@/components/FilterMenu";
import { GithubSyncDialog } from "@/components/GithubSyncDialog";
import {
  Avatar,
  Button,
  Content,
  CvssBox,
  Dialog,
  Empty,
  ErrorBanner,
  Field,
  Icon,
  Input,
  PageHeader,
  SeverityBadge,
  SkeletonRows,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  Verdict,
} from "@/components/ui";

const PAGE = 12;
type View = "open" | "crit" | "new" | "review" | "mine" | "suppressed" | "all";
const LIST_KEYS = ["severity", "cwe", "owasp", "engine", "language", "status", "verdict", "level"] as const;
type ListKey = (typeof LIST_KEYS)[number];

const EXT_LANG: Record<string, string> = {
  py: "Python",
  js: "JavaScript",
  mjs: "JavaScript",
  cjs: "JavaScript",
  jsx: "JavaScript",
  ts: "TypeScript",
  tsx: "TypeScript",
  java: "Java",
  go: "Go",
  rb: "Ruby",
  php: "PHP",
  cs: "C#",
  kt: "Kotlin",
  tf: "IaC",
  yml: "IaC",
  yaml: "IaC",
  json: "Config",
  toml: "Config",
  txt: "Dependencies",
  lock: "Dependencies",
};

export function languageOf(f: Finding): string {
  if (f.language) return f.language.charAt(0).toUpperCase() + f.language.slice(1);
  const p = locationOf(f)?.path ?? "";
  if (/dockerfile/i.test(p)) return "IaC";
  const ext = p.split(".").pop()?.toLowerCase() ?? "";
  return EXT_LANG[ext] ?? "Other";
}

function verdictKey(f: Finding): string {
  const v = verdictOf(f);
  if (v) return v.kind;
  return f.llm_reviewed ? "reviewed" : "none";
}

const VERDICT_NAMES: Record<string, string> = {
  conf: "Confirmed",
  like: "Likely",
  rev: "Needs review",
  fp: "False positive",
  reviewed: "Reviewed by LLM",
  none: "Not sent to a model",
};

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const { scanId, scans } = useSelectedScan();
  const sorted = useMemo(() => sortScans(scans), [scans]);
  const scan = sorted.find((s) => s.id === scanId);
  const baseline = useMemo(() => {
    const i = sorted.findIndex((s) => s.id === scanId);
    return i < 0 ? undefined : sorted.slice(i + 1).find((s) => s.status === "completed");
  }, [sorted, scanId]);
  const findingsQ = useFindings(scanId);
  const baseQ = useFindings(baseline?.id);
  const { user, can } = useSession();
  const { current } = useCurrentProject();
  const users = useUsers().data;
  const toast = useToast();
  const qc = useQueryClient();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<null | "assign" | "suppress" | "sync">(null);
  const [busy, setBusy] = useState(false);

  const view = (params.get("view") as View) || "open";
  const page = Math.max(1, Number(params.get("page") ?? 1) || 1);
  const list = (k: ListKey) => (params.get(k) ?? "").split(",").filter(Boolean);
  const setParam = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v);
    else n.delete(k);
    if (k !== "page") n.delete("page");
    setParams(n, { replace: true });
  };

  useEffect(() => {
    const t = setTimeout(() => {
      if ((params.get("q") ?? "") !== q) setParam("q", q || null);
    }, 200);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);
  useEffect(() => setSelected(new Set()), [scanId]);

  const all = useMemo(() => [...(findingsQ.data ?? [])].sort(bySeverity), [findingsQ.data]);
  const baseFp = useMemo(() => new Set((baseQ.data ?? []).map((f) => f.fingerprint).filter(Boolean)), [baseQ.data]);
  const stateOf = (f: Finding): "new" | "unchanged" | "fixed" | null => {
    if (f.baseline_state === "new" || f.baseline_state === "unchanged" || f.baseline_state === "fixed") return f.baseline_state;
    if (f.status === "fixed") return "fixed";
    if (!baseline || !baseQ.data) return null;
    return f.fingerprint && baseFp.has(f.fingerprint) ? "unchanged" : "new";
  };
  const me = user?.username;
  const inView = (f: Finding, v: View) => {
    switch (v) {
      case "open":
        return isOpen(f);
      case "crit":
        return isOpen(f) && (f.severity === "critical" || f.severity === "high");
      case "new":
        return stateOf(f) === "new";
      case "review": {
        const c = confidenceFraction(f.llm?.confidence ?? f.confidence);
        return isOpen(f) && (verdictOf(f)?.kind === "rev" || (c !== null && c < 0.65));
      }
      case "mine":
        return !!me && (f.assignee === me || f.assignee === user?.id);
      case "suppressed":
        return f.status === "accepted_risk" || f.status === "false_positive";
      default:
        return true;
    }
  };

  const valueOf: Record<ListKey, (f: Finding) => string> = {
    severity: (f) => f.severity,
    cwe: (f) => f.cwe ?? "—",
    owasp: (f) => parseOwasp(f.owasp)?.code ?? "—",
    engine: (f) => engineLabel(f.engine).toLowerCase(),
    language: (f) => languageOf(f),
    status: (f) => f.status,
    verdict: (f) => verdictKey(f),
    level: () => scan?.privacy_level ?? "—",
  };
  const lik = Number(params.get("likelihood") ?? 0);
  const imp = Number(params.get("impact") ?? 0);
  const qq = (params.get("q") ?? "").toLowerCase();
  const filtered = all.filter((f) => {
    if (!inView(f, view)) return false;
    for (const k of LIST_KEYS) {
      const vals = list(k);
      if (vals.length && !vals.includes(valueOf[k](f))) return false;
    }
    if (lik && riskLevel(f.likelihood) !== lik) return false;
    if (imp && riskLevel(f.impact) !== imp) return false;
    if (qq) {
      const hay = `${f.title} ${f.id} ${findingLabel(f.id)} ${locationOf(f)?.path ?? ""} ${f.cwe ?? ""}`.toLowerCase();
      if (!hay.includes(qq)) return false;
    }
    return true;
  });
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const pg = Math.min(page, pages);
  const rows = filtered.slice((pg - 1) * PAGE, pg * PAGE);
  const allSel = rows.length > 0 && rows.every((r) => selected.has(r.id));

  const opts = (k: ListKey, label?: (v: string) => string) => {
    const m = new Map<string, number>();
    for (const f of all) {
      const v = valueOf[k](f);
      m.set(v, (m.get(v) ?? 0) + 1);
    }
    return [...m.entries()].map(([value, count]) => ({ value, count, label: label ? label(value) : value }));
  };
  const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const anyFilter = LIST_KEYS.some((k) => list(k).length) || !!qq || !!lik || !!imp;

  const tabs: { id: View; label: string }[] = [
    { id: "open", label: "All open" },
    { id: "crit", label: "Critical and high" },
    { id: "new", label: "New since baseline" },
    { id: "review", label: "Needs review" },
    { id: "mine", label: "Assigned to me" },
    { id: "suppressed", label: "Suppressed" },
    { id: "all", label: "All" },
  ];

  const patchAll = async (patch: FindingPatch, done: string) => {
    setBusy(true);
    const ids = [...selected];
    const res = await Promise.allSettled(ids.map((id) => endpoints.patchFinding(id, patch)));
    const failed = res.filter((r) => r.status === "rejected").length;
    setBusy(false);
    void qc.invalidateQueries({ queryKey: qk.findingsAll });
    void qc.invalidateQueries({ queryKey: qk.stats });
    if (failed) toast.error("Some updates failed", `${ids.length - failed} updated, ${failed} failed.`);
    else toast.success("Findings updated", `${ids.length} ${done}.`);
    setSelected(new Set());
    setDialog(null);
  };

  const exportCsv = async () => {
    if (!scanId) return;
    try {
      const { blob, filename } = await fetchReport(scanId, "csv");
      saveBlob(blob, filename);
    } catch (e) {
      toast.error("Export failed", e instanceof Error ? e.message : undefined);
    }
  };

  const triage = can("findings:triage");
  const noScans = !scanId && scans.length === 0;

  return (
    <Content>
      <PageHeader
        crumbs={[{ label: scan?.project_name ?? current?.name ?? "Project", to: "/" }, { label: "Findings" }]}
        title="Findings"
        actions={
          <>
            {scan && (
              <span className="sub">
                Scan <span className="mono">{scanLabel(scan.id)}</span>
                {baseline ? (
                  <>
                    {" "}
                    compared with baseline <span className="mono">{scanLabel(baseline.id)}</span>
                  </>
                ) : (
                  " · no earlier scan to compare with"
                )}
              </span>
            )}
            <Button onClick={exportCsv} disabled={!scanId}>
              Export CSV
            </Button>
            <Button disabled title="SARIF import is not available on this server yet.">
              Upload SARIF
            </Button>
          </>
        }
      />

      <Tabs
        label="Saved views"
        value={view}
        onChange={(v) => setParam("view", v === "open" ? null : v)}
        tabs={tabs.map((t) => ({
          id: t.id,
          label: t.label,
          count: findingsQ.data ? all.filter((f) => inView(f, t.id)).length : undefined,
        }))}
      />

      <div className="row" style={{ gap: 8 }}>
        <label className="search" style={{ maxWidth: 300, background: "var(--surface)", cursor: "text" }}>
          <Icon name="search" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter by title, file or ID"
            aria-label="Filter by title, file or ID"
            style={{ border: 0, outline: 0, background: "transparent", font: "inherit", color: "var(--text)", flex: 1, minWidth: 0 }}
          />
        </label>
        <FilterMenu
          label="Severity"
          value={list("severity")}
          onChange={(v) => setParam("severity", v.join(",") || null)}
          options={sevOrder
            .map((s) => ({ value: s, label: SEVERITY_LABEL[s], count: all.filter((f) => f.severity === s).length }))
            .filter((o) => o.count)}
        />
        <FilterMenu label="CWE" value={list("cwe")} onChange={(v) => setParam("cwe", v.join(",") || null)} options={opts("cwe")} />
        <FilterMenu label="OWASP" value={list("owasp")} onChange={(v) => setParam("owasp", v.join(",") || null)} options={opts("owasp")} />
        <FilterMenu
          label="Engine"
          value={list("engine")}
          onChange={(v) => setParam("engine", v.join(",") || null)}
          options={opts("engine", (v) => engineLabel(v))}
        />
        <FilterMenu label="Language" value={list("language")} onChange={(v) => setParam("language", v.join(",") || null)} options={opts("language")} />
        <FilterMenu
          label="Status"
          value={list("status")}
          onChange={(v) => setParam("status", v.join(",") || null)}
          options={opts("status", (v) => STATUS_LABEL[v as keyof typeof STATUS_LABEL] ?? v)}
        />
        <FilterMenu
          label="Verdict"
          value={list("verdict")}
          onChange={(v) => setParam("verdict", v.join(",") || null)}
          options={opts("verdict", (v) => VERDICT_NAMES[v] ?? v)}
        />
        <FilterMenu
          label="Privacy level"
          value={list("level")}
          onChange={(v) => setParam("level", v.join(",") || null)}
          options={opts("level", (v) => (v in LEVEL_NAME ? `${v} ${LEVEL_NAME[v as keyof typeof LEVEL_NAME]}` : v))}
        />
        <button
          className="btn sm ghost"
          type="button"
          onClick={() => {
            setQ("");
            const n = new URLSearchParams();
            if (params.get("scan")) n.set("scan", params.get("scan")!);
            if (params.get("view")) n.set("view", params.get("view")!);
            setParams(n, { replace: true });
          }}
        >
          Clear
        </button>
      </div>

      {selected.size > 0 && (
        <div className="bulkbar">
          <span className="sm">
            <b>{selected.size} selected</b>
          </span>
          <div className="row">
            <Button size="sm" onClick={() => setDialog("assign")} disabled={busy}>
              Assign
            </Button>
            <Button size="sm" onClick={() => setDialog("suppress")} disabled={busy}>
              Suppress with reason
            </Button>
            <Button size="sm" disabled={busy} onClick={() => void patchAll({ status: "false_positive" }, "marked false positive")}>
              Mark false positive
            </Button>
            {can("github:sync") && (
              <Button size="sm" onClick={() => setDialog("sync")} disabled={busy}>
                Sync to GitHub
              </Button>
            )}
          </div>
        </div>
      )}

      {findingsQ.isError ? (
        <ErrorBanner what="Findings could not be loaded." error={findingsQ.error} onRetry={() => void findingsQ.refetch()} />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                {triage && (
                  <th style={{ width: 32 }}>
                    <input
                      type="checkbox"
                      className="chk"
                      aria-label="Select all"
                      checked={allSel}
                      ref={(el) => {
                        if (el) el.indeterminate = selected.size > 0 && !allSel;
                      }}
                      onChange={(e) =>
                        setSelected((s) => {
                          const n = new Set(s);
                          for (const r of rows) {
                            if (e.target.checked) n.add(r.id);
                            else n.delete(r.id);
                          }
                          return n;
                        })
                      }
                    />
                  </th>
                )}
                <th>Severity</th>
                <th>Finding</th>
                <th>CWE</th>
                <th>OWASP</th>
                <th>CVSS 4.0</th>
                <th>Location</th>
                <th>Engines</th>
                <th>LLM verdict</th>
                <th className="num">Conf.</th>
                <th>Status</th>
                <th>Assignee</th>
              </tr>
            </thead>
            <tbody>
              {findingsQ.isLoading || (!scanId && !noScans) ? (
                <SkeletonRows cols={triage ? 12 : 11} />
              ) : (
                rows.map((f) => {
                  const loc = locationOf(f);
                  const st = stateOf(f);
                  const v = verdictOf(f);
                  const conf = confidenceFraction(f.llm?.confidence ?? f.confidence);
                  const engines = f.engines?.length ? f.engines : f.provenance?.engines?.map((e) => e.engine) ?? [f.engine ?? ""];
                  const engNames = [...new Set(engines.map(engineLabel))];
                  return (
                    <tr key={f.id} className={selected.has(f.id) ? "sel" : undefined}>
                      {triage && (
                        <td>
                          <input
                            type="checkbox"
                            className="chk"
                            aria-label={`Select ${findingLabel(f.id)}`}
                            checked={selected.has(f.id)}
                            onChange={(e) =>
                              setSelected((s) => {
                                const n = new Set(s);
                                if (e.target.checked) n.add(f.id);
                                else n.delete(f.id);
                                return n;
                              })
                            }
                          />
                        </td>
                      )}
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="wrap">
                        <Link className="t-title clamp" to={`/findings/${f.id}`} title={f.title}>
                          {f.title}
                        </Link>
                        <div className="xs faint mono">
                          <span title={f.id}>{findingLabel(f.id)}</span>
                          {st && " · "}
                          {st === "new" && <span style={{ color: "var(--accent)" }}>New</span>}
                          {st === "unchanged" && "Unchanged"}
                          {st === "fixed" && <span className="okc">Fixed in branch</span>}
                        </div>
                      </td>
                      <td className="mono sm">{f.cwe ?? "—"}</td>
                      <td className="mono sm">{parseOwasp(f.owasp)?.code ?? "—"}</td>
                      <td>
                        <CvssBox score={f.cvss4_score} />
                      </td>
                      <td className="mono xs">{loc ? `${loc.path}:${loc.line}` : "—"}</td>
                      <td className="sm">
                        {engNames.join(", ")}
                        {engNames.length > 1 && <span className="faint"> · merged from {engNames.length}</span>}
                      </td>
                      <td>
                        {v ? (
                          <Verdict kind={v.kind} />
                        ) : f.llm_reviewed ? (
                          <span className="vd">Reviewed</span>
                        ) : (
                          <span className="sm faint">Not sent</span>
                        )}
                      </td>
                      <td className="num mono">{conf === null ? "—" : conf.toFixed(2)}</td>
                      <td className="sm">
                        <StatusBadge status={f.status} />
                      </td>
                      <td>
                        {f.assignee ? (
                          <span title={f.assignee}>
                            <Avatar name={users?.find((u) => u.id === f.assignee || u.username === f.assignee)?.display_name ?? f.assignee} size="sm" />
                          </span>
                        ) : (
                          <span className="faint sm">Unassigned</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
          {!findingsQ.isLoading && scanId && filtered.length === 0 && (
            anyFilter ? (
              <Empty
                title="No findings match these filters"
                action="Clear filters"
                onAction={() => {
                  setQ("");
                  setParams(new URLSearchParams(params.get("scan") ? { scan: params.get("scan")! } : {}), { replace: true });
                }}
              />
            ) : (
              <Empty title="No findings in this view">Pick another view above.</Empty>
            )
          )}
          {noScans && (
            <Empty title="No findings yet" action="Run a scan" to="/projects/new">
              Run a scan to see results here.
            </Empty>
          )}
        </div>
      )}

      <div className="row between sm muted">
        <span>
          Showing {filtered.length ? (pg - 1) * PAGE + 1 : 0}-{Math.min(pg * PAGE, filtered.length)} of {filtered.length}
        </span>
        <div className="row">
          <Button size="sm" disabled={pg <= 1} onClick={() => setParam("page", String(pg - 1))}>
            Previous
          </Button>
          <Button size="sm" disabled={pg >= pages} onClick={() => setParam("page", String(pg + 1))}>
            Next
            <Icon name="arrow-right" />
          </Button>
        </div>
      </div>

      <AssignDialog
        open={dialog === "assign"}
        onClose={() => setDialog(null)}
        users={users?.map((u) => ({ id: u.username, name: u.display_name || u.username })) ?? []}
        busy={busy}
        onAssign={(a) => void patchAll({ assignee: a }, `assigned to ${a}`)}
      />
      <SuppressDialog
        open={dialog === "suppress"}
        onClose={() => setDialog(null)}
        busy={busy}
        onSuppress={(reason) => void patchAll({ status: "accepted_risk", comment: reason }, "suppressed")}
      />
      {scanId && dialog === "sync" && (
        <GithubSyncDialog scanId={scanId} open onClose={() => setDialog(null)} findingIds={[...selected]} />
      )}
    </Content>
  );
}

export function AssignDialog({
  open,
  onClose,
  users,
  busy,
  onAssign,
}: {
  open: boolean;
  onClose: () => void;
  users: { id: string; name: string }[];
  busy?: boolean;
  onAssign: (assignee: string) => void;
}) {
  const [v, setV] = useState("");
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Assign findings"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!v.trim()} loading={busy} onClick={() => onAssign(v.trim())}>
            Assign
          </Button>
        </>
      }
    >
      <Field label="Assignee" help={users.length ? undefined : "Enter a username."}>
        {(id, d) =>
          users.length ? (
            <select id={id} aria-describedby={d} className="inp" value={v} onChange={(e) => setV(e.target.value)}>
              <option value="">Choose a person</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name}
                </option>
              ))}
            </select>
          ) : (
            <Input id={id} aria-describedby={d} value={v} onChange={(e) => setV(e.target.value)} />
          )
        }
      </Field>
    </Dialog>
  );
}

export function SuppressDialog({
  open,
  onClose,
  busy,
  onSuppress,
}: {
  open: boolean;
  onClose: () => void;
  busy?: boolean;
  onSuppress: (reason: string) => void;
}) {
  const [v, setV] = useState("");
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Suppress with reason"
      description="The finding is kept as accepted risk. The reason is recorded in its activity history."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={v.trim().length < 3} loading={busy} onClick={() => onSuppress(v.trim())}>
            Suppress
          </Button>
        </>
      }
    >
      <Field label="Reason">
        {(id) => <Textarea id={id} rows={3} value={v} onChange={(e) => setV(e.target.value)} />}
      </Field>
    </Dialog>
  );
}
