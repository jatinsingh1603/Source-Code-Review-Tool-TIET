import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { qk, useFindings, useUsers } from "@/api/queries";
import { endpoints, fetchReport, saveBlob } from "@/api/endpoints";
import type { Finding, FindingPatch, SavedView, Severity } from "@/api/types";
import { useSelectedScan } from "@/app/useSelectedScan";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { bySeverity, enginesOf, isOpen, locationOf, sortScans, verdictOf } from "@/lib/domain";
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
/** Filters a saved view keeps (the server's `FindingFilters` names). */
const VIEW_KEYS = [...LIST_KEYS, "q", "assignee", "baseline_state"] as const;
/** A saved view's tab id in `?view=`. */
const SAVED = "saved:";

/** The filters a built-in tab stands for, so a view saved from it keeps meaning the same. */
const BASE_FILTERS: Partial<Record<View, Record<string, string>>> = {
  open: { status: "open,confirmed" },
  crit: { severity: "critical,high", status: "open,confirmed" },
  new: { baseline_state: "new" },
  mine: { assignee: "me" },
  suppressed: { status: "accepted_risk,false_positive" },
};

function savedViews(data: unknown): SavedView[] {
  const list = Array.isArray(data) ? data : ((data as { items?: unknown[] } | null)?.items ?? []);
  return (list as SavedView[]).filter((v) => v && !v.builtin && v.id && v.name);
}

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

/** How a language id from the server is written (anything else is capitalised). */
const LANG_NAME: Record<string, string> = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  yaml: "YAML",
  json: "JSON",
  toml: "TOML",
  hcl: "Terraform",
  php: "PHP",
  csharp: "C#",
  dockerfile: "Dockerfile",
};

export function languageOf(f: Finding): string {
  const id = f.language?.toLowerCase();
  if (id && id !== "unknown" && id !== "text") return LANG_NAME[id] ?? id.charAt(0).toUpperCase() + id.slice(1);
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

type SortKey = "severity" | "cvss" | "location" | "confidence";
/** Ascending comparators for the sortable headers of the findings table. */
const SORTERS: Record<SortKey, (a: Finding, b: Finding) => number> = {
  severity: (a, b) => -bySeverity(a, b),
  cvss: (a, b) => (a.cvss4_score ?? -1) - (b.cvss4_score ?? -1),
  location: (a, b) => {
    const la = locationOf(a);
    const lb = locationOf(b);
    return (la?.path ?? "").localeCompare(lb?.path ?? "") || (la?.line ?? 0) - (lb?.line ?? 0);
  },
  confidence: (a, b) => (shownConfidence(a) ?? -1) - (shownConfidence(b) ?? -1),
};

/** Headers whose rows can lack a value; those rows sort last whichever way the column runs. */
const BLANK: Partial<Record<SortKey, (f: Finding) => boolean>> = {
  cvss: (f) => f.cvss4_score == null,
  confidence: (f) => shownConfidence(f) === null,
};

function parseSort(raw: string | null): { key: SortKey; dir: 1 | -1 } | null {
  if (!raw) return null;
  const key = raw.replace(/^-/, "");
  return Object.hasOwn(SORTERS, key) ? { key: key as SortKey, dir: raw.startsWith("-") ? -1 : 1 } : null;
}

/** The confidence the Conf. column shows: the model's when it reviewed the finding, else the engine's. */
function shownConfidence(f: Finding): number | null {
  return confidenceFraction(f.llm?.confidence ?? f.llm_confidence ?? f.confidence);
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const { scanId, scans } = useSelectedScan();
  const sorted = useMemo(() => sortScans(scans), [scans]);
  const scan = sorted.find((s) => s.id === scanId);
  const baseline = useMemo(() => {
    const i = sorted.findIndex((s) => s.id === scanId);
    return i < 0 ? undefined : sorted.slice(i + 1).find((s) => s.status === "completed");
  }, [sorted, scanId]);
  const findingsQ = useFindings(scanId);
  const baseQ = useFindings(baseline?.id);
  // Triage carries forward only when a scan runs, so decisions on an older scan stay there.
  const newest = sorted.find((s) => s.status === "completed");
  const olderScan = !!scan && !!newest && scan.status === "completed" && newest.id !== scan.id;
  const { user, can } = useSession();
  const { current } = useCurrentProject();
  const users = useUsers().data;
  const toast = useToast();
  const qc = useQueryClient();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<null | "assign" | "suppress" | "sync" | "save">(null);
  const viewsQ = useQuery({ queryKey: ["views"], queryFn: () => endpoints.views(), retry: false, staleTime: 60_000 });
  const saved = useMemo(() => savedViews(viewsQ.data), [viewsQ.data]);
  const [busy, setBusy] = useState(false);

  const rawView = params.get("view") ?? "open";
  const savedView = rawView.startsWith(SAVED) ? saved.find((v) => SAVED + v.id === rawView) : undefined;
  const view = (rawView.startsWith(SAVED) ? "all" : rawView) as View;
  const page = Math.max(1, Number(params.get("page") ?? 1) || 1);
  // The sort lives in the URL ("-confidence" = highest first), so Back to page 2 shows the same rows.
  const sort = parseSort(params.get("sort"));
  const list = (k: ListKey) => (params.get(k) ?? "").split(",").filter(Boolean);
  const setParam = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v);
    else n.delete(k);
    if (k !== "page") n.delete("page");
    // A page turn is a step the reader expects Back to undo; filter edits replace the entry.
    setParams(n, { replace: !(k === "page" && v) });
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
        const c = shownConfidence(f);
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
  /** Whether `f` passes a set of filters (the URL's, or a saved view's). */
  const matches = (f: Finding, get: (k: string) => string) => {
    for (const k of LIST_KEYS) {
      const vals = get(k).split(",").filter(Boolean);
      if (vals.length && !vals.includes(valueOf[k](f))) return false;
    }
    const who = get("assignee");
    if (who && !(who === "me" ? inView(f, "mine") : f.assignee === who)) return false;
    const bs = get("baseline_state");
    if (bs && !bs.split(",").includes(stateOf(f) ?? "")) return false;
    const text = get("q").toLowerCase();
    if (text) {
      // Every report format prints the fingerprint, so a report's finding can be found here.
      const hay = `${f.title} ${f.id} ${findingLabel(f.id)} ${locationOf(f)?.path ?? ""} ${f.cwe ?? ""} ${f.fingerprint ?? ""}`.toLowerCase();
      if (!hay.includes(text)) return false;
    }
    return true;
  };
  const filtered = all.filter((f) => {
    if (!inView(f, view)) return false;
    if (!matches(f, (k) => params.get(k) ?? "")) return false;
    if (lik && riskLevel(f.likelihood) !== lik) return false;
    if (imp && riskLevel(f.impact) !== imp) return false;
    return true;
  });
  if (sort) {
    const cmp = SORTERS[sort.key];
    const blank = (f: Finding) => (BLANK[sort.key]?.(f) ? 1 : 0);
    // Rows without a value (no CVSS, no confidence) stay at the end in both directions.
    filtered.sort((a, b) => blank(a) - blank(b) || sort.dir * cmp(a, b) || bySeverity(a, b));
  }
  const sortTh = (key: SortKey, label: string, className?: string) => (
    <th
      className={className}
      aria-sort={sort?.key === key ? (sort.dir === 1 ? "ascending" : "descending") : undefined}
    >
      <button
        type="button"
        className="linkbtn"
        style={{ color: "inherit", fontWeight: "inherit", fontSize: "inherit" }}
        title={`Sort by ${label.toLowerCase()}`}
        onClick={() => {
          // Text sorts A to Z first, figures highest first; the third click restores the default.
          const first: 1 | -1 = key === "location" ? 1 : -1;
          const next = sort?.key !== key ? first : sort.dir === first ? -first : null;
          // setParam drops the page: a new order starts on page 1.
          setParam("sort", next === null ? null : `${next === -1 ? "-" : ""}${key}`);
        }}
      >
        {label}
        {sort?.key === key ? (sort.dir === 1 ? " ↑" : " ↓") : ""}
      </button>
    </th>
  );
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const pg = Math.min(page, pages);
  const rows = filtered.slice((pg - 1) * PAGE, pg * PAGE);
  const allSel = rows.length > 0 && rows.every((r) => selected.has(r.id));

  // Facet counts follow the selected tab, so "Low 5" under "All open" matches the rows shown.
  const inTab = all.filter((f) => inView(f, view));
  const opts = (k: ListKey, label?: (v: string) => string) => {
    const m = new Map<string, number>();
    for (const v of list(k)) m.set(v, 0);
    for (const f of inTab) {
      const v = valueOf[k](f);
      m.set(v, (m.get(v) ?? 0) + 1);
    }
    // Most frequent first, then in natural order (CWE-22 before CWE-200), "—" last.
    return [...m.entries()]
      .sort(([a, x], [b, y]) => (a === "—" ? 1 : b === "—" ? -1 : y - x || a.localeCompare(b, undefined, { numeric: true })))
      .map(([value, count]) => ({ value, count, label: label ? label(value) : value }));
  };
  const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const anyFilter =
    LIST_KEYS.some((k) => list(k).length) || !!qq || !!lik || !!imp || !!params.get("assignee") || !!params.get("baseline_state");
  /** The current tab and filters as the server's filter names, for "+ Save view". */
  const currentFilters = (): Record<string, string> => {
    const out: Record<string, string> = { ...(BASE_FILTERS[view] ?? {}) };
    for (const k of VIEW_KEYS) {
      const v = params.get(k);
      if (v) out[k] = v;
    }
    return out;
  };
  const openView = (id: string) => {
    const n = new URLSearchParams();
    if (params.get("scan")) n.set("scan", params.get("scan")!);
    const sv = id.startsWith(SAVED) ? saved.find((v) => SAVED + v.id === id) : undefined;
    if (sv) {
      n.set("view", id);
      for (const [k, v] of Object.entries(sv.filters ?? {})) if (v && (VIEW_KEYS as readonly string[]).includes(k)) n.set(k, v);
      setQ(sv.filters?.q ?? "");
    } else {
      if (id !== "open") n.set("view", id);
      if (!savedView) for (const k of VIEW_KEYS) if (params.get(k)) n.set(k, params.get(k)!);
      if (savedView) setQ("");
    }
    setParams(n, { replace: true });
  };
  const removeView = async (v: SavedView) => {
    try {
      await endpoints.deleteView(v.id);
      toast.success("View deleted", `"${v.name}" was removed.`);
      void qc.invalidateQueries({ queryKey: ["views"] });
      openView("open");
    } catch (e) {
      toast.error("The view could not be deleted", e instanceof Error ? e.message : undefined);
    }
  };

  const tabs: { id: View; label: string; title: string }[] = [
    { id: "open", label: "All open", title: "Findings not yet fixed, accepted as a risk or marked a false positive" },
    { id: "crit", label: "Critical and high", title: "Open findings rated critical or high" },
    { id: "new", label: "New since baseline", title: "Findings this scan reports that the previous scan of the project did not" },
    { id: "review", label: "Needs review", title: "Open findings the model left undecided, or with a confidence below 0.65" },
    { id: "mine", label: "Assigned to me", title: "Findings assigned to you" },
    { id: "suppressed", label: "Suppressed", title: "Findings marked accepted risk or false positive; they stay in the record" },
    { id: "all", label: "All", title: "Every finding of this scan, whatever its status" },
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

      {olderScan && (
        <div className="banner warn sm">
          This is an earlier scan of {scan?.project_name ?? current?.name ?? "this project"}. Status changes made here are not copied to the latest
          scan, {scanLabel(newest!.id)};{" "}
          <Link to={`/findings?scan=${newest!.id}`}>triage the latest scan</Link> so the decisions carry into future scans.
        </div>
      )}
      <Tabs
        label="Saved views"
        value={savedView ? rawView : view}
        onChange={openView}
        tabs={[
          ...tabs.map((t) => ({
            id: t.id as string,
            label: t.label,
            title: t.title,
            count: findingsQ.data ? all.filter((f) => inView(f, t.id)).length : undefined,
          })),
          ...saved.map((v) => ({
            id: SAVED + v.id,
            label: v.name,
            count: findingsQ.data ? all.filter((f) => matches(f, (k) => v.filters?.[k] ?? "")).length : undefined,
          })),
        ]}
        after={
          viewsQ.data !== null && (
            <button type="button" className="tab-act" onClick={() => setDialog("save")} disabled={!scanId}>
              + Save view
            </button>
          )
        }
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
            .map((s) => ({ value: s, label: SEVERITY_LABEL[s], count: inTab.filter((f) => f.severity === s).length }))
            .filter((o) => o.count || list("severity").includes(o.value))}
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
            if (params.get("view") && !savedView) n.set("view", params.get("view")!);
            setParams(n, { replace: true });
          }}
        >
          Clear
        </button>
        {savedView && (
          <button className="btn sm ghost" type="button" onClick={() => void removeView(savedView)}>
            Delete view “{savedView.name}”
          </button>
        )}
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
            <Button size="sm" loading={busy} onClick={() => void patchAll({ status: "false_positive" }, "marked false positive")}>
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
                {sortTh("severity", "Severity")}
                <th>Finding</th>
                <th>CWE</th>
                <th>OWASP</th>
                {sortTh("cvss", "CVSS 4.0")}
                {sortTh("location", "Location")}
                <th>Engines</th>
                <th>LLM verdict</th>
                {sortTh("confidence", "Conf.", "num")}
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
                  const conf = shownConfidence(f);
                  const engNames = enginesOf(f);
                  return (
                    <tr
                      key={f.id}
                      className={`click${selected.has(f.id) ? " sel" : ""}`}
                      // The whole row opens the finding, not only its title; controls inside keep their own click.
                      onClick={(e) => {
                        if ((e.target as HTMLElement).closest("a, button, input, label, select")) return;
                        if (window.getSelection()?.toString()) return;
                        if (e.ctrlKey || e.metaKey) window.open(`/findings/${f.id}`, "_blank");
                        else navigate(`/findings/${f.id}`);
                      }}
                    >
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
                          <span
                            className="sm faint"
                            title="Not reviewed by a model: beyond the scan's review limit, or no code slice to send. The engine evidence stands; open the finding to ask the model."
                          >
                            Not sent
                          </span>
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
            ) : all.length === 0 ? (
              <Empty title="This scan reported no findings">
                No engine flagged anything in the files it read. The scan page shows how many files that was.
              </Empty>
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
      <SaveViewDialog
        open={dialog === "save"}
        onClose={() => setDialog(null)}
        filters={dialog === "save" ? currentFilters() : {}}
        taken={[...tabs.map((t) => t.label), ...saved.map((v) => v.name)]}
        onSaved={(v) => {
          setDialog(null);
          qc.setQueryData(["views"], (old: unknown) => [...(Array.isArray(old) ? old : []), v]);
          const n = new URLSearchParams();
          if (params.get("scan")) n.set("scan", params.get("scan")!);
          n.set("view", SAVED + v.id);
          for (const [k, val] of Object.entries(v.filters ?? {})) if (val) n.set(k, val);
          setParams(n, { replace: true });
          toast.success("View saved", `"${v.name}" is now one of your tabs.`);
        }}
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
      title="Assign to a reviewer"
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

const FILTER_NAMES: Record<string, string> = {
  severity: "Severity",
  cwe: "CWE",
  owasp: "OWASP",
  engine: "Engine",
  language: "Language",
  status: "Status",
  verdict: "Verdict",
  level: "Privacy level",
  q: "Text",
  assignee: "Assignee",
  baseline_state: "Baseline",
};

function SaveViewDialog({
  open,
  onClose,
  filters,
  onSaved,
  taken = [],
}: {
  open: boolean;
  onClose: () => void;
  filters: Record<string, string>;
  onSaved: (v: SavedView) => void;
  /** Names already in use: views and built-in tabs, so two tabs never read the same. */
  taken?: string[];
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (open) {
      setName("");
      setError(null);
    }
  }, [open]);
  const entries = Object.entries(filters);
  const clash = taken.some((t) => t.trim().toLowerCase() === name.trim().toLowerCase());
  const save = async () => {
    if (!name.trim() || clash || busy) return;
    setBusy(true);
    setError(null);
    try {
      onSaved(await endpoints.createView(name.trim(), filters));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Save view"
      description="Keeps the current tab and filters under a name, as a tab of your own on Findings."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!name.trim() || clash} loading={busy} onClick={() => void save()}>
            Save view
          </Button>
        </>
      }
    >
      <form
        className="stack s12"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Field label="Name" error={clash ? "A tab with this name already exists. Choose another name." : undefined}>
          {(id) => (
            <Input id={id} value={name} maxLength={128} autoFocus placeholder="For example: Open injection flaws" onChange={(e) => setName(e.target.value)} />
          )}
        </Field>
        <div className="stack s6">
          <span className="lbl">Filters</span>
          {entries.length ? (
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {entries.map(([k, v]) => (
                <span key={k} className="tag">
                  {FILTER_NAMES[k] ?? k}: {v.split(",").join(", ")}
                </span>
              ))}
            </div>
          ) : (
            <span className="sm muted">No filters: the view lists every finding of the scan.</span>
          )}
        </div>
        {error !== null && <ErrorBanner what="The view could not be saved." error={error} />}
      </form>
    </Dialog>
  );
}
