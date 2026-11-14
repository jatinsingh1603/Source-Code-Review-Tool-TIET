import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCurrentProject } from "@/app/project-context";
import { useSession } from "@/app/session";
import { useDeleteProject, useProject, useProviders, useScans } from "@/api/queries";
import { sortScans } from "@/lib/domain";
import { fmtInt, fmtShort, languageLabel, scanLabel } from "@/lib/display";
import { ScansTable } from "./OverviewPage";
import {
  Button,
  ButtonLink,
  Content,
  Dialog,
  Empty,
  ErrorBanner,
  LevelBadge,
  PageHeader,
  ScanStatusBadge,
  Skeleton,
  useToast,
} from "@/components/ui";

/** Scans list (not drawn): the Overview "Recent scans" table, full width, across projects. */
export function ScansPage() {
  const scansQ = useScans();
  const providers = useProviders().data;
  const { projects, current } = useCurrentProject();
  const { can } = useSession();
  const [project, setProject] = useState("");
  const target = project || current?.id || projects[0]?.id;
  const scans = useMemo(
    () => sortScans(scansQ.data ?? []).filter((s) => !project || s.project_id === project),
    [scansQ.data, project],
  );
  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Scans" }]}
        title="Scans"
        actions={
          <>
            <select className="inp" style={{ width: 220 }} aria-label="Project" value={project} onChange={(e) => setProject(e.target.value)}>
              <option value="">All projects</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            {can("scans:run") && target && (
              <ButtonLink variant="primary" to={`/projects/${target}/scan`}>
                New scan
              </ButtonLink>
            )}
          </>
        }
      />
      {scansQ.isError ? (
        <ErrorBanner what="Scans could not be loaded." error={scansQ.error} onRetry={() => void scansQ.refetch()} />
      ) : (
        <ScansTable scans={scans} providers={providers} loading={scansQ.isLoading} showProject={!project} />
      )}
    </Content>
  );
}

/** Projects list (not drawn): the same table pattern, one row per project. */
export function ProjectsPage() {
  const { projects, loading, setCurrentId } = useCurrentProject();
  const { can } = useSession();
  const navigate = useNavigate();
  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Projects" }]}
        title="Projects"
        actions={
          can("projects:write") && (
            <ButtonLink variant="primary" to="/projects/new">
              Set up a project
            </ButtonLink>
          )
        }
      />
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Project</th>
              <th>Source</th>
              <th>Languages</th>
              <th className="num">Files</th>
              <th className="num">Scans</th>
              <th>Last scan</th>
              <th>Level</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8}>
                  <Skeleton />
                </td>
              </tr>
            ) : (
              projects.map((p) => (
                <tr key={p.id}>
                  <td className="wrap">
                    <Link className="t-title" to={`/projects/${p.id}`} onClick={() => setCurrentId(p.id)}>
                      {p.name}
                    </Link>
                    {p.description && <div className="xs faint">{p.description}</div>}
                  </td>
                  <td className="mono sm">{p.source.type}</td>
                  <td className="sm">{(p.languages ?? []).map(languageLabel).join(", ") || "—"}</td>
                  <td className="num mono">{fmtInt(p.files)}</td>
                  <td className="num mono">{fmtInt(p.scan_count ?? p.scans)}</td>
                  <td className="mono sm">
                    {p.last_scan ? (
                      <Link className="t-title" to={`/scans/${p.last_scan.id}`}>
                        {scanLabel(p.last_scan.id)}
                      </Link>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td>{p.last_scan ? <LevelBadge level={p.last_scan.privacy_level} /> : "—"}</td>
                  <td>{p.last_scan ? <ScanStatusBadge status={p.last_scan.status} error={p.last_scan.error} /> : <span className="faint sm">No scans</span>}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        {!loading && projects.length === 0 && (
          <Empty title="No projects yet" action="Set up a project" onAction={() => navigate("/projects/new")}>
            Connect a repository to start a review.
          </Empty>
        )}
      </div>
    </Content>
  );
}

/** Project detail (not drawn): summary, scans and actions. */
export function ProjectDetailPage() {
  const { id } = useParams();
  const q = useProject(id);
  const scansQ = useScans(id);
  const providers = useProviders().data;
  const del = useDeleteProject();
  const { can } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const p = q.data;
  const { current, setCurrentId } = useCurrentProject();
  // A deep link to a project makes it the top bar's project, as a click in the list does.
  useEffect(() => {
    if (p && current?.id !== p.id) setCurrentId(p.id);
  }, [p, current?.id, setCurrentId]);
  if (q.isError) {
    return (
      <Content>
        <ErrorBanner what="This project could not be loaded." error={q.error} />
      </Content>
    );
  }
  const src = p?.source;
  return (
    <Content>
      <PageHeader
        crumbs={[{ label: "Projects", to: "/projects" }, { label: p?.name ?? "…" }]}
        title={p?.name ?? "Project"}
        sub={p?.description ?? undefined}
        actions={
          <>
            {can("projects:write") && (
              <Button variant="danger" onClick={() => setConfirm(true)}>
                Delete project
              </Button>
            )}
            {can("scans:run") && id && (
              <ButtonLink variant="primary" to={`/projects/${id}/scan`}>
                New scan
              </ButtonLink>
            )}
          </>
        }
      />
      <div className="card">
        {!p ? (
          <Skeleton />
        ) : (
          <dl className="dl">
            <dt>Source</dt>
            <dd className="mono sm">
              {src?.type}
              {src?.path ? ` · ${src.path}` : ""}
              {src?.url ? ` · ${src.url}` : ""}
              {src?.ref ? ` · ${src.ref}` : ""}
            </dd>
            <dt>Languages</dt>
            <dd>{(p.languages ?? []).map(languageLabel).join(", ") || "—"}</dd>
            <dt>Files</dt>
            <dd className="mono">{fmtInt(p.files)}</dd>
            <dt>Created</dt>
            <dd className="sm">{fmtShort(p.created_at)}</dd>
          </dl>
        )}
      </div>
      <h2 style={{ fontSize: 14, fontWeight: 600 }}>Scans</h2>
      <ScansTable scans={sortScans(scansQ.data ?? [])} providers={providers} loading={scansQ.isLoading} />
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Delete this project?"
        description="Its scans, findings and ledgers are removed from this server. Reports already downloaded are unaffected."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={del.isPending}
              onClick={() =>
                del.mutate(id!, {
                  onSuccess: () => {
                    toast.success("Project deleted");
                    navigate("/projects");
                  },
                  onError: (e) => toast.error("Could not delete", e.message),
                })
              }
            >
              Delete project
            </Button>
          </>
        }
      />
    </Content>
  );
}

export function NotFoundPage() {
  return (
    <Content>
      <h1 className="sr-only">Page not found</h1>
      <div className="card">
        <Empty title="Page not found" action="Back to Overview" to="/">
          This address does not match any screen.
        </Empty>
      </div>
    </Content>
  );
}
