import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Archive, FlaskConical, FolderGit2, FolderOpen, GitBranch, Play, Plus } from "lucide-react";
import { useProjects } from "@/api/queries";
import type { Project, SourceType } from "@/api/types";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge, Button, Card, EmptyState, ErrorState, ScanStatusBadge, Skeleton } from "@/components/ui";
import { NewProjectDialog } from "@/components/NewProjectDialog";
import { SeverityCountsInline } from "@/components/ScanTable";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { fmtRelative } from "@/lib/format";

export const SOURCE_ICON: Record<SourceType, typeof GitBranch> = {
  sample: FlaskConical,
  git: GitBranch,
  path: FolderOpen,
  upload: Archive,
};

export function sourceText(p: Project): string {
  const s = p.source;
  if (s.type === "git") return `${s.url ?? ""}${s.ref ? ` @ ${s.ref}` : ""}`;
  if (s.type === "path") return s.path ?? "";
  if (s.type === "sample") return s.path ?? "Built-in sample";
  return "Uploaded archive";
}

function ProjectCard({ p }: { p: Project }) {
  const Icon = SOURCE_ICON[p.source.type] ?? FolderGit2;
  const navigate = useNavigate();
  const { can } = useSession();
  const { setCurrentId } = useCurrentProject();
  return (
    <Card className="flex flex-col transition-shadow hover:shadow-md">
      <Link to={`/projects/${p.id}`} className="block flex-1 p-5" onClick={() => setCurrentId(p.id)}>
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary">
            <Icon className="h-5 w-5" aria-hidden />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="truncate text-lg font-semibold text-fg">{p.name}</h3>
            <p className="truncate font-mono text-xs text-fg-subtle">{sourceText(p)}</p>
          </div>
          <Badge tone="neutral">{p.source.type}</Badge>
        </div>
        {p.description && <p className="mt-3 line-clamp-2 text-sm text-fg-muted">{p.description}</p>}
        <div className="mt-4 flex flex-wrap gap-1.5">
          {(p.languages ?? []).map((l) => (
            <Badge key={l} tone="accent">
              {l}
            </Badge>
          ))}
        </div>
      </Link>
      <div className="flex items-center justify-between gap-3 border-t border-border px-5 py-3">
        {p.last_scan ? (
          <div className="flex min-w-0 items-center gap-3">
            <ScanStatusBadge status={p.last_scan.status} />
            <SeverityCountsInline counts={p.last_scan.counts} />
            <span className="hidden text-xs text-fg-subtle sm:inline">{fmtRelative(p.last_scan.started_at ?? p.last_scan.created_at)}</span>
          </div>
        ) : (
          <span className="text-sm text-fg-subtle">Not scanned yet</span>
        )}
        {can("scans:run") && (
          <Button
            size="sm"
            variant="outline"
            icon={<Play className="h-3.5 w-3.5" />}
            onClick={() => {
              setCurrentId(p.id);
              navigate(`/projects/${p.id}/scan`);
            }}
          >
            Scan
          </Button>
        )}
      </div>
    </Card>
  );
}

export default function ProjectsPage() {
  const q = useProjects();
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const [open, setOpen] = useState(params.get("new") === "1");
  const close = () => {
    setOpen(false);
    if (params.has("new")) {
      params.delete("new");
      setParams(params, { replace: true });
    }
  };
  return (
    <>
      <PageHeader
        title="Projects"
        description="Code bases connected to CodeKavach. Each scan of a project is kept with its findings, ledger and reports."
        actions={
          can("projects:write") && (
            <Button icon={<Plus className="h-4 w-4" />} onClick={() => setOpen(true)}>
              New project
            </Button>
          )
        }
      />
      {q.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-52" />
          ))}
        </div>
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data ?? []).length === 0 ? (
        <Card>
          <EmptyState
            icon={<FolderGit2 className="h-6 w-6" />}
            title="No projects yet"
            description="Start with the KavachBank sample to see a complete review, or connect your own repository."
            action={can("projects:write") && <Button onClick={() => setOpen(true)}>Create a project</Button>}
          />
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {q.data!.map((p) => (
            <ProjectCard key={p.id} p={p} />
          ))}
        </div>
      )}
      <NewProjectDialog open={open} onClose={close} />
    </>
  );
}
