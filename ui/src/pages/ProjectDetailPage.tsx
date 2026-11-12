import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Play, Trash2 } from "lucide-react";
import { useDeleteProject, useProject, useScans } from "@/api/queries";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge, Button, Card, CardHeader, Dialog, EmptyState, ErrorState, Skeleton, StatTile, useToast } from "@/components/ui";
import { ScanTable } from "@/components/ScanTable";
import { useSession } from "@/app/session";
import { fmtDateTime, fmtNum } from "@/lib/format";
import { SOURCE_ICON, sourceText } from "./ProjectsPage";
import { pickDefault } from "@/app/useSelectedScan";

export default function ProjectDetailPage() {
  const { id } = useParams();
  const project = useProject(id);
  const scans = useScans(id, { refetchInterval: (q) => (q.state.data?.some((s) => s.status === "running" || s.status === "queued") ? 3000 : false) });
  const { can } = useSession();
  const navigate = useNavigate();
  const del = useDeleteProject();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);

  if (project.error) return <ErrorState error={project.error} onRetry={() => void project.refetch()} />;
  const p = project.data;
  const Icon = p ? SOURCE_ICON[p.source.type] : null;
  const list = scans.data ?? [];
  const completed = list.filter((s) => s.status === "completed");
  const latest = pickDefault(completed);

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Projects", to: "/projects" }, { label: p?.name ?? "…" }]}
        title={p ? p.name : <Skeleton className="h-8 w-64" />}
        description={p?.description}
        meta={
          p && (
            <>
              <Badge tone="neutral" icon={Icon ? <Icon className="h-3 w-3" /> : undefined}>
                {p.source.type}
              </Badge>
              <span className="font-mono text-xs text-fg-subtle">{sourceText(p)}</span>
              <span className="text-xs text-fg-subtle">· created {fmtDateTime(p.created_at)}</span>
            </>
          )
        }
        actions={
          <>
            {can("projects:write") && can("users:admin") && (
              <Button variant="ghost" icon={<Trash2 className="h-4 w-4" />} onClick={() => setConfirm(true)}>
                Delete
              </Button>
            )}
            {can("scans:run") && id && (
              <Button icon={<Play className="h-4 w-4" />} onClick={() => navigate(`/projects/${id}/scan`)}>
                New scan
              </Button>
            )}
          </>
        }
      />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Scans" value={fmtNum(list.length)} />
        <StatTile label="Files" value={fmtNum(p?.files ?? latest?.files)} tone="accent" />
        <StatTile label="Critical (latest)" value={fmtNum(latest?.counts.critical ?? 0)} tone="danger" />
        <StatTile label="High (latest)" value={fmtNum(latest?.counts.high ?? 0)} tone="warning" />
      </div>
      <Card className="mt-6">
        <CardHeader title="Scan history" description="Every scan of this project, newest first" />
        {scans.isLoading ? (
          <div className="p-5">
            <Skeleton className="h-40" />
          </div>
        ) : (
          <ScanTable
            scans={list}
            empty={
              <EmptyState
                title="No scans yet"
                description="Start a scan to analyse this project."
                action={
                  can("scans:run") && (
                    <Button icon={<Play className="h-4 w-4" />} onClick={() => navigate(`/projects/${id}/scan`)}>
                      Start the first scan
                    </Button>
                  )
                }
              />
            }
          />
        )}
      </Card>
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        size="sm"
        title="Delete this project?"
        description="The project, its scans, findings and reports are removed from this server. The source repository is not touched."
        footer={
          <>
            <Button variant="outline" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={del.isPending}
              onClick={async () => {
                try {
                  await del.mutateAsync(id!);
                  toast.success("Project deleted");
                  navigate("/projects");
                } catch (e) {
                  toast.error("Could not delete the project", e instanceof Error ? e.message : undefined);
                }
              }}
            >
              Delete project
            </Button>
          </>
        }
      />
    </>
  );
}
