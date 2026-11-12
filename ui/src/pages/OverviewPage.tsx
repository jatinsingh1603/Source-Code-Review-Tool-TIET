import { Link, useNavigate } from "react-router-dom";
import { AlertOctagon, Bug, FolderGit2, Plus, ScanSearch, TrendingUp, PieChart as PieIcon, History } from "lucide-react";
import { useScans, useStats } from "@/api/queries";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button, Card, CardBody, CardHeader, EmptyState, ErrorState, Skeleton, StatTile } from "@/components/ui";
import { FindingsTrend, SeverityDonut } from "@/components/charts/SeverityCharts";
import { PrivacyPostureCard } from "@/components/PrivacyPosture";
import { ScanTable } from "@/components/ScanTable";
import { useCurrentProject } from "@/app/project-context";
import { useSession } from "@/app/session";
import { pickDefault } from "@/app/useSelectedScan";
import { fmtNum, fmtRelative } from "@/lib/format";

export default function OverviewPage() {
  const stats = useStats();
  const scans = useScans();
  const { current } = useCurrentProject();
  const { user, can } = useSession();
  const navigate = useNavigate();
  const s = stats.data;
  const recent = (scans.data ?? []).slice(0, 6);
  const projectScan = pickDefault((scans.data ?? []).filter((x) => x.project_id === current?.id));
  const postureScanId = projectScan?.id ?? s?.last_scan?.id;

  if (stats.error) return <ErrorState error={stats.error} onRetry={() => void stats.refetch()} />;

  const sev = s?.findings_by_severity;
  return (
    <>
      <PageHeader
        title={`Welcome back${user?.display_name ? `, ${user.display_name.split(" ")[0]}` : ""}`}
        description="Security posture across your projects, from deterministic analysis and privacy-preserving model review."
        actions={
          can("scans:run") &&
          current && (
            <Button icon={<Plus className="h-4 w-4" />} onClick={() => navigate(`/projects/${current.id}/scan`)}>
              New scan
            </Button>
          )
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {s ? (
          <>
            <StatTile label="Projects" value={fmtNum(s.projects)} icon={<FolderGit2 className="h-5 w-5" />} to="/projects" hint="Connected code bases" />
            <StatTile
              label="Scans"
              value={fmtNum(s.scans)}
              icon={<ScanSearch className="h-5 w-5" />}
              tone="accent"
              to="/scans"
              hint={s.last_scan ? `Last ${fmtRelative(s.last_scan.finished_at ?? s.last_scan.started_at ?? s.last_scan.created_at)}` : "No scans yet"}
            />
            <StatTile label="Open findings" value={fmtNum(s.open_findings)} icon={<Bug className="h-5 w-5" />} tone="warning" to="/findings" hint="Open and confirmed, latest scans" />
            <StatTile
              label="Critical and high"
              value={fmtNum((sev?.critical ?? 0) + (sev?.high ?? 0))}
              icon={<AlertOctagon className="h-5 w-5" />}
              tone="danger"
              to="/findings?severity=critical,high"
              hint={`${sev?.critical ?? 0} critical · ${sev?.high ?? 0} high`}
            />
          </>
        ) : (
          Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-[126px]" />)
        )}
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader icon={<TrendingUp className="h-4 w-4" />} title="Findings trend" description="Findings per completed scan, stacked by severity" />
          <CardBody>
            {s ? (
              s.trend.length ? (
                <FindingsTrend trend={s.trend} />
              ) : (
                <EmptyState title="No completed scans yet" description="The trend appears after the first scan completes." />
              )
            ) : (
              <Skeleton className="h-60" />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<PieIcon className="h-4 w-4" />} title="Open by severity" description="Latest scan of every project" />
          <CardBody>{sev ? <SeverityDonut counts={sev} /> : <Skeleton className="h-44" />}</CardBody>
        </Card>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            icon={<History className="h-4 w-4" />}
            title="Recent scans"
            actions={
              <Link to="/scans" className="text-sm font-medium text-primary hover:underline">
                View all
              </Link>
            }
          />
          {scans.isLoading ? (
            <CardBody>
              <Skeleton className="h-48" />
            </CardBody>
          ) : (
            <ScanTable
              scans={recent}
              showProject
              dense
              empty={<EmptyState title="No scans yet" description="Create a project and start your first scan." />}
            />
          )}
        </Card>
        <PrivacyPostureCard scanId={postureScanId} />
      </div>
    </>
  );
}
