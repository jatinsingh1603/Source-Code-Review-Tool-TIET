import { useState } from "react";
import { useScans } from "@/api/queries";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, EmptyState, ErrorState, Segmented, Skeleton } from "@/components/ui";
import { ScanTable } from "@/components/ScanTable";
import { useCurrentProject } from "@/app/project-context";

export default function ScansPage() {
  const { current } = useCurrentProject();
  const [scope, setScope] = useState<"project" | "all">("all");
  const q = useScans(scope === "project" ? current?.id : undefined, {
    refetchInterval: (qq) => (qq.state.data?.some((s) => s.status === "running" || s.status === "queued") ? 3000 : false),
  });
  return (
    <>
      <PageHeader
        title="Scans"
        description="Every scan with its status, findings, privacy level and model provider."
        actions={
          <Segmented
            label="Scope"
            value={scope}
            onChange={setScope}
            options={[
              { value: "all", label: "All projects" },
              { value: "project", label: current?.name ?? "This project" },
            ]}
          />
        }
      />
      <Card>
        {q.isLoading ? (
          <div className="p-5">
            <Skeleton className="h-64" />
          </div>
        ) : q.error ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <ScanTable scans={q.data ?? []} showProject empty={<EmptyState title="No scans yet" description="Start a scan from a project." />} />
        )}
      </Card>
    </>
  );
}
