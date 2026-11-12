import { useCallback, useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useScan, useScans } from "@/api/queries";
import { useCurrentProject } from "./project-context";
import type { Scan } from "@/api/types";

/**
 * The scan a page shows: `?scan=` in the URL (so views can be linked), else
 * the latest completed scan of the project selected in the top bar.
 */
/**
 * When a linked scan (`?scan=`) belongs to another project than the one in the
 * top bar, switch the top bar to it, so the crumb, the scan list and the
 * baseline all describe the scan on screen.
 */
export function useFollowScanProject(scanId: string | null | undefined) {
  const { current, setCurrentId } = useCurrentProject();
  const scan = useScan(scanId ?? undefined).data;
  const projectId = scan?.project_id;
  useEffect(() => {
    if (projectId && current && current.id !== projectId) setCurrentId(projectId);
  }, [projectId, current, setCurrentId]);
}

export function useSelectedScan() {
  const [params, setParams] = useSearchParams();
  const { current } = useCurrentProject();
  useFollowScanProject(params.get("scan"));
  const scansQ = useScans(current?.id);
  const scans = useMemo(() => scansQ.data ?? [], [scansQ.data]);
  const fromUrl = params.get("scan");
  const scanId: string | undefined =
    fromUrl ?? pickDefault(scans)?.id ?? undefined;
  const setScanId = useCallback(
    (id: string) => {
      const next = new URLSearchParams(params);
      next.set("scan", id);
      setParams(next, { replace: true });
    },
    [params, setParams],
  );
  return { scanId, setScanId, scans, loading: scansQ.isLoading, project: current };
}

export function pickDefault(scans: Scan[]): Scan | undefined {
  const sorted = [...scans].sort((a, b) =>
    (b.created_at ?? b.started_at ?? "").localeCompare(a.created_at ?? a.started_at ?? ""),
  );
  return sorted.find((s) => s.status === "completed") ?? sorted[0];
}
