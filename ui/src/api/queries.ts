/**
 * React Query hooks per resource. Query keys are stable tuples built by `qk`;
 * mutations invalidate by key rather than refetching everything.
 */
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { useCan } from "@/app/session";
import { endpoints } from "./endpoints";
import type {
  Finding,
  FindingFilters,
  FindingPatch,
  GithubSyncRequest,
  ProjectCreate,
  ScanCreate,
  Settings,
  UserCreate,
} from "./types";

export const qk = {
  me: ["me"] as const,
  version: ["version"] as const,
  health: ["health"] as const,
  stats: ["stats"] as const,
  projects: ["projects"] as const,
  project: (id: string) => ["projects", id] as const,
  scans: (projectId?: string) => ["scans", { projectId: projectId ?? null }] as const,
  scansAll: ["scans"] as const,
  scan: (id: string) => ["scan", id] as const,
  findings: (scanId: string, f: FindingFilters = {}) => ["findings", scanId, f] as const,
  findingsAll: ["findings"] as const,
  finding: (id: string) => ["finding", id] as const,
  findingHistory: (id: string) => ["finding", id, "history"] as const,
  privacy: (scanId: string) => ["privacy", scanId] as const,
  ledger: (scanId: string) => ["ledger", scanId] as const,
  ledgerEntry: (scanId: string, seq: number) => ["ledger", scanId, seq] as const,
  reports: (scanId: string) => ["reports", scanId] as const,
  providers: ["providers"] as const,
  settings: ["settings"] as const,
  policy: ["policy"] as const,
  users: ["users"] as const,
};

type Opts<T> = Omit<UseQueryOptions<T, Error, T, readonly unknown[]>, "queryKey" | "queryFn">;

export const useHealth = () =>
  useQuery({ queryKey: qk.health, queryFn: endpoints.health, staleTime: 60_000, retry: false });
export const useAudit = (enabled = true) =>
  useQuery({ queryKey: ["audit"], queryFn: () => endpoints.audit(50), enabled, retry: false });
/** An endpoint from the design's API gaps; `null` data means the server does not have it yet. */
export const useOptional = <T,>(key: string, fn: () => Promise<T | null>, enabled = true) =>
  useQuery({ queryKey: ["optional", key], queryFn: fn, enabled, retry: false, staleTime: 60_000 });

export const useVersion = () =>
  useQuery({ queryKey: qk.version, queryFn: endpoints.version, staleTime: Infinity, retry: false });
/** Dashboard figures; with a project, scoped to it (the invalidations on `qk.stats` match both). */
export const useStats = (projectId?: string) =>
  useQuery({ queryKey: projectId ? [...qk.stats, projectId] : qk.stats, queryFn: () => endpoints.stats(projectId) });
export const useProjects = () => useQuery({ queryKey: qk.projects, queryFn: endpoints.projects });
export const useProject = (id: string | undefined) =>
  useQuery({ queryKey: qk.project(id ?? ""), queryFn: () => endpoints.project(id!), enabled: !!id });

export const useScans = (projectId?: string, opts: Opts<Awaited<ReturnType<typeof endpoints.scans>>> = {}) =>
  useQuery({ queryKey: qk.scans(projectId), queryFn: () => endpoints.scans(projectId), ...opts });

export const useScan = (id: string | undefined, opts: Opts<Awaited<ReturnType<typeof endpoints.scan>>> = {}) =>
  useQuery({ queryKey: qk.scan(id ?? ""), queryFn: () => endpoints.scan(id!), enabled: !!id, ...opts });

export const useFindings = (scanId: string | undefined, filters: FindingFilters = {}) =>
  useQuery({
    queryKey: qk.findings(scanId ?? "", filters),
    queryFn: () => endpoints.findings(scanId!, filters),
    enabled: !!scanId,
    placeholderData: keepPreviousData,
  });

export const useFinding = (id: string | undefined) =>
  useQuery({ queryKey: qk.finding(id ?? ""), queryFn: () => endpoints.finding(id!), enabled: !!id });

export const useFindingHistory = (id: string | undefined) =>
  useQuery({
    queryKey: qk.findingHistory(id ?? ""),
    queryFn: () => endpoints.findingHistory(id!),
    enabled: !!id,
  });

export const usePrivacy = (scanId: string | undefined) => {
  // A viewer may not read the privacy summary; skip the request instead of drawing a 403.
  const allowed = useCan("privacy:read");
  return useQuery({
    queryKey: qk.privacy(scanId ?? ""),
    queryFn: () => endpoints.privacy(scanId!),
    enabled: !!scanId && allowed,
    retry: false,
  });
};

export const useLedger = (scanId: string | undefined) =>
  useQuery({
    queryKey: qk.ledger(scanId ?? ""),
    queryFn: () => endpoints.ledger(scanId!),
    enabled: !!scanId,
    retry: false,
  });

export const useLedgerEntry = (scanId: string | undefined, seq: number | null) =>
  useQuery({
    queryKey: qk.ledgerEntry(scanId ?? "", seq ?? -1),
    queryFn: () => endpoints.ledgerEntry(scanId!, seq!),
    enabled: !!scanId && seq !== null,
    retry: false,
    gcTime: 0,
  });

export const useReports = (scanId: string | undefined) =>
  useQuery({
    queryKey: qk.reports(scanId ?? ""),
    queryFn: () => endpoints.reports(scanId!),
    enabled: !!scanId,
  });

export const useProviders = () => useQuery({ queryKey: qk.providers, queryFn: endpoints.providers });
export const useSettings = () => useQuery({ queryKey: qk.settings, queryFn: endpoints.settings });
export const usePolicy = () => useQuery({ queryKey: qk.policy, queryFn: endpoints.policy, retry: false });
/** The user list is admin-only on the server; other roles get no list (no assignee names). */
export const useUsers = () => {
  const allowed = useCan("users:admin");
  return useQuery({ queryKey: qk.users, queryFn: endpoints.users, retry: false, enabled: allowed });
};

// ---- mutations -----------------------------------------------------------

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ProjectCreate) => endpoints.createProject(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.projects });
      void qc.invalidateQueries({ queryKey: qk.stats });
    },
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => endpoints.deleteProject(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.projects });
      void qc.invalidateQueries({ queryKey: qk.stats });
    },
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, body }: { projectId: string; body: ScanCreate }) =>
      endpoints.startScan(projectId, body),
    onSuccess: (scan) => {
      qc.setQueryData(qk.scan(scan.id), scan);
      void qc.invalidateQueries({ queryKey: qk.scansAll });
      void qc.invalidateQueries({ queryKey: qk.projects });
    },
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => endpoints.cancelScan(id),
    onSuccess: (_s, id) => {
      void qc.invalidateQueries({ queryKey: qk.scan(id) });
      void qc.invalidateQueries({ queryKey: qk.scansAll });
    },
  });
}

/** Triage with optimistic update and rollback on failure. */
export function usePatchFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: FindingPatch }) =>
      endpoints.patchFinding(id, patch),
    onMutate: async ({ id, patch }) => {
      await qc.cancelQueries({ queryKey: qk.finding(id) });
      const prevDetail = qc.getQueryData<Finding>(qk.finding(id));
      const prevLists = qc.getQueriesData<Finding[]>({ queryKey: qk.findingsAll });
      const apply = (f: Finding): Finding => (f.id === id ? { ...f, ...stripUndef(patch) } : f);
      if (prevDetail) qc.setQueryData(qk.finding(id), apply(prevDetail));
      for (const [key, list] of prevLists) {
        if (Array.isArray(list)) qc.setQueryData(key, list.map(apply));
      }
      return { prevDetail, prevLists };
    },
    onError: (_e, { id }, ctx) => {
      if (!ctx) return;
      if (ctx.prevDetail) qc.setQueryData(qk.finding(id), ctx.prevDetail);
      for (const [key, list] of ctx.prevLists) qc.setQueryData(key, list);
    },
    onSettled: (_d, _e, { id }) => {
      void qc.invalidateQueries({ queryKey: qk.finding(id) });
      void qc.invalidateQueries({ queryKey: qk.findingHistory(id) });
      void qc.invalidateQueries({ queryKey: qk.stats });
    },
  });
}

/** `POST /findings/{id}/review`: the updated finding replaces the cached one. */
export function useReviewFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, provider, model }: { id: string; provider?: string; model?: string }) =>
      endpoints.reviewFinding(id, { provider, model }),
    onSuccess: (f, { id }) => {
      qc.setQueryData(qk.finding(id), f);
      void qc.invalidateQueries({ queryKey: qk.finding(id) });
      void qc.invalidateQueries({ queryKey: qk.findingsAll });
      void qc.invalidateQueries({ queryKey: ["ledger"] });
      void qc.invalidateQueries({ queryKey: qk.stats });
    },
  });
}

function stripUndef<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;
}

export function useVerifyLedger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => endpoints.verifyLedger(scanId),
    onSuccess: (_r, scanId) => void qc.invalidateQueries({ queryKey: qk.privacy(scanId) }),
  });
}

export function useTestProvider() {
  return useMutation({
    mutationFn: ({ id, model }: { id: string; model?: string }) => endpoints.testProvider(id, model),
  });
}

export function useSaveSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<Settings>) => endpoints.saveSettings(body),
    onSuccess: (data) => qc.setQueryData(qk.settings, data),
  });
}

export function useSavePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (toml: string) => endpoints.savePolicy(toml),
    onSuccess: (data) => qc.setQueryData(qk.policy, data),
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UserCreate) => endpoints.createUser(body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.users }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<UserCreate> & { active?: boolean } }) =>
      endpoints.updateUser(id, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.users }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => endpoints.deleteUser(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.users }),
  });
}

export function useGithubSync() {
  return useMutation({
    mutationFn: ({ scanId, body }: { scanId: string; body: GithubSyncRequest }) =>
      endpoints.githubSync(scanId, body),
  });
}
