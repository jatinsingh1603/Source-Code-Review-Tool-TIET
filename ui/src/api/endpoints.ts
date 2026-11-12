/** One typed function per REST endpoint of the shared server contract. */
import { api, ApiError, parseErrorEnvelope } from "./client";
import type {
  Finding,
  FindingFilters,
  FindingHistoryEntry,
  FindingPatch,
  GithubSyncRequest,
  GithubSyncResult,
  Health,
  LedgerDetail,
  LedgerEntry,
  LedgerVerifyResult,
  LoginResponse,
  Policy,
  PrivacySummary,
  Project,
  ProjectCreate,
  ProviderInfo,
  ProviderTestResult,
  ReportFormat,
  Scan,
  ScanCreate,
  Settings,
  Stats,
  User,
  UserCreate,
  VersionInfo,
} from "./types";

/** Lists may come back bare or wrapped (`{items: [...]}`); accept both. */
export function unwrapList<T>(data: unknown, ...keys: string[]): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const d = data as Record<string, unknown>;
    for (const k of [...keys, "items", "results", "data"]) {
      if (Array.isArray(d[k])) return d[k] as T[];
    }
  }
  return [];
}

const enc = encodeURIComponent;

export const endpoints = {
  // auth
  login: (username: string, password: string) =>
    api.post<LoginResponse>("/auth/login", { username, password }),
  me: () => api.get<User>("/auth/me"),
  logout: () => api.post<void>("/auth/logout"),

  // meta
  health: () => api.get<Health>("/health"),
  version: () => api.get<VersionInfo>("/version"),
  stats: () => api.get<Stats>("/stats"),

  // projects
  projects: async () => unwrapList<Project>(await api.get("/projects"), "projects"),
  project: (id: string) => api.get<Project>(`/projects/${enc(id)}`),
  createProject: (body: ProjectCreate) => api.post<Project>("/projects", body),
  updateProject: (id: string, body: Partial<ProjectCreate>) =>
    api.patch<Project>(`/projects/${enc(id)}`, body),
  deleteProject: (id: string) => api.delete<void>(`/projects/${enc(id)}`),

  // scans
  startScan: (projectId: string, body: ScanCreate) =>
    api.post<Scan>(`/projects/${enc(projectId)}/scans`, body),
  scans: async (projectId?: string) =>
    unwrapList<Scan>(await api.get("/scans", { project_id: projectId }), "scans"),
  scan: (id: string) => api.get<Scan>(`/scans/${enc(id)}`),
  cancelScan: (id: string) => api.post<Scan>(`/scans/${enc(id)}/cancel`),

  // findings
  findings: async (scanId: string, filters: FindingFilters = {}) =>
    unwrapList<Finding>(
      await api.get(`/scans/${enc(scanId)}/findings`, { ...filters }),
      "findings",
    ),
  finding: (id: string) => api.get<Finding>(`/findings/${enc(id)}`),
  patchFinding: (id: string, body: FindingPatch) =>
    api.patch<Finding>(`/findings/${enc(id)}`, body),
  findingHistory: async (id: string) =>
    unwrapList<FindingHistoryEntry>(await api.get(`/findings/${enc(id)}/history`), "history"),

  // privacy
  privacy: (scanId: string) => api.get<PrivacySummary>(`/scans/${enc(scanId)}/privacy`),
  ledger: async (scanId: string) =>
    unwrapList<LedgerEntry>(await api.get(`/scans/${enc(scanId)}/ledger`), "entries"),
  ledgerEntry: (scanId: string, seq: number) =>
    api.get<LedgerDetail>(`/scans/${enc(scanId)}/ledger/${seq}`),
  verifyLedger: (scanId: string) =>
    api.post<LedgerVerifyResult>(`/scans/${enc(scanId)}/ledger/verify`),

  // reports
  reports: async (scanId: string) => normaliseFormats(await api.get(`/scans/${enc(scanId)}/reports`)),

  // providers & settings
  providers: async () => unwrapList<ProviderInfo>(await api.get("/providers"), "providers"),
  testProvider: (id: string, model?: string) =>
    api.post<ProviderTestResult>(`/providers/${enc(id)}/test`, model ? { model } : {}),
  settings: () => api.get<Settings>("/settings"),
  saveSettings: (body: Partial<Settings>) => api.put<Settings>("/settings", body),
  policy: () => api.get<Policy>("/policy"),
  savePolicy: (toml: string) => api.put<Policy>("/policy", { toml }),

  // users
  users: async () => unwrapList<User>(await api.get("/users"), "users"),
  createUser: (body: UserCreate) => api.post<User>("/users", body),
  updateUser: (id: string, body: Partial<UserCreate> & { active?: boolean }) =>
    api.patch<User>(`/users/${enc(id)}`, body),
  deleteUser: (id: string) => api.delete<void>(`/users/${enc(id)}`),

  // github
  githubSync: (scanId: string, body: GithubSyncRequest) =>
    api.post<GithubSyncResult>(`/scans/${enc(scanId)}/sync/github`, body),
};

const FORMAT_LABELS: Record<string, string> = {
  html: "HTML report",
  pdf: "PDF report",
  sarif: "SARIF 2.1.0",
  json: "JSON",
  csv: "CSV",
  xlsx: "Excel workbook",
  md: "Markdown report",
  markdown: "Markdown report",
  docx: "Word document",
  compliance: "Compliance mapping",
};

const FORMAT_ORDER = ["html", "pdf", "docx", "xlsx", "compliance", "sarif", "json", "csv", "md", "markdown"];

export const ALL_REPORT_FORMATS = ["html", "pdf", "docx", "xlsx", "sarif", "json", "csv", "md"];

/** The reports listing may be a list of strings, of objects, or `{formats: [...]}`. */
export function normaliseFormats(data: unknown): ReportFormat[] {
  const list = unwrapList<unknown>(data, "formats", "available");
  const out = list.map((f) => {
    if (typeof f === "string") return { format: f, label: FORMAT_LABELS[f] ?? f, available: true };
    const o = f as Partial<ReportFormat> & { fmt?: string; name?: string };
    const format = o.format ?? o.fmt ?? o.name ?? "unknown";
    const serverLabel = o.label && o.label !== format.toUpperCase() ? o.label : undefined;
    return {
      format,
      label: FORMAT_LABELS[format] ?? serverLabel ?? format,
      available: o.available ?? true,
      reason: o.reason ?? null,
      media_type: o.media_type,
    };
  });
  // `markdown` and `md` are the same renderer; show one card.
  const deduped = out.some((f) => f.format === "md") ? out.filter((f) => f.format !== "markdown") : out;
  const rank = (f: string) => {
    const i = FORMAT_ORDER.indexOf(f);
    return i < 0 ? FORMAT_ORDER.length : i;
  };
  return [...deduped].sort((a, b) => rank(a.format) - rank(b.format));
}

export function formatLabel(fmt: string): string {
  return FORMAT_LABELS[fmt] ?? fmt.toUpperCase();
}

/** Fetch a report with authentication and return it as a Blob plus file name. */
export async function fetchReport(
  scanId: string,
  fmt: string,
): Promise<{ blob: Blob; filename: string }> {
  const res = await api.request<Response>("GET", `/scans/${enc(scanId)}/reports/${enc(fmt)}`, {
    raw: true,
  });
  if (res instanceof Blob) {
    return { blob: res, filename: `codekavach-${scanId}.${fmt}` };
  }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
  const filename = m?.[1] ? decodeURIComponent(m[1]) : `codekavach-${scanId}.${fmt === "md" ? "md" : fmt}`;
  return { blob, filename };
}

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * Upload an archive to a project with progress reporting. Uses XHR because
 * `fetch` cannot report upload progress.
 */
export function uploadArchive(
  projectId: string,
  file: File,
  onProgress: (fraction: number) => void,
  signal?: AbortSignal,
): Promise<Project> {
  if (api.isMock) {
    return new Promise((resolve, reject) => {
      let p = 0;
      const t = setInterval(() => {
        p += 0.2;
        onProgress(Math.min(p, 1));
        if (p >= 1) {
          clearInterval(t);
          api.request<Project>("POST", `/projects/${enc(projectId)}/upload`, {}).then(resolve, reject);
        }
      }, 120);
      signal?.addEventListener("abort", () => {
        clearInterval(t);
        reject(new DOMException("Aborted", "AbortError"));
      });
    });
  }
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", api.url(`/projects/${enc(projectId)}/upload`));
    const token = api.getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        body = xhr.responseText;
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as Project);
      else {
        const env = parseErrorEnvelope(xhr.status, body);
        reject(new ApiError(xhr.status, env.code, env.message, env.detail));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, "network_error", "Upload failed."));
    xhr.onabort = () => reject(new DOMException("Aborted", "AbortError"));
    signal?.addEventListener("abort", () => xhr.abort());
    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}
