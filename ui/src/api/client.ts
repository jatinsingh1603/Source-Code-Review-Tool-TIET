/**
 * Thin typed wrapper over `fetch` for the CodeKavach REST API.
 *
 * - Bearer token authentication (held in memory and in sessionStorage so a
 *   reload keeps the session, while closing the tab ends it).
 * - Error envelopes (`{detail}`, `{error:{code,message}}`, `{message}`) are
 *   mapped to a typed `ApiError`.
 * - 401 triggers the registered unauthorised handler (route to login);
 *   429 surfaces the `Retry-After` hint.
 * - In mock mode every call is answered by the in-browser mock backend.
 */
import { isMockMode } from "@/lib/env";

export const API_PREFIX = "/api/v1";
const TOKEN_KEY = "ck-token";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: unknown;
  readonly retryAfter: number | null;

  constructor(
    status: number,
    code: string,
    message: string,
    detail?: unknown,
    retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.retryAfter = retryAfter;
  }
}

/** Turn any server error body into `{code, message}`. */
export function parseErrorEnvelope(
  status: number,
  body: unknown,
): { code: string; message: string; detail: unknown } {
  const fallback = { code: `http_${status}`, message: defaultMessage(status), detail: body };
  if (body === null || body === undefined) return fallback;
  if (typeof body === "string") return { ...fallback, message: body || fallback.message };
  if (typeof body !== "object") return fallback;
  const b = body as Record<string, unknown>;
  if (b.error && typeof b.error === "object") {
    const e = b.error as Record<string, unknown>;
    return {
      code: typeof e.code === "string" ? e.code : fallback.code,
      message: typeof e.message === "string" ? e.message : fallback.message,
      detail: e.detail ?? body,
    };
  }
  if (typeof b.detail === "string") {
    return { code: typeof b.code === "string" ? b.code : fallback.code, message: b.detail, detail: body };
  }
  if (Array.isArray(b.detail)) {
    // FastAPI validation errors: [{loc, msg, type}]
    const msgs = b.detail
      .map((d) => {
        if (d && typeof d === "object") {
          const dd = d as Record<string, unknown>;
          const loc = Array.isArray(dd.loc) ? dd.loc.filter((x) => x !== "body").join(".") : "";
          return loc ? `${loc}: ${String(dd.msg)}` : String(dd.msg);
        }
        return String(d);
      })
      .join("; ");
    return { code: "validation_error", message: msgs || fallback.message, detail: body };
  }
  if (b.detail && typeof b.detail === "object") {
    const d = b.detail as Record<string, unknown>;
    return {
      code: typeof d.code === "string" ? d.code : fallback.code,
      message: typeof d.message === "string" ? d.message : fallback.message,
      detail: body,
    };
  }
  if (typeof b.message === "string") {
    return { code: typeof b.code === "string" ? b.code : fallback.code, message: b.message, detail: body };
  }
  return fallback;
}

function defaultMessage(status: number): string {
  if (status === 0) return "The CodeKavach server could not be reached.";
  if (status === 400) return "The request was not valid.";
  if (status === 401) return "Your session has ended. Please sign in again.";
  if (status === 403) return "You do not have permission to do this.";
  if (status === 404) return "Not found.";
  if (status === 409) return "This conflicts with the current state.";
  if (status === 422) return "Some fields are not valid.";
  if (status === 429) return "Too many requests.";
  if (status >= 500) return "The server hit an error.";
  return `Request failed (${status}).`;
}

export type RequestOptions = {
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  signal?: AbortSignal;
  /** Return the raw Response instead of parsing JSON (downloads). */
  raw?: boolean;
};

export type MockHandler = (method: string, path: string, opts: RequestOptions) => Promise<unknown>;

type FetchLike = typeof fetch;

export class ApiClient {
  private token: string | null = null;
  private unauthorisedHandler: (() => void) | null = null;
  private mock: MockHandler | null = null;

  constructor(
    private readonly fetchImpl: FetchLike = (...a) => fetch(...a),
    private readonly storage: Storage | null = safeSessionStorage(),
  ) {
    try {
      this.token = this.storage?.getItem(TOKEN_KEY) ?? null;
    } catch {
      this.token = null;
    }
  }

  setMockHandler(handler: MockHandler | null): void {
    this.mock = handler;
  }

  get isMock(): boolean {
    return this.mock !== null;
  }

  getToken(): string | null {
    return this.token;
  }

  setToken(token: string | null): void {
    this.token = token;
    try {
      if (token) this.storage?.setItem(TOKEN_KEY, token);
      else this.storage?.removeItem(TOKEN_KEY);
    } catch {
      /* storage unavailable: keep the token in memory only */
    }
  }

  onUnauthorised(handler: (() => void) | null): void {
    this.unauthorisedHandler = handler;
  }

  url(path: string, query?: RequestOptions["query"]): string {
    const qs = new URLSearchParams();
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
      }
    }
    const s = qs.toString();
    return `${API_PREFIX}${path}${s ? `?${s}` : ""}`;
  }

  authHeaders(): Record<string, string> {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    if (this.mock) {
      try {
        return (await this.mock(method, path, opts)) as T;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) this.handleUnauthorised(path);
        throw e;
      }
    }
    const headers: Record<string, string> = { Accept: "application/json", ...this.authHeaders() };
    let body: BodyInit | undefined;
    if (opts.body instanceof FormData) {
      body = opts.body;
    } else if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    let res: Response;
    try {
      res = await this.fetchImpl(this.url(path, opts.query), {
        method,
        headers,
        body,
        credentials: "same-origin",
        signal: opts.signal,
      });
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      throw new ApiError(0, "network_error", defaultMessage(0), e);
    }
    if (!res.ok) {
      const parsed = await readBody(res);
      const env = parseErrorEnvelope(res.status, parsed);
      const ra = res.headers.get("Retry-After");
      const retryAfter = ra !== null && ra !== "" && !Number.isNaN(Number(ra)) ? Number(ra) : null;
      let message = env.message;
      if (res.status === 429 && retryAfter !== null) {
        message = `${message} Try again in ${retryAfter} s.`;
      }
      if (res.status === 401) this.handleUnauthorised(path);
      throw new ApiError(res.status, env.code, message, env.detail, retryAfter);
    }
    if (opts.raw) return res as unknown as T;
    if (res.status === 204) return undefined as T;
    return (await readBody(res)) as T;
  }

  private handleUnauthorised(path: string): void {
    if (path.startsWith("/auth/login")) return;
    this.setToken(null);
    this.unauthorisedHandler?.();
  }

  get<T>(path: string, query?: RequestOptions["query"], signal?: AbortSignal): Promise<T> {
    return this.request<T>("GET", path, { query, signal });
  }
  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, { body });
  }
  put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PUT", path, { body });
  }
  patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PATCH", path, { body });
  }
  delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }
}

async function readBody(res: Response): Promise<unknown> {
  const ct = res.headers.get("Content-Type") ?? "";
  try {
    if (ct.includes("json")) return await res.json();
    const text = await res.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch {
    return null;
  }
}

function safeSessionStorage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

/** Shared client instance used by the hooks. */
export const api = new ApiClient();

export function installMockIfRequested(install: () => MockHandler): void {
  if (isMockMode()) api.setMockHandler(install());
}
