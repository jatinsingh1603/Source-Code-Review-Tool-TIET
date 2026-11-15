import type { ReactElement } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { api, ApiError, type MockHandler } from "@/api/client";
import { ProjectProvider } from "@/app/project-context";
import { SessionProvider } from "@/app/session";
import { ToastProvider } from "@/components/ui";
import { installMockBackend } from "@/mock/backend";

type Reply = unknown | ((body: Record<string, unknown>, query: Record<string, unknown>) => unknown);

/** Requests the page under test made, as "METHOD /path". */
export const calls: string[] = [];

/**
 * Answer the dashboard's API calls in a test. `routes` maps "METHOD /path" (no query string) to a
 * reply and wins over the preview backend; a route mapped to `undefined` answers 404, like a
 * server without it.
 */
export async function serveApi(
  routes: Record<string, Reply> = {},
  as: "admin" | "auditor" | "developer" | "viewer" = "admin",
): Promise<void> {
  calls.length = 0;
  api.setToken(null);
  const preview: MockHandler = installMockBackend(api);
  api.setMockHandler(async (method, path, opts) => {
    const key = `${method.toUpperCase()} ${path.split("?")[0]}`;
    calls.push(key);
    if (key in routes) {
      const reply = routes[key];
      if (reply === undefined) throw new ApiError(404, "not_found", "Not found.");
      return typeof reply === "function"
        ? (reply as (b: Record<string, unknown>, q: Record<string, unknown>) => unknown)(
            (opts.body ?? {}) as Record<string, unknown>,
            (opts.query ?? {}) as Record<string, unknown>,
          )
        : reply;
    }
    return preview(method, path, opts);
  });
  const password = as === "developer" ? "kavach-dev" : `kavach-${as}`;
  const { token } = await api.post<{ token: string }>("/auth/login", { username: as, password });
  api.setToken(token);
}

/** Render one page inside the providers the app shell gives it, at `path`. */
export function renderPage(page: ReactElement, path = "/", pattern = "*") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <ToastProvider>
          <SessionProvider>
            <ProjectProvider>
              <Routes>
                <Route path={pattern} element={page} />
              </Routes>
            </ProjectProvider>
          </SessionProvider>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
