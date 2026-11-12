import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import "./styles/index.css";
import { api, ApiError } from "./api/client";
import { isMockMode } from "./lib/env";
import { router } from "./app/router";

async function bootstrap() {
  if (isMockMode()) {
    const { installMockBackend } = await import("./mock/backend");
    installMockBackend(api);
  }
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: (count, err) =>
          !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
      },
    },
  });
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </StrictMode>,
  );
}

void bootstrap();
