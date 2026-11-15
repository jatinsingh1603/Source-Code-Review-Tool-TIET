import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { api } from "@/api/client";
import { SessionProvider } from "@/app/session";
import { MockBar } from "@/components/layout/MockBar";
import { ToastProvider } from "@/components/ui";
import { installMockBackend } from "@/mock/backend";
import LoginPage from "@/pages/LoginPage";

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const SRC = join(__dirname, "..", "src");

describe("product wording", () => {
  // The dashboard is delivered as a product: nothing in it addresses a presenter or calls
  // itself a demonstration. The hosted build is a "Hosted preview".
  it.each([/demo/i, /presenter/i, /\bon stage\b/i])("no source file says %s", (word) => {
    const offenders = walk(SRC).filter((f) => /\.(ts|tsx|css)$/.test(f) && word.test(readFileSync(f, "utf8")));
    expect(offenders.map((f) => f.slice(SRC.length + 1))).toEqual([]);
  });
});

function login() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={["/login"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <ToastProvider>
          <SessionProvider>
            <LoginPage />
          </SessionProvider>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Login", () => {
  it("offers only what the server has: a local account", () => {
    api.setMockHandler(null);
    api.setToken(null);
    login();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
    // One organisation and local accounts: no tenant choice, no single sign-on, no preview entry.
    expect(screen.queryByLabelText("Organisation")).toBeNull();
    expect(screen.queryByRole("button", { name: /SSO/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Explore the preview" })).toBeNull();
    expect(document.querySelectorAll("button:disabled")).toHaveLength(0);
  });

  it("opens the hosted preview from its own button and labels the sample data", () => {
    installMockBackend(api);
    api.setToken(null);
    login();
    expect(screen.getByRole("button", { name: "Explore the preview" })).toBeTruthy();
    expect(screen.getByRole("note").textContent).toMatch(/sample data/i);
    api.setMockHandler(null);
  });

  it("shows no sample-data strip against a real server", () => {
    api.setMockHandler(null);
    const { container } = render(<MockBar />);
    expect(container.textContent).toBe("");
  });
});
