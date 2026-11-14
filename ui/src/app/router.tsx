import { lazy, useEffect, type ReactNode } from "react";
import { createBrowserRouter, Navigate, Outlet, useRouteError } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Content, ErrorBanner, ToastProvider } from "@/components/ui";
import type { Permission } from "@/lib/permissions";
import { RequireAuth, RequirePermission, SessionProvider } from "./session";
import { ProjectProvider } from "./project-context";
import LoginPage from "@/pages/LoginPage";

const OverviewPage = lazy(() => import("@/pages/OverviewPage"));
const ProjectsPage = lazy(() => import("@/pages/ListPages").then((m) => ({ default: m.ProjectsPage })));
const ProjectDetailPage = lazy(() => import("@/pages/ListPages").then((m) => ({ default: m.ProjectDetailPage })));
const ScansPage = lazy(() => import("@/pages/ListPages").then((m) => ({ default: m.ScansPage })));
const NotFoundPage = lazy(() => import("@/pages/ListPages").then((m) => ({ default: m.NotFoundPage })));
const OnboardingPage = lazy(() => import("@/pages/OnboardingPage"));
const ScanLaunchPage = lazy(() => import("@/pages/ScanLaunchPage"));
const ScanPage = lazy(() => import("@/pages/ScanPage"));
const FindingsPage = lazy(() => import("@/pages/FindingsPage"));
const FindingDetailPage = lazy(() => import("@/pages/FindingDetailPage"));
const PrivacyPage = lazy(() => import("@/pages/PrivacyPage"));
const InspectPage = lazy(() => import("@/pages/InspectPage"));
const LedgerPage = lazy(() => import("@/pages/LedgerPage"));
const PolicyPage = lazy(() => import("@/pages/PolicyPage"));
const ReportsPage = lazy(() => import("@/pages/ReportsPage"));
const IntegrationsPage = lazy(() => import("@/pages/IntegrationsPage"));
const ProvidersPage = lazy(() => import("@/pages/ProvidersPage"));
const EvaluationPage = lazy(() => import("@/pages/EvaluationPage"));
const AdminPage = lazy(() => import("@/pages/AdminPage"));
const SettingsPage = lazy(() => import("@/pages/SettingsPage"));
const DemoPage = lazy(() => import("@/pages/DemoPage"));
const HowItWorksPage = lazy(() => import("@/pages/HowItWorksPage"));

function Root() {
  return (
    <ToastProvider>
      <SessionProvider>
        <Outlet />
      </SessionProvider>
    </ToastProvider>
  );
}

function Authed() {
  return (
    <RequireAuth>
      <ProjectProvider>
        <AppShell />
      </ProjectProvider>
    </RequireAuth>
  );
}

// A tab opened before the server was upgraded asks for page chunks that the new build no
// longer has. Reload once to pick up the new build; if that does not help, say so plainly.
const STALE_BUILD = /dynamically imported module|Importing a module script failed|Loading chunk|error loading dynamically/i;
const RELOAD_KEY = "ck-stale-build-reload";

function RouteError() {
  const error = useRouteError();
  const stale = error instanceof Error && STALE_BUILD.test(error.message);
  useEffect(() => {
    if (!stale) return;
    try {
      const last = Number(sessionStorage.getItem(RELOAD_KEY) ?? 0);
      if (Date.now() - last < 30_000) return;
      sessionStorage.setItem(RELOAD_KEY, String(Date.now()));
    } catch {
      return;
    }
    window.location.reload();
  }, [stale]);
  if (stale) {
    return (
      <Content>
        <ErrorBanner
          what="CodeKavach was updated while this tab was open."
          error={new Error("Reload the page to load the new version.")}
          onRetry={() => window.location.reload()}
        />
      </Content>
    );
  }
  return (
    <Content>
      <ErrorBanner what="This page could not be displayed." error={error} onRetry={() => window.location.reload()} />
    </Content>
  );
}

const guard = (permission: Permission, el: ReactNode) => <RequirePermission permission={permission}>{el}</RequirePermission>;

export const router = createBrowserRouter(
  [
    {
      element: <Root />,
      errorElement: <RouteError />,
      children: [
        { path: "/login", element: <LoginPage /> },
        {
          element: <Authed />,
          errorElement: <RouteError />,
          children: [
            { index: true, element: <OverviewPage /> },
            { path: "projects", element: <ProjectsPage /> },
            { path: "projects/new", element: guard("projects:write", <OnboardingPage />) },
            { path: "projects/:id", element: <ProjectDetailPage /> },
            { path: "projects/:id/scan", element: guard("scans:run", <ScanLaunchPage />) },
            { path: "scans", element: <ScansPage /> },
            { path: "scans/:id", element: <ScanPage /> },
            { path: "findings", element: <FindingsPage /> },
            { path: "findings/:id", element: <FindingDetailPage /> },
            { path: "privacy", element: guard("privacy:read", <PrivacyPage />) },
            { path: "privacy/inspect", element: guard("privacy:read", <InspectPage />) },
            { path: "privacy/inspect/:scanId/:seq", element: guard("privacy:read", <InspectPage />) },
            { path: "privacy/ledger", element: guard("privacy:read", <LedgerPage />) },
            { path: "privacy/policy", element: guard("privacy:read", <PolicyPage />) },
            { path: "reports", element: guard("reports:read", <ReportsPage />) },
            { path: "integrations", element: <IntegrationsPage /> },
            { path: "providers", element: <ProvidersPage /> },
            { path: "evaluation", element: <EvaluationPage /> },
            { path: "admin", element: guard("audit:read", <AdminPage />) },
            { path: "admin/:tab", element: guard("audit:read", <AdminPage />) },
            { path: "settings", element: <SettingsPage /> },
            { path: "demo", element: <DemoPage /> },
            { path: "how-it-works", element: <HowItWorksPage /> },
            // Old addresses kept working.
            { path: "users", element: <Navigate to="/admin/users" replace /> },
            { path: "*", element: <NotFoundPage /> },
          ],
        },
      ],
    },
  ],
  {
    future: {
      v7_relativeSplatPath: true,
      v7_fetcherPersist: true,
      v7_normalizeFormMethod: true,
      v7_partialHydration: true,
      v7_skipActionErrorRevalidation: true,
    },
  },
);
