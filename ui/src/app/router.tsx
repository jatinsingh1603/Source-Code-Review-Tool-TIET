import { lazy } from "react";
import { createBrowserRouter, Outlet } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { RouteError } from "@/components/layout/PageHeader";
import { ToastProvider } from "@/components/ui";
import { RequireAuth, RequirePermission, SessionProvider } from "./session";
import { ProjectProvider } from "./project-context";
import LoginPage from "@/pages/LoginPage";
import NotFoundPage from "@/pages/NotFoundPage";

const OverviewPage = lazy(() => import("@/pages/OverviewPage"));
const ProjectsPage = lazy(() => import("@/pages/ProjectsPage"));
const ProjectDetailPage = lazy(() => import("@/pages/ProjectDetailPage"));
const NewScanPage = lazy(() => import("@/pages/NewScanPage"));
const ScansPage = lazy(() => import("@/pages/ScansPage"));
const ScanPage = lazy(() => import("@/pages/ScanPage"));
const FindingsPage = lazy(() => import("@/pages/FindingsPage"));
const FindingDetailPage = lazy(() => import("@/pages/FindingDetailPage"));
const PrivacyPage = lazy(() => import("@/pages/PrivacyPage"));
const ReportsPage = lazy(() => import("@/pages/ReportsPage"));
const SettingsPage = lazy(() => import("@/pages/SettingsPage"));
const UsersPage = lazy(() => import("@/pages/UsersPage"));

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

export const router = createBrowserRouter([
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
          { path: "projects/:id", element: <ProjectDetailPage /> },
          {
            path: "projects/:id/scan",
            element: (
              <RequirePermission permission="scans:run">
                <NewScanPage />
              </RequirePermission>
            ),
          },
          { path: "scans", element: <ScansPage /> },
          { path: "scans/:id", element: <ScanPage /> },
          { path: "findings", element: <FindingsPage /> },
          { path: "findings/:id", element: <FindingDetailPage /> },
          {
            path: "privacy",
            element: (
              <RequirePermission permission="privacy:read">
                <PrivacyPage />
              </RequirePermission>
            ),
          },
          {
            path: "reports",
            element: (
              <RequirePermission permission="reports:read">
                <ReportsPage />
              </RequirePermission>
            ),
          },
          { path: "settings", element: <SettingsPage /> },
          {
            path: "admin/users",
            element: (
              <RequirePermission permission="users:admin">
                <UsersPage />
              </RequirePermission>
            ),
          },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
]);
