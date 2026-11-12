import { Suspense, useState } from "react";
import { Outlet } from "react-router-dom";
import { FlaskConical } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { Spinner } from "@/components/ui";
import { api } from "@/api/client";

export function AppShell() {
  const [navOpen, setNavOpen] = useState(false);
  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-fg focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <Sidebar open={navOpen} onNavigate={() => setNavOpen(false)} />
      {navOpen && (
        <div className="fixed inset-0 z-30 bg-overlay/40 lg:hidden" aria-hidden onClick={() => setNavOpen(false)} />
      )}
      <div className="flex min-h-screen flex-col lg:pl-sidebar">
        {api.isMock && (
          <div className="flex items-center justify-center gap-2 bg-warning-soft px-4 py-1 text-xs font-medium text-warning">
            <FlaskConical className="h-3.5 w-3.5" aria-hidden />
            Demo data mode: the dashboard is running on built-in sample data, not a live server.
          </div>
        )}
        <TopBar onMenu={() => setNavOpen(true)} />
        <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 lg:px-8">
          <Suspense
            fallback={
              <div className="flex justify-center py-24">
                <Spinner className="h-7 w-7" />
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </main>
        <footer className="border-t border-border px-4 py-4 text-center text-xs text-fg-subtle lg:px-8">
          CodeKavach · Privacy-preserving secure code review · Thapar Institute of Engineering &amp; Technology
        </footer>
      </div>
    </div>
  );
}
