import { NavLink } from "react-router-dom";
import {
  Bug,
  FileText,
  FolderGit2,
  LayoutDashboard,
  Lock,
  ScanSearch,
  Settings2,
  Users,
  type LucideIcon,
} from "lucide-react";
import { useSession } from "@/app/session";
import { useVersion } from "@/api/queries";
import type { Permission } from "@/lib/permissions";
import { cn } from "@/lib/format";
import { Wordmark } from "./Logo";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  permission?: Permission;
  end?: boolean;
}

const MAIN: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/scans", label: "Scans", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/privacy", label: "Privacy Centre", icon: Lock, permission: "privacy:read" },
  { to: "/reports", label: "Reports", icon: FileText, permission: "reports:read" },
];

const ADMIN: NavItem[] = [
  { to: "/settings", label: "Providers & settings", icon: Settings2 },
  { to: "/admin/users", label: "Users", icon: Users, permission: "users:admin" },
];

export function Sidebar({ open, onNavigate }: { open: boolean; onNavigate: () => void }) {
  const { can } = useSession();
  const version = useVersion().data?.version;
  const renderItems = (items: NavItem[]) =>
    items
      .filter((i) => !i.permission || can(i.permission))
      .map((i) => (
        <li key={i.to}>
          <NavLink
            to={i.to}
            end={i.end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "group flex items-center gap-3 rounded-md px-3 py-2 text-[13.5px] font-medium transition-colors",
                isActive
                  ? "bg-sidebar-active-bg text-sidebar-active"
                  : "text-sidebar-fg hover:bg-white/5 hover:text-sidebar-active",
              )
            }
          >
            {({ isActive }) => (
              <>
                <i.icon
                  className={cn("h-[18px] w-[18px]", isActive ? "text-[rgb(var(--ck-accent))]" : "text-sidebar-muted group-hover:text-sidebar-fg")}
                  aria-hidden
                />
                {i.label}
              </>
            )}
          </NavLink>
        </li>
      ));

  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-40 flex w-sidebar flex-col bg-sidebar transition-transform lg:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full",
      )}
      aria-label="Primary"
    >
      <div className="flex h-topbar items-center border-b border-white/5 px-5">
        <Wordmark inverted />
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <p className="px-3 pb-2 text-[10.5px] font-semibold uppercase tracking-widest text-sidebar-muted">Workspace</p>
        <ul className="space-y-0.5">{renderItems(MAIN)}</ul>
        <p className="mt-6 px-3 pb-2 text-[10.5px] font-semibold uppercase tracking-widest text-sidebar-muted">
          Administration
        </p>
        <ul className="space-y-0.5">{renderItems(ADMIN)}</ul>
      </nav>
      <div className="border-t border-white/5 px-5 py-4 text-[11px] leading-snug text-sidebar-muted">
        <p className="font-medium text-sidebar-fg">Thapar Institute of Engineering &amp; Technology</p>
        {version && <p className="mt-0.5">CodeKavach v{version}</p>}
      </div>
    </aside>
  );
}
