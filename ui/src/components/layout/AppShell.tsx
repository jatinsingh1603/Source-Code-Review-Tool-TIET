import { Suspense, useEffect, useRef, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { ShellProvider, useShellOverrides } from "@/app/shell-context";
import { useHealth, useProviders, useScans, useSettings, useVersion } from "@/api/queries";
import { api } from "@/api/client";
import type { PrivacyLevel } from "@/api/types";
import type { Permission } from "@/lib/permissions";
import { roleLabel } from "@/lib/permissions";
import { cn } from "@/lib/format";
import { fmtShort, LEVEL_NAME } from "@/lib/display";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";
import { pickDefault } from "@/app/useSelectedScan";
import { Avatar, Icon, Logo, Skeleton, type IconName } from "@/components/ui";
import { CommandPalette } from "./CommandPalette";

interface NavItem {
  to: string;
  label: string;
  icon?: IconName;
  sub?: boolean;
  permission?: Permission;
  match: (path: string) => boolean;
}

type NavEntry = NavItem | { heading: string };

const NAV: NavEntry[] = [
  { to: "/", label: "Overview", icon: "grid", match: (p) => p === "/" },
  { to: "/projects", label: "Projects", icon: "folder", match: (p) => p.startsWith("/projects") && !/\/scan$/.test(p) },
  { to: "/scans", label: "Scans", icon: "gauge", match: (p) => p.startsWith("/scans") || /^\/projects\/[^/]+\/scan$/.test(p) },
  { to: "/findings", label: "Findings", icon: "flag", match: (p) => p.startsWith("/findings") },
  { heading: "Privacy" },
  { to: "/privacy", label: "Privacy Centre", icon: "shield", permission: "privacy:read", match: (p) => p === "/privacy" },
  { to: "/privacy/inspect", label: "Privacy Inspect", sub: true, permission: "privacy:read", match: (p) => p.startsWith("/privacy/inspect") },
  { to: "/privacy/ledger", label: "Egress Ledger", icon: "lines", permission: "privacy:read", match: (p) => p.startsWith("/privacy/ledger") },
  { to: "/privacy/policy", label: "Policy", icon: "sliders", permission: "privacy:read", match: (p) => p.startsWith("/privacy/policy") },
  { heading: "Deliver" },
  { to: "/reports", label: "Reports", icon: "doc", permission: "reports:read", match: (p) => p.startsWith("/reports") },
  { to: "/integrations", label: "Integrations", icon: "plug", match: (p) => p.startsWith("/integrations") },
  { to: "/providers", label: "Providers", icon: "chip", match: (p) => p.startsWith("/providers") },
  { heading: "Organisation" },
  { to: "/evaluation", label: "Evaluation", icon: "bars", match: (p) => p.startsWith("/evaluation") },
  { to: "/admin", label: "Admin", icon: "users", permission: "users:admin", match: (p) => p.startsWith("/admin") },
  { to: "/settings", label: "Settings", icon: "cog", match: (p) => p.startsWith("/settings") },
];

function Sidebar() {
  const { can } = useSession();
  const { pathname } = useLocation();
  const version = useVersion().data?.version;
  const org = useSettings().data?.org_name;
  // Hide a heading when every item under it is hidden for this role.
  const visible: NavEntry[] = [];
  NAV.forEach((e, i) => {
    if ("heading" in e) {
      const rest = NAV.slice(i + 1);
      const end = rest.findIndex((x) => "heading" in x);
      const group = (end < 0 ? rest : rest.slice(0, end)) as NavItem[];
      if (group.some((g) => !g.permission || can(g.permission))) visible.push(e);
    } else if (!e.permission || can(e.permission)) visible.push(e);
  });
  const demoOn = pathname.startsWith("/demo");
  const howOn = pathname.startsWith("/how-it-works");
  return (
    <aside className="side" aria-label="Main navigation">
      <Link className="brand" to="/">
        <Logo />
        <span>
          <span className="brand-name">CodeKavach</span>
          <br />
          <span className="brand-sub">कवच · secure code review</span>
        </span>
      </Link>
      <nav className="nav">
        {visible.map((e) =>
          "heading" in e ? (
            <div key={e.heading} className="nav-h">
              {e.heading}
            </div>
          ) : (
            <Link
              key={e.to}
              to={e.to}
              className={cn(e.sub && "subnav", e.match(pathname) && "on")}
              aria-current={e.match(pathname) ? "page" : undefined}
            >
              {e.icon && <Icon name={e.icon} />}
              {e.label}
            </Link>
          ),
        )}
      </nav>
      <div className="side-foot">
        <Link
          className="btn sm"
          to="/demo"
          style={{
            justifyContent: "flex-start",
            ...(demoOn ? { borderColor: "var(--accent)", background: "var(--accent-soft)" } : {}),
          }}
          aria-current={demoOn ? "page" : undefined}
        >
          <Icon name="play" />
          Demo mode
        </Link>
        <Link
          className={cn("btn sm ghost", howOn && "on")}
          to="/how-it-works"
          style={{ justifyContent: "flex-start", ...(howOn ? { color: "var(--text)" } : {}) }}
          aria-current={howOn ? "page" : undefined}
        >
          How it works
        </Link>
        <div className="xs faint" style={{ padding: "4px 10px" }}>
          {version ? `v${version}` : "—"}
          {org ? ` · ${org}` : ""}
        </div>
      </div>
    </aside>
  );
}

function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);
  return ref;
}

function ProjectPill() {
  const { projects, current, setCurrentId } = useCurrentProject();
  const o = useShellOverrides();
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const navigate = useNavigate();
  if (o.projectPill) {
    return (
      <span className="pill">
        {o.projectIcon && <Icon name="folder" />}
        {o.projectPill}
      </span>
    );
  }
  return (
    <div className="ck-pop" ref={ref}>
      <button className="pill" type="button" aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((x) => !x)}>
        {current?.name ?? "No project"}
        <Icon name="chevron-down" />
      </button>
      {open && (
        <div className="ck-menu" role="listbox" aria-label="Projects">
          <div className="mh">Projects</div>
          {projects.map((p) => (
            <button
              key={p.id}
              type="button"
              role="option"
              aria-selected={p.id === current?.id}
              className={cn("mi", p.id === current?.id && "on")}
              onClick={() => {
                setCurrentId(p.id);
                setOpen(false);
              }}
            >
              <Icon name="folder" />
              {p.name}
            </button>
          ))}
          {projects.length === 0 && <span className="mi faint">No projects yet</span>}
          <div className="hr" style={{ margin: "4px 0" }} />
          <button
            type="button"
            className="mi"
            onClick={() => {
              setOpen(false);
              navigate("/projects/new");
            }}
          >
            + New project
          </button>
        </div>
      )}
    </div>
  );
}

function LevelPill() {
  const o = useShellOverrides();
  const { current } = useCurrentProject();
  const scans = useScans(current?.id).data;
  const settings = useSettings().data;
  const latest = scans ? pickDefault(scans) : undefined;
  const lv = (latest?.privacy_level ?? settings?.default_privacy_level) as PrivacyLevel | undefined;
  const text = o.levelPill ?? (lv ? `${lv} · ${LEVEL_NAME[lv] ?? ""}` : null);
  if (!text) return null;
  return (
    <span className="pill priv" title="Privacy level of the latest scan">
      <Icon name="shield" />
      {text}
    </span>
  );
}

function NetworkPill() {
  const net = useHealth().data?.network;
  if (net !== "offline") return null;
  return (
    <span className="pill off">
      <span className="dot" />
      Offline · air-gapped
    </span>
  );
}

function ProviderPill() {
  const o = useShellOverrides();
  const settings = useSettings().data;
  const providers = useProviders().data;
  if (o.hideProvider || !settings) return null;
  const p = providers?.find((x) => x.id === settings.default_provider);
  return <span className="pill">{p?.name ?? settings.default_provider}</span>;
}

function Bell() {
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const qc = useQueryClient();
  const navigate = useNavigate();
  const feed = useQuery({ queryKey: ["notifications"], queryFn: endpoints.notifications, refetchInterval: 60_000, retry: false }).data;
  const unread = feed?.unread ?? 0;
  const toggle = () => {
    setOpen((x) => !x);
    if (!open && unread) {
      void endpoints.markNotificationsRead().then(() => qc.invalidateQueries({ queryKey: ["notifications"] }), () => undefined);
    }
  };
  return (
    <div className="ck-pop" ref={ref}>
      <button
        className="iconbtn"
        type="button"
        aria-label={`Notifications, ${unread ? `${unread} unread` : "none unread"}`}
        aria-expanded={open}
        onClick={toggle}
      >
        <Icon name="bell" />
        {unread > 0 && <span className="badge-n">{unread}</span>}
      </button>
      {open && (
        <div className="ck-menu right" style={{ width: 320 }}>
          <div className="mh">Notifications</div>
          {feed?.items.length ? (
            feed.items.slice(0, 8).map((n) => (
              <button
                key={n.id}
                type="button"
                className="mi"
                style={{ whiteSpace: "normal", alignItems: "flex-start", flexDirection: "column", gap: 2 }}
                onClick={() => {
                  setOpen(false);
                  if (n.link) navigate(n.link);
                }}
              >
                <span className="sm" style={{ fontWeight: n.read ? 400 : 600 }}>
                  {n.title}
                </span>
                <span className="xs faint">{fmtShort(n.at)}</span>
              </button>
            ))
          ) : (
            <div className="empty" style={{ padding: "16px 8px" }}>
              <b style={{ color: "var(--text)" }}>No notifications</b>
              <span className="sm">Finished scans and findings assigned to you appear here.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useSession();
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  if (!user) return null;
  const name = user.display_name || user.full_name || user.username;
  return (
    <div className="ck-pop" ref={ref}>
      <button
        type="button"
        className="user linkbtn"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((x) => !x)}
        style={{ textAlign: "left" }}
      >
        <Avatar name={name} />
        <span style={{ lineHeight: 1.15 }}>
          <span className="sm" style={{ fontWeight: 600 }}>
            {name}
          </span>
          <br />
          <span className="role">{roleLabel(user.role)}</span>
        </span>
      </button>
      {open && (
        <div className="ck-menu right" role="menu">
          <div style={{ padding: "6px 10px 8px" }}>
            <div className="sm" style={{ fontWeight: 600 }}>
              {name}
            </div>
            <div className="xs faint">
              {user.email || user.username} · {roleLabel(user.role)}
            </div>
          </div>
          <div className="hr" style={{ margin: "2px 0 4px" }} />
          <Link role="menuitem" className="mi" to="/settings" onClick={() => setOpen(false)}>
            <Icon name="cog" />
            Settings
          </Link>
          <button role="menuitem" type="button" className="mi" onClick={() => void logout()}>
            <Icon name="arrow-right" />
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

function TopBar({ onSearch }: { onSearch: () => void }) {
  return (
    <header className="top">
      <ProjectPill />
      <LevelPill />
      <NetworkPill />
      <ProviderPill />
      <span className="grow" />
      <button type="button" className="search" role="search" aria-label="Search findings, files, scans (Ctrl+K)" onClick={onSearch}>
        <Icon name="search" />
        <span className="grow">Search findings, files, scans</span>
        <span className="kbd">⌘K</span>
      </button>
      <Bell />
      <UserMenu />
    </header>
  );
}

export function AppShell() {
  const [palette, setPalette] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((x) => !x);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  return (
    <ShellProvider>
      <a className="btn pri sm skip" href="#main">
        Skip to content
      </a>
      <div className="app">
        <Sidebar />
        <div className="main">
          {api.isMock && (
            <div className="mockbar">Demo data mode: the dashboard is showing built-in sample data, not a live server.</div>
          )}
          <TopBar onSearch={() => setPalette(true)} />
          <Suspense
            fallback={
              <main className="content">
                <Skeleton rows={2} />
              </main>
            }
          >
            <Outlet />
          </Suspense>
        </div>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </ShellProvider>
  );
}
