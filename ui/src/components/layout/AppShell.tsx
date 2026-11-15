import { Suspense, useEffect, useState, type MouseEvent } from "react";
import { Link, Outlet, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { ShellProvider, useShellOverrides } from "@/app/shell-context";
import { useHealth, useProviders, useScan, useScans, useSettings, useVersion } from "@/api/queries";
import type { PrivacyLevel } from "@/api/types";
import type { Permission } from "@/lib/permissions";
import { roleLabel } from "@/lib/permissions";
import { cn } from "@/lib/format";
import { fmtShort, LEVEL_NAME } from "@/lib/display";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";
import { pickDefault } from "@/app/useSelectedScan";
import { Avatar, Icon, Logo, Skeleton, type IconName } from "@/components/ui";
import { usePopover } from "@/components/ui/Popover";
import { CommandPalette } from "./CommandPalette";
import { MockBar } from "./MockBar";
import { useA11yShell } from "@/lib/a11y";
import { providerName } from "@/lib/domain";

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
  {
    to: "/projects",
    label: "Projects",
    icon: "folder",
    match: (p) => p.startsWith("/projects") && !/\/scan$/.test(p),
  },
  {
    to: "/scans",
    label: "Scans",
    icon: "gauge",
    match: (p) => p.startsWith("/scans") || /^\/projects\/[^/]+\/scan$/.test(p),
  },
  { to: "/findings", label: "Findings", icon: "flag", match: (p) => p.startsWith("/findings") },
  { heading: "Privacy" },
  {
    to: "/privacy",
    label: "Privacy Centre",
    icon: "shield",
    permission: "privacy:read",
    match: (p) => p === "/privacy",
  },
  {
    to: "/privacy/inspect",
    label: "Privacy Inspect",
    sub: true,
    // Inspect is the original beside the payload; a role without originals can read nothing there.
    permission: "privacy:read_original",
    match: (p) => p.startsWith("/privacy/inspect"),
  },
  {
    to: "/privacy/ledger",
    label: "Egress Ledger",
    icon: "lines",
    permission: "privacy:read",
    match: (p) => p.startsWith("/privacy/ledger"),
  },
  {
    to: "/privacy/policy",
    label: "Policy",
    icon: "sliders",
    permission: "privacy:read",
    match: (p) => p.startsWith("/privacy/policy"),
  },
  { heading: "Deliver" },
  {
    to: "/reports",
    label: "Reports",
    icon: "doc",
    permission: "reports:read",
    match: (p) => p.startsWith("/reports"),
  },
  {
    to: "/integrations",
    label: "Integrations",
    icon: "plug",
    match: (p) => p.startsWith("/integrations"),
  },
  { to: "/providers", label: "Providers", icon: "chip", match: (p) => p.startsWith("/providers") },
  { heading: "Organisation" },
  {
    to: "/evaluation",
    label: "Evaluation",
    icon: "bars",
    match: (p) => p.startsWith("/evaluation"),
  },
  {
    to: "/admin",
    label: "Admin",
    icon: "users",
    permission: "audit:read",
    match: (p) => p.startsWith("/admin"),
  },
  { to: "/settings", label: "Settings", icon: "cog", match: (p) => p.startsWith("/settings") },
];

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
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
  const startOn = pathname.startsWith("/start");
  const howOn = pathname.startsWith("/how-it-works");
  return (
    // Close the phone drawer on any link, including the page already open (no route change then).
    <aside
      id="main-nav"
      className={cn("side", open && "open")}
      aria-label="Main navigation"
      onClick={(e) => {
        if (open && (e.target as HTMLElement).closest("a")) onClose();
      }}
    >
      <div className="side-head">
        <Link className="brand" to="/">
          <Logo />
          <span>
            <span className="brand-name">CodeKavach</span>
            <br />
            <span className="brand-sub">कवच · secure code review</span>
          </span>
        </Link>
        <button type="button" className="iconbtn side-close" aria-label="Close menu" onClick={onClose}>
          <Icon name="close" />
        </button>
      </div>
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
          to="/start"
          style={{
            justifyContent: "flex-start",
            ...(startOn ? { borderColor: "var(--accent)", background: "var(--accent-soft)" } : {}),
          }}
          aria-current={startOn ? "page" : undefined}
        >
          <Icon name="play" />
          Getting started
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

function ProjectPill() {
  const { projects, current, setCurrentId } = useCurrentProject();
  const o = useShellOverrides();
  const { open, toggle, close, ref } = usePopover();
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
      <button
        className="pill"
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={toggle}
      >
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
                close(true);
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
              close();
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
  // A page showing one scan (?scan=) names that scan's level, not the latest one's.
  const linked = useScan(useSearchParams()[0].get("scan") ?? undefined).data;
  const latest = scans ? pickDefault(scans) : undefined;
  const shown = linked ?? latest;
  const lv = (shown?.privacy_level ?? settings?.default_privacy_level) as PrivacyLevel | undefined;
  const text = o.levelPill ?? (lv ? `${lv} · ${LEVEL_NAME[lv] ?? ""}` : null);
  if (!text) return null;
  return (
    <span
      className="pill priv"
      title={linked ? "Privacy level of the scan on screen" : "Privacy level of the latest scan"}
    >
      <Icon name="shield" />
      {text}
    </span>
  );
}

function NetworkPill() {
  const net = useHealth().data?.network;
  if (net !== "offline") return null;
  return (
    <span
      className="pill off"
      title="The default provider runs on this machine: a scan sends no code out unless you pick a remote provider"
    >
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
  return <span className="pill">{o.providerPill ?? providerName(settings.default_provider, providers)}</span>;
}

function Bell() {
  const { open, toggle: flip, close, ref } = usePopover();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const feed = useQuery({
    queryKey: ["notifications"],
    queryFn: endpoints.notifications,
    refetchInterval: 60_000,
    retry: false,
  }).data;
  const unread = feed?.unread ?? 0;
  const toggle = (e: MouseEvent) => {
    flip(e);
    if (!open && unread) {
      void endpoints.markNotificationsRead().then(
        () => qc.invalidateQueries({ queryKey: ["notifications"] }),
        () => undefined,
      );
    }
  };
  return (
    <div className="ck-pop" ref={ref}>
      <button
        className="iconbtn"
        type="button"
        aria-label={`Notifications, ${unread ? `${unread} unread` : "none unread"}`}
        aria-haspopup="true"
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
                style={{
                  whiteSpace: "normal",
                  alignItems: "flex-start",
                  flexDirection: "column",
                  gap: 2,
                }}
                onClick={() => {
                  close();
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
  const { open, toggle, close, ref } = usePopover();
  if (!user) return null;
  const name = user.display_name || user.full_name || user.username;
  return (
    <div className="ck-pop" ref={ref}>
      <button
        type="button"
        className="user linkbtn"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={toggle}
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
          <Link role="menuitem" className="mi" to="/settings" onClick={() => close()}>
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

function TopBar({ onSearch, navOpen, onMenu }: { onSearch: () => void; navOpen: boolean; onMenu: () => void }) {
  return (
    <header className="top">
      <button
        type="button"
        className="iconbtn menu-btn"
        aria-label="Menu"
        aria-controls="main-nav"
        aria-expanded={navOpen}
        onClick={onMenu}
      >
        <Icon name="menu" />
      </button>
      <ProjectPill />
      <LevelPill />
      <NetworkPill />
      <ProviderPill />
      <span className="grow" />
      <button
        type="button"
        className="search"
        aria-label="Search findings, files, scans (Ctrl+K)"
        onClick={onSearch}
      >
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
  const [navOpen, setNavOpen] = useState(false);
  const { pathname } = useLocation();
  // On a phone the sidebar is a drawer: it closes on navigation and on Escape, and moves focus
  // into itself when it opens so a keyboard or screen reader user lands on the links.
  useEffect(() => setNavOpen(false), [pathname]);
  useEffect(() => {
    if (!navOpen) return;
    document.querySelector<HTMLElement>("#main-nav .nav a")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setNavOpen(false);
        document.querySelector<HTMLElement>(".menu-btn")?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [navOpen]);
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
    // A link to /page#section (Admin's "+ New token" opens /settings#tokens) lands on the
    // section; any other navigation starts at the top. This runs after the page's own effects,
    // so the section is on the page by now when the page renders it straight away.
    const id = decodeURIComponent(window.location.hash.slice(1));
    const target = id ? document.getElementById(id) : null;
    if (target) target.scrollIntoView({ block: "start" });
    else window.scrollTo(0, 0);
  }, [pathname]);
  useA11yShell(pathname);
  return (
    <ShellProvider>
      <a className="btn pri sm skip" href="#main">
        Skip to content
      </a>
      <div className={cn("app", navOpen && "nav-open")}>
        <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
        {navOpen && <div className="side-scrim" aria-hidden onClick={() => setNavOpen(false)} />}
        <div className="main">
          <MockBar />
          <TopBar onSearch={() => setPalette(true)} navOpen={navOpen} onMenu={() => setNavOpen((x) => !x)} />
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
