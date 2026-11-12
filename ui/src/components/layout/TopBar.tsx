import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Check, ChevronDown, FolderGit2, LogOut, Menu, Moon, Plus, Sun, Monitor, UserCircle2 } from "lucide-react";
import { useSession } from "@/app/session";
import { useCurrentProject } from "@/app/project-context";
import { useTheme, type ThemeChoice } from "@/lib/theme";
import { cn, initials } from "@/lib/format";
import { roleLabel } from "@/lib/permissions";
import { Button, IconButton } from "@/components/ui";

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

function ProjectSwitcher() {
  const { projects, current, setCurrentId } = useCurrentProject();
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const navigate = useNavigate();
  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 max-w-[16rem] items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm font-medium text-fg hover:bg-surface-2"
      >
        <FolderGit2 className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
        <span className="truncate">{current?.name ?? "No project"}</span>
        <ChevronDown className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
      </button>
      {open && (
        <div className="absolute left-0 top-11 z-30 w-72 animate-pop-in rounded-lg border border-border bg-surface p-1 shadow-lg">
          <p className="px-2.5 pb-1 pt-1.5 text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">Projects</p>
          <ul role="listbox" aria-label="Projects" className="max-h-72 overflow-y-auto">
            {projects.map((p) => (
              <li key={p.id}>
                <button
                  type="button"
                  role="option"
                  aria-selected={p.id === current?.id}
                  onClick={() => {
                    setCurrentId(p.id);
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm hover:bg-surface-2"
                >
                  <span className="flex-1 truncate text-fg">{p.name}</span>
                  {p.id === current?.id && <Check className="h-4 w-4 text-primary" aria-hidden />}
                </button>
              </li>
            ))}
            {projects.length === 0 && <li className="px-2.5 py-2 text-sm text-fg-muted">No projects yet</li>}
          </ul>
          <div className="mt-1 border-t border-border pt-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                navigate("/projects?new=1");
              }}
              className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm font-medium text-primary hover:bg-surface-2"
            >
              <Plus className="h-4 w-4" aria-hidden /> New project
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ThemeMenu() {
  const { choice, resolved, setChoice } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const opts: { v: ThemeChoice; label: string; icon: typeof Sun }[] = [
    { v: "light", label: "Light", icon: Sun },
    { v: "dark", label: "Dark", icon: Moon },
    { v: "system", label: "System", icon: Monitor },
  ];
  return (
    <div className="relative" ref={ref}>
      <IconButton label="Change theme" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {resolved === "dark" ? <Moon className="h-[18px] w-[18px]" /> : <Sun className="h-[18px] w-[18px]" />}
      </IconButton>
      {open && (
        <div role="menu" className="absolute right-0 top-11 z-30 w-36 animate-pop-in rounded-lg border border-border bg-surface p-1 shadow-lg">
          {opts.map((o) => (
            <button
              key={o.v}
              role="menuitemradio"
              aria-checked={choice === o.v}
              type="button"
              onClick={() => {
                setChoice(o.v);
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-sm hover:bg-surface-2",
                choice === o.v ? "text-primary" : "text-fg",
              )}
            >
              <o.icon className="h-4 w-4" aria-hidden /> {o.label}
            </button>
          ))}
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
  const name = user.display_name || user.username;
  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 hover:bg-surface-2"
      >
        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-[rgb(var(--ck-primary))] to-[rgb(var(--ck-accent))] text-xs font-bold text-white">
          {initials(name)}
        </span>
        <span className="hidden text-left leading-tight sm:block">
          <span className="block text-sm font-medium text-fg">{name}</span>
          <span className="block text-xs text-fg-subtle">{roleLabel(user.role)}</span>
        </span>
        <ChevronDown className="hidden h-4 w-4 text-fg-subtle sm:block" aria-hidden />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-12 z-30 w-60 animate-pop-in rounded-lg border border-border bg-surface p-1 shadow-lg">
          <div className="px-3 py-2.5">
            <p className="text-sm font-semibold text-fg">{name}</p>
            <p className="text-xs text-fg-muted">
              {user.email ?? user.username} · {roleLabel(user.role)}
            </p>
          </div>
          <div className="border-t border-border pt-1">
            <Link
              role="menuitem"
              to="/settings"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-fg hover:bg-surface-2"
            >
              <UserCircle2 className="h-4 w-4" aria-hidden /> Settings
            </Link>
            <button
              role="menuitem"
              type="button"
              onClick={() => void logout()}
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-danger hover:bg-surface-2"
            >
              <LogOut className="h-4 w-4" aria-hidden /> Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function TopBar({ onMenu }: { onMenu: () => void }) {
  const { can } = useSession();
  const { current } = useCurrentProject();
  const navigate = useNavigate();
  return (
    <header className="sticky top-0 z-20 flex h-topbar items-center gap-3 border-b border-border bg-surface/85 px-4 backdrop-blur lg:px-6">
      <IconButton label="Open navigation" className="lg:hidden" onClick={onMenu}>
        <Menu className="h-5 w-5" />
      </IconButton>
      <ProjectSwitcher />
      <div className="flex-1" />
      {can("scans:run") && current && (
        <Button
          size="sm"
          icon={<Plus className="h-4 w-4" />}
          onClick={() => navigate(`/projects/${current.id}/scan`)}
          className="hidden sm:inline-flex"
        >
          New scan
        </Button>
      )}
      <ThemeMenu />
      <UserMenu />
    </header>
  );
}
