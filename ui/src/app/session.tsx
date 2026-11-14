import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { ASK_TIMEOUT_MS, openTabChannel, signOutNotice } from "@/app/tab-sync";
import type { User } from "@/api/types";
import { minimumRoleFor, permissionsFor, roleLabel, type Permission } from "@/lib/permissions";
import { Content, Empty, Skeleton } from "@/components/ui";

interface Session {
  user: User | null;
  loading: boolean;
  permissions: Set<Permission>;
  can: (p: Permission) => boolean;
  login: (username: string, password: string, remember?: boolean) => Promise<User>;
  logout: () => Promise<void>;
}

const Ctx = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  // Without a token of its own, a tab first asks the other open tabs (see tab-sync.ts).
  const [loading, setLoading] = useState<boolean>(() => !api.isMock || api.getToken() !== null);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const tabs = useRef<ReturnType<typeof openTabChannel> | null>(null);

  useEffect(() => {
    const channel = openTabChannel((m) => {
      if (m.type === "ask") {
        const token = api.getToken();
        if (token) channel.post({ type: "token", token });
      } else if (m.type === "token") {
        if (api.getToken()) return;
        api.setToken(m.token);
        endpoints
          .me()
          .then((u) => setUser(u))
          .catch(() => api.setToken(null))
          .finally(() => setLoading(false));
      } else if (m.type === "signed-out" && api.getToken()) {
        api.setToken(null);
        signOutNotice.elsewhere = true;
        setUser(null);
        qc.clear();
        navigate("/login", { replace: true, state: { from: window.location.pathname } });
      }
    });
    tabs.current = channel;
    return () => {
      channel.close();
      tabs.current = null;
    };
  }, [navigate, qc]);

  useEffect(() => {
    api.onUnauthorised(() => {
      setUser(null);
      qc.clear();
      if (!window.location.pathname.startsWith("/login")) {
        signOutNotice.expired = true;
        navigate("/login", { replace: true, state: { from: window.location.pathname } });
      }
    });
    return () => api.onUnauthorised(null);
  }, [navigate, qc]);

  useEffect(() => {
    if (!api.getToken()) {
      if (api.isMock) {
        setLoading(false);
        return;
      }
      tabs.current?.post({ type: "ask" });
      // No open tab answered: show the sign-in page.
      const t = window.setTimeout(() => {
        if (!api.getToken()) setLoading(false);
      }, ASK_TIMEOUT_MS);
      return () => window.clearTimeout(t);
    }
    let live = true;
    endpoints
      .me()
      .then((u) => live && setUser(u))
      .catch(() => live && setUser(null))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, []);

  const login = useCallback(async (username: string, password: string, remember = false) => {
    const res = await endpoints.login(username, password);
    api.setToken(res.token, remember);
    signOutNotice.elsewhere = false;
    signOutNotice.expired = false;
    setUser(res.user);
    return res.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await endpoints.logout();
    } catch {
      /* the token is dropped locally either way */
    }
    api.setToken(null);
    tabs.current?.post({ type: "signed-out" });
    setUser(null);
    qc.clear();
    navigate("/login", { replace: true });
  }, [navigate, qc]);

  const value = useMemo<Session>(() => {
    const permissions = permissionsFor(user?.role, user?.permissions);
    return { user, loading, permissions, can: (p) => permissions.has(p), login, logout };
  }, [user, loading, login, logout]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession must be used inside SessionProvider");
  return v;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useSession();
  const location = useLocation();
  if (loading) {
    return (
      <div style={{ padding: 48, maxWidth: 480 }}>
        <Skeleton />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
}

/**
 * Whether the signed-in user holds a permission, or true outside a session
 * (unit tests that render a page without one). Used to skip requests the
 * server would answer with 403, which would otherwise show as console errors.
 */
export function useCan(permission: Permission): boolean {
  const v = useContext(Ctx);
  return v ? v.can(permission) : true;
}

/** Presentation-only guard; the server still enforces every request. */
export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const { can } = useSession();
  if (!can(permission)) return <AccessDenied permission={permission} />;
  return <>{children}</>;
}

export function AccessDenied({ permission }: { permission: Permission }) {
  const role = minimumRoleFor(permission);
  return (
    <Content>
      <div className="card">
        <Empty title="Access denied" action="Back to Overview" to="/">
          {`This area needs the ${roleLabel(role)} role${role === "admin" ? "" : " or higher"}. Ask an administrator if you need access.`}
        </Empty>
      </div>
    </Content>
  );
}
