import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldOff } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import type { User } from "@/api/types";
import { minimumRoleFor, permissionsFor, roleLabel, type Permission } from "@/lib/permissions";
import { EmptyState, Spinner } from "@/components/ui";

interface Session {
  user: User | null;
  loading: boolean;
  permissions: Set<Permission>;
  can: (p: Permission) => boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
}

const Ctx = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(() => api.getToken() !== null);
  const navigate = useNavigate();
  const qc = useQueryClient();

  useEffect(() => {
    api.onUnauthorised(() => {
      setUser(null);
      qc.clear();
      if (!window.location.pathname.startsWith("/login")) {
        navigate("/login", { replace: true, state: { from: window.location.pathname, expired: true } });
      }
    });
    return () => api.onUnauthorised(null);
  }, [navigate, qc]);

  useEffect(() => {
    if (!api.getToken()) {
      setLoading(false);
      return;
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

  const login = useCallback(async (username: string, password: string) => {
    const res = await endpoints.login(username, password);
    api.setToken(res.token);
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
    setUser(null);
    qc.clear();
    navigate("/login", { replace: true });
  }, [navigate, qc]);

  const value = useMemo<Session>(() => {
    const permissions = permissionsFor(user?.role);
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
      <div className="flex h-screen items-center justify-center">
        <Spinner className="h-7 w-7" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
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
    <EmptyState
      icon={<ShieldOff className="h-6 w-6" aria-hidden />}
      title="Access denied"
      description={`This area needs the ${roleLabel(role)} role or higher. Ask an administrator if you need access.`}
    />
  );
}
