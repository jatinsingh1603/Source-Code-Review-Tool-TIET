import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/**
 * Lets a page adjust the top bar the way the design does per screen: the
 * project pill reads "New project" on onboarding and the organisation on
 * Admin; the level pill follows the level chosen on onboarding and Privacy
 * Inspect; Admin drops the provider pill.
 */
export interface ShellOverrides {
  projectPill?: string;
  projectIcon?: boolean;
  levelPill?: string;
  hideProvider?: boolean;
  /** The provider pill text (the scan page shows the scan's own provider). */
  providerPill?: string;
}

interface Ctx {
  overrides: ShellOverrides;
  set: (o: ShellOverrides) => void;
}

const ShellCtx = createContext<Ctx | null>(null);

export function ShellProvider({ children }: { children: ReactNode }) {
  const [overrides, set] = useState<ShellOverrides>({});
  const value = useMemo(() => ({ overrides, set }), [overrides]);
  return <ShellCtx.Provider value={value}>{children}</ShellCtx.Provider>;
}

export function useShellOverrides(): ShellOverrides {
  return useContext(ShellCtx)?.overrides ?? {};
}

/** Apply top-bar overrides while the calling page is mounted. */
export function useShell(o: ShellOverrides): void {
  const ctx = useContext(ShellCtx);
  const set = ctx?.set;
  const key = JSON.stringify(o);
  useEffect(() => {
    if (!set) return;
    set(JSON.parse(key) as ShellOverrides);
    return () => set({});
  }, [set, key]);
}
