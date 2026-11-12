import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useProjects } from "@/api/queries";
import type { Project } from "@/api/types";

interface ProjectCtx {
  projects: Project[];
  current: Project | null;
  setCurrentId: (id: string) => void;
  loading: boolean;
}

const Ctx = createContext<ProjectCtx | null>(null);
const KEY = "ck-current-project";
const SAMPLE_ID = "prj_kavachbank_sample";

/** The project selected in the top bar; pages default to its latest scan. */
export function ProjectProvider({ children }: { children: ReactNode }) {
  const { data, isLoading } = useProjects();
  const [currentId, setId] = useState<string | null>(() => {
    try {
      return localStorage.getItem(KEY);
    } catch {
      return null;
    }
  });
  const projects = useMemo(() => data ?? [], [data]);
  // With no choice stored yet, open on the bundled KavachBank sample (the demo's project), else the newest.
  const current = projects.find((p) => p.id === currentId) ?? projects.find((p) => p.id === SAMPLE_ID) ?? projects[0] ?? null;

  useEffect(() => {
    if (current && current.id !== currentId) setId(current.id);
  }, [current, currentId]);

  const setCurrentId = useCallback((id: string) => {
    setId(id);
    try {
      localStorage.setItem(KEY, id);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo(
    () => ({ projects, current, setCurrentId, loading: isLoading }),
    [projects, current, setCurrentId, isLoading],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useCurrentProject(): ProjectCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useCurrentProject must be used inside ProjectProvider");
  return v;
}
