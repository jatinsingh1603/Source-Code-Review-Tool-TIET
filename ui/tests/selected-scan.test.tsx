import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

const state = { projectsLoading: false, scansLoading: false, scans: [] as unknown[] };

vi.mock("@/app/project-context", () => ({
  useCurrentProject: () => ({
    projects: [],
    current: state.projectsLoading ? null : { id: "prj_1", name: "P" },
    setCurrentId: () => {},
    loading: state.projectsLoading,
  }),
}));

vi.mock("@/api/queries", () => ({
  useScan: () => ({ data: undefined }),
  useScans: () => ({ data: state.scansLoading ? undefined : state.scans, isLoading: state.scansLoading }),
}));

const { useSelectedScan } = await import("@/app/useSelectedScan");
const wrapper = ({ children }: { children: ReactNode }) => <MemoryRouter>{children}</MemoryRouter>;

describe("useSelectedScan", () => {
  beforeEach(() => {
    state.projectsLoading = false;
    state.scansLoading = false;
    state.scans = [];
  });

  it("is loading while the projects load, so pages do not say there are no scans", () => {
    state.projectsLoading = true;
    const { result } = renderHook(() => useSelectedScan(), { wrapper });
    expect(result.current.loading).toBe(true);
  });

  it("is loading while the scan list loads", () => {
    state.scansLoading = true;
    const { result } = renderHook(() => useSelectedScan(), { wrapper });
    expect(result.current.loading).toBe(true);
    expect(result.current.scans).toEqual([]);
  });

  it("reports no scans only once both have loaded", () => {
    const { result } = renderHook(() => useSelectedScan(), { wrapper });
    expect(result.current.loading).toBe(false);
    expect(result.current.scanId).toBeUndefined();
  });
});
