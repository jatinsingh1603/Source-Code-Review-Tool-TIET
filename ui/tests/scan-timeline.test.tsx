import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, renderHook } from "@testing-library/react";
import type { ScanEvent } from "@/api/types";

type Handlers = { onEvent: (e: ScanEvent) => void; onState?: (s: string) => void };
let handlers: Handlers | null = null;

vi.mock("@/api/events", () => ({
  subscribeScanEvents: (_id: string, h: Handlers) => {
    handlers = h;
    return () => {};
  },
}));

const { useScanTimeline } = await import("@/app/useScanTimeline");

const stage = { type: "stage", name: "intake", status: "done", at: "2026-11-14T20:00:00Z" } as unknown as ScanEvent;
const done = { type: "done", status: "completed", at: "2026-11-14T20:00:05Z" } as unknown as ScanEvent;

describe("useScanTimeline", () => {
  beforeEach(() => {
    handlers = null;
    vi.useFakeTimers();
  });

  it("holds a finished scan's replay until it is complete", () => {
    const { result } = renderHook(() => useScanTimeline("scn_1", true, true));
    expect(result.current.ready).toBe(false);
    act(() => {
      handlers!.onEvent(stage);
      vi.advanceTimersByTime(500);
    });
    expect(result.current.events).toHaveLength(0);
    expect(result.current.ready).toBe(false);
    act(() => handlers!.onEvent(done));
    expect(result.current.events).toHaveLength(2);
    expect(result.current.ready).toBe(true);
  });

  it("shows what arrived when the stream ends without done", () => {
    const { result } = renderHook(() => useScanTimeline("scn_1", true, true));
    act(() => {
      handlers!.onEvent(stage);
      handlers!.onState!("fallback");
    });
    expect(result.current.events).toHaveLength(1);
    expect(result.current.ready).toBe(true);
  });

  it("streams a running scan's events as they come", () => {
    const { result } = renderHook(() => useScanTimeline("scn_1", true, false));
    expect(result.current.ready).toBe(true);
    act(() => {
      handlers!.onEvent(stage);
      vi.advanceTimersByTime(100);
    });
    expect(result.current.events).toHaveLength(1);
  });
});
