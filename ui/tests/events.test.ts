import { describe, expect, it, vi } from "vitest";
import { SseParser, subscribeScanEvents, toScanEvent, type StreamState } from "@/api/events";
import { groupStages, reduceLive } from "@/api/useScanEvents";
import type { ScanEvent } from "@/api/types";

describe("SseParser", () => {
  it("parses frames split across chunks", () => {
    const p = new SseParser();
    expect(p.push("id: 1\nevent: stage\nda")).toEqual([]);
    const out = p.push('ta: {"name":"parse","status":"started"}\n\n: keep-alive\n\n');
    expect(out).toEqual([{ id: "1", event: "stage", data: '{"name":"parse","status":"started"}' }]);
  });
  it("maps messages to typed events", () => {
    expect(toScanEvent({ event: "done", data: '{"status":"completed"}' })).toEqual({ type: "done", status: "completed" });
    expect(toScanEvent({ event: "progress", data: '{"percent":40,"message":"m"}' })).toEqual({
      type: "progress",
      percent: 40,
      message: "m",
    });
    expect(toScanEvent({ event: "unknown", data: "{}" })).toBeNull();
  });
});

function streamOf(text: string): Response {
  // A minimal Response-like object: jsdom's Blob streams cross realms badly.
  const chunks = [text];
  const body = {
    getReader: () => ({
      read: async () => {
        const c = chunks.shift();
        return c === undefined ? { done: true, value: undefined } : { done: false, value: c };
      },
    }),
  };
  return { ok: true, status: 200, body } as unknown as Response;
}

describe("subscribeScanEvents", () => {
  it("delivers events and resumes with Last-Event-ID", async () => {
    const calls: Record<string, string>[] = [];
    let n = 0;
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
      calls.push(init.headers as Record<string, string>);
      n++;
      if (n === 1) return streamOf('id: 4\nevent: log\ndata: {"level":"info","message":"a"}\n\n');
      return streamOf('id: 5\nevent: done\ndata: {"status":"completed"}\n\n');
    });
    const events: ScanEvent[] = [];
    const states: StreamState[] = [];
    await new Promise<void>((resolve) => {
      subscribeScanEvents("s1", {
        onEvent: (e) => events.push(e),
        onState: (s) => {
          states.push(s);
          if (s === "closed") resolve();
        },
        baseDelayMs: 1,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
    });
    expect(events.map((e) => e.type)).toEqual(["log", "done"]);
    expect(calls[1]?.["Last-Event-ID"]).toBe("4");
  });

  it("falls back after three failures", async () => {
    const fetchImpl = vi.fn(async () => new Response("no", { status: 503 }));
    const state = await new Promise<StreamState>((resolve) => {
      subscribeScanEvents("s1", {
        onEvent: () => {},
        onState: (s) => s === "fallback" && resolve(s),
        baseDelayMs: 1,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
    });
    expect(state).toBe("fallback");
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
});

describe("live scan reducer", () => {
  it("groups analyse sub-stages and finishes on done", () => {
    let s = reduceLive(undefined as never, { kind: "reset" });
    s = reduceLive(s, { kind: "event", at: 1, e: { type: "stage", name: "analyse-rules", status: "started" } });
    s = reduceLive(s, { kind: "event", at: 2, e: { type: "stage", name: "analyse-taint", status: "completed" } });
    expect(s.stages.find((x) => x.name === "analyse")?.state).toBe("running");
    s = reduceLive(s, { kind: "event", at: 3, e: { type: "done", status: "completed" } });
    expect(s.stages.find((x) => x.name === "analyse")?.state).toBe("done");
    expect(s.stages.find((x) => x.name === "analyse")?.members).toEqual(["analyse-rules", "analyse-taint"]);
    expect(s.percent).toBe(100);
  });
  it("keeps unknown stages as their own steps", () => {
    const v = groupStages({ custom: { state: "done" } }, ["custom"], null);
    expect(v[v.length - 1]).toMatchObject({ name: "custom", state: "done" });
  });
});
