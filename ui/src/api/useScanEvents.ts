import { useEffect, useReducer } from "react";
import { subscribeScanEvents, type StreamState } from "./events";
import type { ScanEvent, ScanStatus, Severity } from "./types";

export const DEFAULT_STAGES = [
  "ingest",
  "parse",
  "analyse",
  "aggregate",
  "privacy-prepare",
  "llm-review",
  "restore",
  "rate",
  "report",
  "sync",
];

export type StageState = "pending" | "running" | "done" | "skipped" | "failed";

export interface LiveScan {
  stages: { name: string; state: StageState; startedAt?: number; endedAt?: number }[];
  percent: number | null;
  message: string | null;
  logs: { at: number; level: string; message: string }[];
  findings: { id: string; severity: Severity; title: string }[];
  done: ScanStatus | null;
  stream: StreamState;
}

type Action = { kind: "event"; e: ScanEvent; at: number } | { kind: "stream"; s: StreamState } | { kind: "reset" };

const init = (): LiveScan => ({
  stages: DEFAULT_STAGES.map((name) => ({ name, state: "pending" })),
  percent: null,
  message: null,
  logs: [],
  findings: [],
  done: null,
  stream: "connecting",
});

export function reduceLive(s: LiveScan, a: Action): LiveScan {
  if (a.kind === "reset") return init();
  if (a.kind === "stream") return { ...s, stream: a.s };
  const e = a.e;
  switch (e.type) {
    case "stage": {
      const st: StageState =
        e.status === "started" || e.status === "running"
          ? "running"
          : e.status === "completed" || e.status === "done" || e.status === "ok"
            ? "done"
            : e.status === "skipped"
              ? "skipped"
              : e.status === "failed" || e.status === "error"
                ? "failed"
                : "running";
      const stages = s.stages.some((x) => x.name === e.name) ? [...s.stages] : [...s.stages, { name: e.name, state: "pending" as StageState }];
      return {
        ...s,
        stages: stages.map((x) => {
          if (x.name === e.name) {
            return {
              ...x,
              state: st,
              startedAt: st === "running" ? (x.startedAt ?? a.at) : x.startedAt,
              endedAt: st === "done" || st === "failed" || st === "skipped" ? a.at : x.endedAt,
            };
          }
          // A stage starting implies earlier running stages finished.
          if (st === "running" && x.state === "running") return { ...x, state: "done", endedAt: a.at };
          return x;
        }),
      };
    }
    case "progress":
      return { ...s, percent: e.percent, message: e.message ?? s.message };
    case "log":
      return { ...s, logs: [...s.logs.slice(-499), { at: a.at, level: e.level, message: e.message }] };
    case "finding":
      if (s.findings.some((f) => f.id === e.id)) return s;
      return { ...s, findings: [...s.findings, { id: e.id, severity: e.severity, title: e.title }] };
    case "done":
      return {
        ...s,
        done: e.status,
        percent: e.status === "completed" ? 100 : s.percent,
        stages: s.stages.map((x) => (x.state === "running" ? { ...x, state: e.status === "completed" ? "done" : "failed", endedAt: a.at } : x)),
      };
    default:
      return s;
  }
}

/** Subscribe to a scan's event stream while `active` is true. */
export function useScanEvents(scanId: string | undefined, active: boolean): LiveScan {
  const [state, dispatch] = useReducer(reduceLive, undefined, init);
  useEffect(() => {
    dispatch({ kind: "reset" });
  }, [scanId]);
  useEffect(() => {
    if (!scanId || !active) return;
    return subscribeScanEvents(scanId, {
      onEvent: (e) => dispatch({ kind: "event", e, at: Date.now() }),
      onState: (s) => dispatch({ kind: "stream", s }),
    });
  }, [scanId, active]);
  return state;
}
