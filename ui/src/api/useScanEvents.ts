import { useEffect, useReducer } from "react";
import { subscribeScanEvents, type StreamState } from "./events";
import type { ScanEvent, ScanStatus, Severity } from "./types";

/** Display groups of the pipeline, in order. Real stage names map onto them via `groupOf`. */
export const DEFAULT_STAGES = [
  "ingest",
  "parse",
  "analyse",
  "aggregate",
  "privacy-prepare",
  "llm-review",
  "restore",
  "rate",
  "privacy-check",
  "report",
];

/** `intake` belongs to ingest; `analyse-rules`, `analyse-taint`, ... to analyse. */
export function groupOf(stage: string): string {
  if (stage === "intake") return "ingest";
  if (stage.startsWith("analyse")) return "analyse";
  return stage;
}

export type StageState = "pending" | "running" | "done" | "skipped" | "failed";

interface RawStage {
  state: StageState;
  startedAt?: number;
  endedAt?: number;
}

export interface StageView {
  name: string;
  state: StageState;
  startedAt?: number;
  endedAt?: number;
  members: string[];
}

export interface LiveScan {
  raw: Record<string, RawStage>;
  order: string[];
  stages: StageView[];
  percent: number | null;
  message: string | null;
  logs: { at: number; level: string; message: string }[];
  findings: { id: string; severity: Severity; title: string }[];
  done: ScanStatus | null;
  stream: StreamState;
}

type Action = { kind: "event"; e: ScanEvent; at: number } | { kind: "stream"; s: StreamState } | { kind: "reset" };

const init = (): LiveScan => ({
  raw: {},
  order: [],
  stages: groupStages({}, [], null),
  percent: null,
  message: null,
  logs: [],
  findings: [],
  done: null,
  stream: "connecting",
});

function toState(status: string): StageState {
  if (status === "started" || status === "running") return "running";
  if (status === "completed" || status === "done" || status === "ok") return "done";
  if (status === "skipped") return "skipped";
  if (status === "failed" || status === "error") return "failed";
  return "running";
}

/** Fold raw stage states into display groups. */
export function groupStages(raw: Record<string, RawStage>, order: string[], done: ScanStatus | null): StageView[] {
  const groups = [...DEFAULT_STAGES];
  for (const name of order) {
    const g = groupOf(name);
    if (!groups.includes(g)) groups.push(g);
  }
  return groups.map((g) => {
    const members = order.filter((n) => groupOf(n) === g);
    const states = members.map((m) => raw[m]!);
    let state: StageState = "pending";
    if (states.some((s) => s.state === "running")) state = "running";
    else if (states.some((s) => s.state === "failed")) state = "failed";
    else if (states.length && states.every((s) => s.state === "skipped")) state = "skipped";
    else if (states.length && states.every((s) => s.state === "done" || s.state === "skipped")) state = "done";
    if (state === "pending" && done) state = done === "completed" ? "skipped" : "pending";
    const starts = states.map((s) => s.startedAt).filter((x): x is number => x !== undefined);
    const ends = states.map((s) => s.endedAt).filter((x): x is number => x !== undefined);
    return {
      name: g,
      state,
      members,
      startedAt: starts.length ? Math.min(...starts) : undefined,
      endedAt: ends.length && state !== "running" ? Math.max(...ends) : undefined,
    };
  });
}

export function reduceLive(s: LiveScan, a: Action): LiveScan {
  if (a.kind === "reset") return init();
  if (a.kind === "stream") return { ...s, stream: a.s };
  const e = a.e;
  switch (e.type) {
    case "stage": {
      const st = toState(e.status);
      const prev = s.raw[e.name];
      const raw = {
        ...s.raw,
        [e.name]: {
          state: st,
          startedAt: prev?.startedAt ?? a.at,
          endedAt: st === "running" ? undefined : a.at,
        },
      };
      const order = s.order.includes(e.name) ? s.order : [...s.order, e.name];
      return { ...s, raw, order, stages: groupStages(raw, order, s.done) };
    }
    case "progress":
      return { ...s, percent: e.percent, message: e.message ?? s.message };
    case "log":
      return { ...s, logs: [...s.logs.slice(-499), { at: a.at, level: e.level, message: e.message }] };
    case "finding":
      if (s.findings.some((f) => f.id === e.id)) return s;
      return { ...s, findings: [...s.findings, { id: e.id, severity: e.severity, title: e.title }] };
    case "done": {
      const raw = Object.fromEntries(
        Object.entries(s.raw).map(([k, v]) => [
          k,
          v.state === "running" ? { ...v, state: (e.status === "completed" ? "done" : "failed") as StageState, endedAt: a.at } : v,
        ]),
      );
      return {
        ...s,
        raw,
        done: e.status,
        percent: e.status === "completed" ? 100 : s.percent,
        stages: groupStages(raw, s.order, e.status),
      };
    }
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
