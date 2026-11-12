/**
 * Server-sent events for a running scan (`GET /scans/{id}/events`).
 *
 * `EventSource` cannot send an Authorization header, so the stream is read
 * with `fetch` and parsed here. The reader resumes with `Last-Event-ID`,
 * reconnects with exponential backoff, and after three consecutive failures
 * reports `fallback` so the caller can switch to polling the scan summary.
 */
import { api } from "./client";
import type { ScanEvent } from "./types";

export interface SseMessage {
  id?: string;
  event: string;
  data: string;
}

/** Incremental parser for the `text/event-stream` format. */
export class SseParser {
  private buffer = "";
  private id: string | undefined;
  private event = "";
  private data: string[] = [];

  push(chunk: string): SseMessage[] {
    this.buffer += chunk;
    const out: SseMessage[] = [];
    let idx: number;
    while ((idx = this.buffer.search(/\r\n|\n|\r/)) >= 0) {
      const line = this.buffer.slice(0, idx);
      const nl = this.buffer.startsWith("\r\n", idx) ? 2 : 1;
      this.buffer = this.buffer.slice(idx + nl);
      if (line === "") {
        if (this.data.length > 0) {
          out.push({ id: this.id, event: this.event || "message", data: this.data.join("\n") });
        }
        this.event = "";
        this.data = [];
        continue;
      }
      if (line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "data") this.data.push(value);
      else if (field === "event") this.event = value;
      else if (field === "id") this.id = value;
    }
    return out;
  }
}

/** Convert a raw SSE message into a typed scan event, or null if unknown. */
export function toScanEvent(msg: SseMessage): ScanEvent | null {
  let data: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(msg.data);
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    data = { message: msg.data };
  }
  const type = (msg.event !== "message" ? msg.event : (data.type as string)) ?? "message";
  switch (type) {
    case "stage":
      return { type, name: String(data.name ?? data.stage ?? ""), status: String(data.status ?? "") };
    case "progress":
      return {
        type,
        percent: Number(data.percent ?? data.progress ?? 0),
        message: data.message !== undefined ? String(data.message) : undefined,
      };
    case "log":
      return { type, level: String(data.level ?? "info"), message: String(data.message ?? "") };
    case "finding":
      return {
        type,
        id: String(data.id ?? ""),
        severity: (data.severity as ScanEvent & { type: "finding" })["severity"] ?? "info",
        title: String(data.title ?? ""),
      };
    case "done":
      return { type, status: (data.status as "completed") ?? "completed" };
    default:
      return null;
  }
}

export type StreamState = "connecting" | "open" | "reconnecting" | "fallback" | "closed";

export interface SubscribeOptions {
  onEvent: (e: ScanEvent) => void;
  onState?: (s: StreamState) => void;
  /** Base delay of the exponential backoff in ms (tests shorten it). */
  baseDelayMs?: number;
  maxFailures?: number;
  fetchImpl?: typeof fetch;
}

/** Mock mode registers a generator here instead of a network stream. */
export type MockStream = (scanId: string, emit: (e: ScanEvent) => void) => () => void;
let mockStream: MockStream | null = null;
export function setMockStream(s: MockStream | null): void {
  mockStream = s;
}

export function subscribeScanEvents(scanId: string, opts: SubscribeOptions): () => void {
  const { onEvent, onState = () => {}, baseDelayMs = 1000, maxFailures = 3 } = opts;
  if (mockStream) {
    onState("open");
    const stop = mockStream(scanId, (e) => {
      onEvent(e);
      if (e.type === "done") onState("closed");
    });
    return () => {
      stop();
    };
  }
  const fetchImpl = opts.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  let stopped = false;
  let failures = 0;
  let lastId: string | undefined;
  let controller: AbortController | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const connect = async (): Promise<void> => {
    if (stopped) return;
    onState(failures === 0 ? "connecting" : "reconnecting");
    controller = new AbortController();
    const headers: Record<string, string> = { Accept: "text/event-stream", ...api.authHeaders() };
    if (lastId !== undefined) headers["Last-Event-ID"] = lastId;
    let finished = false;
    try {
      const res = await fetchImpl(api.url(`/scans/${encodeURIComponent(scanId)}/events`), {
        headers,
        signal: controller.signal,
        credentials: "same-origin",
      });
      if (!res.ok || !res.body) throw new Error(`stream status ${res.status}`);
      onState("open");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SseParser();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = typeof value === "string" ? value : decoder.decode(value, { stream: true });
        for (const msg of parser.push(chunk)) {
          if (msg.id !== undefined) lastId = msg.id;
          const ev = toScanEvent(msg);
          if (!ev) continue;
          failures = 0;
          onEvent(ev);
          if (ev.type === "done") finished = true;
        }
        if (finished) break;
      }
      if (!finished) failures += 1;
    } catch (e) {
      if (stopped) return;
      failures += 1;
      void e;
    }
    if (stopped) return;
    if (finished) {
      stopped = true;
      onState("closed");
      controller?.abort();
      return;
    }
    if (failures >= maxFailures) {
      onState("fallback");
      return;
    }
    const delay = baseDelayMs * 2 ** Math.max(0, failures - 1);
    onState("reconnecting");
    timer = setTimeout(() => void connect(), delay);
  };

  void connect();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    controller?.abort();
  };
}
