import { useEffect, useRef, useState } from "react";
import { subscribeScanEvents, type StreamState } from "@/api/events";
import type { ScanEvent } from "@/api/types";

export type Ev = ScanEvent & { t: number };

/**
 * Collect a scan's events: the server replays history, then streams until `done`.
 * For a scan that has already ended (`settled`), the replay is held back until it
 * is complete, so the pipeline and the log do not show every stage as skipped
 * and then count up through the history; `ready` says when it is in.
 */
export function useScanTimeline(scanId: string | undefined, enabled: boolean, settled: boolean) {
  const [events, setEvents] = useState<Ev[]>([]);
  const [stream, setStream] = useState<StreamState>("connecting");
  const [replayed, setReplayed] = useState(false);
  const settledRef = useRef(settled);
  settledRef.current = settled;
  useEffect(() => {
    setEvents([]);
    setReplayed(false);
    if (!scanId || !enabled) return;
    const buf: Ev[] = [];
    let raf: number | null = null;
    const flush = () => {
      if (raf !== null) clearTimeout(raf);
      raf = null;
      setEvents([...buf]);
    };
    const stop = subscribeScanEvents(scanId, {
      onEvent: (e) => {
        const t = e.at ? Date.parse(e.at) : Date.now();
        buf.push({ ...e, t: Number.isNaN(t) ? Date.now() : t });
        if (e.type === "done") {
          flush();
          setReplayed(true);
        } else if (!settledRef.current && raf === null) raf = window.setTimeout(flush, 80) as unknown as number;
      },
      onState: (s) => {
        setStream(s);
        // The stream ended without a `done` (or gave up): show what arrived.
        if (s === "closed" || s === "fallback") {
          flush();
          setReplayed(true);
        }
      },
    });
    return () => {
      stop();
      if (raf !== null) clearTimeout(raf);
    };
  }, [scanId, enabled]);
  return { events, stream, ready: !settled || replayed };
}
