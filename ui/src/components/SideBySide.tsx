import { useMemo, useState } from "react";
import { Cloud, HardDrive, Lock } from "lucide-react";
import type { LedgerDetail, MarkupKind } from "@/api/types";
import { cn, shortHash } from "@/lib/format";
import { MARK_CLASS, MARK_LABEL, segmentLines, type Segment } from "@/lib/markup";
import { Callout, Segmented } from "@/components/ui";

function Pane({
  title,
  icon,
  note,
  lines,
  tone,
}: {
  title: string;
  icon: React.ReactNode;
  note: string;
  lines: Segment[][];
  tone: "local" | "remote";
}) {
  const width = String(lines.length).length;
  return (
    <div className="flex min-w-0 flex-col overflow-hidden rounded-lg border border-border">
      <div
        className={cn(
          "flex items-center gap-2 border-b border-border px-3 py-2",
          tone === "local" ? "bg-success-soft/50" : "bg-info-soft/50",
        )}
      >
        {icon}
        <div className="min-w-0">
          <p className="text-sm font-semibold text-fg">{title}</p>
          <p className="text-xs text-fg-muted">{note}</p>
        </div>
      </div>
      <pre className="flex-1 overflow-auto bg-code-bg py-2 font-mono text-[12.5px] leading-[21px]">
        {lines.map((segs, i) => (
          <div key={i} className="flex min-w-max pr-4">
            <span aria-hidden className="select-none pl-3 pr-3 text-right text-code-gutter" style={{ minWidth: `calc(${width}ch + 1.5rem)` }}>
              {i + 1}
            </span>
            <span className="whitespace-pre text-fg">
              {segs.length === 0
                ? " "
                : segs.map((s, j) =>
                    s.kind ? (
                      <mark key={j} className={cn("rounded-sm px-px", MARK_CLASS[s.kind])} title={s.label ? `${MARK_LABEL[s.kind]}: ${s.label}` : MARK_LABEL[s.kind]}>
                        {s.text}
                      </mark>
                    ) : (
                      <span key={j}>{s.text}</span>
                    ),
                  )}
            </span>
          </div>
        ))}
      </pre>
    </div>
  );
}

export function MarkLegend() {
  return (
    <ul className="flex flex-wrap gap-3 text-xs" aria-label="Markup legend">
      {(Object.keys(MARK_LABEL) as MarkupKind[]).map((k) => (
        <li key={k} className="flex items-center gap-1.5 text-fg-muted">
          <mark className={cn("rounded-sm px-1.5 font-mono", MARK_CLASS[k])}>abc</mark>
          {MARK_LABEL[k]}
        </li>
      ))}
    </ul>
  );
}

/**
 * Original slice (stays local) next to the exact payload the provider
 * received. Rendered as text only; no mapping between pseudonyms and names is
 * shown or exported.
 */
export function SideBySide({ detail }: { detail: LedgerDetail }) {
  const [view, setView] = useState<"split" | "payload">("split");
  const hasOriginal = !!detail.original_text;
  const blocked = (detail.entry.outcome ?? "").startsWith("blocked");
  const original = useMemo(
    () => segmentLines(detail.original_text ?? "", detail.markup.filter((m) => m.side === "original")),
    [detail],
  );
  const payload = useMemo(
    () => segmentLines(detail.payload_text ?? "", detail.markup.filter((m) => m.side === "payload")),
    [detail],
  );
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <MarkLegend />
        {hasOriginal && (
          <Segmented
            label="Viewer layout"
            value={view}
            onChange={setView}
            options={[
              { value: "split", label: "Side by side" },
              { value: "payload", label: "Payload only" },
            ]}
          />
        )}
      </div>
      {!hasOriginal && (
        <Callout tone="info" icon={<Lock className="h-4 w-4" />} title="Original code not shown">
          Reading the original side requires the Auditor role or higher. The payload below is exactly what the provider received.
        </Callout>
      )}
      <div className={cn("grid gap-3", hasOriginal && view === "split" ? "lg:grid-cols-2" : "grid-cols-1")}>
        {hasOriginal && view === "split" && (
          <Pane
            title="Original (stays on this machine)"
            note="Your source as analysed locally"
            icon={<HardDrive className="h-4 w-4 text-success" aria-hidden />}
            lines={original}
            tone="local"
          />
        )}
        <Pane
          title={blocked ? "Payload (blocked before egress, never sent)" : "Payload (what the provider received)"}
          note={`${detail.entry.provider} · ${detail.entry.model} · sha256 ${shortHash(detail.entry.payload_hash, 12)}`}
          icon={<Cloud className="h-4 w-4 text-info" aria-hidden />}
          lines={payload}
          tone="remote"
        />
      </div>
    </div>
  );
}
