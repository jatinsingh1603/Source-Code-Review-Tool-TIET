import { useState, type ReactNode } from "react";
import { Check, ChevronDown, ChevronUp, Copy } from "lucide-react";
import { cn } from "@/lib/format";

export interface CodeLineInput {
  number: number;
  text: string;
}

export interface CodeBlockProps {
  /** Either plain text (numbered from `startLine`) or explicit numbered lines. */
  code?: string;
  lines?: CodeLineInput[];
  startLine?: number;
  /** Inclusive line ranges to highlight, in file line numbers. */
  highlight?: { start: number; end: number }[];
  /** Optional title bar text, usually the file path. */
  title?: ReactNode;
  language?: string;
  /** Collapse to this many pixels with an expand control. */
  maxHeight?: number;
  className?: string;
  /** Per-line decoration (e.g. redaction spans); must return text nodes only. */
  renderLine?: (line: CodeLineInput) => ReactNode;
  copyable?: boolean;
}

/**
 * Renders code as text with a line-number gutter and highlighted ranges.
 * It never accepts HTML: everything is rendered through React text nodes.
 */
export function CodeBlock({
  code,
  lines,
  startLine = 1,
  highlight = [],
  title,
  language,
  maxHeight,
  className,
  renderLine,
  copyable = true,
}: CodeBlockProps) {
  const rows: CodeLineInput[] =
    lines ?? (code ?? "").replace(/\n$/, "").split("\n").map((text, i) => ({ number: startLine + i, text }));
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const isHl = (n: number) => highlight.some((r) => n >= r.start && n <= r.end);
  const gutterWidth = String(rows[rows.length - 1]?.number ?? 1).length;
  const collapsible = maxHeight !== undefined && rows.length * 21 > maxHeight;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(rows.map((r) => r.text).join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className={cn("overflow-hidden rounded-lg border border-border bg-code-bg", className)}>
      {(title || copyable || language) && (
        <div className="flex items-center justify-between gap-3 border-b border-border bg-surface-2/70 px-3 py-1.5">
          <div className="min-w-0 truncate font-mono text-xs text-fg-muted">{title}</div>
          <div className="flex items-center gap-2">
            {language && <span className="text-xs uppercase tracking-wide text-fg-subtle">{language}</span>}
            {copyable && (
              <button
                type="button"
                onClick={copy}
                className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-fg-muted hover:bg-surface-3 hover:text-fg"
                aria-label="Copy code as text"
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "Copied" : "Copy"}
              </button>
            )}
          </div>
        </div>
      )}
      <div
        className="overflow-auto"
        style={collapsible && !expanded ? { maxHeight } : undefined}
      >
        <pre className="min-w-full py-2 font-mono text-[12.5px] leading-[21px]">
          <code>
            {rows.map((r) => {
              const hl = isHl(r.number);
              return (
                <div
                  key={r.number}
                  data-line={r.number}
                  data-highlighted={hl || undefined}
                  className={cn(
                    "flex min-w-max border-l-[3px] pr-4",
                    hl ? "border-code-hl-border bg-code-hl" : "border-transparent",
                  )}
                >
                  <span
                    aria-hidden
                    className="sticky left-0 select-none bg-inherit pl-3 pr-4 text-right text-code-gutter"
                    style={{ minWidth: `${gutterWidth + 3}ch` }}
                  >
                    {r.number}
                  </span>
                  <span className="whitespace-pre text-fg">{renderLine ? renderLine(r) : r.text || " "}</span>
                </div>
              );
            })}
          </code>
        </pre>
      </div>
      {collapsible && (
        <button
          type="button"
          onClick={() => setExpanded((x) => !x)}
          className="flex w-full items-center justify-center gap-1 border-t border-border bg-surface-2/60 py-1.5 text-xs font-medium text-fg-muted hover:text-fg"
        >
          {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          {expanded ? "Collapse" : `Show all ${rows.length} lines`}
        </button>
      )}
    </div>
  );
}
