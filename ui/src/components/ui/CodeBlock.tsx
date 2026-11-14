import type { CSSProperties, ReactNode } from "react";
import { cn } from "@/lib/format";

export interface CodeLineInput {
  number: number;
  text: string;
}

export type LineKind = "hl" | "src" | "sink" | "out" | "diff-add" | "diff-del" | undefined;

export interface CodeBlockProps {
  /** Either plain text (numbered from `startLine`) or explicit numbered lines. */
  code?: string;
  lines?: CodeLineInput[];
  startLine?: number;
  /** Inclusive line ranges to highlight (`.ln.hl`), in file line numbers. */
  highlight?: { start: number; end: number }[];
  /** Per-line kind, overriding `highlight` (source, sink, out of slice, diff). */
  kindOf?: (n: number) => LineKind;
  /** Optional `.code-h` header: left and right parts. */
  title?: ReactNode;
  titleRight?: ReactNode;
  className?: string;
  style?: CSSProperties;
  /** Per-line decoration (e.g. privacy markup); must return text nodes only. */
  renderLine?: (line: CodeLineInput) => ReactNode;
  /** Extra rows rendered after a line (folds, vault tooltips). */
  after?: (line: CodeLineInput) => ReactNode;
  /** Id prefix for line anchors, e.g. `L` gives `id="L58"`. */
  anchor?: string;
  /** Accessible name of the scrollable code region; defaults to a string `title`. */
  label?: string;
}

/**
 * Code viewer (`.code`, COMPONENTS.md §13). Renders code as text with a line
 * number gutter; it never accepts HTML.
 */
export function CodeBlock({
  code,
  lines,
  startLine = 1,
  highlight = [],
  kindOf,
  title,
  titleRight,
  className,
  style,
  renderLine,
  after,
  anchor,
  label,
}: CodeBlockProps) {
  const rows: CodeLineInput[] =
    lines ?? (code ?? "").replace(/\n$/, "").split("\n").map((text, i) => ({ number: startLine + i, text }));
  const isHl = (n: number) => highlight.some((r) => n >= r.start && n <= r.end);
  return (
    <div>
      {(title || titleRight) && (
        <div className="code-h">
          <span>{title}</span>
          {titleRight}
        </div>
      )}
      <div
        className={cn("code", className)}
        style={style}
        tabIndex={0}
        role="region"
        aria-label={label ?? (typeof title === "string" ? title : "Code")}
      >
        {rows.map((r) => {
          const kind = kindOf?.(r.number) ?? (isHl(r.number) ? "hl" : undefined);
          const hl = kind !== undefined && kind !== "out";
          return (
            <div key={r.number} style={{ display: "contents" }}>
              <div
                className={cn("ln", kind)}
                id={anchor ? `${anchor}${r.number}` : undefined}
                data-line={r.number}
                data-highlighted={hl || undefined}
              >
                <span className="n" aria-hidden="true">
                  {r.number}
                </span>
                {renderLine ? renderLine(r) : r.text}
              </div>
              {after?.(r)}
            </div>
          );
        })}
      </div>
    </div>
  );
}
