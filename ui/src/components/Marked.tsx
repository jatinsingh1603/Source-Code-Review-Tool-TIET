import type { ReactNode } from "react";
import type { Markup } from "@/api/types";
import { segmentLines, type Segment } from "@/lib/markup";
import { PAYLOAD_HEADER } from "@/lib/display";
import { CodeBlock, type CodeLineInput, type LineKind } from "@/components/ui";

const MARK_CLASS: Record<string, string> = { secret: "rd", pii: "rd", identifier: "rn", literal: "gen" };

/** One line of privacy markup: `.rd` redacted, `.rn` renamed, `.gen` generalised. Text only. */
export function Segments({ segs, onIdent }: { segs: Segment[]; onIdent?: (s: Segment) => ReactNode }) {
  return (
    <>
      {segs.map((s, i) => {
        if (!s.kind) return <span key={i}>{s.text}</span>;
        const cls = MARK_CLASS[s.kind];
        if (s.kind === "identifier" && onIdent) return <span key={i}>{onIdent(s)}</span>;
        return (
          <span key={i} className={cls} title={s.label ? s.label : undefined}>
            {s.text}
          </span>
        );
      })}
    </>
  );
}

/**
 * Code with privacy markup applied (payload or original side), rendered with
 * the design's code viewer. Lines are numbered from `startLine`.
 */
export function MarkedCode({
  text,
  markup,
  side,
  startLine = 1,
  kindOf,
  title,
  titleRight,
  after,
  style,
}: {
  text: string;
  markup: Markup[];
  side: "original" | "payload";
  startLine?: number;
  kindOf?: (n: number) => LineKind;
  title?: ReactNode;
  titleRight?: ReactNode;
  after?: (line: CodeLineInput) => ReactNode;
  style?: React.CSSProperties;
}) {
  const lines = segmentLines(text.replace(/\n$/, ""), markup.filter((m) => m.side === side));
  const rows = lines.map((_, i) => ({ number: startLine + i, text: "" }));
  return (
    <CodeBlock
      lines={rows}
      kindOf={kindOf}
      title={title}
      titleRight={titleRight}
      after={after}
      style={style}
      renderLine={(r) => {
        const segs = lines[r.number - startLine] ?? [];
        if (side === "payload" && PAYLOAD_HEADER.test(segs.map((s) => s.text).join(""))) {
          return <span className="tc">{segs.map((s) => s.text).join("")}</span>;
        }
        return <Segments segs={segs} />;
      }}
    />
  );
}

/** Counts of markup on the payload side, by design category. */
export function markupCounts(markup: Markup[]): { renamed: number; redacted: number; generalised: number } {
  const pay = markup.filter((m) => m.side === "payload");
  return {
    renamed: pay.filter((m) => m.kind === "identifier").length,
    redacted: pay.filter((m) => m.kind === "secret" || m.kind === "pii").length,
    generalised: pay.filter((m) => m.kind === "literal").length,
  };
}

export function MarkupLegend() {
  return (
    <div className="legend">
      <span>
        <span className="rd">red</span> redacted secret
      </span>
      <span>
        <span className="rn">blue</span> renamed identifier
      </span>
      <span>
        <span className="gen">grey italic</span> generalised string or comment
      </span>
      <span>
        <span className="fold" style={{ margin: 0, display: "inline-flex" }}>
          dashed
        </span>{" "}
        not sent
      </span>
    </div>
  );
}
