import type { Markup, MarkupKind } from "@/api/types";

export interface Segment {
  text: string;
  kind?: MarkupKind;
  label?: string;
}

/**
 * Split `text` into lines of segments, applying character-offset markup
 * ranges (half-open [start, end)). Overlapping ranges: the first one wins.
 * Ranges crossing a newline are split across lines.
 */
export function segmentLines(text: string, markup: Markup[]): Segment[][] {
  const ranges = [...markup]
    .filter((m) => m.end > m.start && m.start < text.length)
    .sort((a, b) => a.start - b.start);
  const owner: (Markup | undefined)[] = new Array(text.length);
  for (const r of ranges) {
    for (let i = Math.max(0, r.start); i < Math.min(text.length, r.end); i++) {
      if (owner[i] === undefined) owner[i] = r;
    }
  }
  const lines: Segment[][] = [[]];
  let cur: Segment | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === "\n") {
      cur = null;
      lines.push([]);
      continue;
    }
    const m = owner[i];
    if (cur && cur.kind === m?.kind && cur.label === m?.label) {
      cur.text += ch;
    } else {
      cur = { text: ch, kind: m?.kind, label: m?.label };
      lines[lines.length - 1]!.push(cur);
    }
  }
  return lines;
}

/** Count placeholders like `<SECRET_AWS_ACCESS_KEY_1>` in a payload, by type. */
export function countPlaceholders(payload: string): Record<string, number> {
  const out: Record<string, number> = {};
  const seen = new Set<string>();
  for (const m of payload.matchAll(/<([A-Z][A-Z0-9_]*?)_(\d+)>/g)) {
    const full = m[0];
    if (seen.has(full)) continue;
    seen.add(full);
    const type = m[1]!;
    out[type] = (out[type] ?? 0) + 1;
  }
  return out;
}

export const MARK_CLASS: Record<MarkupKind, string> = {
  secret: "bg-mark-secret/15 text-mark-secret ring-1 ring-inset ring-mark-secret/40",
  pii: "bg-mark-pii/15 text-mark-pii ring-1 ring-inset ring-mark-pii/40",
  identifier: "bg-mark-identifier/15 text-mark-identifier",
  literal: "bg-mark-literal/15 text-mark-literal",
};

export const MARK_LABEL: Record<MarkupKind, string> = {
  secret: "Secret",
  pii: "Personal data",
  identifier: "Identifier",
  literal: "Literal / comment",
};
